"""A tamper-evident append-only log, shared by every durable ledger.

BLACKHEART keeps three durable ledgers: scheduled jobs, research triggers, and
bounty evaluations. Each is an append-only JSONL log where every record is
hash-chained to the one before it (and HMAC-signed when a key is configured), so
deletion, reordering, insertion, or truncation is detectable by
:func:`blackheart.integrity.verify_chain`.

That property is subtle enough that it must exist **once**. This module is that
one implementation; :class:`blackheart.scheduler.store.JobStore` and the trigger
and bounty ledgers are thin replayers over it. They differ only in the *shape* of
the record they store, never in how it is chained or verified.

The on-disk wire format is unchanged from the original job store (``type`` =
``"state"``, plus ``id``/``content``/``seq``/``prev``/``content_sha256``/
``chain_sha256`` and an optional ``hmac``), so logs written before this module
existed verify with it. A ledger that needs several record kinds puts its own
discriminator inside ``content`` -- the chain never inspects it.
"""

from __future__ import annotations

import json
import os
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator, Optional

try:  # POSIX advisory locking; absent on Windows, where a single writer is assumed
    import fcntl
except ImportError:  # pragma: no cover - platform-specific
    fcntl = None  # type: ignore[assignment]

from .integrity import (
    GENESIS,
    IntegrityKey,
    chain_hash,
    content_hash,
    record_mac,
    verify_chain,
)
from .models import utcnow


class _ProcessLock:
    """One re-entrant lock per canonical log path, shared by every FileLock on it.

    The depth counter is guarded by the lock itself: ``__enter__``/``__exit__`` are
    always called while holding the RLock, so the increment and decrement are
    already serialised for the owning thread. Because the RLock is re-entrant and
    the depth is per-path (not per-instance), an inner ``FileLock`` on the same
    path sees depth > 0 and skips the OS lock.
    """

    __slots__ = ("rlock", "depth")

    def __init__(self) -> None:
        self.rlock = threading.RLock()
        self.depth = 0


_PROCESS_LOCKS: dict[str, _ProcessLock] = {}
_PROCESS_LOCKS_GUARD = threading.Lock()


def _process_lock(path: Path) -> _ProcessLock:
    key = str(path.resolve())
    with _PROCESS_LOCKS_GUARD:
        lock = _PROCESS_LOCKS.get(key)
        if lock is None:
            lock = _PROCESS_LOCKS[key] = _ProcessLock()
        return lock


class FileLock:
    """A re-entrant, cross-process exclusive lock for one log file.

    Two properties are required and neither alone is enough:

      * **In-process re-entrancy.** A caller may hold a :meth:`ChainedLog.transaction`
        and, inside it, call :meth:`ChainedLog.append` -- which also locks. A plain
        ``flock`` on a second descriptor would deadlock against itself. A
        per-path ``threading.RLock`` plus a depth counter makes the inner
        acquisition a no-op.
      * **Cross-process exclusion.** Two processes on one log must not interleave
        "read head, append". ``fcntl.flock`` on a sibling lock file gives that. On
        a platform without ``fcntl`` this degrades to in-process locking only,
        which is safe for a single writer -- the caller documents that limit.
    """

    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock = _process_lock(path)
        self._fh = None

    def __enter__(self):
        self._lock.rlock.acquire()
        self._lock.depth += 1
        if self._lock.depth == 1 and fcntl is not None:
            lockfile = self.path.with_suffix(self.path.suffix + ".lock")
            lockfile.parent.mkdir(parents=True, exist_ok=True)
            try:
                self._fh = lockfile.open("a")
                fcntl.flock(self._fh.fileno(), fcntl.LOCK_EX)
            except BaseException:
                if self._fh is not None:
                    self._fh.close()
                    self._fh = None
                self._lock.depth -= 1
                self._lock.rlock.release()
                raise
        return self

    def __exit__(self, *exc) -> None:
        if self._lock.depth == 1 and self._fh is not None:
            fcntl.flock(self._fh.fileno(), fcntl.LOCK_UN)
            self._fh.close()
            self._fh = None
        self._lock.depth -= 1
        self._lock.rlock.release()


class ChainedLog:
    """An append-only, hash-chained, replay-rebuilt JSONL log of records.

    A record is ``(record_id, content)``. Appending a new content for an existing
    ``record_id`` supersedes the earlier one on replay -- the log keeps the full
    history (every state is a link in the chain), and :meth:`state` returns the
    latest. That is what lets a caller persist successive snapshots of one job or
    one trigger without a separate "update" verb.
    """

    def __init__(
        self, path: str | os.PathLike, *, key: Optional[IntegrityKey] = None,
    ) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.key = key
        self._last_skipped = 0

    # -- locking -------------------------------------------------------- #
    def _locked(self) -> "FileLock":
        return FileLock(self.path)

    @contextmanager
    def transaction(self):
        """Hold the log lock across a read-modify-append sequence.

        Callers that must decide *from the log's current state* and then append --
        dedupe, "is this the first accept", a rate-limit count -- need the read and
        the write to be one atomic step. Without this, two threads both read "no
        duplicate" and both append, which is exactly how a duplicate job is created
        under concurrent delivery. ``append`` re-enters the same lock, so calling it
        inside a transaction is safe and cheap.
        """
        with self._locked():
            yield self

    # -- low level ------------------------------------------------------ #
    def _append_line(self, event: dict) -> None:
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps({"at": utcnow(), **event}, default=str) + "\n")

    def events(self) -> list[dict]:
        events: list[dict] = []
        skipped = 0
        if not self.path.exists():
            self._last_skipped = 0
            return events
        for line in self.path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                # A process killed mid-write leaves a truncated final line. Skip
                # it, but count it so ``corruption_report`` surfaces the loss.
                skipped += 1
        self._last_skipped = skipped
        return events

    def corruption_report(self) -> dict:
        self.events()
        n = self._last_skipped
        return {"skipped_lines": n, "ok": n == 0}

    def _state_events(self) -> Iterator[dict]:
        for ev in self.events():
            if ev.get("type") == "state" and ev.get("content"):
                yield ev

    # -- head ----------------------------------------------------------- #
    def _head(self) -> tuple[int, str]:
        seq = 0
        prev = GENESIS
        for ev in self._state_events():
            prev = ev.get("chain_sha256") or chain_hash(
                ev.get("seq", seq), prev, content_hash(ev["content"])
            )
            seq = ev.get("seq", seq) + 1
        return seq, prev

    def head(self) -> tuple[int, str]:
        """The ``(head_seq, head_chain)`` of the log -- what a checkpoint pins."""
        seq, prev = self._head()
        return seq - 1, prev

    # -- append --------------------------------------------------------- #
    def append(self, record_id: str, content: dict) -> None:
        """Append a hash-chained snapshot of *content* under *record_id*."""
        with self._locked():
            seq, prev = self._head()
            ch = content_hash(content)
            chain = chain_hash(seq, prev, ch)
            event = {
                "type": "state", "id": record_id, "content": content,
                "seq": seq, "prev": prev, "content_sha256": ch,
                "chain_sha256": chain,
            }
            if self.key is not None:
                event["hmac"] = record_mac(self.key, seq, prev, ch)
                event["key_id"] = self.key.key_id
            self._append_line(event)

    # -- replay --------------------------------------------------------- #
    def state(self) -> dict[str, dict]:
        """Replay into the latest content of every record id."""
        out: dict[str, dict] = {}
        for ev in self._state_events():
            out[ev.get("id", "")] = ev["content"]
        return out

    def get(self, record_id: str) -> Optional[dict]:
        return self.state().get(record_id)

    # -- integrity ------------------------------------------------------ #
    def verify_integrity(
        self, *, key: Optional[IntegrityKey] = None,
        require_signatures: bool = False, checkpoint: Any = None,
    ) -> dict:
        result = verify_chain(
            self.path, key=key or self.key,
            require_signatures=require_signatures, checkpoint=checkpoint,
        )
        return result.to_dict()


__all__ = ["ChainedLog", "FileLock"]
