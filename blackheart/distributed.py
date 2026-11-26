"""A file-backed work queue with leases, epochs and stale-lease recovery.

The corpus shards are portable, but several workers on one shared filesystem
still need to agree on who owns a key. This module is that agreement: a
hash-chained queue where a claim is a lease with a monotonic epoch, a completion
is fenced by the epoch it was claimed under, and an expired lease can be
recovered by another worker.

It is a shared-filesystem protocol, not a network service. Two processes on the
same host or volume get mutual exclusion from :class:`~blackheart.chainedlog.FileLock`;
processes on different volumes do not share a queue.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from .chainedlog import ChainedLog


@dataclass(frozen=True)
class Lease:
    key: str
    worker: str
    epoch: int
    expires: float

    def to_dict(self) -> dict:
        return {"key": self.key, "worker": self.worker, "epoch": self.epoch,
                "expires": self.expires}


@dataclass
class QueueStats:
    pending: int = 0
    leased: int = 0
    done: int = 0
    dead: int = 0

    def to_dict(self) -> dict:
        return {"pending": self.pending, "leased": self.leased,
                "done": self.done, "dead": self.dead}


class LeaseQueue:
    """Claim, complete and recover keys with an epoch-fenced lease."""

    def __init__(self, path: str | Path, *, ttl: float = 300.0,
                 max_attempts: int = 3) -> None:
        self.log = ChainedLog(path)
        self.ttl = float(ttl)
        self.max_attempts = max(1, int(max_attempts))

    def _now(self, now: Optional[float]) -> float:
        return time.time() if now is None else float(now)

    def _active(self, record: dict, now: float) -> bool:
        return (record.get("status") == "leased"
                and float(record.get("expires", 0)) > now)

    def claim(self, worker: str, keys: list[str], *, limit: int = 1,
              now: Optional[float] = None) -> list[Lease]:
        """Lease up to ``limit`` keys that are pending or whose lease expired."""
        if not worker:
            raise ValueError("worker name is required")
        now = self._now(now)
        claimed: list[Lease] = []
        claimed_keys: set[str] = set()
        with self.log.transaction():
            state = self.log.state()
            for key in keys:
                if len(claimed) >= max(0, limit):
                    break
                if key in claimed_keys:
                    continue
                record = state.get(key) or {}
                if record.get("status") in ("done", "dead"):
                    continue
                if self._active(record, now):
                    continue
                epoch = int(record.get("epoch", 0)) + 1
                expires = now + self.ttl
                content = {"status": "leased", "key": key, "worker": worker,
                           "epoch": epoch, "expires": expires,
                           "attempts": int(record.get("attempts", 0))}
                self.log.append(key, content)
                claimed_keys.add(key)
                claimed.append(Lease(key, worker, epoch, expires))
        return claimed

    def _fenced(self, key: str, worker: str, epoch: int,
                now: float) -> tuple[Optional[dict], str]:
        record = self.log.state().get(key)
        if record is None:
            return None, "unknown key"
        if record.get("status") != "leased":
            return record, f"key is {record.get('status')}"
        if record.get("worker") != worker:
            return record, "lease is held by another worker"
        if int(record.get("epoch", 0)) != int(epoch):
            return record, "lease epoch is stale"
        if float(record.get("expires", 0)) <= now:
            return record, "lease has expired"
        return record, ""

    def complete(self, worker: str, key: str, epoch: int, *, verdict: str,
                 result: Optional[dict] = None, now: Optional[float] = None) -> dict:
        """Complete a key only under the lease and epoch that claimed it."""
        now = self._now(now)
        with self.log.transaction():
            record, reason = self._fenced(key, worker, epoch, now)
            if reason:
                return {"ok": False, "reason": reason, "key": key}
            self.log.append(key, {
                "status": "done", "key": key, "worker": worker,
                "epoch": int(epoch), "verdict": verdict,
                "result": dict(result or {}), "completed_at": now,
                "attempts": int((record or {}).get("attempts", 0)),
            })
        return {"ok": True, "key": key, "verdict": verdict}

    def fail(self, worker: str, key: str, epoch: int, *, error: str,
             now: Optional[float] = None) -> dict:
        """Return a failed lease to pending, or mark it dead after max attempts."""
        now = self._now(now)
        with self.log.transaction():
            record, reason = self._fenced(key, worker, epoch, now)
            if reason:
                return {"ok": False, "reason": reason, "key": key}
            attempts = int((record or {}).get("attempts", 0)) + 1
            status = "dead" if attempts >= self.max_attempts else "pending"
            self.log.append(key, {
                "status": status, "key": key, "attempts": attempts,
                "last_error": error, "epoch": int(epoch),
            })
        return {"ok": True, "key": key, "status": status, "attempts": attempts}

    def recover_stale(self, keys: list[str], *, now: Optional[float] = None) -> dict:
        """Release expired leases so another worker can claim them."""
        now = self._now(now)
        recovered = []
        with self.log.transaction():
            state = self.log.state()
            for key in keys:
                record = state.get(key) or {}
                if (record.get("status") == "leased"
                        and float(record.get("expires", 0)) <= now):
                    self.log.append(key, {
                        "status": "pending", "key": key,
                        "attempts": int(record.get("attempts", 0)),
                        "recovered_from": record.get("worker", ""),
                        "epoch": int(record.get("epoch", 0)),
                    })
                    recovered.append(key)
        return {"recovered": recovered, "count": len(recovered)}

    def pending(self, keys: list[str], *, now: Optional[float] = None) -> list[str]:
        now = self._now(now)
        state = self.log.state()
        out = []
        for key in keys:
            record = state.get(key) or {}
            if record.get("status") in ("done", "dead"):
                continue
            if not self._active(record, now):
                out.append(key)
        return out

    def stats(self) -> QueueStats:
        out = QueueStats()
        for record in self.log.state().values():
            status = record.get("status")
            if status in ("pending", "leased", "done", "dead"):
                setattr(out, status, getattr(out, status) + 1)
        return out

    def verify_integrity(self) -> dict:
        return self.log.verify_integrity()
