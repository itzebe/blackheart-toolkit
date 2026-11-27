"""Durable, deduplicating state for the bounty watchtower.

The state is one JSON document, written atomically (temp file + ``os.replace``)
under an advisory file lock, so a crash mid-write cannot leave a half-valid
baseline and two overlapping runs cannot interleave. It holds:

* the last observation of every policy page, repository and contract,
* every event id already reported (so a restart does not re-notify), and
* per-source failure counters for honest retry/backoff reporting.

A corrupt or missing state file is *not* an error: it is reported as a warning
and treated as an empty baseline, which makes the next cycle a full baseline
observation rather than a false "no change".
"""

from __future__ import annotations

import json
import os
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator, Optional

from ..models import utcnow

__all__ = ["STATE_VERSION", "WatchState", "state_path"]

STATE_VERSION = 1
_MAX_SEEN = 10_000


def state_path(directory: str | Path) -> Path:
    return Path(directory) / "state.json"


class WatchState:
    """The watchtower's durable memory."""

    def __init__(self, path: str | Path, data: Optional[dict] = None,
                 warning: str = "") -> None:
        self.path = Path(path)
        self.warning = warning
        self.data: dict[str, Any] = data if data is not None else _empty()

    # -- lifecycle --------------------------------------------------------- #
    @classmethod
    def load(cls, directory: str | Path) -> "WatchState":
        p = state_path(directory)
        if not p.is_file():
            return cls(p)
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            return cls(p, warning=f"state unreadable ({exc}); starting a new baseline")
        if not isinstance(data, dict) or data.get("version") != STATE_VERSION:
            return cls(
                p,
                warning=(
                    f"state version {data.get('version') if isinstance(data, dict) else '?'} "
                    f"!= {STATE_VERSION}; starting a new baseline"
                ),
            )
        data.setdefault("targets", {})
        data.setdefault("seen_events", {})
        data.setdefault("failures", {})
        data.setdefault("cycles", 0)
        return cls(p, data=data)

    def save(self) -> None:
        self.data["updated_at"] = utcnow()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(prefix=".state-", suffix=".json", dir=str(self.path.parent))
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(self.data, fh, indent=2, sort_keys=True)
                fh.write("\n")
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, self.path)
        finally:
            if os.path.exists(tmp):
                try:
                    os.unlink(tmp)
                except OSError:
                    pass

    @contextmanager
    def lock(self) -> Iterator[None]:
        """Advisory exclusive lock; a no-op where ``fcntl`` is unavailable."""
        lock_file = self.path.with_suffix(".lock")
        lock_file.parent.mkdir(parents=True, exist_ok=True)
        try:
            import fcntl  # type: ignore
        except ImportError:  # pragma: no cover -- non-POSIX
            yield
            return
        with open(lock_file, "w", encoding="utf-8") as fh:
            fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(fh.fileno(), fcntl.LOCK_UN)

    # -- target records ---------------------------------------------------- #
    def target(self, slug: str) -> dict:
        targets = self.data.setdefault("targets", {})
        return targets.setdefault(
            slug, {"policy": {}, "repos": {}, "contracts": {}, "last_cycle": ""}
        )

    def policy(self, slug: str, url: str) -> dict:
        return self.target(slug).setdefault("policy", {}).get(url, {})

    def set_policy(self, slug: str, url: str, record: dict) -> None:
        self.target(slug).setdefault("policy", {})[url] = record

    def repo(self, slug: str, repo: str) -> dict:
        return self.target(slug).setdefault("repos", {}).get(repo, {})

    def set_repo(self, slug: str, repo: str, record: dict) -> None:
        self.target(slug).setdefault("repos", {})[repo] = record

    def contract(self, slug: str, key: str) -> dict:
        return self.target(slug).setdefault("contracts", {}).get(key, {})

    def set_contract(self, slug: str, key: str, record: dict) -> None:
        self.target(slug).setdefault("contracts", {})[key] = record

    def mark_cycle(self, slug: str) -> None:
        self.target(slug)["last_cycle"] = utcnow()

    # -- event dedupe ------------------------------------------------------ #
    def seen(self, event_id: str) -> bool:
        return event_id in self.data.setdefault("seen_events", {})

    def remember(self, event_id: str) -> None:
        seen = self.data.setdefault("seen_events", {})
        now = utcnow()
        entry = seen.get(event_id)
        if entry:
            entry["count"] = int(entry.get("count", 1)) + 1
            entry["last_seen"] = now
        else:
            seen[event_id] = {"first_seen": now, "last_seen": now, "count": 1}
        self._prune_seen()

    def _prune_seen(self) -> None:
        seen = self.data.get("seen_events") or {}
        if len(seen) <= _MAX_SEEN:
            return
        ordered = sorted(
            seen.items(), key=lambda kv: kv[1].get("last_seen", ""), reverse=True
        )
        self.data["seen_events"] = dict(ordered[:_MAX_SEEN])

    # -- failures ---------------------------------------------------------- #
    def record_failure(self, source: str, error: str) -> None:
        failures = self.data.setdefault("failures", {})
        entry = failures.setdefault(source, {"count": 0})
        entry["count"] = int(entry.get("count", 0)) + 1
        entry["last_error"] = error[:500]
        entry["last_seen"] = utcnow()

    def clear_failure(self, source: str) -> None:
        self.data.setdefault("failures", {}).pop(source, None)

    # -- reporting --------------------------------------------------------- #
    def begin_cycle(self) -> int:
        self.data["cycles"] = int(self.data.get("cycles", 0)) + 1
        self.data.setdefault("created_at", utcnow())
        self.data["last_cycle_at"] = utcnow()
        return self.data["cycles"]

    def summary(self) -> dict:
        targets = self.data.get("targets") or {}
        return {
            "version": self.data.get("version", STATE_VERSION),
            "cycles": self.data.get("cycles", 0),
            "last_cycle_at": self.data.get("last_cycle_at", ""),
            "targets_tracked": len(targets),
            "policy_observations": sum(len(t.get("policy") or {}) for t in targets.values()),
            "repo_observations": sum(len(t.get("repos") or {}) for t in targets.values()),
            "contract_observations": sum(
                len(t.get("contracts") or {}) for t in targets.values()
            ),
            "seen_events": len(self.data.get("seen_events") or {}),
            "failing_sources": len(self.data.get("failures") or {}),
            "warning": self.warning,
        }


def _empty() -> dict:
    now = utcnow()
    return {
        "version": STATE_VERSION,
        "created_at": now,
        "updated_at": now,
        "cycles": 0,
        "targets": {},
        "seen_events": {},
        "failures": {},
    }
