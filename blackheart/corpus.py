"""A durable, deduplicated corpus for long-running research.

Search results are only useful if the next run can see them. This store keeps
one hash-chained record per input identity, so a repeated input is returned
instead of recomputed, and the corpus can be integrity-checked like every other
BLACKHEART ledger. It is deliberately a store, not a search engine: callers
decide what an entry means.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

from .chainedlog import ChainedLog
from .parallel import map_parallel


def input_key(payload: Any) -> str:
    """A stable identity for an input, independent of dict ordering."""
    text = json.dumps(payload, sort_keys=True, default=str, separators=(",", ":"))
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


@dataclass
class CorpusEntry:
    key: str
    verdict: str
    payload: dict
    new: bool = True

    def to_dict(self) -> dict:
        return {"key": self.key, "verdict": self.verdict, "payload": self.payload,
                "new": self.new}


class CorpusStore:
    """Append-only corpus keyed by the hash of its input."""

    def __init__(self, path: str | Path) -> None:
        self.log = ChainedLog(path)

    def add(self, payload: Any, *, verdict: str, result: Optional[dict] = None,
            replace_invalidated: bool = False) -> CorpusEntry:
        key = input_key(payload)
        with self.log.transaction():
            existing = self.log.get(key)
            if existing is not None:
                if not (replace_invalidated
                        and existing.get("verdict") in ("INVALIDATED", "ERROR")):
                    return CorpusEntry(key, str(existing.get("verdict", "")),
                                       dict(existing.get("result") or {}), new=False)
            content = {"verdict": verdict, "result": dict(result or {}),
                       "input": payload}
            self.log.append(key, content)
        return CorpusEntry(key, verdict, dict(result or {}), new=True)

    def get(self, payload: Any) -> Optional[CorpusEntry]:
        key = input_key(payload)
        found = self.log.get(key)
        if found is None:
            return None
        return CorpusEntry(key, str(found.get("verdict", "")),
                           dict(found.get("result") or {}), new=False)

    def all(self) -> list[CorpusEntry]:
        return [CorpusEntry(key, str(content.get("verdict", "")),
                            dict(content.get("result") or {}), new=False)
                for key, content in sorted(self.log.state().items())]

    def pending(self, payloads: list[Any]) -> list[Any]:
        """Inputs not present, or invalidated and therefore due for a retry."""
        out = []
        for payload in payloads:
            entry = self.get(payload)
            if entry is None or entry.verdict in ("INVALIDATED", "ERROR"):
                out.append(payload)
        return out

    def invalidate(self, payload: Any, *, reason: str,
                   verdict: str = "INVALIDATED") -> CorpusEntry:
        """Supersede an entry without deleting its history."""
        key = input_key(payload)
        content = {"verdict": verdict, "result": {"reason": reason},
                   "input": payload, "invalidated": True}
        with self.log.transaction():
            self.log.append(key, content)
        return CorpusEntry(key, verdict, {"reason": reason}, new=False)

    def resume(self, payloads: list[Any], worker: Any, *, workers: int = 4) -> dict:
        """Run only unseen inputs in bounded parallel and store their results.

        A worker returns ``{"verdict": str, "result": dict}``. A worker error is
        stored as ``ERROR`` so a later run can retry it explicitly, never as a
        silent success.
        """
        missing = self.pending(payloads)
        outcomes = map_parallel(missing, worker, workers=workers)
        stored = []
        for payload, outcome in zip(missing, outcomes):
            if outcome.ok:
                value = outcome.value if isinstance(outcome.value, dict) else {}
                entry = self.add(payload, verdict=str(value.get("verdict", "DONE")),
                                 result=value.get("result") or {},
                                 replace_invalidated=True)
                stored.append(entry.to_dict())
            else:
                entry = self.add(payload, verdict="ERROR",
                                 result={"error": outcome.error})
                stored.append(entry.to_dict())
        return {"requested": len(payloads), "skipped": len(payloads) - len(missing),
                "ran": len(missing), "stored": stored}

    def export_shard(self, path: str | Path) -> dict:
        """Write the latest entries as a portable JSON shard."""
        entries = []
        for key, content in sorted(self.log.state().items()):
            entries.append({"key": key, "content": content})
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps({"format": "blackheart-corpus-shard-v1",
                                      "entries": entries}, indent=2,
                                     default=str), encoding="utf-8")
        return {"path": str(target), "entries": len(entries)}

    def merge_shard(self, path: str | Path) -> dict:
        """Merge a shard, rejecting a key that does not match its input."""
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        if data.get("format") != "blackheart-corpus-shard-v1":
            return {"ok": False, "reason": "unknown shard format", "merged": 0}
        merged = 0
        rejected = 0
        with self.log.transaction():
            for entry in data.get("entries") or []:
                key = str(entry.get("key", ""))
                content = entry.get("content") or {}
                if key != input_key(content.get("input")):
                    rejected += 1
                    continue
                if self.log.get(key) is not None:
                    continue
                self.log.append(key, content)
                merged += 1
        return {"ok": rejected == 0, "merged": merged, "rejected": rejected}

    def verify_integrity(self) -> dict:
        return self.log.verify_integrity()
