"""Resumable research queue (mission Phase 8).

A persistent, crash-safe queue of research tasks. Each entry is one authorized
(target, asset) plus the budget, completion criteria, and progress needed to pick
the work up again after a restart -- including after the sandbox that created it
disappears.

Design rules the mission demands:

  * **Authorization is re-checked on every dequeue.** An entry only runs while its
    recorded authorization still passes the gate (asset AUTHORIZED, evidence fresh,
    program checks intact). A stale or revoked scope is moved to BLOCKED, never
    run -- this is how a closed program stops affected testing immediately.
  * **Bounded.** Every entry carries an attempt budget. A target that exhausts its
    budget without progress is BLOCKED, so the queue cannot loop forever.
  * **Completion criteria are explicit.** An entry completes when its hypothesis is
    CONFIRMED and reported, or DISPROVEN, or the budget is spent.
  * **Recoverable.** State is an append-only JSONL log; the queue is rebuilt by
    replay, so a restart loses nothing.

The queue stores state; it does not perform the research. The campaign/hypothesis
engine does that, and reports the outcome back here.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Optional

from ..authz import authorize_active_testing, evidence_age
from ..models import AuthorizationRecord, utcnow
from ..objectives import TargetProfile


class QueueState:
    PENDING = "PENDING"
    IN_PROGRESS = "IN_PROGRESS"
    BLOCKED = "BLOCKED"
    COMPLETED = "COMPLETED"
    ABANDONED = "ABANDONED"


@dataclass
class QueueEntry:
    entry_id: str
    target: str
    asset: str
    profile: dict                      # TargetProfile as a dict
    authz: dict                        # AuthorizationRecord as a dict
    priority: int = 0
    state: str = QueueState.PENDING
    attempts: int = 0
    max_attempts: int = 5
    next_hypothesis_id: str = ""
    completion_criteria: str = "hypothesis CONFIRMED+reported, or DISPROVEN, or budget spent"
    last_error: str = ""
    history: list[str] = field(default_factory=list)
    created_at: str = field(default_factory=utcnow)
    updated_at: str = field(default_factory=utcnow)

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "QueueEntry":
        known = {f for f in cls.__dataclass_fields__}  # type: ignore[attr-defined]
        return cls(**{k: v for k, v in d.items() if k in known})

    def budget_spent(self) -> bool:
        return self.attempts >= self.max_attempts


class ResumableResearchQueue:
    def __init__(self, root: str | Path, name: str = "queue") -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.path = self.root / f"{name}.jsonl"

    # ------------------------------------------------------------------ #
    def _append(self, event: dict) -> None:
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps({"at": utcnow(), **event}, default=str) + "\n")

    def _events(self) -> list[dict]:
        if not self.path.exists():
            return []
        return [
            json.loads(line)
            for line in self.path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]

    # ------------------------------------------------------------------ #
    def enqueue(self, entry: QueueEntry) -> QueueEntry:
        self._append({"type": "entry", "id": entry.entry_id, "content": entry.to_dict()})
        return entry

    def all(self) -> list[QueueEntry]:
        state: dict[str, QueueEntry] = {}
        for ev in self._events():
            if ev.get("type") == "entry" and ev.get("content"):
                e = QueueEntry.from_dict(ev["content"])
                state[e.entry_id] = e
            elif ev.get("type") == "patch" and ev.get("id") in state:
                e = state[ev["id"]]
                for k, v in ev.get("fields", {}).items():
                    setattr(e, k, v)
                if ev.get("history"):
                    e.history.append(ev["history"])
                e.updated_at = ev.get("at", utcnow())
        return list(state.values())

    def get(self, entry_id: str) -> Optional[QueueEntry]:
        return next((e for e in self.all() if e.entry_id == entry_id), None)

    def _patch(self, entry_id: str, history: str = "", **fields) -> None:
        self._append({"type": "patch", "id": entry_id, "fields": fields, "history": history})

    # ------------------------------------------------------------------ #
    # Dequeue with a live authorization re-check
    # ------------------------------------------------------------------ #
    def _authorization_ok(self, entry: QueueEntry) -> tuple[bool, str]:
        """Re-run the gate on the entry's recorded authorization, right now."""
        try:
            record = AuthorizationRecord.from_dict(entry.authz)
        except Exception as exc:  # malformed record cannot authorize
            return False, f"authorization record unreadable: {exc}"
        decision = authorize_active_testing(record, entry.asset)
        if not decision.allowed:
            return False, "; ".join(decision.blockers)
        age = evidence_age(record)
        if age is None:
            return False, "authorization evidence has no parsable timestamp"
        return True, ""

    def next(self) -> Optional[QueueEntry]:
        """Return the highest-priority runnable entry, or None.

        Entries whose authorization no longer passes are moved to BLOCKED (with the
        reason) instead of being returned -- an expired or closed scope must not run.
        """
        candidates = [
            e for e in self.all()
            if e.state in (QueueState.PENDING, QueueState.IN_PROGRESS)
        ]
        candidates.sort(key=lambda e: (-e.priority, e.created_at))
        for entry in candidates:
            if entry.budget_spent():
                self._patch(entry.entry_id,
                            state=QueueState.BLOCKED, last_error="attempt budget exhausted",
                            history="blocked: attempt budget exhausted")
                continue
            ok, reason = self._authorization_ok(entry)
            if not ok:
                self._patch(entry.entry_id,
                            state=QueueState.BLOCKED, last_error=reason,
                            history=f"blocked: {reason}")
                continue
            return entry
        return None

    # ------------------------------------------------------------------ #
    def start(self, entry_id: str, hypothesis_id: str = "") -> None:
        entry = self.get(entry_id)
        if entry is None:
            return
        self._patch(entry_id, f"started attempt {entry.attempts + 1}",
                    state=QueueState.IN_PROGRESS, attempts=entry.attempts + 1,
                    next_hypothesis_id=hypothesis_id or entry.next_hypothesis_id)

    def complete(self, entry_id: str, outcome: str) -> None:
        self._patch(entry_id, f"completed: {outcome}",
                    state=QueueState.COMPLETED, last_error="")

    def block(self, entry_id: str, reason: str) -> None:
        self._patch(entry_id, f"blocked: {reason}",
                    state=QueueState.BLOCKED, last_error=reason)

    def abandon(self, entry_id: str, reason: str) -> None:
        self._patch(entry_id, f"abandoned: {reason}",
                    state=QueueState.ABANDONED, last_error=reason)

    # ------------------------------------------------------------------ #
    def resume_plan(self) -> list[dict]:
        """What would run next, in order, with the reason for each decision."""
        plan: list[dict] = []
        for entry in sorted(self.all(), key=lambda e: (-e.priority, e.created_at)):
            if entry.state in (QueueState.COMPLETED, QueueState.ABANDONED):
                continue
            ok, reason = self._authorization_ok(entry)
            plan.append({
                "entry_id": entry.entry_id,
                "target": entry.target,
                "asset": entry.asset,
                "state": entry.state,
                "attempts": f"{entry.attempts}/{entry.max_attempts}",
                "runnable": ok and not entry.budget_spent(),
                "reason": reason if not ok else (
                    "budget exhausted" if entry.budget_spent() else "ready"
                ),
                "next_hypothesis_id": entry.next_hypothesis_id,
            })
        return plan

    def summary(self) -> dict:
        entries = self.all()
        counts: dict[str, int] = {}
        for e in entries:
            counts[e.state] = counts.get(e.state, 0) + 1
        return {"total": len(entries), "by_state": counts}

    @staticmethod
    def entry_from(
        entry_id: str,
        profile: TargetProfile,
        asset: str,
        authz: AuthorizationRecord,
        *,
        priority: int = 0,
        max_attempts: int = 5,
    ) -> QueueEntry:
        return QueueEntry(
            entry_id=entry_id,
            target=profile.name,
            asset=asset,
            profile=asdict(profile),
            authz=authz.to_dict(),
            priority=priority,
            max_attempts=max_attempts,
        )
