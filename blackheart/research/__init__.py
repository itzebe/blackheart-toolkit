"""Persistent, searchable research memory (mission Part 2).

Every investigation writes one :class:`~blackheart.models.ResearchRecord`. The
memory is an append-only JSONL log; the current view of each record is derived by
replaying the log, so a status change is a new event and history is never lost.

The memory keeps the four buckets strictly separate -- confirmed, unconfirmed,
disproven, incomplete -- and exposes only *confirmed* records through
``attack_knowledge()``. Everything else is a lead or a negative result used to
steer the search; nothing unverified is ever read back as a vulnerability.

It also answers the retrieval question the hypothesis engine depends on: *have we
already tried this, and what happened?* ``search()`` matches on target, class,
and free text across hypothesis/strategy/lessons, and ``disproven_signatures()``
lets the engine skip a hypothesis that was already falsified -- unless new
evidence changes the conditions.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Optional

from ..models import InvestigationStatus, ResearchRecord, sha256_of, utcnow


class ResearchMemory:
    """Append-only, replayable store of :class:`ResearchRecord` objects."""

    def __init__(self, root: str | os.PathLike, engagement: str = "research") -> None:
        self.root = Path(root)
        self.engagement = engagement
        self.root.mkdir(parents=True, exist_ok=True)
        self.path = self.root / f"{engagement}-memory.jsonl"

    # ------------------------------------------------------------------ #
    # Writing
    # ------------------------------------------------------------------ #
    def record_event(self, event: dict) -> None:
        event = {"at": utcnow(), **event}
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(event, default=str) + "\n")

    def save(self, record: ResearchRecord) -> ResearchRecord:
        """Persist a record (full snapshot as the latest event).

        The record's content hash is stamped so the memory is tamper-evident: a
        later ``verify_integrity`` can detect an edited record.
        """
        record.updated_at = utcnow()
        self.record_event(
            {
                "type": "record",
                "id": record.record_id,
                "content": record.to_dict(),
                "content_sha256": sha256_of(record.to_dict()),
            }
        )
        return record

    def update_status(
        self, record_id: str, status: InvestigationStatus | str, note: str = ""
    ) -> None:
        value = status.value if isinstance(status, InvestigationStatus) else status
        self.record_event({"type": "status", "id": record_id, "status": value, "note": note})

    # ------------------------------------------------------------------ #
    # Reading
    # ------------------------------------------------------------------ #
    def _events(self) -> list[dict]:
        if not self.path.exists():
            return []
        return [
            json.loads(line)
            for line in self.path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]

    def all(self) -> list[ResearchRecord]:
        """Replay the log into the current state of every record."""
        state: dict[str, ResearchRecord] = {}
        for ev in self._events():
            if ev.get("type") == "record" and ev.get("content"):
                rec = ResearchRecord.from_dict(ev["content"])
                state[rec.record_id] = rec
            elif ev.get("type") == "status" and ev.get("id") in state:
                state[ev["id"]].status = ev["status"]
                if ev.get("note"):
                    state[ev["id"]].lessons.append(ev["note"])
        return list(state.values())

    def get(self, record_id: str) -> Optional[ResearchRecord]:
        for rec in self.all():
            if rec.record_id == record_id:
                return rec
        return None

    # ------------------------------------------------------------------ #
    # Buckets -- kept strictly separate
    # ------------------------------------------------------------------ #
    def by_status(self, status: InvestigationStatus | str) -> list[ResearchRecord]:
        value = status.value if isinstance(status, InvestigationStatus) else status
        return [r for r in self.all() if r.status == value]

    def confirmed(self) -> list[ResearchRecord]:
        return self.by_status(InvestigationStatus.CONFIRMED)

    def unconfirmed(self) -> list[ResearchRecord]:
        return self.by_status(InvestigationStatus.UNCONFIRMED)

    def disproven(self) -> list[ResearchRecord]:
        return self.by_status(InvestigationStatus.DISPROVEN)

    def incomplete(self) -> list[ResearchRecord]:
        return self.by_status(InvestigationStatus.INCOMPLETE)

    def attack_knowledge(self) -> list[ResearchRecord]:
        """Only CONFIRMED records -- the sole source of 'this is real' claims."""
        return [r for r in self.all() if r.may_be_read_as_attack_knowledge()]

    # ------------------------------------------------------------------ #
    # Search / retrieval
    # ------------------------------------------------------------------ #
    def search(
        self,
        *,
        target: str = "",
        vulnerability_class: str = "",
        text: str = "",
        status: Optional[InvestigationStatus | str] = None,
        limit: int = 20,
    ) -> list[ResearchRecord]:
        """Retrieve records relevant to a query.

        Matching is conjunctive across the supplied filters and, for ``text``,
        scans hypothesis, strategy, lessons, impact, and false-positive reason --
        the fields a later investigation most needs.
        """
        status_value = (
            status.value if isinstance(status, InvestigationStatus) else status
        )
        needle = text.lower().strip()
        hits: list[ResearchRecord] = []
        for rec in self.all():
            if target and rec.target != target:
                continue
            if vulnerability_class and rec.vulnerability_class != vulnerability_class:
                continue
            if status_value and rec.status != status_value:
                continue
            if needle:
                haystack = " ".join(
                    [
                        rec.hypothesis,
                        rec.attack_strategy,
                        rec.impact,
                        rec.false_positive_reason,
                        rec.actual_outcome,
                        " ".join(rec.lessons),
                    ]
                ).lower()
                if needle not in haystack:
                    continue
            hits.append(rec)
        # Most recent first.
        hits.sort(key=lambda r: r.updated_at, reverse=True)
        return hits[:limit]

    def lessons_for(
        self, *, target: str = "", vulnerability_class: str = ""
    ) -> list[str]:
        """Reusable lessons from prior investigations of a target/class.

        Confirmed lessons and the reasons a hypothesis was disproven are both
        returned -- knowing what *did not* work is as valuable as what did.
        """
        out: list[str] = []
        for rec in self.search(target=target, vulnerability_class=vulnerability_class, limit=100):
            out.extend(rec.lessons)
            if rec.status == InvestigationStatus.DISPROVEN.value and rec.false_positive_reason:
                out.append(
                    f"[disproven {rec.vulnerability_class}] {rec.false_positive_reason}"
                )
        # Stable, de-duplicated.
        seen: set[str] = set()
        uniq: list[str] = []
        for lesson in out:
            if lesson not in seen:
                seen.add(lesson)
                uniq.append(lesson)
        return uniq

    def disproven_signatures(self) -> set[tuple[str, str]]:
        """(target, class) pairs already falsified -- skip unless new evidence.

        The hypothesis engine treats these as closed unless it is explicitly given
        new evidence (``new_evidence=True``), so the engine does not burn budget
        re-running a disproven idea (mission Part 3).
        """
        return {
            (r.target, r.vulnerability_class)
            for r in self.disproven()
            if r.vulnerability_class
        }

    # ------------------------------------------------------------------ #
    # Integrity
    # ------------------------------------------------------------------ #
    def verify_integrity(self) -> dict:
        """Re-hash every stored record and report any that changed."""
        checked = 0
        bad: list[str] = []
        for ev in self._events():
            if ev.get("type") == "record" and ev.get("content"):
                checked += 1
                rec = ResearchRecord.from_dict(ev["content"])
                digest = sha256_of(rec.to_dict())
                if ev.get("content_sha256") and ev["content_sha256"] != digest:
                    bad.append(rec.record_id)
        return {"checked": checked, "mismatched": bad, "ok": not bad}

    # ------------------------------------------------------------------ #
    # Reporting
    # ------------------------------------------------------------------ #
    def summary(self) -> dict:
        recs = self.all()
        return {
            "total": len(recs),
            "confirmed": len(self.confirmed()),
            "unconfirmed": len(self.unconfirmed()),
            "disproven": len(self.disproven()),
            "incomplete": len(self.incomplete()),
            "lessons": sum(len(r.lessons) for r in recs),
        }

    def export_markdown(self) -> str:
        """Human-readable dump, honestly labelled by bucket."""
        lines = [f"# Research memory: {self.engagement}", ""]
        for title, recs in (
            ("Confirmed", self.confirmed()),
            ("Unconfirmed", self.unconfirmed()),
            ("Disproven", self.disproven()),
            ("Incomplete", self.incomplete()),
        ):
            lines.append(f"## {title} ({len(recs)})")
            if not recs:
                lines.append("_none_")
            for r in recs:
                lines.append(f"- **{r.record_id}** [{r.vulnerability_class}] {r.target}: {r.hypothesis}")
                for lesson in r.lessons:
                    lines.append(f"  - lesson: {lesson}")
            lines.append("")
        return "\n".join(lines)
