"""A content-addressed finding baseline, so a re-run shows regressions, not noise.

A baseline records the identity of each known finding (the same fingerprint the
SARIF writer emits), not its row order or timestamps. Comparing a fresh
repository against it separates:

* **new** -- a fingerprint the baseline has never seen;
* **resolved** -- a baseline fingerprint that is no longer present;
* **changed** -- the same defect whose verdict or severity moved;
* **unchanged** -- everything else, including a new id or title for the same
  root cause.

The baseline is a plain JSON document. It carries no secrets and no evidence
content, only the identifying metadata, so it can be committed or attached to a
CI job.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from typing import Any, Iterable

from .findings.fingerprint import finding_fingerprint
from .models import utcnow

BASELINE_VERSION = 1

_SEVERITY_RANK = {
    "critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1, "informational": 1,
}
_STATUS_RANK = {
    "CONFIRMED": 6, "STRONGLY_SUPPORTED": 5, "UNCONFIRMED": 4,
    "INFORMATIONAL": 3, "NOT_REPRODUCIBLE": 2, "FALSE_POSITIVE": 1, "OUT_OF_SCOPE": 0,
}


def _rank(record: Any) -> tuple[int, int]:
    return (
        _STATUS_RANK.get(str(getattr(record, "status", "")).upper(), 0),
        _SEVERITY_RANK.get(str(getattr(record, "severity", "")).lower(), 0),
    )


@dataclass(frozen=True)
class BaselineEntry:
    fingerprint: str
    finding_id: str
    title: str
    status: str
    severity: str
    target: str
    component: str
    category: str
    location: str

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_record(cls, record: Any) -> "BaselineEntry":
        return cls(
            fingerprint=finding_fingerprint(record),
            finding_id=getattr(record, "finding_id", ""),
            title=getattr(record, "title", ""),
            status=getattr(record, "status", ""),
            severity=getattr(record, "severity", ""),
            target=getattr(record, "target", ""),
            component=getattr(record, "component", ""),
            category=getattr(record, "category", ""),
            location=":".join(
                part for part in (
                    getattr(record, "root_cause_file", ""),
                    getattr(record, "root_cause_location", ""),
                ) if part
            ),
        )


def create(records: Iterable[Any]) -> dict:
    """Build a baseline, keeping the strongest record for a shared fingerprint."""
    best: dict[str, tuple[tuple[int, int], BaselineEntry]] = {}
    for record in records:
        entry = BaselineEntry.from_record(record)
        rank = _rank(record)
        current = best.get(entry.fingerprint)
        if current is None or rank > current[0]:
            best[entry.fingerprint] = (rank, entry)
    entries = [entry.to_dict() for _, entry in sorted(best.values(), key=lambda item: item[1].fingerprint)]
    return {
        "version": BASELINE_VERSION,
        "created_at": utcnow(),
        "entries": entries,
    }


def load(document: dict) -> dict[str, BaselineEntry]:
    if not isinstance(document, dict):
        raise ValueError("baseline is not an object")
    if document.get("version") != BASELINE_VERSION:
        raise ValueError(f"unsupported baseline version {document.get('version')!r}")
    entries = document.get("entries")
    if not isinstance(entries, list):
        raise ValueError("baseline.entries must be an array")
    out: dict[str, BaselineEntry] = {}
    for raw in entries:
        if not isinstance(raw, dict) or not raw.get("fingerprint"):
            raise ValueError("every baseline entry needs a fingerprint")
        entry = BaselineEntry(**{k: raw.get(k, "") for k in BaselineEntry.__dataclass_fields__})
        if entry.fingerprint in out:
            raise ValueError(f"duplicate baseline fingerprint {entry.fingerprint!r}")
        out[entry.fingerprint] = entry
    return out


@dataclass
class BaselineDiff:
    new: list[BaselineEntry]
    resolved: list[BaselineEntry]
    changed: list[tuple[BaselineEntry, BaselineEntry]]
    unchanged: list[BaselineEntry]

    def to_dict(self) -> dict:
        return {
            "new": [e.to_dict() for e in self.new],
            "resolved": [e.to_dict() for e in self.resolved],
            "changed": [
                {"baseline": before.to_dict(), "current": after.to_dict()}
                for before, after in self.changed
            ],
            "unchanged": [e.to_dict() for e in self.unchanged],
            "counts": {
                "new": len(self.new),
                "resolved": len(self.resolved),
                "changed": len(self.changed),
                "unchanged": len(self.unchanged),
            },
        }

    @property
    def has_new(self) -> bool:
        return bool(self.new)


def compare(baseline: dict, records: Iterable[Any]) -> BaselineDiff:
    known = load(baseline)
    best: dict[str, tuple[tuple[int, int], BaselineEntry]] = {}
    for record in records:
        entry = BaselineEntry.from_record(record)
        rank = _rank(record)
        existing = best.get(entry.fingerprint)
        if existing is None or rank > existing[0]:
            best[entry.fingerprint] = (rank, entry)
    current = {fp: entry for fp, (_, entry) in best.items()}
    new = [current[fp] for fp in sorted(set(current) - set(known))]
    resolved = [known[fp] for fp in sorted(set(known) - set(current))]
    changed: list[tuple[BaselineEntry, BaselineEntry]] = []
    unchanged: list[BaselineEntry] = []
    for fp in sorted(set(current) & set(known)):
        before, after = known[fp], current[fp]
        if (before.status, before.severity) != (after.status, after.severity):
            changed.append((before, after))
        else:
            unchanged.append(after)
    return BaselineDiff(new=new, resolved=resolved, changed=changed, unchanged=unchanged)


def render_markdown(diff: BaselineDiff) -> str:
    lines = ["# Finding baseline diff", ""]
    lines.append(
        f"{len(diff.new)} new, {len(diff.resolved)} resolved, "
        f"{len(diff.changed)} changed, {len(diff.unchanged)} unchanged."
    )
    for title, entries in (("New", diff.new), ("Resolved", diff.resolved)):
        lines.append("")
        lines.append(f"## {title} ({len(entries)})")
        lines.append("")
        if not entries:
            lines.append("_none_")
        for entry in entries:
            lines.append(
                f"- **{entry.finding_id}** [{entry.status}/{entry.severity}] "
                f"{entry.target}: {entry.title}"
            )
    lines.append("")
    lines.append(f"## Changed ({len(diff.changed)})")
    lines.append("")
    if not diff.changed:
        lines.append("_none_")
    for before, after in diff.changed:
        lines.append(
            f"- **{after.finding_id}**: {before.status}/{before.severity} -> "
            f"{after.status}/{after.severity} ({after.title})"
        )
    lines.append("")
    return "\n".join(lines)


def dumps(document: dict) -> str:
    return json.dumps(document, indent=2, sort_keys=True, default=str)
