"""Compose a monitoring cycle with an explicit, authorized enqueue callback.

The watchtower finds a change; the scheduler runs work. This module joins them
without inventing a verdict: only a lead the watchtower already marked
``recommend``, non-blocked and above its own threshold is offered to the caller's
``enqueue`` callback. The callback is where authorization lives, so a policy
blocked lead is never enqueued. The result records what was enqueued and why the
rest was skipped.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

from ..watch import CycleConfig, CycleReport, run_cycle
from ..watch.classify import SCORE_THRESHOLD


@dataclass
class ContinuousResult:
    cycle_id: str
    counts: dict = field(default_factory=dict)
    enqueued: list[dict] = field(default_factory=list)
    offered: list[dict] = field(default_factory=list)
    skipped: list[dict] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "cycle_id": self.cycle_id,
            "counts": dict(self.counts),
            "enqueued": list(self.enqueued),
            "offered": list(self.offered),
            "skipped": list(self.skipped),
            "errors": list(self.errors),
            "note": "a watch lead is a candidate; the callback must authorize it",
        }


def run_continuous(
    config: CycleConfig,
    *,
    enqueue: Callable[[dict], Any],
    cycle_runner: Callable[..., CycleReport] = run_cycle,
    dry_run: bool = False,
    **cycle_kwargs: Any,
) -> ContinuousResult:
    """Run one cycle, then offer every actionable lead to ``enqueue``.

    ``enqueue`` receives the lead's own dictionary. An exception is captured as
    an error for that lead; it never hides the other leads or the cycle report.
    ``dry_run`` only records the lead as offered, so a dry run cannot be read as
    a dispatched job.
    """
    report = cycle_runner(config, **cycle_kwargs)
    result = ContinuousResult(report.cycle_id, report.counts())
    for lead in report.leads:
        payload = lead.to_dict()
        if lead.policy_blocked:
            result.skipped.append({**payload, "skip": "policy blocked"})
            continue
        if not lead.recommend:
            result.skipped.append({**payload, "skip": "not recommended"})
            continue
        if lead.score < SCORE_THRESHOLD:
            result.skipped.append({**payload, "skip": (
                f"score {lead.score} is below {SCORE_THRESHOLD}")})
            continue
        if dry_run:
            result.offered.append(payload)
            continue
        try:
            enqueue(payload)
        except Exception as exc:  # noqa: BLE001 -- one lead must not stop the cycle
            result.errors.append(f"{lead.target.slug}: {exc}")
            result.skipped.append({**payload, "skip": f"enqueue failed: {exc}"})
            continue
        result.enqueued.append(payload)
    return result


__all__ = ["ContinuousResult", "run_continuous"]
