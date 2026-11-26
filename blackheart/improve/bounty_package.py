"""Turn a finding and its official policy into a submission package.

The bounty package already had evaluation and gate steps. This module joins them
with the published payout and the exact policy sections a submission must cite,
and it keeps ``submission_allowed`` false unless the program's own rules and the
technical evidence both pass. It never sends anything.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from ..bounty import (
    CandidateRecord,
    ProgramPolicy,
    evaluate,
    gate_candidate,
    prepare_submission,
)
from ..models import Finding


@dataclass
class PolicyPackage:
    outcome: str
    determination: str
    severity: str
    payout: str
    submission_allowed: bool
    policy_sections: list[str] = field(default_factory=list)
    blockers: list[str] = field(default_factory=list)
    package: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "outcome": self.outcome,
            "determination": self.determination,
            "severity": self.severity,
            "payout": self.payout,
            "submission_allowed": self.submission_allowed,
            "policy_sections": list(self.policy_sections),
            "blockers": list(self.blockers),
            "package": dict(self.package),
            "note": "prepared only; BLACKHEART never submits a report",
        }


def package_from_policy(
    finding: Finding,
    policy: ProgramPolicy,
    *,
    candidate: Optional[CandidateRecord] = None,
) -> PolicyPackage:
    """Evaluate, gate and package one finding against one verified policy."""
    ev = evaluate(finding, policy)
    package = prepare_submission(finding, ev)
    blockers = list(package.get("blockers") or [])
    gate_out: dict = {}
    if candidate is not None:
        gate = gate_candidate(candidate)
        gate_out = gate.to_dict()
        blockers.extend(gate.blockers)
    allowed = bool(package.get("submission_allowed")) and (
        candidate is None or bool(gate_out.get("submission_ready")))
    return PolicyPackage(
        outcome=ev.outcome,
        determination=package.get("disposition", ""),
        severity=ev.severity or "",
        payout=policy.payouts.get(ev.severity or "", ""),
        submission_allowed=allowed,
        policy_sections=list(candidate.policy_sections) if candidate else [],
        blockers=blockers,
        package={**package, "gate": gate_out},
    )


__all__ = ["PolicyPackage", "package_from_policy"]
