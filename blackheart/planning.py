"""Plan research from the program's own policy, not from a generic score.

The objective generator says what an attacker *could* try. The published policy
says what the program *accepts*. This module joins them and keeps the answer
three-valued: a class is allowed only when the policy explicitly says so,
blocked only when it explicitly excludes it, and otherwise unknown. An
unverified policy cannot silently authorise a plan; it is reported as such.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from .objectives import TargetProfile, generate_objectives
from .program_intel.policy import NormalizedPolicy

STATUSES = ("PLANNED", "UNVERIFIED_POLICY", "EMPTY")


@dataclass
class PlannedObjective:
    objective_id: str
    category: str
    title: str
    eligibility: Optional[bool]
    priority: int = 0
    reason: str = ""

    def to_dict(self) -> dict:
        return {"objective_id": self.objective_id, "category": self.category,
                "title": self.title, "eligibility": self.eligibility,
                "priority": self.priority, "reason": self.reason}


@dataclass
class PolicyPlan:
    program: str
    status: str
    policy_verified: bool
    allowed: list[PlannedObjective] = field(default_factory=list)
    blocked: list[PlannedObjective] = field(default_factory=list)
    unknown: list[PlannedObjective] = field(default_factory=list)
    uncertainties: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "program": self.program, "status": self.status,
            "policy_verified": self.policy_verified,
            "allowed": [o.to_dict() for o in self.allowed],
            "blocked": [o.to_dict() for o in self.blocked],
            "unknown": [o.to_dict() for o in self.unknown],
            "uncertainties": list(self.uncertainties),
        }


def plan_from_policy(policy: NormalizedPolicy, profile: TargetProfile) -> PolicyPlan:
    """Filter the objective set through the policy's class rules."""
    objectives = generate_objectives(profile)
    if not objectives:
        return PolicyPlan(policy.program, "EMPTY", policy.is_verified(),
                          uncertainties=list(policy.uncertainties))
    allowed: list[PlannedObjective] = []
    blocked: list[PlannedObjective] = []
    unknown: list[PlannedObjective] = []
    for objective in objectives:
        eligible = policy.class_eligible(objective.category)
        entry = PlannedObjective(
            objective.obj_id, objective.category, objective.title, eligible,
            objective.priority,
            ("the policy explicitly includes this class" if eligible is True
             else "the policy explicitly excludes this class" if eligible is False
             else "the policy does not state a rule for this class"),
        )
        (allowed if eligible is True else blocked if eligible is False else unknown).append(entry)
    status = "PLANNED" if policy.is_verified() else "UNVERIFIED_POLICY"
    return PolicyPlan(
        policy.program, status, policy.is_verified(), allowed, blocked, unknown,
        list(policy.uncertainties) + (
            [] if policy.is_verified() else ["the policy is not verified; planning is advisory"]),
    )
