"""Turning a profile into a staged campaign, and saying what a scanner cannot see.

The planner is objective-first. It starts from *what the actor wants to take*,
checks whether the profile can afford the preconditions, and only then lays out
the stages. Each stage names the engine that executes it, the evidence that
stage must produce, and -- where it matters -- the condition the actor must wait
for. Stages that need a capability outside what a local engine may exercise are
kept in the plan as ``MODEL_ONLY`` so the reasoning is complete and the execution
is impossible.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from ..mindset import OUTCOMES
from ..scope import check_asset
from .profiles import (
    MODEL_ONLY_CAPABILITIES,
    AdversaryProfile,
    Capability,
)

STAGE_ORDER: tuple[str, ...] = (
    "recon", "position", "accumulate", "trigger", "extract", "persist",
)


def _outcome(keyword: str) -> str:
    matches = [o for o in OUTCOMES if keyword in o]
    if len(matches) != 1:
        raise RuntimeError(f"outcome keyword {keyword!r} is ambiguous in mindset.OUTCOMES")
    return matches[0]


#: What each objective needs before it is even possible. Each entry is a tuple of
#: alternatives: satisfying any one of them is enough.
OBJECTIVE_REQUIREMENTS: dict[str, tuple[frozenset[Capability], ...]] = {
    _outcome("more assets"): (
        frozenset({Capability.FLASH_CAPITAL}),
        frozenset({Capability.SUSTAINED_CAPITAL}),
    ),
    _outcome("bypass a restriction"): (frozenset(),),
    _outcome("absorb my loss"): (
        frozenset({Capability.FLASH_CAPITAL}),
        frozenset({Capability.SUSTAINED_CAPITAL}),
    ),
}

#: What a stateless scanner does at each stage, and what it structurally cannot.
_SCANNER_CONTRAST: dict[str, tuple[str, str]] = {
    "recon": (
        "enumerates entrypoints, selectors and declared invariants",
        "cannot say which entrypoint moves value or what a position is worth",
    ),
    "position": (
        "tests single calls in isolation",
        "cannot fund, hold or unwind a position across blocks",
    ),
    "accumulate": (
        "reports a local anomaly in one call",
        "cannot build entitlement from several calls that are each valid alone",
    ),
    "trigger": (
        "has no notion of time",
        "cannot wait for a price move, an epoch boundary or a governance window",
    ),
    "extract": (
        "reports a violated assertion",
        "cannot price the violation, so it cannot separate theft from noise",
    ),
    "persist": (
        "reports the same finding on every run",
        "cannot tell whether the state it exploited can be restored and re-exploited",
    ),
}


@dataclass(frozen=True)
class Stage:
    """One step of a campaign."""

    role: str
    intent: str
    engine: str
    executable: bool
    requires: tuple[Capability, ...] = ()
    evidence_required: tuple[str, ...] = ()
    wait_condition: str = ""
    note: str = ""

    def to_dict(self) -> dict:
        return {
            "role": self.role,
            "intent": self.intent,
            "engine": self.engine,
            "executable": self.executable,
            "requires": [c.value for c in self.requires],
            "evidence_required": list(self.evidence_required),
            "wait_condition": self.wait_condition,
            "note": self.note,
        }


@dataclass
class CampaignPlan:
    target: str
    asset: str
    profile: str
    tier: str
    objective: str
    authorized: bool
    feasible: bool
    stages: list[Stage] = field(default_factory=list)
    blocked: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def executable_stages(self) -> list[Stage]:
        return [s for s in self.stages if s.executable]

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "asset": self.asset,
            "profile": self.profile,
            "tier": self.tier,
            "objective": self.objective,
            "authorized": self.authorized,
            "feasible": self.feasible,
            "stages": [s.to_dict() for s in self.stages],
            "blocked": list(self.blocked),
            "notes": list(self.notes),
        }

    def summary(self) -> str:
        head = (f"campaign target={self.target} asset={self.asset} "
                f"profile={self.profile} objective={self.objective!r}")
        state = ("authorized" if self.authorized else "NOT authorized") + \
                (", feasible" if self.feasible else ", infeasible")
        lines = [f"{head} ({state})"]
        for s in self.stages:
            mark = "run " if s.executable else ("model" if not s.engine else "hold ")
            wait = f" wait={s.wait_condition!r}" if s.wait_condition else ""
            print_note = f" -- {s.note}" if s.note else ""
            lines.append(f"  {mark} {s.role:10} engine={s.engine or '-':18}{wait}{print_note}")
        for b in self.blocked:
            lines.append(f"  blocked: {b}")
        return "\n".join(lines)


def scanner_contrast() -> list[dict]:
    """What a stateless scanner does and cannot do, stage by stage."""
    return [
        {"stage": role, "scanner_does": does, "scanner_cannot": cannot}
        for role, (does, cannot) in _SCANNER_CONTRAST.items()
    ]


def _cap_names(caps: frozenset[Capability]) -> str:
    return ", ".join(sorted(c.value for c in caps)) or "nothing"


def _satisfied_alternative(
    profile: AdversaryProfile, alternatives: tuple[frozenset[Capability], ...],
) -> Optional[frozenset[Capability]]:
    for alt in alternatives:
        if alt <= profile.capabilities:
            return alt
    return None


def plan_campaign(
    profile: AdversaryProfile,
    objective: str,
    asset: str,
    *,
    target: str = "",
    record: Any = None,
) -> CampaignPlan:
    """Lay out the campaign ``profile`` would run to reach ``objective``.

    ``record`` is an :class:`blackheart.models.AuthorizationRecord`. Without one
    the plan is still produced -- the thinking does not need permission -- but no
    stage is executable. With one, the asset must pass the scope gate.
    """
    if objective not in OUTCOMES:
        raise ValueError(
            f"objective {objective!r} is not one of the three outcomes the mindset "
            f"defines: {'; '.join(OUTCOMES)}"
        )

    blocked: list[str] = []
    notes: list[str] = []
    authorized = False
    if record is None:
        blocked.append(
            "no authorization record presented: the plan is thinking only, "
            "no stage is executable"
        )
    else:
        decision = check_asset(record, asset)
        authorized = bool(decision.allowed)
        if not authorized:
            detail = "; ".join(decision.blockers or decision.reasons) or decision.status.value
            blocked.append(f"scope gate refused asset '{asset}': {detail}")

    alternatives = OBJECTIVE_REQUIREMENTS[objective]
    satisfied = _satisfied_alternative(profile, alternatives)
    feasible = satisfied is not None
    if not feasible:
        wanted = " or ".join(_cap_names(alt) for alt in alternatives)
        blocked.append(
            f"objective {objective!r} needs {wanted}; profile '{profile.name}' has "
            f"{_cap_names(profile.capabilities)}"
        )

    can_run = authorized and feasible
    stages: list[Stage] = [
        Stage(
            role="recon",
            intent="learn which entrypoint moves value, and what a position is worth",
            engine="discovery",
            executable=authorized,
            evidence_required=("entrypoint inventory", "value-at-risk per entrypoint"),
            note="" if authorized else "passive reading only until the asset is authorized",
        ),
        Stage(
            role="position",
            intent="acquire the precondition the objective needs, at the cost the "
                   "profile can afford",
            engine="hunt",
            executable=can_run,
            requires=tuple(sorted(satisfied or frozenset(), key=lambda c: c.value)),
            evidence_required=("the preconditions the sequence needs",
                               "the capital and time it costs"),
            note="" if feasible else "no affordable precondition",
        ),
        Stage(
            role="accumulate",
            intent="build entitlement from steps that are each individually valid",
            engine="assure portfolio",
            executable=can_run,
            evidence_required=("a counterexample sequence", "attacker reachability"),
        ),
    ]

    if profile.dwell_days > 0:
        stages.append(Stage(
            role="trigger",
            intent="wait for the state that turns the accumulated position into a loss",
            engine="statespace",
            executable=can_run,
            wait_condition=f"hold up to {profile.dwell_days} days until the condition holds",
            evidence_required=("the condition", "the transition that fires it"),
            note="patience is the lever a one-transaction attacker does not have",
        ))
    else:
        notes.append(
            "no trigger stage: a one-transaction attacker must find the condition "
            "already present, which is what makes flash-loan attacks rare"
        )

    stages.append(Stage(
        role="extract",
        intent="realise the profit and measure it",
        engine="value",
        executable=can_run,
        evidence_required=("attacker profit", "victim loss", "conservation residual"),
    ))

    if profile.can(Capability.SUSTAINED_CAPITAL):
        stages.append(Stage(
            role="persist",
            intent="check whether the state can be restored and the extraction repeated",
            engine="novelty",
            executable=can_run,
            requires=(Capability.SUSTAINED_CAPITAL,),
            evidence_required=("repeatability", "max extraction"),
        ))
    else:
        notes.append(
            "no persist stage: flash capital is repaid in the same transaction, so the "
            "extraction cannot be repeated without new capital"
        )

    for capability in sorted(profile.capabilities & MODEL_ONLY_CAPABILITIES,
                             key=lambda c: c.value):
        stages.append(Stage(
            role=f"model:{capability.value}",
            intent=f"a campaign reachable through {capability.value}",
            engine="",
            executable=False,
            requires=(capability,),
            note="modelled only: no local engine may exercise this capability",
        ))

    return CampaignPlan(
        target=target or asset,
        asset=asset,
        profile=profile.name,
        tier=profile.tier.value,
        objective=objective,
        authorized=authorized,
        feasible=feasible,
        stages=stages,
        blocked=blocked,
        notes=notes,
    )
