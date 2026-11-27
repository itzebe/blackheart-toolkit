"""Attack-surface enumeration and hypothesis generation, including multi-stage paths.

This module turns a target profile plus its applicability result into concrete work
items. It does not run anything -- it *plans*: which entry points exist, which
hypotheses each applicable class yields, and which hypotheses can combine into a
multi-stage path.

Two design commitments:

  * **Assumptions and their violation.** Every hypothesis names an assumption the
    system makes and the specific way that assumption could be violated. A
    hypothesis without both is not emitted, so the engine never produces "test X"
    busywork.
  * **Composition.** Beyond single hypotheses, the generator pairs hypotheses that
    share a trust boundary or sequence into a **multi-stage path** -- the class of
    bug that a per-component review misses, where each step is individually safe.

Hypotheses are labelled as hypotheses. Nothing here is a finding.
"""

from __future__ import annotations

import itertools
import re
from dataclasses import dataclass, field

from ..objectives import TargetProfile
from .applicability import ApplicabilityResult
from .taxonomy import Taxonomy


@dataclass
class EntryPoint:
    """One externally reachable surface of the target."""

    name: str
    kind: str = ""            # entry_points label from the profile
    privileged: bool = False  # requires a role?

    def to_dict(self) -> dict:
        return {"name": self.name, "kind": self.kind, "privileged": self.privileged}


@dataclass
class Hypothesis:
    """A single testable hypothesis: an assumption and how to violate it."""

    hyp_id: str
    class_key: str
    title: str
    assumption: str
    violation: str
    entry_point: str = ""
    roles: list[str] = field(default_factory=list)
    #: Preconditions the attacker must arrange.
    preconditions: list[str] = field(default_factory=list)
    #: Impact band from the class, for ordering only (never payability).
    band: str = ""
    #: True for a same-model/LLM-suggested hypothesis pending verification.
    speculative: bool = False

    def to_dict(self) -> dict:
        return {
            "hyp_id": self.hyp_id, "class_key": self.class_key, "title": self.title,
            "assumption": self.assumption, "violation": self.violation,
            "entry_point": self.entry_point, "roles": list(self.roles),
            "preconditions": list(self.preconditions), "band": self.band,
            "speculative": self.speculative,
        }


@dataclass
class AttackPath:
    """A multi-stage path: ordered hypotheses that individually may be benign."""

    path_id: str
    steps: list[str]                 # hypothesis ids, in order
    class_keys: list[str]
    rationale: str
    band: str = "high"

    def to_dict(self) -> dict:
        return {
            "path_id": self.path_id, "steps": list(self.steps),
            "class_keys": list(self.class_keys), "rationale": self.rationale,
            "band": self.band,
        }


@dataclass
class AttackSurface:
    """The enumerated surface and the work it implies."""

    target: str
    entry_points: list[EntryPoint] = field(default_factory=list)
    hypotheses: list[Hypothesis] = field(default_factory=list)
    paths: list[AttackPath] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "entry_points": [e.to_dict() for e in self.entry_points],
            "hypotheses": [h.to_dict() for h in self.hypotheses],
            "paths": [p.to_dict() for p in self.paths],
            "counts": {
                "entry_points": len(self.entry_points),
                "hypotheses": len(self.hypotheses),
                "attack_paths": len(self.paths),
            },
        }


#: Per-class templates: (assumption, violation, preconditions). Keyed by class key;
#: a class without a template still yields a generic assumption/violation, so a
#: newly discovered class is never dropped.
_TEMPLATES: dict[str, tuple[str, str, tuple[str, ...]]] = {
    "access-control": (
        "the object read/write is gated on the caller's identity matching the owner",
        "supply another principal's object id and act on it",
        ("an object identifier is reachable", "ownership is checked by id, not by session"),
    ),
    "privilege-escalation": (
        "role transitions only reach the intended target role",
        "drive a transition that grants a higher role to the unprivileged actor",
        ("a role-transition path exists",),
    ),
    "auth-bypass": (
        "a protected action requires a valid authenticated session",
        "reach the action without a session or with a forged one",
        ("the action exists behind a gate",),
    ),
    "business-logic": (
        "the workflow's steps occur in the intended order with intended values",
        "skip, reorder, or repeat a step to obtain value out of band",
        ("a multi-step workflow exists",),
    ),
    "state-machine-violation": (
        "the system only enters legal states via legal transitions",
        "force an illegal transition and observe the resulting state",
        ("explicit states exist",),
    ),
    "reentrancy": (
        "effects are applied before any external call can re-enter",
        "re-enter during a callback before state settles",
        ("an external call/callback exists mid-operation",),
    ),
    "replay": (
        "each authorization is usable exactly once for its intended operation",
        "resubmit a previously valid authorization a second time",
        ("signed messages exist",),
    ),
    "signature-bypass": (
        "only a signature from the true key verifies",
        "supply a malleable or forged (v,r,s) that still verifies",
        ("signature verification exists",),
    ),
    "cross-chain-replay": (
        "a message is bound to its source chain/domain",
        "replay the message on a chain or domain it was not signed for",
        ("cross-chain messaging exists",),
    ),
    "oracle-manipulation": (
        "valuation uses a manipulation-resistant price",
        "move the spot price right before the read",
        ("valuation reads an external price",),
    ),
    "accounting-manipulation": (
        "internal accounting equals redeemable external value after every op",
        "desync shares from underlying by donating or sequencing",
        ("share/balance accounting exists",),
    ),
    "rounding-precision": (
        "no sequence of conversions yields net value creation",
        "repeat small conversions to accumulate rounding in the attacker's favour",
        ("conversion math exists",),
    ),
    "dos": (
        "no single cheap input blocks a shared critical path",
        "make a shared path unusable with a low-cost input",
        ("a shared, contended resource exists",),
    ),
    "info-disclosure": (
        "protected data is only observable by the authorized principal",
        "read another principal's protected data through an object reference",
        ("object reads exist",),
    ),
    "compositional-chain": (
        "each component is individually safe",
        "sequence two individually-safe behaviours into a violation",
        ("multiple interacting components exist",),
    ),
}

_GENERIC = (
    "the component behaves correctly under all inputs and states",
    "construct an input/state the component's author did not consider",
    ("the class's required surface is exposed",),
)


class SurfaceEnumerator:
    """Enumerate entry points and generate hypotheses + attack paths."""

    def __init__(self, taxonomy: Taxonomy):
        self.taxonomy = taxonomy

    def enumerate_entries(self, profile: TargetProfile) -> list[EntryPoint]:
        privileged_roles = {r.lower() for r in profile.roles
                            if any(k in r.lower() for k in ("admin", "owner", "manager", "governor"))}
        entries: list[EntryPoint] = []
        for ep in profile.entry_points:
            privileged = any(k in ep.lower() for k in ("admin", "owner", "onlyowner",
                                                       "internal", "privileged"))
            entries.append(EntryPoint(name=ep, kind=profile.kind, privileged=privileged))
        # Note privileged roles as entries so a role-gated hypothesis has a target.
        for role in sorted(privileged_roles):
            entries.append(EntryPoint(name=f"role:{role}", kind="role", privileged=True))
        return entries

    def _hypotheses_for(self, result: ApplicabilityResult,
                        profile: TargetProfile) -> list[Hypothesis]:
        entries = self.enumerate_entries(profile)
        hyps: list[Hypothesis] = []
        for verdict in result.applicable():
            cls = self.taxonomy.get(verdict.key)
            if cls is None:
                continue
            assumption, violation, preconds = _TEMPLATES.get(cls.key, _GENERIC)
            touched = [e.name for e in entries] or [profile.name]
            for i, entry in enumerate(touched):
                hyp_id = f"{cls.key}::{_slug(entry)}::{i}"
                hyps.append(Hypothesis(
                    hyp_id=hyp_id, class_key=cls.key, title=cls.title,
                    assumption=assumption, violation=violation, entry_point=entry,
                    roles=[r for r in profile.roles],
                    preconditions=list(preconds),
                    band=cls.default_band.value,
                ))
        return hyps

    def _paths(self, hyps: list[Hypothesis]) -> list[AttackPath]:
        """Pair hypotheses into multi-stage paths across distinct classes/surfaces.

        Only pairings that are *plausibly composable* are emitted: two classes that
        touch a shared boundary or that sequence (e.g. access-control -> accounting,
        or info-disclosure -> replay). Bounded combinatorially so a large surface
        does not explode; the cap is explicit and recorded.
        """
        # Composable class pairs: the first step enables the second.
        _ENABLES = {
            "info-disclosure": {"replay", "signature-bypass", "access-control", "auth-bypass"},
            "access-control": {"accounting-manipulation", "privilege-escalation", "business-logic"},
            "auth-bypass": {"privilege-escalation", "access-control", "business-logic"},
            "replay": {"accounting-manipulation", "business-logic", "state-machine-violation"},
            "signature-bypass": {"accounting-manipulation", "privilege-escalation"},
            "oracle-manipulation": {"accounting-manipulation", "unbacked-debt", "liquidation-bypass"},
            "race-condition": {"accounting-manipulation", "replay", "business-logic"},
            "state-machine-violation": {"business-logic", "accounting-manipulation"},
            "compositional-chain": {"accounting-manipulation", "access-control", "dos"},
        }
        by_class: dict[str, list[Hypothesis]] = {}
        for h in hyps:
            by_class.setdefault(h.class_key, []).append(h)
        paths: list[AttackPath] = []
        seen: set[tuple[str, str]] = set()
        for a_key, b_keys in _ENABLES.items():
            if a_key not in by_class:
                continue
            for b_key in b_keys:
                if b_key not in by_class:
                    continue
                for a, b in itertools.product(by_class[a_key][:3], by_class[b_key][:3]):
                    sig = (a.hyp_id, b.hyp_id)
                    if sig in seen:
                        continue
                    seen.add(sig)
                    paths.append(AttackPath(
                        path_id=f"path::{a_key}->{b_key}::{len(paths)}",
                        steps=[a.hyp_id, b.hyp_id],
                        class_keys=[a_key, b_key],
                        rationale=(
                            f"{a_key} on '{a.entry_point}' can satisfy the precondition of "
                            f"{b_key} on '{b.entry_point}' -- each step may be individually safe"
                        ),
                        band="critical",
                    ))
        return paths

    def build(self, result: ApplicabilityResult, profile: TargetProfile) -> AttackSurface:
        entries = self.enumerate_entries(profile)
        hyps = self._hypotheses_for(result, profile)
        paths = self._paths(hyps)
        return AttackSurface(target=profile.name, entry_points=entries,
                             hypotheses=hyps, paths=paths)


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-") or "target"
