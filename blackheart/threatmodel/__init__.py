"""Protocol intelligence and threat modeling (mission P1 / Phase 2).

The mission's central principle is that a *human* supplies original,
protocol-specific insight and the AI investigates it. The engine already turns a
:class:`~blackheart.objectives.TargetProfile` straight into attacker objectives,
but it never forces the researcher to write down *what the protocol is, what it
promises, and where it stops trusting*. Without that step, hypotheses drift
toward generic pattern-matching -- the exact failure the mission calls out.

This module produces a protocol-specific **threat model** *before* extensive
automated hunting. It is a gate, not decoration: :meth:`ThreatModel.is_complete`
refuses to let the hunting phase begin until the model names the architecture,
the assets, the trust boundaries, the security assumptions, and -- critically --
at least one **stated security invariant per critical asset**. An invariant is
what a later hypothesis is allowed to attack; a finding that violates no stated
invariant is, by construction, not yet a finding.

The model is also the **impact-selection** record (mission Part 3.B). Rather
than scanning everything, the researcher selects the impacts that matter for
this target; the selected impacts steer objective generation and the hypothesis
engine's ranking, so effort flows to *consequential* bugs, not coverage.

Nothing here asserts a vulnerability. A threat model is a set of *claims about
intended behaviour* that the rest of the pipeline then tries to falsify.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Iterable, Optional

from ..models import utcnow
from ..objectives import TargetProfile


# --------------------------------------------------------------------------- #
# Impact catalogue (mission Part 3.B)
# --------------------------------------------------------------------------- #

# Canonical, stable impact ids. Each carries the *observable* consequence a
# report must ultimately demonstrate -- naming the consequence up front is what
# keeps a finding from being a code smell with no security meaning.
IMPACT_CATALOG: dict[str, dict[str, str]] = {
    "unauthorized-fund-transfer": {
        "title": "Unauthorized transfer of funds",
        "consequence": "value moves out of the system without a valid right to it",
    },
    "theft-or-freeze": {
        "title": "Theft or freezing of funds",
        "consequence": "assets are stolen, or legitimately-owned assets become unredeemable",
    },
    "unauthorized-execution": {
        "title": "Unauthorized execution",
        "consequence": "an operation runs that the caller was not entitled to run",
    },
    "privilege-escalation": {
        "title": "Privilege escalation",
        "consequence": "a low-privilege actor gains a higher privilege",
    },
    "auth-bypass": {
        "title": "Authentication / authorization bypass",
        "consequence": "a protected action completes without the required credential or role",
    },
    "consensus-failure": {
        "title": "Consensus failure or chain split",
        "consequence": "nodes disagree on canonical state, or the chain partitions",
    },
    "network-dos": {
        "title": "Network denial of service",
        "consequence": "honest participants cannot make progress",
    },
    "remote-code-execution": {
        "title": "Remote code execution",
        "consequence": "attacker-controlled code executes in a trusted context",
    },
    "signature-verification-failure": {
        "title": "Signature / cryptographic verification failure",
        "consequence": "an invalid signature, proof, or commitment verifies as valid",
    },
    "state-corruption": {
        "title": "State corruption",
        "consequence": "persistent state becomes internally contradictory or unrecoverable",
    },
    "replay-ordering": {
        "title": "Replay or transaction-ordering attack",
        "consequence": "a message or authorization is reused, or ordering changes the outcome",
    },
    "cross-component-trust": {
        "title": "Cross-component trust failure",
        "consequence": "one component trusts another's output in a way the other can violate",
    },
    "incorrect-settlement": {
        "title": "Incorrect settlement or accounting",
        "consequence": "internal accounting diverges from real assets or obligations",
    },
}


def impact_catalog() -> dict[str, dict[str, str]]:
    """Return the canonical impact catalogue (id -> metadata)."""
    return {k: dict(v) for k, v in IMPACT_CATALOG.items()}


def known_impacts() -> list[str]:
    return sorted(IMPACT_CATALOG)


# --------------------------------------------------------------------------- #
# Model records
# --------------------------------------------------------------------------- #

@dataclass
class TrustBoundary:
    """A place where data or control crosses from a less-trusted to a more-trusted zone.

    The mission requires the model to state, for each boundary, *what is assumed*
    about the crossing. That assumption is the thing an attacker targets.
    """

    name: str
    from_zone: str
    to_zone: str
    assumption: str = ""            # what the trusted side assumes about the untrusted side
    data_crossing: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class SecurityAssumption:
    """A belief the protocol's security depends on.

    If the assumption is false, some invariant is violable. Recording the
    *consequence of violation* makes the assumption testable rather than
    rhetorical.
    """

    statement: str
    depends_on: str = ""            # component / role / external system
    if_false: str = ""              # the invariant that breaks when it does not hold
    testable: bool = True

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Invariant:
    """A property that must hold for a stated asset to remain safe.

    ``applies_to`` ties the invariant to the asset(s) it protects; the
    completeness gate requires every critical asset to be covered by at least one
    invariant. ``expression`` is an optional machine-checkable form (e.g. a
    Foundry invariant signature or a predicate name) so the model can drive the
    executable invariant engine directly.
    """

    inv_id: str
    statement: str
    applies_to: list[str] = field(default_factory=list)
    expression: str = ""
    severity_if_broken: str = "high"

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class StateTransition:
    """A privileged or otherwise security-relevant state change.

    The mission asks for state transitions and their guards explicitly: an
    unguarded transition into a privileged state is a privilege-escalation lead.
    """

    name: str
    from_state: str
    to_state: str
    trigger: str = ""
    guard: str = ""                 # the authorization / condition that must hold
    authorized_actors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ThreatModel:
    """A protocol-specific threat model produced before automated hunting.

    Construction is intentionally *incremental*: a researcher fills in what they
    know via :meth:`add_*`, then calls :meth:`is_complete`. Incompleteness is a
    first-class result -- the model reports exactly what is missing rather than
    pretending to be done, which is how the pipeline stops a hunt that has no
    stated invariant to test against.
    """

    target: str
    revision: str = ""
    summary: str = ""                              # what the protocol is, in two sentences
    architecture: list[str] = field(default_factory=list)   # components
    critical_assets: list[str] = field(default_factory=list)
    trust_boundaries: list[TrustBoundary] = field(default_factory=list)
    assumptions: list[SecurityAssumption] = field(default_factory=list)
    invariants: list[Invariant] = field(default_factory=list)
    transitions: list[StateTransition] = field(default_factory=list)
    dependencies: list[str] = field(default_factory=list)   # external deps / integrations
    selected_impacts: list[str] = field(default_factory=list)
    notes: str = ""
    created_at: str = field(default_factory=utcnow)

    # -- builders --------------------------------------------------------- #

    def add_trust_boundary(self, name: str, from_zone: str, to_zone: str, *,
                           assumption: str = "", data_crossing: Optional[Iterable[str]] = None) -> TrustBoundary:
        tb = TrustBoundary(name=name, from_zone=from_zone, to_zone=to_zone,
                           assumption=assumption, data_crossing=list(data_crossing or []))
        self.trust_boundaries.append(tb)
        return tb

    def add_assumption(self, statement: str, *, depends_on: str = "", if_false: str = "",
                       testable: bool = True) -> SecurityAssumption:
        a = SecurityAssumption(statement=statement, depends_on=depends_on,
                               if_false=if_false, testable=testable)
        self.assumptions.append(a)
        return a

    def add_invariant(self, inv_id: str, statement: str, *, applies_to: Optional[Iterable[str]] = None,
                      expression: str = "", severity_if_broken: str = "high") -> Invariant:
        inv = Invariant(inv_id=inv_id, statement=statement, applies_to=list(applies_to or []),
                        expression=expression, severity_if_broken=severity_if_broken)
        self.invariants.append(inv)
        return inv

    def add_transition(self, name: str, from_state: str, to_state: str, *, trigger: str = "",
                       guard: str = "", authorized_actors: Optional[Iterable[str]] = None) -> StateTransition:
        t = StateTransition(name=name, from_state=from_state, to_state=to_state, trigger=trigger,
                            guard=guard, authorized_actors=list(authorized_actors or []))
        self.transitions.append(t)
        return t

    def select_impacts(self, impacts: Iterable[str]) -> None:
        """Record the impacts that matter for this target (mission Part 3.B).

        Unknown impact ids are rejected rather than silently kept, so a typo
        cannot quietly drop an impact from the model.
        """
        unknown = [i for i in impacts if i not in IMPACT_CATALOG]
        if unknown:
            raise ValueError(f"unknown impact id(s): {', '.join(sorted(unknown))}")
        for i in impacts:
            if i not in self.selected_impacts:
                self.selected_impacts.append(i)

    # -- completeness gate ------------------------------------------------ #

    def missing(self) -> list[str]:
        """Return the list of required elements that are absent or empty.

        The gate is deliberately strict about *security meaning*: an architecture
        list is not enough, the model must also state at least one trust boundary,
        one security assumption, and one invariant covering every critical asset.
        """
        gaps: list[str] = []
        if not self.summary.strip():
            gaps.append("summary")
        if not self.architecture:
            gaps.append("architecture")
        if not self.critical_assets:
            gaps.append("critical_assets")
        if not self.trust_boundaries:
            gaps.append("trust_boundaries")
        if not self.assumptions:
            gaps.append("assumptions")
        if not self.invariants:
            gaps.append("invariants")
        if not self.selected_impacts:
            gaps.append("selected_impacts")
        # Every critical asset must be protected by at least one invariant.
        covered: set[str] = set()
        for inv in self.invariants:
            covered.update(inv.applies_to)
        uncovered = [a for a in self.critical_assets if a not in covered]
        if uncovered:
            gaps.append("uncovered_assets:" + ",".join(uncovered))
        return gaps

    def is_complete(self) -> bool:
        return not self.missing()

    # -- serialisation ---------------------------------------------------- #

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "revision": self.revision,
            "summary": self.summary,
            "architecture": list(self.architecture),
            "critical_assets": list(self.critical_assets),
            "trust_boundaries": [t.to_dict() for t in self.trust_boundaries],
            "assumptions": [a.to_dict() for a in self.assumptions],
            "invariants": [i.to_dict() for i in self.invariants],
            "transitions": [t.to_dict() for t in self.transitions],
            "dependencies": list(self.dependencies),
            "selected_impacts": list(self.selected_impacts),
            "notes": self.notes,
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "ThreatModel":
        return cls(
            target=d["target"],
            revision=d.get("revision", ""),
            summary=d.get("summary", ""),
            architecture=list(d.get("architecture", [])),
            critical_assets=list(d.get("critical_assets", [])),
            trust_boundaries=[TrustBoundary(**t) for t in d.get("trust_boundaries", [])],
            assumptions=[SecurityAssumption(**a) for a in d.get("assumptions", [])],
            invariants=[Invariant(**i) for i in d.get("invariants", [])],
            transitions=[StateTransition(**t) for t in d.get("transitions", [])],
            dependencies=list(d.get("dependencies", [])),
            selected_impacts=list(d.get("selected_impacts", [])),
            notes=d.get("notes", ""),
            created_at=d.get("created_at", utcnow()),
        )

    def to_json(self) -> str:
        import json

        return json.dumps(self.to_dict(), indent=2, sort_keys=True)


# --------------------------------------------------------------------------- #
# Threat modeling from a target profile
# --------------------------------------------------------------------------- #

def model_from_profile(profile: TargetProfile, *, revision: str = "",
                       selected_impacts: Optional[Iterable[str]] = None) -> ThreatModel:
    """Bootstrap a threat model from an existing :class:`TargetProfile`.

    This is a *scaffold*, not a finished model: it transcribes the profile's
    assets, entry points, roles and dependencies into the model's structure and
    proposes a first trust boundary (the profile's own), but it deliberately
    leaves the security-relevant fields that require human insight -- the
    assumptions and the invariants -- empty. The completeness gate then reports
    them as missing, which is the intended behaviour: a profile is not a threat
    model.
    """
    tm = ThreatModel(
        target=profile.name,
        revision=revision,
        summary="",  # must be written by the researcher
        architecture=list(profile.entry_points),
        critical_assets=list(profile.assets),
        dependencies=list(profile.external_deps),
        notes=profile.notes,
    )
    for boundary in profile.trust_boundaries:
        # A profile boundary is a free-text label like "user <-> vault"; keep it
        # verbatim as the boundary name and split it into zones when possible.
        if "<->" in boundary:
            left, right = (p.strip() for p in boundary.split("<->", 1))
        else:
            left, right = boundary.strip(), boundary.strip()
        tm.add_trust_boundary(boundary, left, right)
    if selected_impacts:
        tm.select_impacts(selected_impacts)
    return tm


# --------------------------------------------------------------------------- #
# Impact-aware objective steering
# --------------------------------------------------------------------------- #

# Which objective categories each impact makes *relevant*. Selecting an impact
# narrows the objective set so the hypothesis engine spends its budget on classes
# that can actually produce that consequence -- impact-driven hunting (Part 3.B)
# instead of indiscriminate scanning.
_IMPACT_TO_CATEGORIES: dict[str, set[str]] = {
    "unauthorized-fund-transfer": {"asset-theft", "auth-bypass", "access-control"},
    "theft-or-freeze": {"asset-theft", "accounting-manipulation", "liquidation-bypass",
                        "access-control", "state-inconsistency"},
    "unauthorized-execution": {"auth-bypass", "access-control", "cross-protocol-trust"},
    "privilege-escalation": {"privilege-escalation", "access-control", "auth-bypass"},
    "auth-bypass": {"auth-bypass", "access-control", "replay-forgery", "signature-bypass"},
    "consensus-failure": {"state-inconsistency", "cross-protocol-trust", "ordering-timing"},
    "network-dos": {"state-inconsistency", "callback-reentrancy", "cross-contract"},
    "remote-code-execution": {"state-inconsistency", "cross-protocol-trust", "callback-reentrancy"},
    "signature-verification-failure": {"signature-bypass", "replay-forgery"},
    "state-corruption": {"state-inconsistency", "callback-reentrancy", "cross-contract",
                         "accounting-manipulation"},
    "replay-ordering": {"replay-forgery", "ordering-timing"},
    "cross-component-trust": {"cross-protocol-trust", "cross-contract", "callback-reentrancy"},
    "incorrect-settlement": {"accounting-manipulation", "rounding-precision", "oracle-manipulation",
                             "liquidation-bypass"},
}


def categories_for_impacts(impacts: Iterable[str]) -> set[str]:
    """Return the objective categories that the given impacts make relevant."""
    cats: set[str] = set()
    for i in impacts:
        cats.update(_IMPACT_TO_CATEGORIES.get(i, set()))
    return cats


def steer_objectives(objectives: list, model: ThreatModel) -> list:
    """Re-rank objectives so the ones matching selected impacts come first.

    Objectives whose category cannot produce any selected impact are kept but
    demoted (never dropped): a researcher may still want them, and silently
    deleting work would hide it. The re-rank is stable, so an unselected impact
    set leaves the input order untouched.
    """
    if not model.selected_impacts:
        return list(objectives)
    relevant = categories_for_impacts(model.selected_impacts)
    if not relevant:
        return list(objectives)

    def key(o):
        matches = getattr(o, "category", "") in relevant
        # Impact-relevant first, then by the objective's own priority.
        return (0 if matches else 1, -getattr(o, "priority", 0), getattr(o, "category", ""))

    return sorted(objectives, key=key)
