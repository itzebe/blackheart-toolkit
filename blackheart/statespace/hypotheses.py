"""Model-driven adversarial hypothesis generation.

This turns a :class:`~blackheart.statespace.model.SystemModel` into structured,
**falsifiable** hypotheses about how a sequence of operations could violate a
stated invariant. It is the part of the engine that asks the mission's harder
questions -- operation ordering, cross-user interaction, privilege and ownership
change, partial failure, stale state, replay, cross-component trust -- instead of
matching a known-vulnerability pattern.

Each hypothesis carries the eight fields the mission requires:

  1. attacker capability          5. expected secure behaviour
  2. required preconditions       6. observable evidence needed
  3. targeted asset/property      7. falsification conditions
  4. expected vulnerable sequence 8. authorization boundary

Two design choices are deliberate and load-bearing:

  * **The strategy is a named reasoning pattern, not a code template.** A strategy
    reads the model (which operations are sensitive, which actors are unprivileged,
    which guards exist) and produces a *sequence shape*. Different strategies
    produce genuinely different sequences, so the engine explores the space rather
    than re-emitting a fixed menu. This is the difference from the existing
    ``blackheart.chains`` template list.
  * **A hypothesis is never a finding.** It is a claim about intended behaviour
    with an explicit falsification condition. The explorer tries to *falsify* it;
    the verifier decides its fate. Nothing here is promoted to a vulnerability.

The generator refuses to run against an incomplete model (no actors, operations,
invariants, or assets), so it cannot invent hypotheses about an undescribed
system.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Optional

from ..models import utcnow
from .model import ModelIncomplete, Operation, SystemModel

# --------------------------------------------------------------------------- #
# Strategy catalogue -- the reasoning patterns
# --------------------------------------------------------------------------- #

# A strategy is (id, title, category, which invariant category it targets, and a
# builder). The builder receives the model and returns a *sequence shape* plus the
# narrative fields. Keeping builders as functions (not data) is what lets a
# strategy read the model and compose a real sequence.

@dataclass(frozen=True)
class Strategy:
    strategy_id: str
    title: str
    category: str
    question: str
    # the ordered operation names the strategy wants to try (may include repeats),
    # plus the actors it wants to use for each step (by role predicate)
    rationale: str


# The catalog is intentionally explicit: ten reasoning patterns, each mapping to
# the mission's list. The builders below turn each into a concrete hypothesis.
STRATEGIES: tuple[Strategy, ...] = (
    Strategy("ordering", "Operation reordering", "state-ordering",
             "Does the outcome change if these two operations run in the other order?",
             "Many guards assume a canonical order; a legal permutation can reach a "
             "state the guard never anticipated."),
    Strategy("repetition", "Repeated operation", "idempotency",
             "What happens if the same operation runs twice before any state settles?",
             "Operations that assume single invocation (nonces, one-shot init, "
             "first-depositor) can be re-entered or replayed."),
    Strategy("cross-user", "Cross-user interaction", "cross-user",
             "Can one actor's operation move or lock another actor's asset?",
             "Object-level authorization is often checked at the route but not on the "
             "object, so a different principal can act on it."),
    Strategy("privilege-change", "Privilege change between operations", "privilege",
             "Can a privilege be granted, then the gated operation run with stale rights?",
             "If a right is checked once and cached, a later revocation or grant does "
             "not take effect for the in-flight operation."),
    Strategy("ownership-change", "Ownership change between operations", "ownership",
             "Can ownership move between the check and the effect?",
             "A check-then-act on an owner is a TOCTOU if ownership can change in between."),
    Strategy("partial-failure", "Partial failure mid-sequence", "partial-failure",
             "If an operation fails halfway, is the partial state exploitable?",
             "Non-atomic multi-step writes can leave a half-applied state that a "
             "second sequence finishes into an unauthorized outcome."),
    Strategy("concurrency", "Interleaved operations", "concurrency",
             "Can two actors' operations interleave to bypass a guard neither bypasses alone?",
             "Guards evaluated per-call do not compose; interleaving can violate a "
             "system-level invariant no single call violates."),
    Strategy("stale-state", "Stale state reuse", "stale-state",
             "Can a value read before an update be used after it?",
             "A cached balance/allowance read before a mutation is stale after it, "
             "and using it grants more than entitled."),
    Strategy("replay", "Replay / re-submission", "replay",
             "Can a valid authorization be reused for a second effect?",
             "Signatures and one-time tokens without single-use binding can be "
             "replayed to repeat a privileged effect."),
    Strategy("cross-component", "Cross-component trust", "cross-component",
             "Does a component trust another's output without revalidating it?",
             "A trusted dependency returning a valid-but-unexpected value violates an "
             "assumption the caller never rechecked."),
)

_STRATEGY_BY_ID = {s.strategy_id: s for s in STRATEGIES}


def strategy_ids() -> list[str]:
    return [s.strategy_id for s in STRATEGIES]


def strategy(strategy_id: str) -> Strategy:
    if strategy_id not in _STRATEGY_BY_ID:
        raise KeyError(f"unknown strategy: {strategy_id} (known: {', '.join(strategy_ids())})")
    return _STRATEGY_BY_ID[strategy_id]


# --------------------------------------------------------------------------- #
# The hypothesis record
# --------------------------------------------------------------------------- #

@dataclass
class SequenceStep:
    """One operation in a hypothesised sequence, with the actor and params."""

    actor: str
    operation: str
    params: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {"actor": self.actor, "operation": self.operation, "params": dict(self.params)}

    def key(self) -> tuple:
        return (self.actor, self.operation)


@dataclass
class Hypothesis:
    """A falsifiable, model-derived claim about a sequence of operations.

    Every field maps to one the mission names. ``falsification`` is what makes it
    a real hypothesis: the observation that would prove the claim wrong. A
    hypothesis with no falsification condition is not emitted.
    """

    hyp_id: str
    strategy_id: str
    category: str
    title: str
    target: str
    # 1-8 from the mission
    capability: str
    preconditions: list[str]
    asset: str
    vulnerable_sequence: list[SequenceStep]
    expected_secure: str
    evidence_needed: list[str]
    falsification: list[str]
    authorization_boundary: str
    # linkage
    invariant_id: str = ""
    invariant_statement: str = ""
    transition: str = ""
    priority: int = 50
    rationale: str = ""
    created_at: str = field(default_factory=utcnow)

    def sequence_key(self) -> tuple:
        """A canonical key for duplicate suppression: the ordered (actor, op) list."""
        return tuple(s.key() for s in self.vulnerable_sequence)

    def to_dict(self) -> dict:
        return {
            "hyp_id": self.hyp_id,
            "strategy_id": self.strategy_id,
            "category": self.category,
            "title": self.title,
            "target": self.target,
            "capability": self.capability,
            "preconditions": list(self.preconditions),
            "asset": self.asset,
            "vulnerable_sequence": [s.to_dict() for s in self.vulnerable_sequence],
            "expected_secure": self.expected_secure,
            "evidence_needed": list(self.evidence_needed),
            "falsification": list(self.falsification),
            "authorization_boundary": self.authorization_boundary,
            "invariant_id": self.invariant_id,
            "invariant_statement": self.invariant_statement,
            "transition": self.transition,
            "priority": self.priority,
            "rationale": self.rationale,
            "created_at": self.created_at,
        }


@dataclass
class GenerationReport:
    hypotheses: list[Hypothesis] = field(default_factory=list)
    suppressed_duplicates: int = 0
    skipped: list[tuple[str, str]] = field(default_factory=list)   # (strategy, reason)

    def to_dict(self) -> dict:
        return {
            "count": len(self.hypotheses),
            "suppressed_duplicates": self.suppressed_duplicates,
            "skipped": [{"strategy": s, "reason": r} for s, r in self.skipped],
            "hypotheses": [h.to_dict() for h in self.hypotheses],
        }


# --------------------------------------------------------------------------- #
# Sequence builders per strategy
# --------------------------------------------------------------------------- #

def _attacker(model: SystemModel) -> str:
    """The weakest unprivileged actor an attacker can be."""
    unpriv = model.unprivileged_actors()
    if unpriv:
        return unpriv[0].name
    return model.actors[0].name if model.actors else "attacker"


def _victim(model: SystemModel) -> str:
    """A second distinct actor, when one exists (for cross-user strategies)."""
    names = [a.name for a in model.actors]
    atk = _attacker(model)
    for n in names:
        if n != atk:
            return n
    return atk


def _sensitive(model: SystemModel) -> list[Operation]:
    return model.sensitive_operations() or list(model.operations)


def _build_ordering(model: SystemModel, inv) -> Optional[list[SequenceStep]]:
    atk = _attacker(model)
    ops = _sensitive(model)
    if len(ops) < 2:
        return None
    a, b = ops[0], ops[1]
    return [SequenceStep(atk, b.name), SequenceStep(atk, a.name), SequenceStep(atk, b.name)]


def _build_repetition(model: SystemModel, inv) -> Optional[list[SequenceStep]]:
    atk = _attacker(model)
    ops = _sensitive(model)
    if not ops:
        return None
    op = ops[0]
    return [SequenceStep(atk, op.name), SequenceStep(atk, op.name)]


def _build_cross_user(model: SystemModel, inv) -> Optional[list[SequenceStep]]:
    atk, vic = _attacker(model), _victim(model)
    if atk == vic:
        return None
    ops = _sensitive(model)
    if not ops:
        return None
    op = ops[0]
    return [SequenceStep(vic, op.name), SequenceStep(atk, op.name)]


def _build_privilege_change(model: SystemModel, inv) -> Optional[list[SequenceStep]]:
    atk = _attacker(model)
    ops = _sensitive(model)
    # find a guarded operation (one whose model guard names a role the attacker lacks)
    guarded = [o for o in ops if o.guard_roles]
    if not guarded:
        return None
    op = guarded[0]
    grant = next((o for o in model.operations if o.name != op.name), None)
    if grant is None:
        return None
    return [SequenceStep(atk, grant.name), SequenceStep(atk, op.name)]


def _build_ownership_change(model: SystemModel, inv) -> Optional[list[SequenceStep]]:
    atk, vic = _attacker(model), _victim(model)
    ops = _sensitive(model)
    if not ops:
        return None
    transfer = next((o for o in model.operations if "transfer" in o.name or "owner" in o.name), ops[0])
    act = ops[0]
    return [SequenceStep(vic, transfer.name), SequenceStep(atk, act.name)]


def _build_partial_failure(model: SystemModel, inv) -> Optional[list[SequenceStep]]:
    atk = _attacker(model)
    ops = _sensitive(model)
    if len(ops) < 2:
        return None
    a, b = ops[0], ops[1]
    return [SequenceStep(atk, a.name), SequenceStep(atk, b.name), SequenceStep(atk, a.name)]


def _build_concurrency(model: SystemModel, inv) -> Optional[list[SequenceStep]]:
    atk, vic = _attacker(model), _victim(model)
    ops = _sensitive(model)
    if not ops:
        return None
    op = ops[0]
    return [SequenceStep(atk, op.name), SequenceStep(vic, op.name), SequenceStep(atk, op.name)]


def _build_stale_state(model: SystemModel, inv) -> Optional[list[SequenceStep]]:
    atk = _attacker(model)
    ops = _sensitive(model)
    if len(ops) < 2:
        return None
    read, write = ops[0], ops[1]
    return [SequenceStep(atk, read.name), SequenceStep(atk, write.name), SequenceStep(atk, read.name)]


def _build_replay(model: SystemModel, inv) -> Optional[list[SequenceStep]]:
    atk = _attacker(model)
    ops = _sensitive(model)
    if not ops:
        return None
    op = ops[0]
    return [SequenceStep(atk, op.name), SequenceStep(atk, op.name), SequenceStep(atk, op.name)]


def _build_cross_component(model: SystemModel, inv) -> Optional[list[SequenceStep]]:
    atk = _attacker(model)
    ops = _sensitive(model)
    if not ops:
        return None
    op = ops[0]
    dep = model.dependencies[0] if model.dependencies else "external"
    return [SequenceStep(atk, op.name, {"dependency": dep}), SequenceStep(atk, op.name)]


_BUILDERS: dict[str, Callable[[SystemModel, object], Optional[list[SequenceStep]]]] = {
    "ordering": _build_ordering,
    "repetition": _build_repetition,
    "cross-user": _build_cross_user,
    "privilege-change": _build_privilege_change,
    "ownership-change": _build_ownership_change,
    "partial-failure": _build_partial_failure,
    "concurrency": _build_concurrency,
    "stale-state": _build_stale_state,
    "replay": _build_replay,
    "cross-component": _build_cross_component,
}


# --------------------------------------------------------------------------- #
# The generator
# --------------------------------------------------------------------------- #

# Per-strategy evidence and falsification templates. Kept next to the builder so a
# new strategy is added in one place.
_EVIDENCE: dict[str, list[str]] = {
    "ordering": ["final state snapshot", "per-step snapshot", "invariant id"],
    "repetition": ["second-invocation result", "state after the repeat", "invariant id"],
    "cross-user": ["actor roles", "victim asset balance before/after", "invariant id"],
    "privilege-change": ["role/grant state", "gated operation result", "invariant id"],
    "ownership-change": ["ownership before/after", "actor roles", "invariant id"],
    "partial-failure": ["per-step outcome", "state after the failing step", "invariant id"],
    "concurrency": ["interleaved snapshots", "final state", "invariant id"],
    "stale-state": ["value read", "value after write", "invariant id"],
    "replay": ["both invocations' effects", "single-use marker state", "invariant id"],
    "cross-component": ["dependency response", "caller state", "invariant id"],
}

_FALSIFY: dict[str, list[str]] = {
    "ordering": ["the reversed order also violates the invariant (order-independent, so not a sequencing bug)"],
    "repetition": ["the second invocation is rejected or has no additional effect"],
    "cross-user": ["the second actor cannot affect the first actor's asset"],
    "privilege-change": ["the gated operation is refused after the grant, or requires a right the attacker never holds"],
    "ownership-change": ["ownership cannot change in the modelled window"],
    "partial-failure": ["the sequence is atomic, leaving no exploitable partial state"],
    "concurrency": ["no interleaving produces a state a single-actor sequence could not"],
    "stale-state": ["the read is not used after the write, or is re-validated"],
    "replay": ["the authorization is bound to a single use (nonce/consumed flag)"],
    "cross-component": ["the caller revalidates the dependency's value"],
}


class HypothesisGenerator:
    """Turns a complete :class:`SystemModel` into ranked, falsifiable hypotheses."""

    def __init__(self, model: SystemModel, *, strategies: Optional[list[str]] = None) -> None:
        self.model = model
        self.strategies = list(strategies) if strategies else strategy_ids()

    def generate(self) -> GenerationReport:
        if not self.model.is_complete():
            raise ModelIncomplete(
                "cannot generate hypotheses against an incomplete model; missing: "
                + ", ".join(self.model.missing())
            )
        report = GenerationReport()
        seen: dict[tuple, str] = {}
        for sid in self.strategies:
            strat = strategy(sid)
            for inv in self.model.invariants:
                steps = _BUILDERS[sid](self.model, inv)
                if not steps:
                    report.skipped.append((sid, f"no applicable operations for invariant {inv.inv_id}"))
                    continue
                hyp = self._materialise(strat, inv, steps)
                key = hyp.sequence_key()
                if key in seen:
                    report.suppressed_duplicates += 1
                    continue
                seen[key] = hyp.hyp_id
                report.hypotheses.append(hyp)
        report.hypotheses.sort(key=lambda h: (-h.priority, h.hyp_id))
        return report

    def _materialise(self, strat: Strategy, inv, steps: list[SequenceStep]) -> Hypothesis:
        _atk = _attacker(self.model)
        op_names = " -> ".join(f"{s.operation}({s.actor})" for s in steps)
        hyp_id = f"{self.model.target}:{strat.strategy_id}:{inv.inv_id}"
        boundary = self._boundary_for(steps)
        return Hypothesis(
            hyp_id=hyp_id,
            strategy_id=strat.strategy_id,
            category=strat.category,
            title=f"{strat.title}: {inv.inv_id}",
            target=self.model.target,
            capability=self._capability(steps),
            preconditions=self._preconditions(steps),
            asset=inv.applies_to[0] if inv.applies_to else (self.model.assets[0] if self.model.assets else ""),
            vulnerable_sequence=steps,
            expected_secure=self._expected_secure(inv),
            evidence_needed=list(_EVIDENCE.get(strat.strategy_id, ["final state", "invariant id"])),
            falsification=list(_FALSIFY.get(strat.strategy_id, ["the invariant holds for this sequence"])),
            authorization_boundary=boundary,
            invariant_id=inv.inv_id,
            invariant_statement=inv.statement,
            transition=self._transition_for(steps),
            priority=self._priority(strat, steps),
            rationale=f"{strat.question} Sequence: {op_names}. {strat.rationale}",
        )

    # -- field derivations ---------------------------------------------- #

    def _capability(self, steps: list[SequenceStep]) -> str:
        atk = _attacker(self.model)
        return (
            f"Be the unprivileged actor '{atk}' and invoke "
            + ", ".join(sorted({s.operation for s in steps}))
            + " in the stated order; no privileged role required."
        )

    def _preconditions(self, steps: list[SequenceStep]) -> list[str]:
        pre: list[str] = []
        for s in steps:
            op = self.model.operation(s.operation)
            if op and op.precondition and op.precondition not in pre:
                pre.append(op.precondition)
        if not pre:
            pre.append("the target is in its initial state")
        return pre

    def _expected_secure(self, inv) -> str:
        return f"The invariant '{inv.inv_id}' holds after every prefix of the sequence: {inv.statement}"

    def _boundary_for(self, steps: list[SequenceStep]) -> str:
        names = {s.operation for s in steps}
        for op in self.model.operations:
            if op.name in names and op.guard:
                roles = ", ".join(op.guard_roles) or "the declared guard"
                return f"operation '{op.name}' is guarded by '{op.guard}' ({roles})"
        return "the entry points of the modelled components"

    def _transition_for(self, steps: list[SequenceStep]) -> str:
        names = {s.operation for s in steps}
        for t in self.model.transitions:
            if t.operation in names:
                return t.name
        return ""

    def _priority(self, strat: Strategy, steps: list[SequenceStep]) -> int:
        # Cross-user / privilege / replay strategies are higher value (they yield
        # an unauthorized outcome, not merely a broken assumption).
        high = {"cross-user", "privilege", "ownership", "replay"}
        base = 80 if strat.category in high else 60
        # Sensitive operations raise priority.
        if any((self.model.operation(s.operation) or Operation(s.operation, ())).sensitive
               for s in steps):
            base += 5
        return base


def model_from_threatmodel(tm, *, evidence: Optional[list[str]] = None) -> SystemModel:
    """Adapt an existing :class:`blackheart.threatmodel.ThreatModel` to a SystemModel.

    This is the bridge that lets the state-space engine reuse BLACKHEART's
    existing threat-model artefacts instead of forcing a second description. The
    threat model already names architecture, assets, boundaries, invariants and
    (now) transitions; the adapter maps those onto the richer model and derives
    actors/operations from the profile's roles and entry points when present.
    """
    model = SystemModel(
        target=tm.target,
        summary=tm.summary,
        assets=list(tm.critical_assets),
        trust_boundaries=[b.name for b in tm.trust_boundaries],
        dependencies=list(tm.dependencies),
        evidence=list(evidence or []),
        revision=tm.revision,
    )
    # Actors: any role mentioned by a transition guard or an assumption.
    role_names: list[str] = []
    for t in tm.transitions:
        for r in t.authorized_actors:
            if r not in role_names:
                role_names.append(r)
    for name in role_names or ["attacker"]:
        model.add_actor(name, roles=(name,), unprivileged=(name in {"attacker", "user", "anonymous"}))
    # Operations: one per transition trigger, guarded by the transition's guard.
    for t in tm.transitions:
        model.add_operation(
            name=t.trigger or t.name,
            actor_roles=tuple(t.authorized_actors) or (),
            sensitive=True,
            guard=t.guard,
            guard_roles=tuple(t.authorized_actors),
            effect=f"{t.from_state} -> {t.to_state}",
            source="threatmodel:" + t.name,
        )
    for inv in tm.invariants:
        model.add_invariant(inv.inv_id, inv.statement, applies_to=tuple(inv.applies_to),
                            expression=inv.expression, severity_if_broken=inv.severity_if_broken)
    return model
