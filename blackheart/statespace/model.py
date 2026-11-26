"""The target security model for adversarial state-machine discovery.

This is the *model* half of the state-space engine: a structured, evidence-tagged
description of a system as a set of **actors**, **operations**, **guards**,
**assets**, and **invariants**, plus the **state transitions** between them. It is
deliberately a description of *intended behaviour* -- what the system promises --
never a claim that the system is broken. The engine's hypotheses are built by
looking for ways to violate what the model promises.

Why a model and not just a target object: the mission requires the engine to
reason about operation ordering, cross-actor interaction, privilege and ownership
changes, partial failures, stale state, replay, and cross-component trust. None of
those are properties of a single function; they are properties of the *system's
shape*. The shape has to be written down before it can be attacked, and every
element carries a ``source`` so a reviewer can see which real artefact (an
interface, an audit note, a test) each claim came from. A model that invents an
architecture is worse than useless -- it produces confident hypotheses about a
system that does not exist -- so construction here is explicit and provenance is
mandatory in spirit (``Operation.source`` and ``SystemModel.evidence``).

Nothing in this module executes anything or asserts a vulnerability. It is data.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional, Protocol

from ..invariants.engine import partition, unevaluable  # noqa: F401 -- re-exported

# --------------------------------------------------------------------------- #
# Dispositions -- the explicit lifecycle statuses the mission requires.
# --------------------------------------------------------------------------- #

# The mission names these exactly. They are the only vocabulary a result may use;
# a hypothesis is never promoted to a confirmed vulnerability except by passing
# through INDEPENDENTLY_VERIFIED.
DISPOSITIONS: tuple[str, ...] = (
    "HYPOTHESIS",
    "UNDER_INVESTIGATION",
    "REPRODUCED",
    "INDEPENDENTLY_VERIFIED",
    "REJECTED",
    "INSUFFICIENT_EVIDENCE",
)

# Dispositions that may never be read back as "a real vulnerability".
UNCONFIRMED_DISPOSITIONS = frozenset(
    {"HYPOTHESIS", "UNDER_INVESTIGATION", "REPRODUCED", "REJECTED", "INSUFFICIENT_EVIDENCE"}
)


# --------------------------------------------------------------------------- #
# Actors, operations, guards
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class Actor:
    """An identity that can invoke operations.

    ``unprivileged`` marks the actors an attacker can actually be: the weakest
    position in the system, per BLACKHEART's doctrine. A hypothesis whose
    vulnerable sequence requires a privileged actor that an attacker cannot hold
    is rejected by the verifier's precondition check -- so the flag matters.
    """

    name: str
    roles: tuple[str, ...] = ()
    unprivileged: bool = True
    note: str = ""

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "roles": list(self.roles),
            "unprivileged": self.unprivileged,
            "note": self.note,
        }


@dataclass(frozen=True)
class Operation:
    """A callable operation an actor may invoke, with its intended guard.

    ``guard`` / ``guard_roles`` describe the authorization the operation is
    *supposed* to enforce; a mismatch between that and what the target actually
    enforces is exactly what the explorer probes for. ``source`` records where the
    operation's existence and guard were read from (an interface file, a test, a
    doc), so the model is auditable rather than invented.
    """

    name: str
    actor_roles: tuple[str, ...]
    asset: str = ""                       # the protected asset/property it touches
    sensitive: bool = False               # does it mutate a protected asset?
    precondition: str = ""                # human-readable precondition
    effect: str = ""                      # human-readable effect
    entry_point: str = ""                 # the real entry point (function/route)
    guard: str = ""                       # the authorization guard the model expects
    guard_roles: tuple[str, ...] = ()     # roles that guard is expected to require
    requires: tuple[str, ...] = ()        # operations that must precede it (benign contract)
    source: str = ""                      # provenance of this claim

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "actor_roles": list(self.actor_roles),
            "asset": self.asset,
            "sensitive": self.sensitive,
            "precondition": self.precondition,
            "effect": self.effect,
            "entry_point": self.entry_point,
            "guard": self.guard,
            "guard_roles": list(self.guard_roles),
            "requires": list(self.requires),
            "source": self.source,
        }


@dataclass(frozen=True)
class TransitionRule:
    """A declared guard on a privileged or security-relevant transition.

    Recorded separately from the operation so the engine can ask the mission's
    question directly: *is there a reachable sequence that enters this transition
    without the guard having been satisfied?*
    """

    name: str
    guard: str
    guard_roles: tuple[str, ...]
    operation: str = ""
    description: str = ""

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "guard": self.guard,
            "guard_roles": list(self.guard_roles),
            "operation": self.operation,
            "description": self.description,
        }


@dataclass(frozen=True)
class ModelInvariant:
    """A security property the model promises must hold across all sequences.

    ``applies_to`` names the asset(s) protected; ``expression`` is the
    machine-checkable invariant id the executable target reports, so a violation
    the engine finds maps straight back to a stated promise.
    """

    inv_id: str
    statement: str
    applies_to: tuple[str, ...] = ()
    expression: str = ""
    severity_if_broken: str = "high"

    def to_dict(self) -> dict:
        return {
            "inv_id": self.inv_id,
            "statement": self.statement,
            "applies_to": list(self.applies_to),
            "expression": self.expression,
            "severity_if_broken": self.severity_if_broken,
        }


@dataclass
class SystemModel:
    """The complete, evidence-tagged description of a system under test.

    The model is the single source the hypothesis generator and the explorer read.
    ``intended_behaviours`` is the false-positive control: any observation the
    target documents as intended is not a vulnerability, and the verifier rejects
    a hypothesis whose vulnerable behaviour is listed here.
    """

    target: str
    summary: str = ""
    actors: list[Actor] = field(default_factory=list)
    operations: list[Operation] = field(default_factory=list)
    transitions: list[TransitionRule] = field(default_factory=list)
    invariants: list[ModelInvariant] = field(default_factory=list)
    assets: list[str] = field(default_factory=list)
    trust_boundaries: list[str] = field(default_factory=list)
    dependencies: list[str] = field(default_factory=list)
    intended_behaviours: list[str] = field(default_factory=list)
    authorized_entry_points: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    revision: str = ""

    # -- builders -------------------------------------------------------- #

    def add_actor(self, name: str, *, roles: tuple[str, ...] = (), unprivileged: bool = True,
                  note: str = "") -> Actor:
        a = Actor(name=name, roles=tuple(roles), unprivileged=unprivileged, note=note)
        self.actors.append(a)
        return a

    def add_operation(self, name: str, actor_roles: tuple[str, ...], **kw: Any) -> Operation:
        op = Operation(name=name, actor_roles=tuple(actor_roles), **kw)
        self.operations.append(op)
        return op

    def add_transition(self, name: str, guard: str, guard_roles: tuple[str, ...], *,
                       operation: str = "", description: str = "") -> TransitionRule:
        t = TransitionRule(name=name, guard=guard, guard_roles=tuple(guard_roles),
                           operation=operation, description=description)
        self.transitions.append(t)
        return t

    def add_invariant(self, inv_id: str, statement: str, *, applies_to: tuple[str, ...] = (),
                      expression: str = "", severity_if_broken: str = "high") -> ModelInvariant:
        inv = ModelInvariant(inv_id=inv_id, statement=statement, applies_to=tuple(applies_to),
                             expression=expression or inv_id, severity_if_broken=severity_if_broken)
        self.invariants.append(inv)
        return inv

    # -- lookups --------------------------------------------------------- #

    def operation(self, name: str) -> Optional[Operation]:
        for op in self.operations:
            if op.name == name:
                return op
        return None

    def sensitive_operations(self) -> list[Operation]:
        return [op for op in self.operations if op.sensitive]

    def unprivileged_actors(self) -> list[Actor]:
        return [a for a in self.actors if a.unprivileged]

    def actor(self, name: str) -> Optional[Actor]:
        for a in self.actors:
            if a.name == name:
                return a
        return None

    def actors_for(self, op: Operation) -> list[Actor]:
        """Actors that can invoke ``op``: those holding one of its roles, or any
        actor when the operation declares no role restriction (a public op)."""
        if not op.actor_roles:
            return list(self.actors)
        out = [a for a in self.actors if set(a.roles) & set(op.actor_roles)]
        return out or list(self.actors)

    def missing(self) -> list[str]:
        """Required elements absent from the model -- the completeness gate."""
        gaps: list[str] = []
        if not self.summary.strip():
            gaps.append("summary")
        if not self.actors:
            gaps.append("actors")
        if not self.operations:
            gaps.append("operations")
        if not self.invariants:
            gaps.append("invariants")
        if not self.assets:
            gaps.append("assets")
        return gaps

    def is_complete(self) -> bool:
        return not self.missing()

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "summary": self.summary,
            "revision": self.revision,
            "actors": [a.to_dict() for a in self.actors],
            "operations": [o.to_dict() for o in self.operations],
            "transitions": [t.to_dict() for t in self.transitions],
            "invariants": [i.to_dict() for i in self.invariants],
            "assets": list(self.assets),
            "trust_boundaries": list(self.trust_boundaries),
            "dependencies": list(self.dependencies),
            "intended_behaviours": list(self.intended_behaviours),
            "authorized_entry_points": list(self.authorized_entry_points),
            "evidence": list(self.evidence),
        }


class ModelIncomplete(RuntimeError):
    """Raised when a hypothesis is requested against an incomplete model.

    The pipeline fails closed: it will not generate hypotheses about a system that
    has not stated what it protects, exactly as the threat-model gate does.
    """


# --------------------------------------------------------------------------- #
# The executable target protocol
# --------------------------------------------------------------------------- #

class SequenceTarget(Protocol):
    """A system under test the engine can drive.

    This mirrors :class:`blackheart.invariants.engine.Target` (so the existing
    random fuzzer can run the *same* fixtures for a fair ablation) and adds
    :meth:`model`, the richer description the state-space engine reads.
    """

    name: str

    def model(self) -> SystemModel: ...
    def reset(self) -> Any: ...
    def ops(self) -> list[Any]: ...          # list[OpSpec], reusing the existing spec
    def invariants(self) -> list[Any]: ...   # list[InvariantSpec]
    def step(self, state: Any, op_name: str, actor: str, params: dict[str, Any]) -> None: ...
    def snapshot(self, state: Any) -> dict[str, Any]: ...


def violated(state: Any, invariants: list[Any]) -> list[str]:
    """Return the invariant ids a state *demonstrably* violates.

    A predicate that cannot be evaluated is not a violation and is not a pass;
    :func:`unevaluable` names those ids so a caller never reports "no violation"
    when it merely could not tell.
    """
    return partition(state, invariants)[0]
