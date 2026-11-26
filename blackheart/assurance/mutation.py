"""Mutation-test the invariant set, not just the target.

A clean bounded search means little when the property could never fail. This
module applies small semantic mutations after each successful operation and asks
the certifier whether any invariant catches the mutated state:

* ``CAUGHT`` -- the invariant failed on the mutant, so it is sensitive to that
  class of change;
* ``SURVIVED`` -- no invariant noticed, so a clean result is weak evidence;
* ``ERROR`` -- the mutation could not be applied or certified.

The audit is deliberately about oracle strength. It does not claim the original
target is correct, and a survivor is a warning about the invariant, not a bug.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from ..discovery.certify import certify_exhaustive
from ..invariants.engine import InvariantSpec, OpSpec, PureState, Target

STATUSES = ("CAUGHT", "SURVIVED", "ERROR")


@dataclass(frozen=True)
class Mutation:
    name: str
    description: str
    apply: Callable[[Any], None]
    classes: tuple[str, ...] = ()

    def to_dict(self) -> dict:
        return {"name": self.name, "description": self.description,
                "classes": list(self.classes)}


@dataclass
class MutationFinding:
    mutation: str
    status: str
    invariant_id: str = ""
    witness: list[dict] = field(default_factory=list)
    reason: str = ""

    def to_dict(self) -> dict:
        return {"mutation": self.mutation, "status": self.status,
                "invariant_id": self.invariant_id, "witness": list(self.witness),
                "reason": self.reason}


@dataclass
class MutationAudit:
    findings: list[MutationFinding] = field(default_factory=list)
    reason: str = ""

    @property
    def weak(self) -> list[MutationFinding]:
        return [f for f in self.findings if f.status == "SURVIVED"]

    @property
    def trustworthy(self) -> bool:
        return bool(self.findings) and not self.weak

    def to_dict(self) -> dict:
        return {"findings": [f.to_dict() for f in self.findings],
                "weak": [f.mutation for f in self.weak],
                "trustworthy": self.trustworthy, "reason": self.reason}


def _numeric_slots(state: Any, prefix: tuple = ()) -> list[tuple[tuple, int]]:
    out: list[tuple[tuple, int]] = []
    if isinstance(state, dict):
        for key, value in state.items():
            if isinstance(value, bool):
                continue
            if isinstance(value, int):
                out.append((prefix + (key,), value))
            elif isinstance(value, (dict, list)):
                out.extend(_numeric_slots(value, prefix + (key,)))
    elif isinstance(state, list):
        for index, value in enumerate(state):
            if isinstance(value, int) and not isinstance(value, bool):
                out.append((prefix + (index,), value))
            elif isinstance(value, (dict, list)):
                out.extend(_numeric_slots(value, prefix + (index,)))
    return out


def _get(state: Any, path: tuple) -> Any:
    for key in path:
        state = state[key]
    return state


def _set(state: Any, path: tuple, value: int) -> None:
    for key in path[:-1]:
        state = state[key]
    state[path[-1]] = value


def _first(state: Any) -> Optional[tuple]:
    slots = _numeric_slots(state)
    return slots[0][0] if slots else None


def increment_first(state: Any) -> None:
    path = _first(state)
    if path is not None:
        _set(state, path, _get(state, path) + 1)


def zero_first(state: Any) -> None:
    path = _first(state)
    if path is not None:
        _set(state, path, 0)


def double_first(state: Any) -> None:
    path = _first(state)
    if path is not None:
        _set(state, path, _get(state, path) * 2)


def _named_path(state: Any, names: tuple[str, ...]) -> Optional[tuple]:
    for path, _value in _numeric_slots(state):
        if path and str(path[-1]).lower() in names:
            return path
    return None


def _set_named(state: Any, names: tuple[str, ...], value: int) -> None:
    path = _named_path(state, names)
    if path is not None:
        _set(state, path, value)


def _increment_named(state: Any, names: tuple[str, ...]) -> None:
    path = _named_path(state, names)
    if path is not None:
        _set(state, path, _get(state, path) + 1)


def set_owner_to_attacker(state: Any) -> None:
    _set_named(state, ("owner", "admin", "operator", "guardian"), 0xA11CE)


def zero_owner(state: Any) -> None:
    _set_named(state, ("owner", "admin", "operator", "guardian"), 0)


def set_price_to_one(state: Any) -> None:
    _set_named(state, ("price", "oracle", "rate", "exchangerate", "answer"), 1)


def zero_price(state: Any) -> None:
    _set_named(state, ("price", "oracle", "rate", "exchangerate", "answer"), 0)


def increment_votes(state: Any) -> None:
    _increment_named(state, ("votes", "votingpower", "delegated", "weight", "boost"))


def zero_votes(state: Any) -> None:
    _set_named(state, ("votes", "votingpower", "delegated", "weight", "boost"), 0)


def increment_nonce(state: Any) -> None:
    _increment_named(state, ("nonce", "locked", "entered", "status"))


DEFAULT_MUTATIONS = (
    Mutation("increment-first-numeric", "add one to the first numeric field",
             increment_first),
    Mutation("zero-first-numeric", "set the first numeric field to zero", zero_first),
)

#: Class-specific operators. They are still state mutations, not guard removal:
#: a SURVIVED result is weak-oracle evidence, never a claim about the code.
CLASS_MUTATIONS: dict[str, tuple[Mutation, ...]] = {
    "accounting": (
        Mutation("increment-accounting", "add one to the first accounting field",
                 increment_first, ("accounting",)),
        Mutation("zero-accounting", "zero the first accounting field",
                 zero_first, ("accounting",)),
        Mutation("double-accounting", "double the first accounting field",
                 double_first, ("accounting",)),
    ),
    "arithmetic": (
        Mutation("increment-arithmetic", "add one to the first numeric field",
                 increment_first, ("arithmetic",)),
        Mutation("double-arithmetic", "double the first numeric field",
                 double_first, ("arithmetic",)),
    ),
    "access-control": (
        Mutation("owner-to-attacker", "replace the owner/admin/operator field",
                 set_owner_to_attacker, ("access-control",)),
        Mutation("zero-owner", "zero the owner/admin/operator field",
                 zero_owner, ("access-control",)),
    ),
    "oracle": (
        Mutation("price-to-one", "set a price/oracle/rate field to one",
                 set_price_to_one, ("oracle",)),
        Mutation("zero-price", "set a price/oracle/rate field to zero",
                 zero_price, ("oracle",)),
    ),
    "governance": (
        Mutation("increment-votes", "add one to a voting/delegation field",
                 increment_votes, ("governance",)),
        Mutation("zero-votes", "zero a voting/delegation field",
                 zero_votes, ("governance",)),
    ),
    "reentrancy": (
        Mutation("increment-nonce", "increment a nonce/lock/status field",
                 increment_nonce, ("reentrancy",)),
    ),
}


def mutations_for(classes: tuple[str, ...] | list[str]) -> tuple[Mutation, ...]:
    """The class-specific operators for ``classes``, de-duplicated by name."""
    out: list[Mutation] = []
    seen: set[str] = set()
    for name in classes:
        for mutation in CLASS_MUTATIONS.get(name, ()):
            if mutation.name not in seen:
                seen.add(mutation.name)
                out.append(mutation)
    return tuple(out)


class MutantTarget(Target, PureState):
    """Delegate to ``target``, then apply a mutation to the resulting state."""

    def __init__(self, target: Target, mutation: Mutation) -> None:
        self.target = target
        self.mutation = mutation
        self.name = f"mutant:{getattr(target, 'name', 'target')}:{mutation.name}"

    def reset(self) -> Any:
        return self.target.reset()

    def ops(self) -> list[OpSpec]:
        return self.target.ops()

    def invariants(self) -> list[InvariantSpec]:
        return self.target.invariants()

    def snapshot(self, state: Any) -> dict:
        return self.target.snapshot(state)

    def step(self, state: Any, op_name: str, actor: str, params: dict[str, Any]) -> None:
        self.target.step(state, op_name, actor, params)
        self.mutation.apply(state)


def audit_mutations(
    target: Target,
    *,
    mutations: Optional[tuple[Mutation, ...]] = None,
    classes: tuple[str, ...] | list[str] = (),
    max_depth: int = 2,
) -> MutationAudit:
    """Certify each mutant; a mutation no invariant catches is a weak oracle."""
    selected = mutations
    if selected is None:
        selected = mutations_for(tuple(classes)) if classes else DEFAULT_MUTATIONS
    findings: list[MutationFinding] = []
    for mutation in selected:
        mutant = MutantTarget(target, mutation)
        try:
            cert = certify_exhaustive(mutant, max_depth=max_depth)
        except Exception as exc:  # noqa: BLE001 -- an audit failure is named
            findings.append(MutationFinding(mutation.name, "ERROR", reason=str(exc)))
            continue
        if cert.proven:
            findings.append(MutationFinding(
                mutation.name, "CAUGHT", cert.invariant_id,
                [s.to_dict() for s in cert.witness],
                "an invariant caught the mutated state",
            ))
        else:
            findings.append(MutationFinding(
                mutation.name, "SURVIVED", reason=(
                    f"no invariant caught the mutation within depth {max_depth}; "
                    "the clean result is weak evidence"),
            ))
    return MutationAudit(findings)
