"""ABI -> operations: a compiler-accurate read of a contract's surface.

The lexer in :mod:`blackheart.solidity.extract` proposes a model from source text
and is honest that it can miss constructs a compiler would resolve. When a
compiler is available, its ABI is the better source of truth for *which
operations exist and what they take*: it has resolved inheritance, types and
overloads. This module turns that ABI into the operation list the state-space
engine consumes -- and, like the lexer, it invents nothing: a parameter whose
type it cannot turn into a candidate domain is left without one rather than given
a guessed value.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable

from ..statespace.model import SystemModel

#: State mutability values that mean "this call can change state".
MUTATING = ("nonpayable", "payable")

DEFAULT_ACTORS = ("attacker", "victim")


@dataclass(frozen=True)
class AbiFunction:
    """One function entry from a compiler ABI."""

    name: str
    inputs: tuple[dict, ...] = ()
    outputs: tuple[dict, ...] = ()
    state_mutability: str = "nonpayable"

    @property
    def mutating(self) -> bool:
        return self.state_mutability in MUTATING

    @property
    def payable(self) -> bool:
        return self.state_mutability == "payable"

    def signature(self) -> str:
        return f"{self.name}({','.join(i.get('type', '') for i in self.inputs)})"

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "signature": self.signature(),
            "state_mutability": self.state_mutability,
            "mutating": self.mutating,
            "inputs": [dict(i) for i in self.inputs],
            "outputs": [dict(o) for o in self.outputs],
        }


def parse_abi(abi: Iterable[dict]) -> list[AbiFunction]:
    """The function entries of an ABI, in declaration order.

    Events, errors and constructors are not callable operations and are dropped;
    they are not silently mistaken for one.
    """
    functions: list[AbiFunction] = []
    for item in abi or ():
        if not isinstance(item, dict) or item.get("type") != "function":
            continue
        name = str(item.get("name", "")).strip()
        if not name:
            continue
        functions.append(
            AbiFunction(
                name=name,
                inputs=tuple(item.get("inputs", ()) or ()),
                outputs=tuple(item.get("outputs", ()) or ()),
                state_mutability=str(item.get("stateMutability", "nonpayable")),
            )
        )
    return functions


def param_domain(abi_type: str) -> list[Any]:
    """Candidate values for a parameter type, or ``[]`` when none is defensible.

    These are *samples*, not the accepted set; the certifiers treat a numeric
    sample as a bound and probe inside it. An array or struct has no single
    scalar sample, so it gets no domain rather than a fabricated value.
    """
    t = (abi_type or "").strip()
    if t.endswith("[]") or t.startswith("tuple"):
        return []
    if t.startswith("uint") or t.startswith("int"):
        return [0, 1, 100, 10 ** 18]
    if t == "bool":
        return [False, True]
    if t == "address":
        return ["attacker", "victim", "admin"]
    if t.startswith("bytes") or t == "bytes":
        return [b"", b"\x00" * 32]
    if t == "string":
        return [""]
    return []


def operations_from_abi(
    functions: Iterable[AbiFunction], *, actors: tuple[str, ...] = DEFAULT_ACTORS
) -> list[dict]:
    """The mutating functions as operation records the engine can consume.

    ``view``/``pure`` functions cannot change state, so they are not operations an
    attacker drives; they are read by the snapshot instead. A parameter with no
    defensible domain is omitted rather than given a guessed value.
    """
    ops: list[dict] = []
    for fn in functions:
        if not fn.mutating:
            continue
        domain: dict[str, list[Any]] = {}
        for i, inp in enumerate(fn.inputs):
            name = str(inp.get("name") or f"arg{i}")
            values = param_domain(str(inp.get("type", "")))
            if values:
                domain[name] = values
        ops.append(
            {
                "name": fn.name,
                "signature": fn.signature(),
                "actors": list(actors),
                "param_domain": domain,
                "payable": fn.payable,
            }
        )
    return ops


def propose_model_from_abi(
    abi: Iterable[dict],
    *,
    target_name: str,
    actors: tuple[str, ...] = DEFAULT_ACTORS,
) -> SystemModel:
    """Propose a :class:`SystemModel` whose operations come from the ABI.

    Provenance is recorded on every operation, so a reviewer can see the model was
    read from a compiler artifact rather than invented.
    """
    model = SystemModel(target=target_name)
    for actor in actors:
        model.add_actor(actor)
    functions = parse_abi(abi)
    for op in operations_from_abi(functions, actors=actors):
        model.add_operation(
            op["name"],
            actors,
            sensitive=True,
            entry_point=op["signature"],
            source=f"abi:{target_name}",
        )
    return model
