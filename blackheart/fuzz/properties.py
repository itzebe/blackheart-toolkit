"""Property pipeline: turn a written spec into executable invariants and a test.

A fuzzer is only as good as the property it checks. "Call random functions and
see if it reverts" finds crashes; the bugs that pay are *property* violations --
``totalSupply == sum(balances)``, ``assets >= shares * price``, ``sum of deposits
== contract balance``. Scribble and Chimera exist to make writing those properties
cheap. This module brings the same idea to BLACKHEART with no new dependency:

* A tiny, human-readable spec format (INI-like blocks) declares each property in
  two forms: a **Solidity** expression (for the generated Foundry/Chimera test)
  and an optional **Python** expression (for the invariant engine, evaluated over
  a target's ``snapshot`` dict).
* :func:`parse_properties` reads the text; :func:`to_invariant_specs` builds real
  :class:`~blackheart.invariants.engine.InvariantSpec` objects the engine can run;
  :func:`render_invariant_test` emits a Foundry/Chimera ``.t.sol`` harness.

Honesty rules:

* **A property is a hypothesis.** A generated invariant that passes proves
  nothing; a generated invariant that fails is a lead to reproduce, not a finding.
  Nothing here claims a property "holds".
* **A missing Python predicate is unevaluable, not true.** A spec with only a
  Solidity expression yields an ``InvariantSpec`` whose predicate *raises*, which
  the engine records as ``None`` ("could not evaluate") -- so a strategy can never
  mistake the absence of a check for a pass.
* **The Python expression is operator-authored.** It is compiled and evaluated
  with builtins removed; it is never remote input.
"""

from __future__ import annotations

import configparser
from dataclasses import dataclass
from typing import Any, Callable, Optional

from ..invariants.engine import InvariantSpec

#: Builtins a Python predicate may use. Deliberately tiny: a predicate reads a
#: state dict and compares numbers; it has no business importing or doing I/O.
_SAFE_BUILTINS: dict[str, Any] = {
    "sum": sum, "len": len, "min": min, "max": max,
    "abs": abs, "all": all, "any": any, "sorted": sorted,
    "int": int, "bool": bool,
}


class PropertyError(ValueError):
    """A property spec is malformed or cannot be built into an invariant."""


@dataclass
class PropertySpec:
    """One written property, in Solidity and (optionally) Python form."""

    inv_id: str
    solidity: str
    title: str = ""
    python: str = ""
    severity: str = "high"

    def to_dict(self) -> dict[str, Any]:
        return {
            "inv_id": self.inv_id,
            "title": self.title,
            "solidity": self.solidity,
            "python": self.python,
            "severity": self.severity,
        }


def parse_properties(text: str) -> list[PropertySpec]:
    """Parse INI-like blocks into :class:`PropertySpec`s.

    Each ``[inv_id]`` section carries ``solidity`` (required), and optional
    ``title``, ``python`` and ``severity`` keys. Example::

        [total_supply_equals_sum]
        title = totalSupply equals sum of balances
        solidity = totalSupply() == sumBalances()
        python = s["total"] == sum(s["balances"])
        severity = high
    """
    parser = configparser.RawConfigParser()
    parser.optionxform = str  # type: ignore[assignment]  # keep key case
    try:
        parser.read_string(text)
    except configparser.Error as exc:  # pragma: no cover - message passthrough
        raise PropertyError(f"could not parse property spec: {exc}") from exc

    specs: list[PropertySpec] = []
    for section in parser.sections():
        solidity = (parser.get(section, "solidity", fallback="") or "").strip()
        if not solidity:
            raise PropertyError(f"property {section!r} has no 'solidity' expression")
        specs.append(PropertySpec(
            inv_id=section.strip(),
            solidity=solidity,
            title=(parser.get(section, "title", fallback="") or "").strip(),
            python=(parser.get(section, "python", fallback="") or "").strip(),
            severity=(parser.get(section, "severity", fallback="high") or "high").strip(),
        ))
    if not specs:
        raise PropertyError("no properties found in spec")
    return specs


def _compile_predicate(expression: str) -> Callable[[Any], Optional[bool]]:
    """Compile an operator-authored Python predicate over a state dict ``s``."""
    code = compile(expression, "<property>", "eval")

    def predicate(state: Any) -> bool:
        # Exceptions are left to propagate: ``InvariantSpec.evaluate`` turns a
        # raise into ``None`` ("could not evaluate"), the honest third value.
        return bool(eval(code, {"__builtins__": _SAFE_BUILTINS}, {"s": state}))

    return predicate


def to_invariant_specs(properties: list[PropertySpec]) -> list[InvariantSpec]:
    """Build executable :class:`InvariantSpec`s from written properties.

    A property with no ``python`` expression yields a predicate that returns
    ``None`` (unevaluable) -- never ``True`` -- so an engine treats it as "could
    not check", not "passed".
    """
    specs: list[InvariantSpec] = []
    for prop in properties:
        if prop.python:
            predicate = _compile_predicate(prop.python)
        else:
            def predicate(_state: Any) -> bool:  # noqa: ANN001
                # Raising marks the property unevaluable; returning a value would
                # be read by the engine as a verdict.
                raise NotImplementedError(
                    f"property {prop.inv_id!r} has no executable Python predicate"
                )
        specs.append(InvariantSpec(
            inv_id=prop.inv_id,
            title=prop.title or prop.inv_id,
            predicate=predicate,
            severity_if_broken=prop.severity,
        ))
    return specs


def render_invariant_test(properties: list[PropertySpec], *, contract_name: str,
                          target_type: str, target_var: str = "target",
                          target_ctor: str = "", pragma: str = "^0.8.20") -> str:
    """Render a Foundry/Chimera invariant test asserting each Solidity expression.

    This is the Echidna/Foundry/Medusa consumer (it may use forge-std). The
    forge-std-free Halmos path is :mod:`blackheart.symbolic.harness`.
    """
    if not properties:
        raise PropertyError("cannot render a test with no properties")
    lines: list[str] = [
        "// SPDX-License-Identifier: MIT",
        f"pragma solidity {pragma};",
        "",
        "// Generated by blackheart.fuzz.properties -- a hypothesis, not a proof.",
        'import {Test} from "forge-std/Test.sol";',
        "",
        f"contract {contract_name} is Test {{",
        f"    {target_type} internal {target_var};",
        "",
        "    function setUp() public {",
        f"        {target_var} = {target_type}({target_ctor});",
        "    }",
    ]
    for prop in properties:
        lines.append("")
        if prop.title:
            lines.append(f"    /// {prop.title}")
        lines.append(f"    function invariant_{prop.inv_id}() public {{")
        lines.append(f"        assert({prop.solidity});")
        lines.append("    }")
    lines.append("}")
    lines.append("")
    return "\n".join(lines)


def load_specs(text: str) -> tuple[list[PropertySpec], list[InvariantSpec]]:
    """Convenience: parse text and build both representations in one call."""
    props = parse_properties(text)
    return props, to_invariant_specs(props)


__all__ = [
    "PropertyError",
    "PropertySpec",
    "parse_properties",
    "to_invariant_specs",
    "render_invariant_test",
    "load_specs",
]
