"""Witness minimisation and source-mapped traces.

The search already minimises operation sequences (``invariants.engine``) and
calldata (``symbolic.minimize``). This module adds the missing report layer: map
a witness back to the exact source function and line, and expose the certifier's
prefix-minimal witness as one object. It never invents a location: a step with no
matching function is reported as ``unmapped`` with its reason.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, Optional

from .ingest.solidity import ContractSurface, FunctionSurface


@dataclass(frozen=True)
class SourceFrame:
    index: int
    actor: str
    action: str
    params: dict
    contract: str
    function: str
    file: str
    line: int
    snippet: str
    mapped: bool = True
    reason: str = ""

    def to_dict(self) -> dict:
        return {
            "index": self.index, "actor": self.actor, "action": self.action,
            "params": dict(self.params), "contract": self.contract,
            "function": self.function, "file": self.file, "line": self.line,
            "snippet": self.snippet, "mapped": self.mapped,
            "reason": self.reason,
        }


def _function_for(contract: ContractSurface, action: str) -> Optional[FunctionSurface]:
    name = action.rsplit(".", 1)[-1]
    for function in contract.functions:
        if function.name == name:
            return function
    return None


def _snippet(function: FunctionSurface, action: str) -> tuple[int, str]:
    body = function.body or ""
    index = body.find(action)
    if index < 0:
        for offset, text in enumerate(body.splitlines()):
            if text.strip():
                return function.line + offset, " ".join(text.split())
        return function.line, ""
    line = function.line + body[:index].count("\n")
    start = body.rfind("\n", 0, index) + 1
    end = body.find("\n", index)
    if end < 0:
        end = len(body)
    return line, " ".join(body[start:end].split())


def source_trace(contract: ContractSurface, steps: Iterable[Any], *,
                 source_path: str = "") -> list[SourceFrame]:
    """Map a witness sequence to source frames; unmapped steps stay explicit."""
    frames: list[SourceFrame] = []
    for index, step in enumerate(steps):
        action = str(getattr(step, "action", ""))
        actor = str(getattr(step, "actor", ""))
        params = dict(getattr(step, "params", {}) or {})
        function = _function_for(contract, action)
        if function is None:
            frames.append(SourceFrame(
                index, actor, action, params, contract.name, "", source_path or contract.path,
                0, "", False, "no function with this name in the modelled contract"))
            continue
        line, snippet = _snippet(function, action)
        frames.append(SourceFrame(
            index, actor, action, params, contract.name, function.name,
            source_path or contract.path, line, snippet))
    return frames


@dataclass
class MinimizedWitness:
    steps: list[Any] = field(default_factory=list)
    original_length: int = 0
    minimized: bool = False
    proven: bool = False
    reason: str = ""
    certificate: Optional[dict] = None

    def to_dict(self) -> dict:
        return {
            "steps": [getattr(s, "to_dict", lambda: s)() for s in self.steps],
            "original_length": self.original_length,
            "minimized_length": len(self.steps),
            "minimized": self.minimized,
            "proven": self.proven,
            "reason": self.reason,
            "certificate": self.certificate,
        }


def minimize_witness(target: Any, steps: Iterable[Any], invariant_id: str) -> MinimizedWitness:
    """Return the certifier's reproducible prefix-minimal witness, or the input.

    ``target`` is the engine's ``SequenceTarget``. A failure to certify is not a
    failure of minimisation: the original sequence is returned with ``proven``
    false and the reason recorded.
    """
    original = list(steps)
    from .discovery.certify import certify_path

    try:
        cert = certify_path(target, original, invariant_id=invariant_id)
    except Exception as exc:  # noqa: BLE001 -- a minimiser must not hide the witness
        return MinimizedWitness(original, len(original), False, False,
                                f"{type(exc).__name__}: {exc}")
    if not cert.proven:
        return MinimizedWitness(original, len(original), False, False,
                                "the sequence did not certify", cert.to_dict())
    witness = list(cert.witness)
    return MinimizedWitness(
        witness, len(original), len(witness) < len(original), True,
        "certifier prefix-minimal witness", cert.to_dict())


__all__ = ["SourceFrame", "source_trace", "MinimizedWitness", "minimize_witness"]
