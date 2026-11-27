"""Analyse a closed component from its runtime bytecode and decompiled surface.

A decompiled surface answers *what exists*; a concrete witness replay answers
*whether one recorded outcome is reachable*. This module composes both and keeps
the two answers separate. A surface is never promoted to source, and a witness
that matches does not explain why the contract is vulnerable.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from ..bytecode import verify_runtime_hex
from ..ingest.decompiled import parse_decompiled
from ..ingest.solidity import ContractSurface


@dataclass
class ClosedAnalysis:
    status: str  # SURFACE_ONLY | WITNESS_VERIFIED | WITNESS_DIVERGED | INCOMPLETE
    contract: str = ""
    functions: list[dict] = field(default_factory=list)
    witness: dict = field(default_factory=dict)
    reason: str = ""

    @property
    def ok(self) -> bool:
        return self.status in ("SURFACE_ONLY", "WITNESS_VERIFIED")

    def to_dict(self) -> dict:
        return {
            "status": self.status,
            "contract": self.contract,
            "functions": list(self.functions),
            "witness": dict(self.witness),
            "reason": self.reason,
            "note": "a decompiled surface is a lead, never source",
        }


def analyze_closed(
    runtime_hex: str,
    *,
    decompiled_text: str = "",
    witness: Optional[dict[str, Any]] = None,
    expect_revert: Optional[bool] = None,
    expected_storage: Optional[dict[int, int]] = None,
    name: str = "Decompiled",
) -> ClosedAnalysis:
    """Recover the surface and, when given, replay one witness on the runtime."""
    surface: Optional[ContractSurface] = None
    if decompiled_text.strip():
        surface = parse_decompiled(decompiled_text, name=name)
    if witness is None:
        if surface is None:
            return ClosedAnalysis("INCOMPLETE", reason="no decompiled text and no witness")
        return ClosedAnalysis(
            "SURFACE_ONLY", surface.name,
            [{"name": f.name, "signature": f.signature, "visibility": f.visibility}
             for f in surface.functions],
            reason="the surface is recovered; every body is unmodelled",
        )
    result = verify_runtime_hex(
        runtime_hex, witness, expect_revert=expect_revert,
        expected_storage=expected_storage,
    )
    status = {
        "VERIFIED": "WITNESS_VERIFIED",
        "DIVERGED": "WITNESS_DIVERGED",
    }.get(result.status, "INCOMPLETE")
    return ClosedAnalysis(
        status, surface.name if surface else "",
        ([{"name": f.name, "signature": f.signature, "visibility": f.visibility}
          for f in surface.functions] if surface else []),
        result.to_dict(),
        "the concrete EVM reached the recorded outcome"
        if status == "WITNESS_VERIFIED" else result.reason,
    )


__all__ = ["ClosedAnalysis", "analyze_closed"]
