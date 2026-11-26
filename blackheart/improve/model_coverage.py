"""Report exactly what the executable model can and cannot read.

Full-language synthesis is not a switch that can be flipped. This module makes
the remaining gap measurable: for each contract it reports the modelled
operations, the unmodelled operations, every statement the interpreter could not
read, and the external calls it recorded. A caller can then decide whether a
missing feature matters for the target instead of discovering it from a wrong
negative.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from ..ingest.solidity import ContractSurface, ingest, scan_source
from ..ingest.synthesize import synthesize


@dataclass
class ContractCoverage:
    contract: str
    path: str
    modelled_ops: list[str] = field(default_factory=list)
    unmodelled_ops: list[str] = field(default_factory=list)
    unmodelled_statements: list[str] = field(default_factory=list)
    external_calls: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def total_ops(self) -> int:
        return len(self.modelled_ops) + len(self.unmodelled_ops)

    @property
    def coverage_bps(self) -> int:
        total = self.total_ops
        return (10_000 * len(self.modelled_ops)) // total if total else 0

    def to_dict(self) -> dict:
        return {
            "contract": self.contract,
            "path": self.path,
            "modelled_ops": list(self.modelled_ops),
            "unmodelled_ops": list(self.unmodelled_ops),
            "unmodelled_statements": list(self.unmodelled_statements),
            "external_calls": list(self.external_calls),
            "notes": list(self.notes),
            "coverage_bps": self.coverage_bps,
        }


def audit_contract(contract: ContractSurface) -> ContractCoverage:
    _target, report = synthesize(contract)
    return ContractCoverage(
        contract=report.contract, path=report.path,
        modelled_ops=list(report.modelled_ops),
        unmodelled_ops=list(report.unmodelled_ops),
        unmodelled_statements=list(report.unmodelled_statements),
        external_calls=list(report.external_calls),
        notes=list(report.notes),
    )


def audit_source(path: str | Path, *, text: str | None = None) -> list[ContractCoverage]:
    p = Path(path)
    if text is None:
        if p.is_dir():
            report = ingest(p)
            return [audit_contract(c) for c in report.contracts]
        text = p.read_text(encoding="utf-8")
    return [audit_contract(c) for c in scan_source(text, str(p))]


__all__ = ["ContractCoverage", "audit_contract", "audit_source"]
