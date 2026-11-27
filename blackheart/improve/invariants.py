"""Propose invariants from source, with provenance and confidence.

The state-space extractor already emits accounting candidates. This module adds
the common economic and control patterns an operator would otherwise hand-write:
token conservation, privileged mutation, reentrancy exposure and timestamp
dependence. Every result is a *candidate* with a file and line, and a confidence
that says how much the source actually proves. Nothing here confirms a bug.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from ..solidity.extract import propose_model_from_files


@dataclass
class InvariantCandidate:
    kind: str
    statement: str
    provenance: str
    confidence: str = "low"

    def to_dict(self) -> dict:
        return {
            "kind": self.kind,
            "statement": self.statement,
            "provenance": self.provenance,
            "confidence": self.confidence,
        }


@dataclass
class DiscoveryReport:
    files: list[str] = field(default_factory=list)
    candidates: list[InvariantCandidate] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "files": list(self.files),
            "candidates": [c.to_dict() for c in self.candidates],
            "limitations": list(self.limitations),
            "note": "candidates are leads with provenance, not claims",
        }


_MAPPING_UINT = re.compile(
    r"mapping\s*\(\s*[^=]*?=>\s*uint\d*\s*\)\s*(?:public\s+)?([A-Za-z_]\w*)")
_SUPPLY = re.compile(r"\b(totalSupply|total_supply|totalShares|totalAssets)\b")
_GUARD = re.compile(r"\b(onlyOwner|onlyAdmin|onlyRole|onlyGovernance|auth)\b")
_REENTRANCY = re.compile(r"\b(nonReentrant|ReentrancyGuard)\b")
_TIMESTAMP = re.compile(r"\b(block\.timestamp|now)\b")


def _line(text: str, index: int) -> int:
    return text.count("\n", 0, index) + 1


def discover_invariants(paths: list[str] | tuple[str, ...]) -> DiscoveryReport:
    """Scan files and return heuristic invariant candidates with provenance."""
    report = DiscoveryReport(files=[str(p) for p in paths])
    parsed = propose_model_from_files(paths)
    for candidate in parsed.candidates:
        report.candidates.append(InvariantCandidate(
            "accounting", candidate.statement, candidate.provenance,
            candidate.confidence,
        ))
    report.limitations.extend(parsed.limitations)
    for raw in paths:
        p = Path(raw)
        try:
            text = p.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            report.limitations.append(f"{p}: {exc}")
            continue
        mappings = list(_MAPPING_UINT.finditer(text))
        supply = _SUPPLY.search(text)
        if mappings and supply:
            m = mappings[0]
            report.candidates.append(InvariantCandidate(
                "conservation",
                f"sum({m.group(1)}) == {supply.group(1)}",
                f"{p}:{_line(text, m.start())}", "medium",
            ))
        for match in _GUARD.finditer(text):
            report.candidates.append(InvariantCandidate(
                "authorization",
                f"only the declared role may change guarded state ({match.group(1)})",
                f"{p}:{_line(text, match.start())}", "medium",
            ))
            break
        if _REENTRANCY.search(text):
            match = _REENTRANCY.search(text)
            report.candidates.append(InvariantCandidate(
                "reentrancy",
                "state is consistent before an external call returns",
                f"{p}:{_line(text, match.start())}", "low",
            ))
        if _TIMESTAMP.search(text):
            match = _TIMESTAMP.search(text)
            report.candidates.append(InvariantCandidate(
                "timing",
                "a timestamp-dependent branch cannot be moved across its boundary",
                f"{p}:{_line(text, match.start())}", "low",
            ))
    return report


__all__ = ["InvariantCandidate", "DiscoveryReport", "discover_invariants"]
