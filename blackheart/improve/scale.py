"""Bounded parallel ingestion and deterministic target ranking.

Large repositories and multi-target engagements spend most of their time in
independent scans. This module runs those scans with the existing bounded
executor, captures one failure without cancelling its siblings, and ranks the
results by a caller-supplied score. The ranking is stable: equal scores keep the
input order, so a rerun is reproducible.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Iterable

from ..ingest.flags import evaluate as evaluate_flags
from ..ingest.solidity import ingest
from ..parallel import map_parallel


@dataclass
class IngestResult:
    path: str
    status: str
    contracts: int = 0
    functions: int = 0
    flags: int = 0
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "path": self.path, "status": self.status,
            "contracts": self.contracts, "functions": self.functions,
            "flags": self.flags, "errors": list(self.errors),
        }


def _ingest_one(path: str) -> IngestResult:
    report = ingest(path)
    flags = evaluate_flags(report)
    return IngestResult(
        path=str(path), status="OK" if not report.errors else "PARTIAL",
        contracts=len(report.contracts),
        functions=len(report.functions),
        flags=len(flags),
        errors=list(report.errors),
    )


def batch_ingest(paths: Iterable[str], *, workers: int = 4) -> list[IngestResult]:
    """Ingest independent paths in parallel; one failure is a result, not a stop."""
    items = [str(p) for p in paths]
    outcomes = map_parallel(items, _ingest_one, workers=workers)
    results: list[IngestResult] = []
    for item, outcome in zip(items, outcomes):
        if outcome.ok:
            results.append(outcome.value)
        else:
            results.append(IngestResult(item, "ERROR", errors=[outcome.error]))
    return results


@dataclass
class Ranked:
    item: Any
    score: float
    status: str
    index: int = 0

    def to_dict(self) -> dict:
        return {"item": self.item, "score": self.score, "status": self.status}


def rank_targets(
    items: Iterable[Any],
    scorer: Callable[[Any], float],
    *,
    workers: int = 4,
) -> list[Ranked]:
    """Score items in parallel and rank highest first, stable on ties."""
    values = list(items)
    outcomes = map_parallel(values, scorer, workers=workers)
    ranked: list[Ranked] = []
    for index, (item, outcome) in enumerate(zip(values, outcomes)):
        if outcome.ok:
            ranked.append(Ranked(item, float(outcome.value), "OK", index))
        else:
            ranked.append(Ranked(item, float("-inf"), outcome.error, index))
    ranked.sort(key=lambda r: (-r.score, r.index))
    return ranked


__all__ = ["IngestResult", "batch_ingest", "Ranked", "rank_targets"]
