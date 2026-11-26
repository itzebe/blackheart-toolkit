"""Universal Vulnerability Coverage Engine.

A persistent, reusable capability that makes it substantially harder for
BLACKHEART to *overlook* an applicable vulnerability within an authorized program.
It is not a checklist: it enumerates the applicable class space for a specific
target, generates and prioritises hypotheses (including multi-stage paths),
adapts when an approach fails, and keeps an honest coverage ledger of what was
tested, what was not, and why.

The pieces:

  * :mod:`~blackheart.coverage_engine.taxonomy` -- an extensible class universe,
    wider than the model set, so a class with no model is a visible gap not an
    invisible blind spot.
  * :mod:`~blackheart.coverage_engine.applicability` -- target-aware classification
    (applicable / inapplicable-with-reason / unresolved).
  * :mod:`~blackheart.coverage_engine.surface` -- attack-surface enumeration,
    hypothesis generation, and multi-stage attack paths.
  * :mod:`~blackheart.coverage_engine.strategy` -- materially different strategies
    on failure, with dedup and a finite, honest stop.
  * :mod:`~blackheart.coverage_engine.record` -- the durable coverage ledger and
    its states (never equating TESTED_NO_ISSUE_FOUND with "clean").
  * :mod:`~blackheart.coverage_engine.controller` -- coverage-driven continuation
    with a transparent priority model and a named stop reason.

Honesty is the design constraint: nothing here confirms a finding, a simulation is
never real execution, and an incomplete run reports as ``INCOMPLETE``.
"""

from __future__ import annotations

from .applicability import (
    ApplicabilityEngine,
    ApplicabilityResult,
    ClassVerdict,
    SurfaceReport,
    seed_record,
)
from .controller import (
    ControllerConfig,
    ControlResult,
    ProbeOutcome,
    ProbeRunner,
    ResearchController,
    StopReason,
)
from .record import (
    ClassCoverage,
    CoverageRecord,
    CoverageState,
    LedgerError,
    OPEN_STATES,
)
from .strategy import (
    DIMENSIONS,
    Attempt,
    FailureKind,
    Strategy,
    StrategySpace,
)
from .surface import (
    AttackPath,
    AttackSurface,
    EntryPoint,
    Hypothesis,
    SurfaceEnumerator,
)
from .taxonomy import (
    DEFAULT_TAXONOMY,
    SURFACES,
    SeverityBand,
    Taxonomy,
    VulnClass,
)

__all__ = [
    "ApplicabilityEngine",
    "ApplicabilityResult",
    "AttackPath",
    "AttackSurface",
    "Attempt",
    "ClassCoverage",
    "ClassVerdict",
    "ControllerConfig",
    "ControlResult",
    "CoverageRecord",
    "CoverageState",
    "DEFAULT_TAXONOMY",
    "DIMENSIONS",
    "EntryPoint",
    "FailureKind",
    "Hypothesis",
    "LedgerError",
    "OPEN_STATES",
    "ProbeOutcome",
    "ProbeRunner",
    "ResearchController",
    "SURFACES",
    "SeverityBand",
    "StopReason",
    "Strategy",
    "StrategySpace",
    "SurfaceEnumerator",
    "SurfaceReport",
    "Taxonomy",
    "VulnClass",
    "seed_record",
]
