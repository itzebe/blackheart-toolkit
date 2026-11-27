"""Adversarial state-machine discovery -- BLACKHEART's sequence-level engine.

Conventional scanners and per-function analysis ask "is this function
vulnerable?". This engine asks the harder, higher-value questions: what can an
attacker achieve by *combining* individually-legitimate operations, by reordering
them, by acting across identities, by exploiting a privilege change between two
operations, by leaving a partial state after a half-failure, or by violating an
invariant no single call violates.

The pipeline:

    SystemModel  --(HypothesisGenerator)-->  hypotheses (falsifiable claims)
                 --(StateSpaceExplorer)-->   violations (minimal sequences)
                 --(IndependentSequenceVerifier)-->  dispositions

Nothing in this package asserts a vulnerability. A hypothesis is a claim about
intended behaviour; a violation is a sequence that broke a stated invariant; only
the independent verifier may return ``INDEPENDENTLY_VERIFIED``, and even then the
result is a claim about a *modelled* target unless it was run against a real,
authorized one.

Reuse: this engine builds on BLACKHEART's existing invariant engine
(:mod:`blackheart.invariants.engine`) -- it reuses ``OpSpec``, ``InvariantSpec``,
the ``Target`` protocol, and the minimiser's delta-debugging shape -- rather than
introducing a parallel target model. A ``SystemModel`` can be derived from an
existing :class:`blackheart.threatmodel.ThreatModel` via
:func:`blackheart.statespace.hypotheses.model_from_threatmodel`.
"""

from __future__ import annotations

from .explore import (
    ExploreConfig,
    ExploreReport,
    StateSpaceExplorer,
    Violation,
    minimize,
    run_sequence,
)
from .fixtures import FIXTURE_PAIRS, fixture_names, make_fixture
from .hypotheses import (
    STRATEGIES,
    GenerationReport,
    Hypothesis,
    HypothesisGenerator,
    SequenceStep,
    model_from_threatmodel,
    strategy,
    strategy_ids,
)
from .model import (
    DISPOSITIONS,
    UNCONFIRMED_DISPOSITIONS,
    Actor,
    ModelIncomplete,
    ModelInvariant,
    Operation,
    SystemModel,
    TransitionRule,
)
from .verify import (
    IndependentSequenceVerifier,
    VerifyConfig,
    VerifyResult,
    verify_report,
)

__all__ = [
    # model
    "Actor", "Operation", "TransitionRule", "ModelInvariant", "SystemModel",
    "ModelIncomplete", "DISPOSITIONS", "UNCONFIRMED_DISPOSITIONS",
    # hypotheses
    "Hypothesis", "SequenceStep", "HypothesisGenerator", "GenerationReport",
    "STRATEGIES", "strategy", "strategy_ids", "model_from_threatmodel",
    # explore
    "StateSpaceExplorer", "ExploreConfig", "ExploreReport", "Violation",
    "run_sequence", "minimize",
    # verify
    "IndependentSequenceVerifier", "VerifyConfig", "VerifyResult", "verify_report",
    # fixtures
    "FIXTURE_PAIRS", "fixture_names", "make_fixture",
]
