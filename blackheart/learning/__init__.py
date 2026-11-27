"""Self-improvement engine (mission Phase 6).

BLACKHEART learns from its own research outcomes. This engine closes the loop the
mission describes:

    extract lesson -> identify the strategy weakness -> propose an improvement
    -> demonstrate the OLD weakness with a failing test -> benchmark the
    improvement on the historical corpus AND the negative (anti-overfitting)
    corpus -> measure -> accept or reject -> emit a regression test.

Two hard safety properties:

  * The engine may never rewrite its own authorization controls or verification
    gates. ``PROTECTED_PATHS`` names them, and ``propose``/``evaluate`` refuse any
    improvement that targets them. Learning must not weaken safety.
  * An improvement is adopted only when it does not regress the negative corpus.
    A change that only memorises the historical corpus is rejected -- that is the
    overfitting guard.

The engine does not edit source. An "improvement" is a *value* -- a
:class:`~blackheart.hypothesis.Strategy` -- which the benchmark measures directly.
Adoption is recorded, not applied by rewriting code, so a human can review it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from ..hypothesis import BASELINE_STRATEGY, HypothesisEngine, Strategy
from ..models import ResearchRecord, InvestigationStatus
from ..research import ResearchMemory
from .benchmark import RankingBenchmark, Scenario, HISTORICAL, NEGATIVE

# Modules an improvement may never modify. Learning must not weaken the safety
# controls that gate active testing and gate findings.
PROTECTED_PATHS = frozenset(
    {
        "blackheart/authz",
        "blackheart/verify",
    }
)


@dataclass
class Improvement:
    """A proposed, benchmarkable strategy change."""

    name: str
    description: str
    strategy: Strategy
    targets: tuple[str, ...] = ()          # modules the change would touch
    lesson: str = ""

    def touches_protected(self) -> bool:
        return any(
            t == p or t.startswith(p + "/") or p.startswith(t)
            for t in self.targets
            for p in PROTECTED_PATHS
        )

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "description": self.description,
            "strategy": self.strategy.to_dict(),
            "targets": list(self.targets),
            "lesson": self.lesson,
            "touches_protected": self.touches_protected(),
        }


@dataclass
class ImprovementVerdict:
    improvement: str
    accepted: bool = False
    reasons: list[str] = field(default_factory=list)
    before: dict = field(default_factory=dict)
    after: dict = field(default_factory=dict)
    failing_test: str = ""

    def to_dict(self) -> dict:
        return {
            "improvement": self.improvement,
            "accepted": self.accepted,
            "reasons": self.reasons,
            "before": self.before,
            "after": self.after,
            "failing_test": self.failing_test,
        }


class LearningEngine:
    def __init__(self, memory: Optional[ResearchMemory] = None,
                 benchmark: Optional[RankingBenchmark] = None) -> None:
        self.memory = memory
        self.benchmark = benchmark or RankingBenchmark()

    # ------------------------------------------------------------------ #
    # 1. Extract a lesson from a finished investigation.
    # ------------------------------------------------------------------ #
    def extract_lesson(self, record: ResearchRecord) -> str:
        """Turn a research record into one reusable lesson sentence."""
        if record.status == InvestigationStatus.DISPROVEN.value and record.false_positive_reason:
            return (
                f"Class '{record.vulnerability_class}' on '{record.target}' was "
                f"disproven: {record.false_positive_reason}"
            )
        if record.status == InvestigationStatus.CONFIRMED.value:
            return (
                f"Class '{record.vulnerability_class}' on '{record.target}' was "
                f"confirmed: {record.impact or record.actual_outcome}"
            )
        return (
            f"Class '{record.vulnerability_class}' on '{record.target}' remains "
            f"{record.status}: {record.actual_outcome or 'no outcome recorded'}"
        )

    # ------------------------------------------------------------------ #
    # 2. Identify a weakness and propose an improvement.
    # ------------------------------------------------------------------ #
    def propose_surface_awareness(self) -> Improvement:
        """The improvement demonstrated in Phase 10: rank by target surface.

        The baseline strategy scores every class from static constants, so it
        ranks the same class first for every target regardless of whether the
        target exposes that class's surface. The surface-applicability model fixes
        that. This method returns it as a benchmarkable :class:`Improvement`.
        """
        return Improvement(
            name="surface-aware-ranking-v1",
            description=(
                "Multiply each class score by a target-surface applicability factor: "
                "damp classes whose required surface (oracle, signature, proxy, "
                "callback, shares, access-control, bridge) is absent; boost those "
                "present. Negation-aware so 'no external price dependency' does not "
                "count as an oracle."
            ),
            strategy=Strategy(
                "surface-aware-v1", dict(BASELINE_STRATEGY.weights), use_surface=True,
                notes="surface applicability model (blackheart/hypothesis/surface.py)",
            ),
            targets=("blackheart/hypothesis",),
            lesson=(
                "Ranking must consider whether the target exposes the surface a class "
                "requires; static per-class constants rank the same class first for all targets."
            ),
        )

    # ------------------------------------------------------------------ #
    # 3. Demonstrate the OLD weakness with a concrete, failing example.
    # ------------------------------------------------------------------ #
    def demonstrate_weakness(self, scenario: Scenario) -> dict:
        """Show the baseline ranks the target's real class below the top.

        Returns a dict describing the failing case, suitable for turning into a
        regression test: the scenario, the baseline's wrong top-1, and the
        candidate's correct top-1.
        """
        baseline_engine = HypothesisEngine(scenario.profile, None, strategy=BASELINE_STRATEGY)
        cand_engine = HypothesisEngine(scenario.profile, None, strategy=self.propose_surface_awareness().strategy)
        base_rank = self._class_ranking(baseline_engine)
        cand_rank = self._class_ranking(cand_engine)
        return {
            "scenario": scenario.name,
            "acceptable": list(scenario.acceptable),
            "baseline_top1": base_rank[0] if base_rank else None,
            "candidate_top1": cand_rank[0] if cand_rank else None,
            "baseline_correct": bool(base_rank and base_rank[0] in scenario.acceptable),
            "candidate_correct": bool(cand_rank and cand_rank[0] in scenario.acceptable),
        }

    @staticmethod
    def _class_ranking(engine: HypothesisEngine) -> list[str]:
        best: dict[str, float] = {}
        for h in engine.generate():
            if h.skipped_disproven:
                continue
            best[h.category] = max(best.get(h.category, 0.0), h.score)
        return [c for c, _ in sorted(best.items(), key=lambda kv: (-kv[1], kv[0]))]

    # ------------------------------------------------------------------ #
    # 4/5/6. Benchmark, measure, accept or reject.
    # ------------------------------------------------------------------ #
    def evaluate(self, improvement: Improvement,
                 baseline: Strategy = BASELINE_STRATEGY) -> ImprovementVerdict:
        """Adopt only if it improves the corpora and regresses neither."""
        verdict = ImprovementVerdict(improvement=improvement.name)

        if improvement.touches_protected():
            verdict.accepted = False
            verdict.reasons.append(
                "REFUSED: the improvement targets a protected safety module "
                f"({', '.join(PROTECTED_PATHS)}); the learning engine may not modify "
                "authorization or verification."
            )
            return verdict

        before = self.benchmark.evaluate_all(
            lambda p, m, s=baseline: HypothesisEngine(p, m, strategy=s)
        )
        try:
            after = self.benchmark.evaluate_all(
                lambda p, m, s=improvement.strategy: HypothesisEngine(p, m, strategy=s)
            )
        except Exception as exc:  # a proposal that crashes is not an improvement
            verdict.accepted = False
            verdict.before = before
            verdict.reasons.append(f"REJECTED: the improvement raised during benchmarking: {exc}")
            return verdict
        verdict.before, verdict.after = before, after

        regressions: list[str] = []
        gains: list[str] = []
        for corpus in ("historical", "negative"):
            b, a = before[corpus], after[corpus]
            for metric in ("top1_accuracy", "suppression_accuracy", "mrr"):
                if a[metric] < b[metric] - 1e-9:
                    regressions.append(f"{corpus}.{metric}: {b[metric]} -> {a[metric]}")
                elif a[metric] > b[metric] + 1e-9:
                    gains.append(f"{corpus}.{metric}: {b[metric]} -> {a[metric]}")

        if regressions:
            verdict.accepted = False
            verdict.reasons.append("REJECTED: regression(s) " + "; ".join(regressions))
        elif not gains:
            verdict.accepted = False
            verdict.reasons.append("REJECTED: no measurable improvement")
        else:
            verdict.accepted = True
            verdict.reasons.append("ACCEPTED: " + "; ".join(gains))

        verdict.failing_test = self.render_regression_test(improvement)
        return verdict

    # ------------------------------------------------------------------ #
    # 7. A regression test that preserves the lesson.
    # ------------------------------------------------------------------ #
    def render_regression_test(self, improvement: Improvement) -> str:
        """Render a self-contained pytest that fails on the baseline and passes
        with the improvement. This is the lesson, frozen as a test."""
        weak = [self.demonstrate_weakness(s) for s in HISTORICAL + NEGATIVE]
        failing = [w for w in weak if not w["baseline_correct"]]
        return _REGRESSION_TEMPLATE.format(
            improvement=improvement.name,
            description=improvement.description,
            n_failing=len(failing),
            failing_names=", ".join(w["scenario"] for w in failing) or "none",
        )


_REGRESSION_TEMPLATE = '''"""Auto-generated BLACKHEART learning regression -- DO NOT EDIT BY HAND.

Preserves the lesson from improvement '{improvement}':
{description}

Before this improvement, the baseline strategy mis-ranked {n_failing} corpus
scenario(s) ({failing_names}). This test asserts the adopted strategy keeps
ranking them correctly, so the lesson cannot silently regress.

Regenerate with: python3 -m blackheart learn --demo
"""

from blackheart.hypothesis import BASELINE_STRATEGY, HypothesisEngine
from blackheart.learning.benchmark import HISTORICAL, NEGATIVE


def _top_class(profile, strategy):
    engine = HypothesisEngine(profile, None, strategy=strategy)
    best = {{}}
    for h in engine.generate():
        if h.skipped_disproven:
            continue
        best[h.category] = max(best.get(h.category, 0.0), h.score)
    return next(iter(sorted(best, key=lambda c: (-best[c], c))), None)


def test_surface_aware_beats_baseline_on_the_corpus():
    baseline_top1 = 0
    candidate_top1 = 0
    for scenario in HISTORICAL + NEGATIVE:
        base = _top_class(scenario.profile, BASELINE_STRATEGY)
        cand = _top_class(scenario.profile, _CANDIDATE_STRATEGY())
        if base in scenario.acceptable:
            baseline_top1 += 1
        if cand in scenario.acceptable:
            candidate_top1 += 1
    assert candidate_top1 > baseline_top1, (
        f"surface-aware strategy must beat the baseline "
        f"(baseline={{baseline_top1}}, candidate={{candidate_top1}})"
    )


def test_improvement_does_not_regress_the_negative_corpus():
    for scenario in NEGATIVE:
        cand = _top_class(scenario.profile, _CANDIDATE_STRATEGY())
        assert cand in scenario.acceptable, (
            f"negative-corpus regression on {{scenario.name}}: got {{cand}}"
        )


def _CANDIDATE_STRATEGY():
    from blackheart.hypothesis import Strategy
    return Strategy("surface-aware-v1", dict(BASELINE_STRATEGY.weights), use_surface=True)
'''
