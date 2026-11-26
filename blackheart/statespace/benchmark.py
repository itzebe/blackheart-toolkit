"""Reproducible adversarial-discovery benchmark with an honest ablation.

The mission requires the improvement to be *measurable*, not asserted. This module
runs a fixed, deterministic benchmark that compares BLACKHEART's new state-space
engine against the existing random stateful fuzzer
(:class:`blackheart.invariants.engine.StatefulFuzzer`) on the *same* fixtures and
the *same* invariants, and reports the difference.

What is measured, per fixture pair:

  * **Detection** -- did the engine find a genuine invariant violation on the
    vulnerable variant?
  * **False positives** -- did it (wrongly) report a violation on the secure
    control? A non-zero count here is a failure of the engine, and it is reported,
    not hidden.
  * **Cost** -- sequences tried, steps evaluated, wall-clock seconds.
  * **Minimality** -- the length of the minimal reproducing sequence.

The comparison is deliberately fair and adversarial to our own claim:

  * The random baseline gets the *same* per-invariant failure cap and the *same*
    minimiser, and it is allowed a generous budget.
  * The benchmark reports a **held-out** set (fixtures in
    :mod:`blackheart.statespace.heldout`, not the development set) separately, so
    the headline number is not a tuned-on result.
  * If the model-guided engine does not beat the baseline on some axis, the report
    says so. The engine's value is *sequence-level, minimised, cross-actor
    discovery with a stated invariant and an independent verifier* -- the benchmark
    reports each of those axes rather than a single flattering score.

Nothing here touches a network or a real system: every fixture is local.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from ..invariants.engine import FuzzConfig, StatefulFuzzer
from .explore import (
    ExploreConfig,
    StateSpaceExplorer,
    attack_steps_for,
    enumerate_candidates,
    run_sequence,
)
from .fixtures import FIXTURE_PAIRS, make_fixture
from .hard import HARD_PAIRS, make_hard
from .heldout import HELDOUT_PAIRS, make_heldout
from .hypotheses import HypothesisGenerator


# --------------------------------------------------------------------------- #
# Result records
# --------------------------------------------------------------------------- #

@dataclass
class CaseResult:
    case_id: str
    suite: str            # "development" | "heldout" | "hard"
    invariant: str
    description: str
    # model-guided engine
    guided_detected: bool = False
    guided_false_positive: bool = False
    guided_sequences: int = 0
    guided_steps: int = 0
    guided_seconds: float = 0.0
    guided_minimal_len: int = 0
    guided_strategy: str = ""
    guided_seqs_to_detect: int = 0     # candidates evaluated before the first genuine hit
    # random baseline
    baseline_detected: bool = False
    baseline_false_positive: bool = False
    baseline_sequences: int = 0
    baseline_steps: int = 0
    baseline_seconds: float = 0.0
    baseline_minimal_len: int = 0
    baseline_seqs_to_detect: int = 0   # random sequences tried before the first genuine hit

    def to_dict(self) -> dict:
        return {
            "case_id": self.case_id,
            "suite": self.suite,
            "invariant": self.invariant,
            "description": self.description,
            "guided": {
                "detected": self.guided_detected,
                "false_positive": self.guided_false_positive,
                "sequences": self.guided_sequences,
                "steps": self.guided_steps,
                "seconds": self.guided_seconds,
                "minimal_len": self.guided_minimal_len,
                "strategy": self.guided_strategy,
                "seqs_to_detect": self.guided_seqs_to_detect,
            },
            "baseline": {
                "detected": self.baseline_detected,
                "false_positive": self.baseline_false_positive,
                "sequences": self.baseline_sequences,
                "steps": self.baseline_steps,
                "seconds": self.baseline_seconds,
                "minimal_len": self.baseline_minimal_len,
                "seqs_to_detect": self.baseline_seqs_to_detect,
            },
        }


@dataclass
class BenchmarkReport:
    cases: list[CaseResult] = field(default_factory=list)
    guided_runs: int = 200
    baseline_runs: int = 400

    # -- aggregates ------------------------------------------------------ #

    def _rate(self, cases: list[CaseResult], attr: str) -> float:
        if not cases:
            return 0.0
        return round(sum(1 for c in cases if getattr(c, attr)) / len(cases), 4)

    def summary(self, *, heldout: Optional[bool] = None, hard: Optional[bool] = None) -> dict:
        if hard is True:
            cases = [c for c in self.cases if c.suite == "hard"]
        elif heldout is True:
            cases = [c for c in self.cases if c.suite == "heldout"]
        elif heldout is False:
            cases = [c for c in self.cases if c.suite == "development"]
        else:
            cases = list(self.cases)
        return {
            "cases": len(cases),
            "guided_detection_rate": self._rate(cases, "guided_detected"),
            "baseline_detection_rate": self._rate(cases, "baseline_detected"),
            "guided_false_positive_rate": self._rate(cases, "guided_false_positive"),
            "baseline_false_positive_rate": self._rate(cases, "baseline_false_positive"),
            "guided_total_sequences": sum(c.guided_sequences for c in cases),
            "baseline_total_sequences": sum(c.baseline_sequences for c in cases),
            "guided_total_steps": sum(c.guided_steps for c in cases),
            "baseline_total_steps": sum(c.baseline_steps for c in cases),
            "guided_seqs_to_detect_total": sum(c.guided_seqs_to_detect for c in cases),
            "baseline_seqs_to_detect_total": sum(c.baseline_seqs_to_detect for c in cases),
        }

    def to_dict(self) -> dict:
        return {
            "guided_runs": self.guided_runs,
            "baseline_runs": self.baseline_runs,
            "all": self.summary(),
            "development": self.summary(heldout=False),
            "heldout": self.summary(heldout=True),
            "hard": self.summary(hard=True),
            "cases": [c.to_dict() for c in self.cases],
        }


# --------------------------------------------------------------------------- #
# Running one case
# --------------------------------------------------------------------------- #

def _run_case(case_id: str, vuln_name: str, guard_name: str, invariant: str, desc: str,
              suite: str, maker, guided_cfg: ExploreConfig, baseline_runs: int) -> CaseResult:
    res = CaseResult(case_id=case_id, suite=suite, invariant=invariant, description=desc)

    # ---- model-guided engine on the vulnerable variant ----
    t0 = time.monotonic()
    vt = maker(vuln_name)
    hyps = HypothesisGenerator(vt.model()).generate().hypotheses
    guided = StateSpaceExplorer(vt, guided_cfg).explore(hyps)
    res.guided_seconds = round(time.monotonic() - t0, 4)
    res.guided_sequences = guided.sequences_tried
    res.guided_steps = guided.steps_evaluated
    hits = [v for v in guided.violations if v.invariant_id == invariant]
    res.guided_detected = bool(hits)
    if hits:
        best = min(hits, key=lambda v: len(v.minimal_sequence))
        res.guided_minimal_len = len(best.minimal_sequence)
        res.guided_strategy = best.strategy_id

    # ---- model-guided engine on the secure control (false-positive check) ----
    gt = maker(guard_name)
    ghyps = HypothesisGenerator(gt.model()).generate().hypotheses
    gguided = StateSpaceExplorer(gt, guided_cfg).explore(ghyps)
    res.guided_false_positive = any(v.invariant_id == invariant for v in gguided.violations)

    # ---- random baseline (existing StatefulFuzzer) on the vulnerable variant ----
    t1 = time.monotonic()
    bt = maker(vuln_name)
    bcfg = FuzzConfig(runs=baseline_runs, steps_per_run=guided_cfg.max_steps, seed=guided_cfg.seed)
    breport = StatefulFuzzer(bt, bcfg).run()
    res.baseline_seconds = round(time.monotonic() - t1, 4)
    res.baseline_sequences = breport.seeds_tried
    res.baseline_steps = breport.seeds_tried * bcfg.steps_per_run
    bhits = [f for f in breport.failures if f.inv_id == invariant]
    res.baseline_detected = bool(bhits)
    if bhits:
        res.baseline_minimal_len = min(len(f.minimal_sequence) for f in bhits)

    # ---- random baseline on the secure control (false-positive check) ----
    bt2 = maker(guard_name)
    breport2 = StatefulFuzzer(bt2, bcfg).run()
    res.baseline_false_positive = any(f.inv_id == invariant for f in breport2.failures)

    # ---- efficiency: candidates to first genuine detection (budget-controlled) ----
    res.guided_seqs_to_detect = _seqs_to_detect_guided(vt, hyps, guided_cfg, invariant)
    res.baseline_seqs_to_detect = _seqs_to_detect_baseline(bt, bcfg, invariant)
    return res


def _seqs_to_detect_guided(target, hypotheses, cfg: ExploreConfig, invariant: str) -> int:
    """How many ordered candidates the guided search evaluates before the first hit."""
    for i, cand in enumerate(enumerate_candidates(target, hypotheses, cfg), start=1):
        _, bad = run_sequence(target, attack_steps_for(target, cand))
        if invariant in bad:
            return i
    return 0


def _seqs_to_detect_baseline(target, cfg: FuzzConfig, invariant: str) -> int:
    """How many random sequences the *real* baseline tries before the first hit.

    Uses the existing engine's own sequence generator and per-step evaluation, with
    the same per-seed RNG the :class:`StatefulFuzzer` uses, so this is an
    apples-to-apples measure of the baseline's search order (not a re-implementation
    that could be accidentally weaker). Returns 0 when the budget is exhausted with
    no hit -- which is reported honestly as "not found within budget".
    """
    import random

    from ..invariants.engine import _generate_sequence, run_sequence as engine_run

    for i in range(cfg.runs):
        rng = random.Random(cfg.seed + i)
        seq = _generate_sequence(target, rng, cfg.steps_per_run)
        res = engine_run(target, seq)
        if invariant in res.violated:
            return i + 1
    return 0


# --------------------------------------------------------------------------- #
# The benchmark
# --------------------------------------------------------------------------- #

def run_benchmark(*, guided_runs: int = 200, baseline_runs: int = 400, seed: int = 0,
                  include_heldout: bool = True, include_hard: bool = True) -> BenchmarkReport:
    """Run the full benchmark deterministically and return the report."""
    report = BenchmarkReport(guided_runs=guided_runs, baseline_runs=baseline_runs)
    guided_cfg = ExploreConfig(seed=seed)
    for vuln, guard, inv, desc in FIXTURE_PAIRS:
        report.cases.append(_run_case(
            case_id=vuln, vuln_name=vuln, guard_name=guard, invariant=inv, desc=desc,
            suite="development", maker=make_fixture, guided_cfg=guided_cfg,
            baseline_runs=baseline_runs,
        ))
    if include_heldout:
        for vuln, guard, inv, desc in HELDOUT_PAIRS:
            report.cases.append(_run_case(
                case_id=vuln, vuln_name=vuln, guard_name=guard, invariant=inv, desc=desc,
                suite="heldout", maker=make_heldout, guided_cfg=guided_cfg,
                baseline_runs=baseline_runs,
            ))
    if include_hard:
        for vuln, guard, inv, desc in HARD_PAIRS:
            report.cases.append(_run_case(
                case_id=vuln, vuln_name=vuln, guard_name=guard, invariant=inv, desc=desc,
                suite="hard", maker=make_hard, guided_cfg=guided_cfg,
                baseline_runs=baseline_runs,
            ))
    return report


def write_benchmark(out: str | Path, **kw) -> dict:
    import json

    report = run_benchmark(**kw)
    Path(out).write_text(json.dumps(report.to_dict(), indent=2), encoding="utf-8")
    return report.to_dict()


if __name__ == "__main__":
    import json

    print(json.dumps(run_benchmark().to_dict()["all"], indent=2))
