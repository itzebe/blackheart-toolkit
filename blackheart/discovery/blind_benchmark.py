"""Mission-06 comparative benchmark over the blind hold-out corpus.

Runs four configurations over identical targets, starting states and budgets:

  1. **baseline**  -- the random stateful fuzzer
     (:class:`blackheart.invariants.engine.StatefulFuzzer`).
  2. **guided**    -- the PR #47 state-space explorer, driven by a model derived
     from the target's own surface (:func:`harness.model_from_target`).
  3. **enhanced**  -- the parameter-aware search (``discovery.search``).
  4. **adaptive**  -- this mission's feedback-driven controller
     (:class:`blackheart.statespace.adaptive.AdaptiveExplorer`).

Ground truth (which cases are vulnerable, which are clean controls) lives in
:mod:`blackheart.discovery.blind` and is **never** read by the engines -- they see
only a target's ``ops()`` / ``invariants()`` / ``step()``. The benchmark scores
each engine's *reported candidates* against that ground truth, and independently
verifies every candidate with :class:`~blackheart.statespace.verify.IndependentSequenceVerifier`
(independent re-run + attacker reachability + patched-control differential).

Nothing here asserts a production vulnerability: these are local, in-memory
models of known-vulnerable logic. A "detection" is a *rediscovery*.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Optional

from ..invariants.engine import FuzzConfig, StatefulFuzzer, Target
from ..statespace.adaptive import AdaptiveConfig, AdaptiveExplorer
from ..statespace.explore import ExploreConfig, StateSpaceExplorer
from ..statespace.hypotheses import HypothesisGenerator
from ..statespace.verify import IndependentSequenceVerifier, VerifyConfig
from . import blind as blind_mod
from .harness import ModelTarget
from .search import discover as enhanced_discover


@dataclass
class EngineOutcome:
    detected: bool = False
    sequences: int = 0
    steps: int = 0
    minimal_len: int = 0
    priority_divergences: int = 0
    verified: bool = False           # independently verified on the vulnerable model
    verified_rejected_by_control: bool = False
    disposition: str = ""


@dataclass
class BlindCaseResult:
    case_id: str
    root_cause: str
    vulnerable_case: bool                # ground truth: True = a real bug exists
    engines: dict = field(default_factory=dict)  # name -> EngineOutcome

    def to_dict(self) -> dict:
        return {
            "case_id": self.case_id,
            "root_cause": self.root_cause,
            "vulnerable_case": self.vulnerable_case,
            "engines": {k: vars(v) for k, v in self.engines.items()},
        }


# --------------------------------------------------------------------------- #
# Engine runners -- each returns (detected, sequences, steps, minimal_len, extras)
# --------------------------------------------------------------------------- #

def _run_baseline(target: Target, cfg: FuzzConfig) -> EngineOutcome:
    rep = StatefulFuzzer(target, cfg).run()
    return EngineOutcome(detected=bool(rep.failures), sequences=rep.seeds_tried,
                         steps=rep.seeds_tried * cfg.steps_per_run)


def _run_guided(target: Target, cfg: ExploreConfig) -> EngineOutcome:
    mt = ModelTarget(target)
    hyps = HypothesisGenerator(mt.model()).generate().hypotheses
    rep = StateSpaceExplorer(mt, cfg).explore(hyps)
    out = EngineOutcome(detected=bool(rep.violations), sequences=rep.sequences_tried,
                        steps=rep.steps_evaluated)
    if rep.violations:
        out.minimal_len = len(rep.violations[0].minimal_sequence)
    return out


def _run_enhanced(target: Target, cfg: ExploreConfig) -> EngineOutcome:
    mt = ModelTarget(target)
    viols = enhanced_discover(mt, cfg=cfg)
    out = EngineOutcome(detected=bool(viols))
    if viols:
        out.minimal_len = len(viols[0].minimal_sequence)
        out.sequences = getattr(viols[0], "_seqs_tried", 0)
    return out


def _run_adaptive(target: Target, cfg: AdaptiveConfig) -> EngineOutcome:
    rep = AdaptiveExplorer(ModelTarget(target), cfg).explore()
    out = EngineOutcome(detected=bool(rep.violations), sequences=rep.sequences_tried,
                        steps=rep.steps_evaluated,
                        priority_divergences=rep.priority_divergences)
    if rep.violations:
        out.minimal_len = len(rep.violations[0].minimal_sequence)
    return out


# --------------------------------------------------------------------------- #
# Independent verification of an engine's candidate on the vulnerable model
# --------------------------------------------------------------------------- #

def _verify_candidate(vulnerable_cls, patched_cls, cfg: AdaptiveConfig) -> tuple[bool, bool, str]:
    """Verify the adaptive engine's candidate against a fresh re-run and control.

    Returns ``(verified, control_rejects, disposition)``. The verifier builds its
    own fresh target and its own control; it does not trust the engine.
    """
    rep = AdaptiveExplorer(ModelTarget(vulnerable_cls()), cfg).explore()
    if not rep.violations:
        return False, False, ""
    v = rep.violations[0]
    verifier = IndependentSequenceVerifier(
        lambda: ModelTarget(vulnerable_cls()),
        VerifyConfig(control_factory=lambda: ModelTarget(patched_cls()),
                     in_scope=True, scope_reference="blind-holdout",
                     authorization_gate_passed=True),
    )
    res = verifier.verify(v, model=ModelTarget(vulnerable_cls()).model(),
                          preconditions_satisfiable=True)
    control_rejects = res.checks.get("control_integrity", (None,))[0] is True
    verified = res.disposition == "INDEPENDENTLY_VERIFIED"
    return verified, control_rejects, res.disposition


# --------------------------------------------------------------------------- #
# The benchmark
# --------------------------------------------------------------------------- #

@dataclass
class BlindBenchmarkReport:
    cases: list[BlindCaseResult] = field(default_factory=list)
    elapsed_seconds: float = 0.0
    fuzz_cfg: dict = field(default_factory=dict)
    explore_cfg: dict = field(default_factory=dict)
    adaptive_cfg: dict = field(default_factory=dict)

    def _agg(self, vulnerable: bool) -> dict:
        rows = [c for c in self.cases if c.vulnerable_case == vulnerable]
        n = len(rows)
        out: dict = {"cases": n}
        for name in ("baseline", "guided", "enhanced", "adaptive"):
            det = sum(1 for c in rows if c.engines[name].detected)
            fp = sum(1 for c in rows if (not c.vulnerable_case) and c.engines[name].detected)
            out[f"{name}_detected"] = det
            out[f"{name}_recall"] = round(det / n, 4) if n else 0.0
            out[f"{name}_false_positives"] = fp
        return out

    def to_dict(self) -> dict:
        verified = sum(1 for c in self.cases
                       if c.vulnerable_case and c.engines["adaptive"].verified)
        n_vuln = sum(1 for c in self.cases if c.vulnerable_case)
        n_clean = sum(1 for c in self.cases if not c.vulnerable_case)
        clean_fp = sum(1 for c in self.cases
                       if not c.vulnerable_case and c.engines["adaptive"].detected)
        control_rejects = sum(1 for c in self.cases
                              if c.vulnerable_case
                              and c.engines["adaptive"].verified_rejected_by_control)
        return {
            "elapsed_seconds": round(self.elapsed_seconds, 2),
            "config": {"fuzz": self.fuzz_cfg, "explore": self.explore_cfg,
                       "adaptive": self.adaptive_cfg},
            "vulnerable_cases": self._agg(True),
            "clean_negative_controls": self._agg(False),
            "adaptive_independently_verified": verified,
            "adaptive_verified_recall": round(verified / n_vuln, 4) if n_vuln else 0.0,
            "adaptive_control_rejections": control_rejects,
            "adaptive_clean_negative_false_positives": clean_fp,
            "clean_negative_controls_total": n_clean,
            "cases": [c.to_dict() for c in self.cases],
        }


def run_blind_benchmark(*, fuzz_cfg: Optional[FuzzConfig] = None,
                        explore_cfg: Optional[ExploreConfig] = None,
                        adaptive_cfg: Optional[AdaptiveConfig] = None,
                        verify: bool = True) -> BlindBenchmarkReport:
    """Run all four engines over the blind corpus with independent verification."""
    fuzz_cfg = fuzz_cfg or FuzzConfig(runs=300, steps_per_run=10, seed=0)
    explore_cfg = explore_cfg or ExploreConfig(seed=0, max_steps=4)
    adaptive_cfg = adaptive_cfg or AdaptiveConfig(seed=0, max_steps=4)
    start = time.monotonic()
    report = BlindBenchmarkReport(
        fuzz_cfg=vars(fuzz_cfg), explore_cfg=vars(explore_cfg),
        adaptive_cfg=vars(adaptive_cfg))

    def measure(case_id: str, root_cause: str, vulnerable_case: bool,
                vuln_cls, patched_cls) -> None:
        res = BlindCaseResult(case_id=case_id, root_cause=root_cause,
                              vulnerable_case=vulnerable_case, engines={})
        # The engines only ever see the *vulnerable* target object here; the clean
        # controls are their own targets. False positives are measured separately.
        target = vuln_cls()
        res.engines["baseline"] = _run_baseline(target, fuzz_cfg)
        res.engines["guided"] = _run_guided(target, explore_cfg)
        res.engines["enhanced"] = _run_enhanced(target, explore_cfg)
        res.engines["adaptive"] = _run_adaptive(target, adaptive_cfg)
        if verify and vulnerable_case:
            verified, control_rejects, disposition = _verify_candidate(
                vuln_cls, patched_cls, adaptive_cfg)
            res.engines["adaptive"].verified = verified
            res.engines["adaptive"].verified_rejected_by_control = control_rejects
            res.engines["adaptive"].disposition = disposition
        report.cases.append(res)

    for pair in blind_mod.blind_pairs():
        measure(pair.case_id, pair.root_cause, True, pair.vulnerable, pair.patched)
    for cls in blind_mod.NEGATIVE_CONTROLS:
        measure(cls.name, "clean-control", False, cls, cls)

    report.elapsed_seconds = time.monotonic() - start
    return report
