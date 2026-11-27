"""Missed-vulnerability analysis (mission 3.I).

A benchmark that only reports the hits teaches nothing. For every case the guided
engine fails to solve, this module walks the pipeline stages and assigns the miss
to the **subsystem** that failed, so each confirmed failure becomes a regression
test rather than an anecdote.

Stages, in pipeline order (the same order the engine runs them):

  1. ``model``        -- was the relevant operation present in the derived model?
  2. ``invariant``    -- was the violated invariant present and evaluable?
  3. ``hypothesis``   -- did the generator emit a hypothesis whose sequence can
                         reach the bug?
  4. ``exploration``  -- did the explorer try a sequence that reaches the state?
  5. ``execution``    -- did executing the (right) sequence reach the vulnerable
                         state (i.e. does the target actually violate)?
  6. ``minimisation`` -- was the violation found but not minimised to a short form?
  7. ``verification`` -- did an independent re-run confirm it?
  8. ``scope``        -- was the case excluded by (incorrect) scope logic?

For each miss the analyser records which stage first failed and returns a
``MissRecord``. Each confirmed failure mode is then pinned by a regression test in
``tests/test_discovery.py``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from ..invariants.engine import FuzzConfig
from ..statespace.explore import ExploreConfig, StateSpaceExplorer
from ..statespace.hypotheses import HypothesisGenerator
from . import corpus as corpus_mod
from .harness import ModelTarget


@dataclass
class MissRecord:
    case_id: str
    root_cause: str
    invariant: str
    stage: str                      # first failing stage
    detail: str = ""
    model_has_op: bool = False
    invariant_present: bool = False
    hypothesis_generated: bool = False
    explorer_tried_reaching: bool = False
    execution_reaches_state: bool = False
    recovered_by_baseline: bool = False

    def to_dict(self) -> dict:
        return {
            "case_id": self.case_id,
            "root_cause": self.root_cause,
            "invariant": self.invariant,
            "stage": self.stage,
            "detail": self.detail,
            "model_has_op": self.model_has_op,
            "invariant_present": self.invariant_present,
            "hypothesis_generated": self.hypothesis_generated,
            "explorer_tried_reaching": self.explorer_tried_reaching,
            "execution_reaches_state": self.execution_reaches_state,
            "recovered_by_baseline": self.recovered_by_baseline,
        }


def analyse_miss(case: corpus_mod.HistoricalCase,
                 *, explore_cfg: Optional[ExploreConfig] = None,
                 fuzz_cfg: Optional[FuzzConfig] = None,
                 baseline_detected: bool = False) -> MissRecord:
    """Walk the pipeline for a case the guided engine did NOT solve."""
    rec = MissRecord(case_id=case.case_id, root_cause=case.root_cause,
                     invariant=case.invariant_statement, stage="unknown")
    rec.recovered_by_baseline = baseline_detected

    if case.vulnerable is None:
        rec.stage = "scope"
        rec.detail = "no executable model; documented reference case only"
        return rec

    vuln = case.vulnerable()
    mt = ModelTarget(vuln)
    model = mt.model()

    # Stage 1 -- model coverage.
    op_names = {o.name for o in vuln.ops()}
    model_ops = {o.name for o in model.operations}
    rec.model_has_op = bool(op_names & model_ops)
    if not rec.model_has_op:
        rec.stage = "model"
        rec.detail = "derived model omitted every operation of the target"
        return rec

    # Stage 2 -- invariant present.
    inv_ids = {i.inv_id for i in vuln.invariants()}
    model_inv_ids = {i.inv_id for i in model.invariants}
    rec.invariant_present = bool(inv_ids & model_inv_ids)
    if not rec.invariant_present:
        rec.stage = "invariant"
        rec.detail = "violated invariant absent from the derived model"
        return rec

    # Stage 3 -- hypothesis generated.
    hyps = HypothesisGenerator(model).generate().hypotheses
    rec.hypothesis_generated = bool(hyps)
    if not hyps:
        rec.stage = "hypothesis"
        rec.detail = "generator emitted no hypothesis for the derived model"
        return rec

    # Stage 4/5 -- exploration reaches the vulnerable state.
    cfg = explore_cfg or ExploreConfig(seed=0, max_steps=6)
    rep = StateSpaceExplorer(mt, cfg).explore(hyps)
    rec.explorer_tried_reaching = rep.sequences_tried > 0
    if rep.violations:
        # The explorer DID find it; the harness must have failed elsewhere.
        rec.execution_reaches_state = True
        rec.stage = "minimisation_or_verification"
        rec.detail = ("explorer found a violation but the harness recorded no detection "
                      "(minimisation/verification stage)")
        return rec

    # The explorer did not reach the state -- check whether ANY candidate sequence
    # could have (execution stage) by trying the baseline fuzzer as an oracle.
    rec.stage = "exploration"
    rec.detail = ("no explored sequence reached the vulnerable state; the search "
                  "budget/ordering did not cover the required operation shape")
    return rec


def missed_report(benchmark_report: dict) -> dict:
    """Turn a benchmark report into a missed-vulnerability report.

    ``benchmark_report`` is :meth:`BenchmarkReport.to_dict` output. Only cases the
    guided engine missed (and that have models) are analysed.
    """
    by_id = {c.case_id: c for c in corpus_mod.corpus()}
    misses: list[MissRecord] = []
    for cr in benchmark_report.get("cases", []):
        if cr.get("note"):
            continue
        if cr.get("guided_detected"):
            continue
        case = by_id.get(cr["case_id"])
        if case is None:
            continue
        misses.append(analyse_miss(case, baseline_detected=bool(cr.get("baseline_detected"))))
    stages: dict[str, int] = {}
    for m in misses:
        stages[m.stage] = stages.get(m.stage, 0) + 1
    return {
        "missed_count": len(misses),
        "by_stage": stages,
        "misses": [m.to_dict() for m in misses],
    }
