"""Historical-rediscovery benchmark harness (mission 3.A / 3.B / 3.H).

This module runs the *existing* engines over the historical corpus and reports
honest, raw metrics. It adds no new search of its own -- the value is the
comparison and the measurement discipline:

  * **Baseline** -- the existing random stateful fuzzer
    (:class:`blackheart.invariants.engine.StatefulFuzzer`).
  * **Guided** -- the state-space engine
    (:class:`blackheart.statespace.explore.StateSpaceExplorer`) driven by a
    :class:`~blackheart.statespace.model.SystemModel` that is **derived from the
    executable target** (:func:`model_from_target`). Deriving the model from the
    target's own ``ops()``/``invariants()`` -- rather than hand-writing it -- is
    the honest form of Capability B: the engine reconstructs the protocol model
    from what the system exposes, not from the answer key.

Metrics, per case and in aggregate (raw numerators and denominators only):

  * detection on the vulnerable model,
  * false positives on the patched model (the patched-version-rejection control),
  * sequences tried and steps evaluated (cost / efficiency),
  * sequences-to-first-detection where measurable.

Nothing here decides that a vulnerability is real. A "detection" is the engine
finding a sequence that violates the case's stated invariant on a model of known
vulnerable logic -- a *rediscovery*, which is an internal capability result, never
a bounty finding. The harness reports the unverified commit pins rather than
inventing them.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Optional

from ..invariants.engine import FuzzConfig, StatefulFuzzer, Target
from ..statespace.explore import ExploreConfig, StateSpaceExplorer
from ..statespace.hypotheses import HypothesisGenerator
from ..statespace.model import SystemModel
from ..learning.transfer import AttackMemory
from . import corpus as corpus_mod
from .certify import certify_exhaustive
from . import heldout as heldout_mod


#: Default location of the cross-target attack memory. A certified finding is
#: appended here and its shape becomes a seed for later targets.
DEFAULT_MEMORY = "research/private/attack-memory.jsonl"


# --------------------------------------------------------------------------- #
# Capability B: derive a SystemModel from the executable target.
# --------------------------------------------------------------------------- #

def model_from_target(target: Target) -> SystemModel:
    """Reconstruct a :class:`SystemModel` from a target's exposed surface.

    Provenance is explicit (``source="derived:Target.ops()"``): every element is
    read from what the target *exposes* (its operations, actors, invariants),
    never from a hidden answer key. This is the mechanism by which the engine
    builds a protocol model for a system it was only given a runtime view of.
    """
    m = SystemModel(
        target=target.name,
        summary=f"Model derived from the executable surface of {target.name}.",
        evidence=[f"derived:Target.ops()@{target.name}"],
    )
    ops = target.ops()
    # Actors = every distinct actor named on any operation.
    actor_names: list[str] = []
    for op in ops:
        for a in op.actors:
            if a not in actor_names:
                actor_names.append(a)
    for a in actor_names:
        # Each actor gets a role equal to its own name, so ``actors_for`` resolves
        # an operation's declared actors correctly. Marking only attacker-like
        # names unprivileged keeps the attacker-reachability semantics honest.
        m.add_actor(a, roles=(a,), unprivileged=a in {"attacker", "user", "anonymous"})

    for op in ops:
        # With only the executable surface available we cannot know which
        # operation participates in a violation, so every operation is marked
        # sensitive. This is deliberately permissive: sensitivity drives *ordering*
        # priority, and the invariant check is what actually decides. Marking all
        # operations sensitive means no multi-step sequence is filtered out before
        # it is tried -- correctness over budget tuning.
        m.add_operation(op.name, tuple(op.actors), sensitive=True,
                        effect=op.description, source="derived:Target.ops()")

    for inv in target.invariants():
        m.add_invariant(inv.inv_id, getattr(inv, "title", inv.inv_id),
                        expression=inv.inv_id,
                        severity_if_broken=getattr(inv, "severity_if_broken", "high"))

    m.assets = ["value"]
    m.trust_boundaries = ["unprivileged <-> system"]
    return m


class ModelTarget:
    """Wrap a plain :class:`Target` so the state-space engine can drive it.

    The wrapper only *adds* :meth:`model`; every execution method is delegated
    verbatim, so the guided engine and the random baseline run the exact same
    target logic (a fair ablation).
    """

    def __init__(self, target: Target) -> None:
        self._t = target
        self.name = target.name
        self._model = model_from_target(target)

    def model(self) -> SystemModel:
        return self._model

    def reset(self) -> Any:
        return self._t.reset()

    def ops(self):
        return self._t.ops()

    def invariants(self):
        return self._t.invariants()

    def step(self, state: Any, op_name: str, actor: str, params: dict) -> None:
        return self._t.step(state, op_name, actor, params)

    def snapshot(self, state: Any) -> dict:
        return self._t.snapshot(state)

    def state_is_isolated(self) -> bool:
        """Delegate the isolation declaration to the wrapped target.

        Defaults to ``False`` (reuse disabled) unless the target explicitly
        declares its state self-contained, so a real-runtime target -- where a
        prefix's state may depend on external effects -- is never reused.
        """
        fn = getattr(self._t, "state_is_isolated", None)
        return bool(fn()) if callable(fn) else False


# --------------------------------------------------------------------------- #
# Per-case result
# --------------------------------------------------------------------------- #

@dataclass
class CaseResult:
    case_id: str
    root_cause: str
    protocol: str
    holdout: bool
    invariant: str
    baseline_detected: bool = False
    guided_detected: bool = False
    enhanced_detected: bool = False
    baseline_false_positive: bool = False
    guided_false_positive: bool = False
    enhanced_false_positive: bool = False
    baseline_sequences: int = 0
    guided_sequences: int = 0
    enhanced_sequences: int = 0
    baseline_steps: int = 0
    guided_steps: int = 0
    enhanced_steps: int = 0
    guided_minimal_len: int = 0
    enhanced_minimal_len: int = 0
    guided_violation_sequence: list[dict] = field(default_factory=list)
    enhanced_violation_sequence: list[dict] = field(default_factory=list)
    #: Whether a *proof* was produced for this case: the engine found a violation
    #: and the certifier reproduced it on a minimal witness (T2.4). A detection is
    #: a lead; a certified detection is evidence.
    certified: bool = False
    certificate: dict = field(default_factory=dict)
    #: Cross-target memory: how many proven-attack seeds were transferred in, and
    #: whether this case's own certified finding was recorded back to the memory.
    transferred_seeds: int = 0
    recorded_to_memory: bool = False
    note: str = ""

    def to_dict(self) -> dict:
        return {
            "case_id": self.case_id,
            "root_cause": self.root_cause,
            "protocol": self.protocol,
            "holdout": self.holdout,
            "invariant": self.invariant,
            "baseline_detected": self.baseline_detected,
            "guided_detected": self.guided_detected,
            "enhanced_detected": self.enhanced_detected,
            "certified": self.certified,
            "certificate": self.certificate,
            "transferred_seeds": self.transferred_seeds,
            "recorded_to_memory": self.recorded_to_memory,
            "baseline_false_positive": self.baseline_false_positive,
            "guided_false_positive": self.guided_false_positive,
            "enhanced_false_positive": self.enhanced_false_positive,
            "baseline_sequences": self.baseline_sequences,
            "guided_sequences": self.guided_sequences,
            "enhanced_sequences": self.enhanced_sequences,
            "baseline_steps": self.baseline_steps,
            "guided_steps": self.guided_steps,
            "enhanced_steps": self.enhanced_steps,
            "guided_minimal_len": self.guided_minimal_len,
            "enhanced_minimal_len": self.enhanced_minimal_len,
            "guided_violation_sequence": self.guided_violation_sequence,
            "enhanced_violation_sequence": self.enhanced_violation_sequence,
            "note": self.note,
        }


def _invariant_ids(target: Target) -> list[str]:
    return [inv.inv_id for inv in target.invariants()]


def _baseline_detect(target: Target, cfg: FuzzConfig) -> tuple[bool, int, int]:
    """Run the random fuzzer; return (detected, sequences_tried, steps)."""
    rep = StatefulFuzzer(target, cfg).run()
    detected = bool(rep.failures)
    return detected, rep.seeds_tried, rep.seeds_tried * cfg.steps_per_run


def _guided_detect(target: Target, cfg: ExploreConfig) -> tuple[bool, int, int, int, list[dict]]:
    """Run the state-space engine; return (detected, sequences, steps, min_len, seq)."""
    mt = ModelTarget(target)
    model = mt.model()
    gen = HypothesisGenerator(model)
    hyps = gen.generate().hypotheses
    rep = StateSpaceExplorer(mt, cfg).explore(hyps)
    detected = bool(rep.violations)
    min_len = 0
    seq: list[dict] = []
    if rep.violations:
        v = rep.violations[0]
        min_len = len(v.minimal_sequence)
        seq = [s.to_dict() for s in v.minimal_sequence]
    return detected, rep.sequences_tried, rep.steps_evaluated, min_len, seq


def _enhanced_detect(target: Target, cfg: ExploreConfig,
                     extra_seeds: Optional[list[list]] = None) -> tuple[bool, int, int, int, list[dict]]:
    """Run the parameter-aware enhanced search; return the same tuple shape."""
    from .search import discover
    mt = ModelTarget(target)
    violations = discover(mt, cfg=cfg, extra_seeds=extra_seeds)
    detected = bool(violations)
    seqs = getattr(violations[0], "_seqs_tried", 0) if violations else 0
    min_len = 0
    seq: list[dict] = []
    if violations:
        v = violations[0]
        min_len = len(v.minimal_sequence)
        seq = [s.to_dict() for s in v.minimal_sequence]
    # Recover the number of sequences tried even when nothing was found.
    if not violations:
        from .search import enhanced_candidates
        seqs = len(enhanced_candidates(mt.model(), {op.name: op for op in mt.ops()}, cfg))
    return detected, seqs, min_len, min_len, seq


def run_case(case: corpus_mod.HistoricalCase,
             *, fuzz_cfg: Optional[FuzzConfig] = None,
             explore_cfg: Optional[ExploreConfig] = None,
             memory: Optional[AttackMemory] = None,
             memory_min_score: float = 0.35) -> CaseResult:
    """Run all three configurations on a case's vulnerable and patched models.

    When ``memory`` is supplied, the enhanced search is *seeded* with proven
    attacks transferred from structurally similar targets before it enumerates its
    own candidates, and a newly certified finding is appended back to the memory --
    so a run both consumes and grows the cross-target knowledge. The seed is a lead
    only: the same execution and certification gates apply to it as to any candidate.
    """
    fuzz_cfg = fuzz_cfg or FuzzConfig(runs=300, steps_per_run=10, seed=0)
    explore_cfg = explore_cfg or ExploreConfig(seed=0, max_steps=4)

    res = CaseResult(
        case_id=case.case_id,
        root_cause=case.root_cause,
        protocol=case.protocol,
        holdout=case.holdout,
        invariant=case.invariant_statement,
    )

    if case.vulnerable is None or case.patched is None:
        res.note = "no hermetic model (documented reference case)"
        return res

    vuln = case.vulnerable()
    patched = case.patched()

    # Transferred seeds: proven attacks from similar targets, projected onto this
    # one. Empty when no memory is supplied or nothing is similar enough.
    transferred: list[list] = []
    if memory is not None:
        from ..models import AttackStep

        seeds = memory.seeds_for(vuln, min_score=memory_min_score,
                                 root_cause=case.root_cause)
        transferred = [
            [AttackStep(index=s.index, actor=s.actor, action=s.action, params=s.params,
                        target_contract=s.target_contract, expected_effect=s.expected_effect)
             for s in seq]
            for seq in seeds
        ]
        res.transferred_seeds = len(transferred)

    # Baseline on the vulnerable model, then the patched control.
    res.baseline_detected, res.baseline_sequences, res.baseline_steps = _baseline_detect(vuln, fuzz_cfg)
    b_fp, _, _ = _baseline_detect(patched, fuzz_cfg)
    res.baseline_false_positive = b_fp

    # Guided on the vulnerable model, then the patched control.
    (res.guided_detected, res.guided_sequences, res.guided_steps,
     res.guided_minimal_len, res.guided_violation_sequence) = _guided_detect(vuln, explore_cfg)
    g_fp, _, _, _, _ = _guided_detect(patched, explore_cfg)
    res.guided_false_positive = g_fp

    # Enhanced (parameter-aware) on the vulnerable model, then the patched control.
    (res.enhanced_detected, res.enhanced_sequences, _, res.enhanced_minimal_len,
     res.enhanced_violation_sequence) = _enhanced_detect(vuln, explore_cfg, transferred)
    e_fp, _, _, _, _ = _enhanced_detect(patched, explore_cfg, transferred)
    res.enhanced_false_positive = e_fp

    # Certify: turn the detection into a proof (a minimal, reproduced witness), and
    # require the same certification to *fail* on the patched control. This is what
    # separates "we found a sequence" from "we proved a violation".
    if res.guided_detected or res.enhanced_detected:
        cert = certify_exhaustive(vuln, max_depth=max(explore_cfg.max_steps, 4))
        res.certified = cert.proven
        res.certificate = cert.to_dict()
        if res.certified:
            control = certify_exhaustive(patched, max_depth=max(explore_cfg.max_steps, 4))
            if control.proven:
                # The witness breaks the patched control too: it is not a
                # vulnerability, it is an artifact. Downgrade honestly.
                res.certified = False
                res.certificate["downgraded"] = (
                    "witness also broke the patched control; not a real violation")
            elif memory is not None:
                # A certified, distinguishing finding becomes a transferable shape
                # for later targets. Only certified findings are recorded.
                from ..models import AttackStep

                witness = cert.witness or []
                seq = [AttackStep(index=s.index, actor=s.actor, action=s.action,
                                  params=s.params, target_contract=s.target_contract,
                                  expected_effect=s.expected_effect) for s in witness]
                inv_id = cert.invariant_id
                memory.record_from_certificate(
                    target=vuln, sequence=seq, root_cause=case.root_cause,
                    invariant_id=inv_id, certificate=res.certificate,
                    outcome=case.attacker_outcome,
                    evidence=case.advisory or case.reference,
                )
                res.recorded_to_memory = True

    return res


# --------------------------------------------------------------------------- #
# Aggregate benchmark
# --------------------------------------------------------------------------- #

@dataclass
class BenchmarkReport:
    cases: list[CaseResult] = field(default_factory=list)
    elapsed_seconds: float = 0.0
    corpus_summary: dict = field(default_factory=dict)
    #: Cross-target memory state after the run, when a memory was supplied.
    memory_summary: dict = field(default_factory=dict)

    def _agg(self, subset: list[CaseResult]) -> dict:
        modelled = [c for c in subset if c.note == ""]
        n = len(modelled)
        if n == 0:
            return {"cases": 0}
        b_det = sum(c.baseline_detected for c in modelled)
        g_det = sum(c.guided_detected for c in modelled)
        e_det = sum(c.enhanced_detected for c in modelled)
        b_fp = sum(c.baseline_false_positive for c in modelled)
        g_fp = sum(c.guided_false_positive for c in modelled)
        e_fp = sum(c.enhanced_false_positive for c in modelled)
        certified = sum(c.certified for c in modelled)
        return {
            "cases": n,
            "baseline_detected": b_det,
            "guided_detected": g_det,
            "enhanced_detected": e_det,
            "certified": certified,
            "certified_rate": round(certified / n, 4),
            "baseline_recall": round(b_det / n, 4),
            "guided_recall": round(g_det / n, 4),
            "enhanced_recall": round(e_det / n, 4),
            "baseline_false_positives": b_fp,
            "guided_false_positives": g_fp,
            "enhanced_false_positives": e_fp,
            "baseline_fp_rate": round(b_fp / n, 4),
            "guided_fp_rate": round(g_fp / n, 4),
            "enhanced_fp_rate": round(e_fp / n, 4),
            "baseline_total_sequences": sum(c.baseline_sequences for c in modelled),
            "guided_total_sequences": sum(c.guided_sequences for c in modelled),
            "enhanced_total_sequences": sum(c.enhanced_sequences for c in modelled),
            "baseline_total_steps": sum(c.baseline_steps for c in modelled),
            "guided_total_steps": sum(c.guided_steps for c in modelled),
        }

    def to_dict(self) -> dict:
        dev = [c for c in self.cases if not c.holdout]
        ho = [c for c in self.cases if c.holdout]
        modelled_dev = [c for c in dev if c.note == ""]
        modelled_ho = [c for c in ho if c.note == ""]
        # Root-cause recall: how many distinct root causes each engine solved.
        def solved(attr: str) -> set:
            return {c.root_cause for c in self.cases if getattr(c, attr)}
        all_causes = {c.root_cause for c in self.cases if c.note == ""}
        b_solved, g_solved, e_solved = solved("baseline_detected"), solved("guided_detected"), solved("enhanced_detected")
        return {
            "elapsed_seconds": round(self.elapsed_seconds, 2),
            "corpus_summary": self.corpus_summary,
            "memory_summary": self.memory_summary,
            "transferred_seeds_total": sum(c.transferred_seeds for c in self.cases),
            "recorded_to_memory_total": sum(c.recorded_to_memory for c in self.cases),
            "development": self._agg(dev),
            "holdout": self._agg(ho),
            "all_modelled": self._agg(modelled_dev + modelled_ho),
            "root_causes_modelled": sorted(all_causes),
            "root_causes_solved_baseline": sorted(b_solved & all_causes),
            "root_causes_solved_guided": sorted(g_solved & all_causes),
            "root_causes_solved_enhanced": sorted(e_solved & all_causes),
            "root_cause_recall_baseline": round(len(b_solved & all_causes) / max(1, len(all_causes)), 4),
            "root_cause_recall_guided": round(len(g_solved & all_causes) / max(1, len(all_causes)), 4),
            "root_cause_recall_enhanced": round(len(e_solved & all_causes) / max(1, len(all_causes)), 4),
            "cases": [c.to_dict() for c in self.cases],
        }


def benchmark(*, include_holdout: bool = True,
              fuzz_cfg: Optional[FuzzConfig] = None,
              explore_cfg: Optional[ExploreConfig] = None,
              memory: Optional[AttackMemory] = None) -> BenchmarkReport:
    """Run the full benchmark over the corpus (and optionally the holdout set).

    When ``memory`` is supplied, cases are run in order and each certified finding
    is appended to the shared memory before the next case runs -- a curriculum in
    which earlier proofs seed later searches. That makes the result *order
    dependent by construction*; the report records how many seeds each case
    received so the effect is visible rather than hidden.
    """
    start = time.monotonic()
    cases = list(corpus_mod.modelled_cases())
    if include_holdout:
        cases += list(heldout_mod.holdout_cases())
    results = [run_case(c, fuzz_cfg=fuzz_cfg, explore_cfg=explore_cfg, memory=memory)
               for c in cases]
    rep = BenchmarkReport(cases=results)
    rep.elapsed_seconds = time.monotonic() - start
    rep.corpus_summary = corpus_mod.summary()
    if memory is not None:
        rep.memory_summary = memory.summary()
    return rep
