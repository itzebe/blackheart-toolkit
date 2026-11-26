"""Tests for the evolving research engine (mission Parts 2, 3, 4, 6, Phase 6-10).

Covers: persistent research memory (buckets, confirmation gate, retrieval),
the autonomous hypothesis engine (ranking, skip-disproven, surface awareness),
class-based tool selection, the adversarial-verification extensions, the
self-improvement loop and its safety refusals, the resumable queue's
authorization gate, and the end-to-end learning cycle.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from blackheart.authz import new_record
from blackheart.exploit.toolselect import known_classes, select_tools
from blackheart.hypothesis import (
    BASELINE_STRATEGY,
    HypothesisEngine,
    Strategy,
)
from blackheart.hypothesis.surface import applicability, detect_surface
from blackheart.learning import LearningEngine, Improvement, PROTECTED_PATHS
from blackheart.learning.benchmark import (
    HISTORICAL,
    NEGATIVE,
    RankingBenchmark,
)
from blackheart.models import (
    AssetStatus,
    Classification,
    Finding,
    InvestigationStatus,
    ResearchRecord,
)
from blackheart.objectives import TargetProfile
from blackheart.research import ResearchMemory
from blackheart.research.queue import QueueState, ResumableResearchQueue
from blackheart.verify import IndependentVerifier, VerificationContext


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def _vault_profile() -> TargetProfile:
    return TargetProfile(
        name="VaultNoOracle", kind="smart-contract",
        assets=["shares", "funds"],
        entry_points=["deposit(uint256)", "withdraw(uint256)"],
        trust_boundaries=["user <-> vault"], roles=["depositor"],
        external_deps=[], notes="ERC4626 vault with no external price dependency",
    )


def _authorized_record() -> object:
    rec = new_record(
        "Example", "immunefi", "https://x", "https://scope",
        program_active=True, safe_harbor=True, poc_required=True,
        nigerian_eligible=True, payout_feasible=True, zero_cost=True,
    )
    rec.asset_classes = {"vault": AssetStatus.AUTHORIZED.value}
    rec.retrieved_scope = {"source_url": "https://scope", "text": "vault in scope"}
    rec.verified = True
    rec.evidence = ["ev-1"]
    return rec


# --------------------------------------------------------------------------- #
# Phase 2 -- persistent research memory
# --------------------------------------------------------------------------- #

def test_memory_buckets_are_strictly_separate(tmp_path: Path):
    mem = ResearchMemory(tmp_path, "eng")
    for i, status in enumerate(
        [InvestigationStatus.CONFIRMED, InvestigationStatus.UNCONFIRMED,
         InvestigationStatus.DISPROVEN, InvestigationStatus.INCOMPLETE]
    ):
        r = ResearchRecord(record_id=f"r{i}", target="t", vulnerability_class="c",
                           status=status.value)
        if status == InvestigationStatus.CONFIRMED:
            r.independently_verified = True
            r.evidence_hashes = ["h"]
        mem.save(r)
    assert len(mem.confirmed()) == 1
    assert len(mem.unconfirmed()) == 1
    assert len(mem.disproven()) == 1
    assert len(mem.incomplete()) == 1


def test_only_confirmed_records_are_attack_knowledge(tmp_path: Path):
    mem = ResearchMemory(tmp_path, "eng")
    unverified = ResearchRecord(record_id="u", target="t", status=InvestigationStatus.UNCONFIRMED.value)
    mem.save(unverified)
    assert mem.attack_knowledge() == []
    confirmed = ResearchRecord(record_id="c", target="t", status=InvestigationStatus.CONFIRMED.value,
                               independently_verified=True, evidence_hashes=["h"])
    mem.save(confirmed)
    assert [r.record_id for r in mem.attack_knowledge()] == ["c"]


def test_promotion_to_confirmed_requires_independent_verification():
    r = ResearchRecord(record_id="x", target="t", status=InvestigationStatus.UNCONFIRMED.value)
    r.promote(InvestigationStatus.CONFIRMED)
    assert r.status == InvestigationStatus.UNCONFIRMED.value  # refused
    r.independently_verified = True
    r.verification_ref = "ev-9"
    r.promote(InvestigationStatus.CONFIRMED)
    assert r.status == InvestigationStatus.CONFIRMED.value


def test_memory_search_and_lessons_retrieval(tmp_path: Path):
    mem = ResearchMemory(tmp_path, "eng")
    rec = ResearchRecord(
        record_id="d1", target="Vault", vulnerability_class="rounding-precision",
        status=InvestigationStatus.DISPROVEN.value,
        false_positive_reason="virtual offset prevents the inflation",
        lessons=["check the virtual-shares offset before claiming inflation"],
    )
    mem.save(rec)
    hits = mem.search(target="Vault", vulnerability_class="rounding-precision")
    assert [h.record_id for h in hits] == ["d1"]
    lessons = mem.lessons_for(target="Vault", vulnerability_class="rounding-precision")
    assert any("virtual-shares offset" in l for l in lessons)
    assert ("Vault", "rounding-precision") in mem.disproven_signatures()


def test_memory_integrity_is_clean_and_summary_counts(tmp_path: Path):
    mem = ResearchMemory(tmp_path, "eng")
    mem.save(ResearchRecord(record_id="r", target="t"))
    assert mem.verify_integrity()["ok"] is True
    assert mem.summary()["total"] == 1


def test_memory_survives_reconstruction(tmp_path: Path):
    ResearchMemory(tmp_path, "eng").save(
        ResearchRecord(record_id="r", target="t", status=InvestigationStatus.UNCONFIRMED.value)
    )
    reopened = ResearchMemory(tmp_path, "eng")
    assert reopened.get("r") is not None
    assert reopened.get("r").status == InvestigationStatus.UNCONFIRMED.value


# --------------------------------------------------------------------------- #
# Phase 3 -- hypothesis engine
# --------------------------------------------------------------------------- #

def test_hypothesis_engine_ranks_and_explains():
    eng = HypothesisEngine(_vault_profile())
    hyps = eng.generate()
    assert hyps
    assert hyps == sorted(hyps, key=lambda h: (-h.score, h.hyp_id))
    explanation = eng.explain_selection()
    assert "NEXT:" in explanation
    assert eng.select_next() is not None


def test_hypothesis_skips_disproven_unless_new_evidence(tmp_path: Path):
    mem = ResearchMemory(tmp_path, "eng")
    mem.save(ResearchRecord(
        record_id="d", target="VaultNoOracle", vulnerability_class="oracle-manipulation",
        status=InvestigationStatus.DISPROVEN.value, false_positive_reason="no oracle present",
    ))
    eng = HypothesisEngine(_vault_profile(), mem)
    hyps = eng.generate()
    oracle = [h for h in hyps if h.category == "oracle-manipulation"]
    assert oracle and all(h.skipped_disproven for h in oracle)
    # With new evidence the same hypothesis is allowed to be revisited.
    hyps2 = eng.generate(new_evidence=True)
    oracle2 = [h for h in hyps2 if h.category == "oracle-manipulation"]
    assert oracle2 and not any(h.skipped_disproven for h in oracle2)


def test_surface_applicability_damps_absent_and_boosts_present():
    surface = detect_surface(_vault_profile())
    assert surface.has_oracle is False          # "no external price dependency"
    assert applicability("oracle-manipulation", surface).multiplier < 1.0
    assert applicability("rounding-precision", surface).multiplier > 1.0


def test_surface_detector_ignores_negation_in_camelcase_name():
    # VaultNoOracle must not read as having an oracle.
    assert detect_surface(_vault_profile()).has_oracle is False


# --------------------------------------------------------------------------- #
# Phase 4 -- tool selection by class
# --------------------------------------------------------------------------- #

def test_tool_selection_is_class_specific_and_reports_missing():
    assert len(known_classes()) >= 10
    plan = select_tools("rounding-precision", available={"forge", "echidna"})
    assert "forge" in plan.primary and "echidna" in plan.primary
    assert "halmos" in plan.missing or "medusa" in plan.missing
    assert plan.control and plan.rationale


# --------------------------------------------------------------------------- #
# Phase 5 -- adversarial verification extensions
# --------------------------------------------------------------------------- #

def _ctx(**over) -> VerificationContext:
    base = dict(in_scope=True, scope_reference="s#1", protection_exists=False,
                behavior_intentional=False, duplicate_known=False,
                attacker_controls_input=True, reachable=True, measurable_impact=True,
                reproduce=lambda: True, evidence_ids=["e1"])
    base.update(over)
    return VerificationContext(**base)


def test_phase5_control_reproduces_is_false_positive():
    r = IndependentVerifier().verify(Finding("f", "t", "t"), _ctx(control_reproduces=True))
    assert r.classification == Classification.FALSE_POSITIVE
    assert "reproduction-integrity" in r.challenges


def test_phase5_benign_explanation_is_false_positive():
    r = IndependentVerifier().verify(Finding("f", "t", "t"), _ctx(benign_explanation=True))
    assert r.classification == Classification.FALSE_POSITIVE


def test_phase5_unauthorized_asset_is_out_of_scope():
    r = IndependentVerifier().verify(Finding("f", "t", "t"), _ctx(authorization_gate_passed=False))
    assert r.classification == Classification.OUT_OF_SCOPE


def test_phase5_missing_root_cause_needs_more_evidence():
    r = IndependentVerifier().verify(Finding("f", "t", "t"), _ctx(root_cause_established=False))
    assert r.classification == Classification.NEEDS_MORE_EVIDENCE


def test_phase5_fields_absent_preserve_original_verdict():
    r = IndependentVerifier().verify(Finding("f", "t", "t"), _ctx())
    assert r.classification == Classification.CONFIRMED
    assert "root-cause" not in r.challenges


# --------------------------------------------------------------------------- #
# Phase 6 + 10 -- benchmark and learning engine
# --------------------------------------------------------------------------- #

def _surface_engine(p, m):
    return HypothesisEngine(p, m, strategy=Strategy("surface-aware", use_surface=True))


def _baseline_engine(p, m):
    return HypothesisEngine(p, m, strategy=BASELINE_STRATEGY)


def test_benchmark_shows_the_improvement():
    bench = RankingBenchmark()
    before = bench.evaluate_all(_baseline_engine)["historical"]
    after = bench.evaluate_all(_surface_engine)["historical"]
    assert after["top1_accuracy"] > before["top1_accuracy"]
    assert after["mrr"] > before["mrr"]


def test_benchmark_does_not_regress_the_negative_corpus():
    bench = RankingBenchmark()
    before = bench.evaluate_all(_baseline_engine)["negative"]
    after = bench.evaluate_all(_surface_engine)["negative"]
    assert after["top1_accuracy"] >= before["top1_accuracy"]
    assert after["suppression_accuracy"] >= before["suppression_accuracy"]


def test_every_benchmark_scenario_has_a_reachable_acceptable_class():
    for sc in HISTORICAL + NEGATIVE:
        engine = _surface_engine(sc.profile, None)
        ranking = {h.category for h in engine.generate() if not h.skipped_disproven}
        assert ranking & set(sc.acceptable), f"{sc.name}: no acceptable class rankable"


def test_learning_engine_accepts_the_surface_improvement():
    verdict = LearningEngine().evaluate(LearningEngine().propose_surface_awareness())
    assert verdict.accepted
    assert any("historical" in r for r in verdict.reasons)
    compile(verdict.failing_test, "<regression>", "exec")


def test_learning_engine_refuses_protected_modules():
    for path in PROTECTED_PATHS:
        imp = Improvement("bad", "x", Strategy("bad"), targets=(path,))
        verdict = LearningEngine().evaluate(imp)
        assert not verdict.accepted
        assert "REFUSED" in verdict.reasons[0]


def test_learning_engine_rejects_a_no_op_improvement():
    noop = Improvement("noop", "x",
                       Strategy("noop", dict(BASELINE_STRATEGY.weights), use_surface=False),
                       targets=("blackheart/hypothesis",))
    verdict = LearningEngine().evaluate(noop)
    assert not verdict.accepted


def test_learning_engine_rejects_a_regressing_improvement():
    harm = Improvement("harm", "x",
                       Strategy("harm", {"impact": 1.0, "exploitability": 0.0,
                                         "novelty": 0.0, "evidence": 0.0, "feasibility": 0.0}),
                       targets=("blackheart/hypothesis",))
    verdict = LearningEngine().evaluate(harm)
    assert not verdict.accepted


def test_learning_engine_extracts_lessons():
    eng = LearningEngine()
    dis = ResearchRecord(record_id="d", target="t", vulnerability_class="c",
                         status=InvestigationStatus.DISPROVEN.value,
                         false_positive_reason="no reachable path")
    assert "disproven" in eng.extract_lesson(dis)
    con = ResearchRecord(record_id="c", target="t", vulnerability_class="c",
                         status=InvestigationStatus.CONFIRMED.value, impact="drained funds")
    assert "confirmed" in eng.extract_lesson(con)


# --------------------------------------------------------------------------- #
# Phase 8 -- resumable queue with a live authorization gate
# --------------------------------------------------------------------------- #

def test_queue_blocks_unauthorized_and_runs_authorized(tmp_path: Path):
    q = ResumableResearchQueue(tmp_path)
    prof = _vault_profile()
    unauth = new_record("p", "immunefi", "https://x", "https://s")
    unauth.assets = {"vault": "UNKNOWN"}
    q.enqueue(ResumableResearchQueue.entry_from("e1", prof, "vault", unauth, priority=10))
    assert q.next() is None
    assert q.get("e1").state == QueueState.BLOCKED

    q.enqueue(ResumableResearchQueue.entry_from("e2", prof, "vault", _authorized_record(), priority=1))
    entry = q.next()
    assert entry is not None and entry.entry_id == "e2"


def test_queue_resumes_after_reconstruction(tmp_path: Path):
    q = ResumableResearchQueue(tmp_path)
    q.enqueue(ResumableResearchQueue.entry_from(
        "e1", _vault_profile(), "vault", _authorized_record()))
    q.start("e1", "hyp-1")
    reopened = ResumableResearchQueue(tmp_path)
    assert reopened.get("e1").state == QueueState.IN_PROGRESS
    assert reopened.get("e1").attempts == 1


def test_queue_enforces_attempt_budget(tmp_path: Path):
    q = ResumableResearchQueue(tmp_path)
    q.enqueue(ResumableResearchQueue.entry_from(
        "e1", _vault_profile(), "vault", _authorized_record(), max_attempts=1))
    q.start("e1")
    assert q.next() is None
    assert q.get("e1").state == QueueState.BLOCKED


# --------------------------------------------------------------------------- #
# Phase 10 -- end-to-end learning cycle
# --------------------------------------------------------------------------- #

def test_end_to_end_learning_cycle(tmp_path: Path):
    """Discover a class -> record it -> retrieve the lesson -> improve -> verify."""
    mem = ResearchMemory(tmp_path / "memory", "eng")

    # 1. A prior investigation disproved a class on this target.
    mem.save(ResearchRecord(
        record_id="prior-1", target="VaultNoOracle", vulnerability_class="oracle-manipulation",
        status=InvestigationStatus.DISPROVEN.value,
        false_positive_reason="the vault has no oracle; price cannot be manipulated",
        lessons=["do not spend budget on oracle attacks for oracle-free targets"],
    ))

    # 2. The hypothesis engine consults the memory and skips the disproven class.
    eng = HypothesisEngine(_vault_profile(), mem, strategy=Strategy("surface-aware", use_surface=True))
    chosen = eng.select_next()
    assert chosen is not None
    assert chosen.category != "oracle-manipulation"
    # The disproven class is still visible, but explicitly skipped.
    oracle = [h for h in eng.generate() if h.category == "oracle-manipulation"]
    assert oracle and all(h.skipped_disproven for h in oracle)
    # And the reusable lesson is retrievable for the next investigation.
    assert mem.lessons_for(target="VaultNoOracle", vulnerability_class="oracle-manipulation")

    # 3. The learning engine benchmarks the surface-aware improvement and adopts it.
    learning = LearningEngine()
    verdict = learning.evaluate(learning.propose_surface_awareness())
    assert verdict.accepted
    assert verdict.after["historical"]["top1_accuracy"] > verdict.before["historical"]["top1_accuracy"]

    # 4. The lesson is frozen as a regression test that passes when executed.
    import subprocess
    import sys

    reg = tmp_path / "test_learned_ranking.py"
    reg.write_text(verdict.failing_test, encoding="utf-8")
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", str(reg), "-q"],
        capture_output=True, text=True,
        cwd=str(Path(__file__).resolve().parent.parent),
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
