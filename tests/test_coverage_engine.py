"""The Universal Vulnerability Coverage Engine's acceptance bar.

The claim under test is narrow and checkable: the engine *reaches* planted defects
it would otherwise miss, over-records rather than under-records what it did not do,
adapts when an approach fails, composes hypotheses into multi-stage paths, and never
reports an incomplete run as complete.

Each planted defect is real *in the fixture*, so a passing test means the engine
drove the real pipeline (applicability -> hypothesis -> probe) to the defect, not
that a string matched.
"""

from __future__ import annotations

import pytest

from blackheart.coverage_engine import (
    ApplicabilityEngine,
    ControllerConfig,
    ControllerConfig as Cfg,
    CoverageRecord,
    CoverageState,
    FailureKind,
    LedgerError,
    ProbeOutcome,
    ResearchController,
    StrategySpace,
    StopReason,
    SurfaceEnumerator,
    Taxonomy,
    seed_record,
)
from blackheart.coverage_engine.fixtures import (
    CompositionalRewardPool,
    GuardedMultiTenantDocs,
    InjectableHandler,
    MultiTenantDocs,
)
from blackheart.objectives import TargetProfile


def _profile(**kw) -> TargetProfile:
    base = dict(
        name="acme-vault", kind="source-repository",
        assets=["0xVault", "0xOracle"], entry_points=["deposit", "withdraw", "claim"],
        trust_boundaries=["oracle", "user"], roles=["admin", "user"],
        external_deps=["chainlink"], notes="share accounting and reward math",
    )
    base.update(kw)
    return TargetProfile(**base)


# --------------------------------------------------------------------------- #
# 1. Applicability is target-aware, with reasons, never silent
# --------------------------------------------------------------------------- #

def test_applicable_and_inapplicable_are_decided_with_reasons():
    tax = Taxonomy()
    engine = ApplicabilityEngine(tax)
    # A pure HTTP echo service with no crypto/signature/financial surface.
    profile = TargetProfile(name="echo", kind="http-service",
                            assets=[], entry_points=["GET /echo"],
                            notes="stateless echo endpoint, no auth")
    result = engine.classify(profile)
    by_key = {v.key: v for v in result.verdicts}
    # 'reentrancy' needs a cross-component surface the echo service lacks.
    assert by_key["reentrancy"].state is CoverageState.INAPPLICABLE
    assert "requires" in by_key["reentrancy"].reason
    # Something must be applicable (input/api at minimum).
    assert result.applicable()


def test_thin_profile_is_unresolved_not_guessed_inapplicable():
    tax = Taxonomy()
    profile = TargetProfile(name="mystery", kind="unknown", assets=[], entry_points=[],
                            notes="")
    result = ApplicabilityEngine(tax).classify(profile)
    assert all(v.state is CoverageState.UNRESOLVED for v in result.verdicts)


def test_every_taxonomy_class_is_seeded_into_the_record():
    tax = Taxonomy()
    profile = _profile()
    result = ApplicabilityEngine(tax).classify(profile)
    rec = seed_record(result)
    # No class is silently omitted: the record has exactly the taxonomy's classes.
    assert set(rec.classes) == set(tax.keys())


# --------------------------------------------------------------------------- #
# 2. Coverage record refuses dishonest states
# --------------------------------------------------------------------------- #

def test_inapplicable_requires_a_reason():
    rec = CoverageRecord("t", [("x", "X")])
    with pytest.raises(LedgerError):
        rec.set_state("x", CoverageState.INAPPLICABLE)


def test_blocked_requires_a_reason():
    rec = CoverageRecord("t", [("x", "X")])
    with pytest.raises(LedgerError):
        rec.set_state("x", CoverageState.BLOCKED)


def test_reproduced_requires_evidence():
    rec = CoverageRecord("t", [("x", "X")])
    with pytest.raises(LedgerError):
        rec.set_state("x", CoverageState.REPRODUCED)


def test_tested_no_issue_is_never_reported_as_clean():
    rec = CoverageRecord("t", [("x", "X"), ("y", "Y")])
    rec.set_state("x", CoverageState.TESTED_NO_ISSUE_FOUND, reason="bounded search")
    rec.set_state("y", CoverageState.INAPPLICABLE, reason="no surface")
    summary = rec.summary()
    assert summary["verdict"] == "NO_FINDINGS_WITHIN_BUDGET"
    assert "NOT proof" in summary["why"]
    assert "never 'clean'" in summary["note"]


def test_any_open_class_makes_the_run_incomplete():
    rec = CoverageRecord("t", [("x", "X"), ("y", "Y")])
    rec.set_state("x", CoverageState.TESTED_NO_ISSUE_FOUND, reason="done")
    # y left NOT_ASSESSED -> open
    assert rec.summary()["verdict"] == "INCOMPLETE"
    assert "y" in rec.summary()["open_classes"]


# --------------------------------------------------------------------------- #
# 3. Strategy space: materially different approaches, no infinite loop
# --------------------------------------------------------------------------- #

def test_new_strategy_differs_materially_from_prior():
    space = StrategySpace()
    first = space.next_strategy("h1")
    assert first is not None
    space.record(_attempt("h1", first, ok=False))
    second = space.next_strategy("h1")
    assert second is not None
    assert second.differ_from(first) >= 1


def test_duplicate_signature_is_not_recorded():
    space = StrategySpace()
    s = space.next_strategy("h1")
    assert space.record(_attempt("h1", s, ok=False)) is True
    assert space.record(_attempt("h1", s, ok=False)) is False
    assert len(space.tried("h1")) == 1


def test_strategy_space_is_finite_and_terminates():
    space = StrategySpace(max_attempts_per_hypothesis=5)
    seen = 0
    while True:
        s = space.next_strategy("h1")
        if s is None:
            break
        space.record(_attempt("h1", s, ok=False))
        seen += 1
        assert seen <= 6  # bounded; cannot spin forever
    assert space.exhausted("h1")


def test_disproven_hypothesis_is_terminal():
    space = StrategySpace()
    s = space.next_strategy("h1")
    space.record(_attempt("h1", s, ok=False,
                          failure_kind=FailureKind.HYPOTHESIS_DISPROVEN.value))
    assert space.exhausted("h1")
    assert space.next_strategy("h1") is None


from blackheart.coverage_engine.strategy import Attempt, Strategy  # noqa: E402


def _attempt(hyp_id: str, strategy: Strategy, *, ok: bool,
             failure_kind: str = FailureKind.STRATEGY_INVALID.value) -> Attempt:
    return Attempt(hyp_id=hyp_id, strategy=strategy, ok=ok, failure_kind=failure_kind)


# --------------------------------------------------------------------------- #
# 4. Surface enumeration + multi-stage paths
# --------------------------------------------------------------------------- #

def test_surface_enumerates_entries_and_hypotheses():
    tax = Taxonomy()
    profile = _profile()
    result = ApplicabilityEngine(tax).classify(profile)
    surface = SurfaceEnumerator(tax).build(result, profile)
    assert surface.entry_points
    assert surface.hypotheses
    # every hypothesis carries an assumption AND a violation
    for h in surface.hypotheses:
        assert h.assumption and h.violation


def test_multi_stage_paths_are_generated_for_composable_classes():
    tax = Taxonomy()
    profile = _profile()
    result = ApplicabilityEngine(tax).classify(profile)
    surface = SurfaceEnumerator(tax).build(result, profile)
    # The profile exposes authorization + financial + callback surfaces, so at
    # least one composable (two-step) path must exist.
    assert surface.paths, "no multi-stage attack path generated for a composable surface"
    for p in surface.paths:
        assert len(p.steps) == 2
        assert len(set(p.class_keys)) == 2


# --------------------------------------------------------------------------- #
# 5. The controller REACHES a planted defect (the central acceptance test)
# --------------------------------------------------------------------------- #

def test_controller_reaches_planted_idor_through_real_pipeline():
    """A planted broken-access-control defect is reproduced by the controller."""
    tax = Taxonomy()
    profile = _profile(name="docs", kind="protocol-implementation",
                       entry_points=["read"],
                       notes="document store with roles and ownership")
    controller = ResearchController(tax, ControllerConfig(max_probes=50))

    from blackheart.coverage_engine.fixtures import MultiTenantDocs as Docs
    from blackheart.coverage_engine.controller import ProbeOutcome as PO

    def probe(class_key, hyp_id, strategy) -> PO:
        # The runner drives the REAL fixture and reports its real result.
        if class_key != "access-control":
            return PO(ok=False, failure_kind=FailureKind.STRATEGY_INVALID.value,
                      failure_reason="out of this fixture's surface")
        target = Docs()
        state = target.reset()
        target.step(state, "read", "alice", {"doc": "bob:secret"})
        broken = [i.inv_id for i in target.invariants() if not i.holds(state)]
        if broken:
            return PO(ok=True, evidence_tier="simulation", reproduced=True,
                      evidence=[f"{hyp_id}:{broken[0]}"])
        return PO(ok=False, failure_kind=FailureKind.HYPOTHESIS_DISPROVEN.value)

    result = controller.run(profile, probe=probe)
    assert result.reproductions >= 1
    assert "access-control" in result.record.summary()["reproduced_classes"]
    cov = result.record.classes["access-control"]
    assert cov.state is CoverageState.REPRODUCED
    assert cov.evidence


def test_controller_reaches_planted_compositional_defect():
    """Two individually-benign ops compose into value creation; the controller finds it."""
    tax = Taxonomy()
    profile = _profile(name="reward-pool", kind="protocol-implementation",
                       entry_points=["claim", "stake"],
                       notes="reward pool with stake and claim, share accounting")

    def probe(class_key, hyp_id, strategy) -> ProbeOutcome:
        if class_key != "compositional-chain" and class_key != "accounting-manipulation":
            return ProbeOutcome(ok=False, failure_kind=FailureKind.STRATEGY_INVALID.value)
        target = CompositionalRewardPool()
        state = target.reset()
        # The composition: stake 0, then claim 10 -> unearned bonus.
        target.step(state, "stake", "anyone", {"amount": 0})
        target.step(state, "claim", "anyone", {"amount": 10})
        broken = [i.inv_id for i in target.invariants() if not i.holds(state)]
        if broken:
            return ProbeOutcome(ok=True, evidence_tier="simulation", reproduced=True,
                                evidence=[f"{hyp_id}:{broken[0]}"])
        return ProbeOutcome(ok=False, failure_kind=FailureKind.HYPOTHESIS_DISPROVEN.value)

    result = ResearchController(tax, ControllerConfig(max_probes=60)).run(
        profile, probe=probe)
    assert result.reproductions >= 1


def test_controller_reaches_planted_injection():
    tax = Taxonomy()
    profile = _profile(name="handler", kind="http-service",
                       entry_points=["query"], notes="HTTP query handler, input validated?")

    def probe(class_key, hyp_id, strategy) -> ProbeOutcome:
        if class_key not in ("injection", "input-validation", "api-security"):
            return ProbeOutcome(ok=False, failure_kind=FailureKind.STRATEGY_INVALID.value)
        target = InjectableHandler()
        state = target.reset()
        target.step(state, "query", "anyone", {"path": "' OR 1=1 --"})
        broken = [i.inv_id for i in target.invariants() if not i.holds(state)]
        if broken:
            return ProbeOutcome(ok=True, evidence_tier="real-execution", reproduced=True,
                                evidence=[f"{hyp_id}:{broken[0]}"])
        return ProbeOutcome(ok=False, failure_kind=FailureKind.HYPOTHESIS_DISPROVEN.value)

    result = ResearchController(tax, ControllerConfig(max_probes=60)).run(
        profile, probe=probe)
    assert result.reproductions >= 1


# --------------------------------------------------------------------------- #
# 6. No infinite retry: a fully-failing probe terminates with an honest stop
# --------------------------------------------------------------------------- #

def test_all_failing_probe_terminates_with_strategy_space_exhausted():
    tax = Taxonomy()
    profile = _profile()
    calls = {"n": 0}

    def probe(class_key, hyp_id, strategy) -> ProbeOutcome:
        calls["n"] += 1
        return ProbeOutcome(ok=False, failure_kind=FailureKind.STRATEGY_INVALID.value)

    result = ResearchController(
        tax, ControllerConfig(max_probes=10000, max_attempts_per_hypothesis=3)
    ).run(profile, probe=probe)
    # It stopped, and it stopped for the right reason -- not by looping forever.
    assert result.stop_reason == StopReason.STRATEGY_SPACE_EXHAUSTED
    assert "not proof" in result.stop_detail.lower()
    # The number of attempts is bounded by hypotheses x attempts-per-hypothesis.
    assert calls["n"] <= len(result.surface.hypotheses) * 3


def test_probe_budget_is_respected():
    tax = Taxonomy()
    profile = _profile()
    calls = {"n": 0}

    def probe(class_key, hyp_id, strategy) -> ProbeOutcome:
        calls["n"] += 1
        return ProbeOutcome(ok=False, failure_kind=FailureKind.STRATEGY_INVALID.value)

    result = ResearchController(tax, ControllerConfig(max_probes=5)).run(
        profile, probe=probe)
    assert calls["n"] == 5
    assert result.stop_reason == StopReason.BUDGET_EXHAUSTED


# --------------------------------------------------------------------------- #
# 7. No backend supplied: structural work, honest block, no fabrication
# --------------------------------------------------------------------------- #

def test_no_probe_runner_reports_environment_blocked_without_fabrication():
    tax = Taxonomy()
    profile = _profile()
    result = ResearchController(tax).run(profile, probe=None)
    assert result.stop_reason == StopReason.ENVIRONMENT_BLOCKED
    assert result.probes == 0
    assert result.reproductions == 0
    assert result.record.environment_limitations
    # Structural work still happened.
    assert result.surface.hypotheses


# --------------------------------------------------------------------------- #
# 8. Prioritisation is transparent, deterministic, and eligibility-aware
# --------------------------------------------------------------------------- #

def test_priority_is_deterministic_and_explained():
    tax = Taxonomy()
    profile = _profile()
    r1 = ResearchController(tax).run(profile, probe=None)
    r2 = ResearchController(tax).run(profile, probe=None)
    assert [p["class_key"] for p in r1.priorities] == [p["class_key"] for p in r2.priorities]
    for p in r1.priorities:
        assert "score" in p and "prior_failures" in p and "on_attack_path" in p


def test_ineligible_class_is_deprioritised_not_rewarded():
    tax = Taxonomy()

    def ineligible(key):
        return False if key == "access-control" else None

    profile = _profile()
    result = ResearchController(
        tax, ControllerConfig(eligible=ineligible)
    ).run(profile, probe=None)
    access = [p for p in result.priorities if p["class_key"] == "access-control"]
    if access:
        assert access[0]["score"] == 0.0


def test_unknown_eligibility_does_not_zero_a_class():
    tax = Taxonomy()
    result = ResearchController(
        tax, ControllerConfig(eligible=lambda key: None)
    ).run(_profile(), probe=None)
    assert any(p["score"] > 0 for p in result.priorities)


# --------------------------------------------------------------------------- #
# 9. Taxonomy discovery: a new class mid-run is recorded as a gap
# --------------------------------------------------------------------------- #

def test_taxonomy_extend_is_idempotent_and_marked_discovered():
    tax = Taxonomy()
    before = len(tax)
    c1 = tax.extend("novel-race", "Novel race", "a newly seen class", requires=("concurrency",))
    c2 = tax.extend("novel-race", "Novel race", "dup")
    assert len(tax) == before + 1
    assert c1 is c2
    assert c1.discovered is True
    assert c1 in tax.discovered()


def test_record_tracks_taxonomy_gaps():
    rec = CoverageRecord("t", [("x", "X")])
    rec.add_class("brand-new", "Brand New")
    assert "brand-new" in rec.taxonomy_gaps
    assert "brand-new" in rec.classes


# --------------------------------------------------------------------------- #
# 10. Reproductions carry their evidence tier (simulation vs real)
# --------------------------------------------------------------------------- #

def test_reproduction_records_the_evidence_tier():
    tax = Taxonomy()
    profile = _profile()

    def probe(class_key, hyp_id, strategy) -> ProbeOutcome:
        if class_key == "access-control":
            return ProbeOutcome(ok=True, evidence_tier="simulation", reproduced=True,
                                evidence=["sim://1"])
        return ProbeOutcome(ok=False, failure_kind=FailureKind.HYPOTHESIS_DISPROVEN.value)

    result = ResearchController(tax, ControllerConfig(max_probes=80)).run(
        profile, probe=probe)
    cov = result.record.classes["access-control"]
    assert cov.best_evidence_tier == "simulation"
    # A simulation reproduction must never be silently promoted to real.
    assert cov.best_evidence_tier != "real-execution"


# --------------------------------------------------------------------------- #
# 11. Taxonomy/model linkage is a real invariant, not a claim
# --------------------------------------------------------------------------- #

def test_every_taxonomy_model_link_resolves_to_a_modelled_category():
    """A link naming a category the registry does not model is a silent blind spot:
    the plan would select a class and then find no executable pair behind it."""
    from blackheart.invariants.coverage import coverage_report

    modelled = {c.category for c in coverage_report() if c.coverage.value == "modelled"}
    broken = [(c.key, c.objective_category) for c in Taxonomy()
              if c.objective_category and c.objective_category not in modelled]
    assert not broken, f"taxonomy links to unmodelled categories: {broken}"


def test_every_modelled_category_is_reachable_from_the_taxonomy():
    """A modelled pair the taxonomy cannot name is dead coverage: no plan selects it."""
    from blackheart.invariants.coverage import coverage_report

    modelled = {c.category for c in coverage_report() if c.coverage.value == "modelled"}
    named = {c.objective_category for c in Taxonomy() if c.objective_category}
    unnamed = sorted(modelled - named)
    assert not unnamed, f"modelled categories the taxonomy cannot select: {unnamed}"


# --------------------------------------------------------------------------- #
# 12. One broken backend must not abort the run or poison the ledger
# --------------------------------------------------------------------------- #

def test_a_raising_probe_does_not_abort_the_run():
    tax = Taxonomy()
    profile = _profile()

    def boom(class_key, hyp_id, strategy):
        raise RuntimeError("backend exploded")

    result = ResearchController(tax, ControllerConfig(max_probes=5)).run(
        profile, probe=boom)
    # The run completes within its budget instead of propagating the exception.
    assert result.probes == 5
    assert result.stop_reason == StopReason.BUDGET_EXHAUSTED


def test_a_backend_error_is_recorded_and_never_reads_as_disproof():
    tax = Taxonomy()
    profile = _profile()

    def boom(class_key, hyp_id, strategy):
        raise RuntimeError("backend exploded")

    result = ResearchController(tax, ControllerConfig(max_probes=5)).run(
        profile, probe=boom)
    assert any("backend error" in lim.lower()
               for lim in result.record.environment_limitations)
    # A backend fault says nothing about the hypothesis: no class may be marked
    # as searched-clean, and the run is honestly INCOMPLETE.
    assert all(c.state is not CoverageState.TESTED_NO_ISSUE_FOUND
               for c in result.record.classes.values())
    assert result.summary()["verdict"] == "INCOMPLETE"


def test_exhausting_strategies_through_backend_faults_never_reads_as_clean():
    """A backend that never ran cannot be a searched-clean class. Exhausting the
    strategy space through faults must leave the class BLOCKED, and the run must
    report INCOMPLETE -- an outage laundered into 'no findings' is the exact
    dishonesty the coverage ledger exists to prevent."""
    def boom(class_key, hyp_id, strategy):
        raise RuntimeError("backend exploded")

    result = ResearchController(Taxonomy(), ControllerConfig(max_probes=400)).run(
        _profile(), probe=boom)
    states = {c.state for c in result.record.classes.values()}
    assert CoverageState.TESTED_NO_ISSUE_FOUND not in states
    assert CoverageState.BLOCKED in states
    assert result.summary()["verdict"] == "INCOMPLETE"
    blocked = [c for c in result.record.classes.values()
               if c.state is CoverageState.BLOCKED]
    assert all(c.backend_faults > 0 for c in blocked)
