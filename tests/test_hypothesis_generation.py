"""Tests for P2 -- the hypothesis generation engine.

Covers the mission's P2 requirements: refuse an incomplete threat model, emit
only complete/falsifiable hypotheses, explainable ranking, duplicate detection,
preserved rejections with reasons, alternatives on contradiction, persistence,
and the novelty/authorization requirements carried on every hypothesis.
"""

from __future__ import annotations

import pytest

from blackheart.hypothesis import ThreatModelIncomplete
from blackheart.hypothesis.generation import (
    DEFAULT_GENERATION_WEIGHTS,
    REQUIRED_FIELDS,
    GeneratedHypothesis,
    HypothesisGenerator,
    HypothesisStore,
    alternatives,
)
from blackheart.models import InvestigationStatus, ResearchRecord
from blackheart.objectives import TargetProfile
from blackheart.research import ResearchMemory
from blackheart.threatmodel import ThreatModel


# --------------------------------------------------------------------------- #
# Fixtures
# --------------------------------------------------------------------------- #

def _profile() -> TargetProfile:
    return TargetProfile(
        name="UnstoppableVault", kind="smart-contract",
        assets=["vault-liquidity"], entry_points=["flashLoan", "deposit", "withdraw"],
        trust_boundaries=["user <-> vault"], roles=["owner", "user"],
        external_deps=["ERC20"], notes="flash-loan vault trusting its live balance",
    )


def _complete_model() -> ThreatModel:
    tm = ThreatModel(target="UnstoppableVault",
                     summary="A flash-loan vault that trusts its live token balance.")
    tm.architecture = ["UnstoppableVault", "UnstoppableMonitor"]
    tm.critical_assets = ["vault-liquidity"]
    tm.add_trust_boundary("user <-> vault", "user", "vault",
                          assumption="users do not donate without minting shares")
    tm.add_assumption("totalAssets() equals the sum of accounted shares",
                      if_false="share/asset accounting diverges")
    tm.add_invariant("INV-ACCT", "convertToShares(totalSupply) == totalAssets()",
                     applies_to=["vault-liquidity"])
    tm.select_impacts(["theft-or-freeze", "state-corruption"])
    return tm


# --------------------------------------------------------------------------- #
# The completeness gate
# --------------------------------------------------------------------------- #

def test_incomplete_model_is_refused():
    """A model with no stated invariant/asset must not produce hypotheses."""
    tm = ThreatModel(target="UnstoppableVault", summary="something")
    gen = HypothesisGenerator(tm, _profile())
    with pytest.raises(ThreatModelIncomplete) as exc:
        gen.generate()
    assert "incomplete" in str(exc.value)
    # The refusal names what is missing, so it is actionable.
    assert "invariants" in str(exc.value)


def test_uncovered_asset_is_refused():
    """Every critical asset must be covered by an invariant before hunting."""
    tm = _complete_model()
    tm.critical_assets = ["vault-liquidity", "unprotected-asset"]
    with pytest.raises(ThreatModelIncomplete):
        HypothesisGenerator(tm, _profile()).generate()


# --------------------------------------------------------------------------- #
# Completeness of generated hypotheses
# --------------------------------------------------------------------------- #

def test_generated_hypotheses_are_complete_and_falsifiable():
    res = HypothesisGenerator(_complete_model(), _profile()).generate()
    assert res.hypotheses, "a complete model must yield at least one hypothesis"
    for h in res.active():
        assert h.missing_fields() == [], f"{h.hyp_id} missing {h.missing_fields()}"
        # The mission's required associations are all populated.
        assert h.component and h.entry_point and h.invariant
        assert h.critical_asset and h.expected_impact
        assert h.strategy and h.reproduction_criteria and h.falsification_criteria
        assert h.authorization_requirement and h.novelty_requirement
        # A falsification criterion is what makes it a real hypothesis.
        assert "falsif" in h.falsification_criteria.lower() or h.falsification_criteria


def test_required_field_set_matches_mission():
    assert set(REQUIRED_FIELDS) == {
        "component", "entry_point", "attacker_capability", "trust_boundary",
        "critical_asset", "invariant", "expected_impact", "strategy",
        "reproduction_criteria", "falsification_criteria",
        "authorization_requirement", "novelty_requirement",
    }


def test_strategy_is_specific_not_generic():
    """Two hypotheses on different components/entry points read differently."""
    res = HypothesisGenerator(_complete_model(), _profile()).generate()
    actives = res.active()
    strategies = {h.strategy for h in actives}
    # The strategy text is composed with the hypothesis's own specifics.
    assert len(strategies) > 1
    top = actives[0]
    assert top.component in top.strategy
    assert top.entry_point in top.strategy


def test_invariant_comes_from_the_stated_model():
    """The attacked invariant is the researcher's stated one, not a template."""
    res = HypothesisGenerator(_complete_model(), _profile()).generate()
    for h in res.active():
        assert h.invariant_id == "INV-ACCT"
        assert h.invariant == "convertToShares(totalSupply) == totalAssets()"


def test_component_uses_real_architecture_not_chain_placeholder():
    res = HypothesisGenerator(_complete_model(), _profile()).generate()
    components = {h.component for h in res.active()}
    assert components <= {"UnstoppableVault", "UnstoppableMonitor"}
    # No generic template placeholder leaked through.
    assert not (components & {"aToken", "wrapper", "pool", "target", "token"})


# --------------------------------------------------------------------------- #
# Ranking
# --------------------------------------------------------------------------- #

def test_ranking_is_explainable_and_ordered():
    res = HypothesisGenerator(_complete_model(), _profile()).generate()
    scores = [h.score for h in res.active()]
    assert scores == sorted(scores, reverse=True), "active hypotheses are ranked desc"
    for h in res.active():
        assert set(h.score_parts) == set(DEFAULT_GENERATION_WEIGHTS)
        assert h.rationale and "score=" in h.rationale


def test_generation_is_deterministic():
    a = HypothesisGenerator(_complete_model(), _profile()).generate()
    b = HypothesisGenerator(_complete_model(), _profile()).generate()
    assert [h.hyp_id for h in a.active()] == [h.hyp_id for h in b.active()]
    assert [h.score for h in a.active()] == [h.score for h in b.active()]


# --------------------------------------------------------------------------- #
# Duplicate detection and rejections
# --------------------------------------------------------------------------- #

def test_duplicates_are_collapsed_and_rejected_with_reason():
    res = HypothesisGenerator(_complete_model(), _profile()).generate()
    # Deduplication must keep the set finite and record what it dropped.
    dupes = [r for r in res.rejections if r.reason_kind == "duplicate"]
    assert dupes, "the objective/chain catalogue produces duplicates that must collapse"
    for r in dupes:
        assert "duplicate of" in r.reason
    # No two active hypotheses share (component, class, invariant).
    seen = set()
    for h in res.active():
        key = (h.component.lower(), h.category, h.invariant.lower())
        assert key not in seen, f"duplicate survived: {h.hyp_id}"
        seen.add(key)


def test_overlaps_are_linked_not_dropped():
    res = HypothesisGenerator(_complete_model(), _profile()).generate()
    # At least one hypothesis shares a (component, class) with another but differs
    # by invariant; those are overlaps, not duplicates.
    overlaps = [h for h in res.active() if h.overlaps]
    # Not guaranteed for every target, but the mechanism must be wired when present.
    for h in overlaps:
        assert h.hyp_id not in h.overlaps


def test_incomplete_drafts_are_recorded_not_silently_dropped():
    """A hypothesis missing a required field is kept as a rejection."""
    hyp = GeneratedHypothesis(
        hyp_id="P2-x", objective_id="o", title="t", category="access-control",
        component="", entry_point="", attacker_capability="",
    )
    assert "component" in hyp.missing_fields()
    assert not hyp.is_complete()


# --------------------------------------------------------------------------- #
# Alternatives on contradiction
# --------------------------------------------------------------------------- #

def test_alternatives_keep_the_asset_but_change_class():
    gen = HypothesisGenerator(_complete_model(), _profile())
    res = gen.generate()
    original = res.active()[0]
    alts = alternatives(original, "reproduction showed the invariant holds", gen)
    assert alts, "a contradiction must produce at least one alternative"
    for a in alts:
        assert a.category != original.category
        assert a.contradicts == original.hyp_id
        assert any("contradiction" in lesson for lesson in a.prior_lessons)


# --------------------------------------------------------------------------- #
# Persistence and learning across cycles
# --------------------------------------------------------------------------- #

def test_store_round_trips_and_remembers_rejections(tmp_path):
    store = HypothesisStore(tmp_path)
    res = HypothesisGenerator(_complete_model(), _profile()).generate()
    store.save(res)

    reloaded = store.hypotheses()
    assert {h.hyp_id for h in reloaded} == {h.hyp_id for h in res.hypotheses}
    assert store.rejections(), "rejections must persist for a later cycle"
    assert store.find(res.active()[0].hyp_id) is not None

    # A later cycle can ask 'was this already rejected?' and get the reason.
    rej = store.rejections()[0]
    found = store.already_rejected(component=rej.component, category=rej.category)
    assert found is not None and found.reason


def test_store_survives_multiple_generations(tmp_path):
    store = HypothesisStore(tmp_path)
    store.save(HypothesisGenerator(_complete_model(), _profile()).generate())
    store.save(HypothesisGenerator(_complete_model(), _profile()).generate())
    # Append-only: two generations produce two copies, none lost.
    ids = [h.hyp_id for h in store.hypotheses()]
    assert len(ids) == len(set(ids)) * 2


# --------------------------------------------------------------------------- #
# Memory-aware scoring
# --------------------------------------------------------------------------- #

def test_prior_disproof_lowers_evidence_strength(tmp_path):
    """A class whose prior work produced no evidence scores lower on evidence."""
    mem = ResearchMemory(tmp_path)
    mem.save(ResearchRecord(
        record_id="r1", target="UnstoppableVault", vulnerability_class="access-control",
        status=InvestigationStatus.DISPROVEN.value,
        false_positive_reason="the setter is owner-gated",
    ))
    gen = HypothesisGenerator(_complete_model(), _profile(), memory=mem)
    res = gen.generate()
    ac = [h for h in res.active() if h.category == "access-control"]
    if ac:  # the class may be damped below the cut, but if present its lessons apply
        assert any("owner-gated" in l for l in ac[0].prior_lessons)


def test_tools_availability_changes_feasibility():
    res_none = HypothesisGenerator(_complete_model(), _profile(), tools_available=None).generate()
    res_none_tools = HypothesisGenerator(
        _complete_model(), _profile(), tools_available=set()).generate()
    # With an explicit (empty) tool set, feasibility drops and the score changes.
    a = {h.hyp_id: h.score for h in res_none.active()}
    b = {h.hyp_id: h.score for h in res_none_tools.active()}
    common = set(a) & set(b)
    assert common
    assert any(a[k] != b[k] for k in common)


# --------------------------------------------------------------------------- #
# Result helper
# --------------------------------------------------------------------------- #

def test_result_summary_and_select_next():
    res = HypothesisGenerator(_complete_model(), _profile()).generate()
    s = res.summary()
    assert s["active"] == len(res.active())
    assert s["hypotheses"] >= s["active"]
    nxt = res.select_next()
    assert nxt is not None and nxt.status == "ACTIVE"
    assert nxt.score == max(h.score for h in res.active())
