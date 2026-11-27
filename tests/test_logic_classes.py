"""Tests for the logic attack classes and the class-coverage ledger.

The three classes here (rounding precision, ordering/timing, info disclosure) were
previously described only as prose in the objectives catalogue: the engine had no
model for them, so every search strategy was blind to them. These tests assert the
new models behave with the same non-vacuity discipline as every other pair (the
vulnerable model breaks, the guarded one holds), and that the coverage ledger
reports the class coverage honestly.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from blackheart.cli import main
from blackheart.invariants import FuzzConfig, StatefulFuzzer
from blackheart.invariants.coverage import (
    CATEGORY_KIND,
    PROSE_ONLY,
    Coverage,
    coverage_report,
    coverage_summary,
    modelled_categories,
    unmodelled_categories,
)
from blackheart.invariants.logic_targets import (
    ExpiringOffer,
    GuardedExpiringOffer,
    GuardedObjectStore,
    GuardedRoundingVault,
    ObjectStore,
    RoundingVault,
)
from blackheart.invariants.registry import make_target
from blackheart.objectives import available_categories


def _run(cls, runs=500, steps=10):
    return StatefulFuzzer(cls(), FuzzConfig(runs=runs, steps_per_run=steps, seed=0)).run()


# --------------------------------------------------------------------------- #
# Per-class contrast: the vulnerable model breaks, the guarded one holds
# --------------------------------------------------------------------------- #

def test_rounding_precision_is_exploitable_and_guarded_is_not():
    vuln = _run(RoundingVault)
    guard = _run(GuardedRoundingVault)
    assert vuln.failures, "rounding-up share issuance must be findable"
    assert all(f.reachable_by_attacker for f in vuln.failures)
    assert any(f.inv_id == "no-material-attacker-profit" for f in vuln.failures)
    assert guard.failures == [], "floored share issuance must not over-credit a deposit"


def test_ordering_timing_is_exploitable_and_guarded_is_not():
    vuln = _run(ExpiringOffer)
    guard = _run(GuardedExpiringOffer)
    assert vuln.failures, "accepting an expired offer must be findable"
    assert any(f.inv_id == "no-expired-acceptance" for f in vuln.failures)
    assert guard.failures == [], "a deadline check must refuse a late acceptance"


def test_info_disclosure_is_exploitable_and_guarded_is_not():
    vuln = _run(ObjectStore)
    guard = _run(GuardedObjectStore)
    assert vuln.failures, "reading another principal's object must be findable"
    assert any(f.inv_id == "object-read-only-by-owner" for f in vuln.failures)
    assert guard.failures == [], "object-level authorization must block a foreign read"


def test_the_guarded_and_vulnerable_models_differ_only_in_the_control():
    """The differential must isolate one control, not a whole redesign."""
    # Rounding: the share formula is the only difference.
    assert RoundingVault()._shares_for(1, RoundingVault().reset()) != \
        GuardedRoundingVault()._shares_for(1, GuardedRoundingVault().reset())
    # Timing: the accept gate is the only difference.
    v, g = ExpiringOffer().reset(), GuardedExpiringOffer().reset()
    v.clock, g.clock = 5, 5
    assert ExpiringOffer()._accept_allowed(v) is True
    assert GuardedExpiringOffer()._accept_allowed(g) is False
    # Info: the read gate is the only difference.
    ov, og = ObjectStore().reset(), GuardedObjectStore().reset()
    assert ObjectStore()._may_read(ov, "attacker", "1") is True
    assert GuardedObjectStore()._may_read(og, "attacker", "1") is False


@pytest.mark.parametrize(
    "vuln,guard",
    [("rounding-precision", "rounding-guarded"),
     ("timing-expiry", "timing-guarded"),
     ("info-disclosure", "info-guarded")],
)
def test_new_pairs_are_registered_and_contrast_through_the_registry(vuln, guard):
    cfg = FuzzConfig(runs=400, steps_per_run=10, seed=0)
    vr = StatefulFuzzer(make_target(vuln), cfg).run()
    gr = StatefulFuzzer(make_target(guard), cfg).run()
    reachable = [f for f in vr.failures if f.reachable_by_attacker]
    assert reachable, f"{vuln} produced no attacker-reachable violation"
    assert not gr.failures, f"{guard} must not violate any invariant"


def test_new_classes_reach_a_confirmed_finding_end_to_end(tmp_path):
    from blackheart.demonstrations import run_class_demonstration

    for vuln, guard in [("rounding-precision", "rounding-guarded"),
                        ("timing-expiry", "timing-guarded"),
                        ("info-disclosure", "info-guarded")]:
        summary = run_class_demonstration(
            tmp_path / vuln, pair=f"{vuln}/{guard}", runs=300, steps_per_run=10
        )
        assert summary["status"] == "CONFIRMED", f"{vuln} did not confirm"
        assert summary["guarded_failures"] == 0
        assert summary["report_path"]


# --------------------------------------------------------------------------- #
# The coverage ledger: every objective category is modelled or a named gap
# --------------------------------------------------------------------------- #

def test_every_objective_category_is_modelled_or_a_named_gap():
    """No category may be silently absent from the ledger.

    Every category the objectives engine can generate is either covered by a
    registered model or explicitly recorded as prose-only. A category that is
    neither is an unmodelled gap, which the ledger must surface -- never hide.
    """
    ledger = {c.category: c for c in coverage_report()}
    assert set(ledger) == set(available_categories())
    for cat, cov in ledger.items():
        assert cov.coverage in (Coverage.MODELLED, Coverage.UNMODELLED, Coverage.PROSE_ONLY)
        if cov.coverage is Coverage.MODELLED:
            assert cov.kind and cov.targets, f"{cat} modelled but names no target"
        else:
            assert cov.reason, f"{cat} is {cov.coverage.value} but gives no reason"


def test_the_three_previously_prose_only_classes_are_now_modelled():
    modelled = set(modelled_categories())
    assert {"rounding-precision", "ordering-timing", "info-disclosure"} <= modelled


def test_a_modelled_category_resolves_to_a_real_registered_pair():
    """A 'modelled' claim must be backed by an actual vulnerable/guarded pair."""
    from blackheart.invariants.registry import TARGET_SPECS

    for cov in coverage_report():
        if cov.coverage is not Coverage.MODELLED:
            continue
        specs = [s for s in TARGET_SPECS if s.kind == cov.kind]
        assert any(not s.guarded for s in specs), f"{cov.category}: no vulnerable model"
        assert any(s.guarded for s in specs), f"{cov.category}: no guarded control"


def test_ledger_is_honest_about_representative_coverage():
    summary = coverage_summary()
    assert summary["categories"] == len(available_categories())
    assert summary["modelled"] + summary["prose_only"] + summary["unmodelled"] == \
        summary["categories"]
    # The note must never claim exhaustive class coverage.
    assert "representative" in summary["note"].lower()
    assert "exhaustive" in summary["note"].lower()


def test_category_kind_map_targets_are_all_declared():
    """Every kind named in the map must exist in the registry (no dead mapping)."""
    from blackheart.invariants.registry import TARGET_SPECS

    kinds = {s.kind for s in TARGET_SPECS}
    for cat, kind in CATEGORY_KIND.items():
        assert kind in kinds, f"{cat} maps to unknown kind {kind!r}"
    for cat in PROSE_ONLY:
        assert cat in available_categories()


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def test_cli_coverage_reports_full_coverage(tmp_path, capsys):
    out = tmp_path / "coverage.json"
    rc = main(["coverage", "--out", str(out)])
    text = capsys.readouterr().out
    assert "objective categories have an executable vulnerable/guarded model" in text
    payload = json.loads(out.read_text())
    assert payload["summary"]["unmodelled"] == 0
    assert payload["summary"]["categories"] == len(available_categories())
    # With full coverage the command succeeds; a gap would exit non-zero.
    assert rc == 0


def test_cli_coverage_lists_the_new_classes(capsys):
    assert main(["coverage"]) == 0
    text = capsys.readouterr().out
    for cat in ("rounding-precision", "ordering-timing", "info-disclosure"):
        assert cat in text


# --------------------------------------------------------------------------- #
# Doctrine wiring (universal)
# --------------------------------------------------------------------------- #

def test_model_doctrine_is_canonical_and_in_every_block():
    from blackheart.mindset import (
        MODEL_DOCTRINE,
        agent_lens_block,
        model_doctrine,
        prompt_block,
        skill_document,
    )

    rules = " ".join(MODEL_DOCTRINE).lower()
    assert "blind" in rules
    assert "model" in rules
    assert model_doctrine() == list(MODEL_DOCTRINE)
    assert "## The model bar" in agent_lens_block()
    assert "## Models" in skill_document()
    assert "unsearchable" in prompt_block().lower() or "model" in prompt_block().lower()


def test_every_agent_carries_the_model_bar():
    root = Path(__file__).resolve().parents[1]
    agents = sorted((root / "agents").glob("*.md"))
    assert agents
    missing = [p.stem for p in agents if "## The model bar" not in p.read_text(encoding="utf-8")]
    assert not missing, f"agents missing the model bar: {missing}"


def test_mindset_json_exposes_the_model_doctrine(capsys):
    assert main(["mindset", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["model_doctrine"]
    assert any("blind" in r.lower() for r in payload["model_doctrine"])
