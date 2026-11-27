"""Tests for protocol intelligence / threat modeling (mission P1, Phase 2).

Covers: the impact catalogue, the incremental threat model and its completeness
gate (including the per-critical-asset invariant requirement), profile
bootstrapping, serialisation round-trips, unknown-impact rejection, impact-driven
objective steering, and the hunting gate in the hypothesis engine.
"""

from __future__ import annotations

import pytest

from blackheart.hypothesis import HypothesisEngine, ThreatModelIncomplete
from blackheart.objectives import TargetProfile, generate_objectives
from blackheart.threatmodel import (
    IMPACT_CATALOG,
    ThreatModel,
    categories_for_impacts,
    impact_catalog,
    known_impacts,
    model_from_profile,
    steer_objectives,
)


def _profile() -> TargetProfile:
    return TargetProfile(
        name="VaultNoOracle", kind="smart-contract",
        assets=["shares", "funds"],
        entry_points=["deposit(uint256)", "withdraw(uint256)"],
        trust_boundaries=["user <-> vault"], roles=["depositor"],
        external_deps=[], notes="ERC4626 vault with no external price dependency",
    )


def _complete_model(impacts=("theft-or-freeze",)) -> ThreatModel:
    tm = ThreatModel(
        target="VaultNoOracle",
        summary="An ERC4626 vault that mints shares for deposited assets.",
        architecture=["Vault", "ShareToken"],
        critical_assets=["shares", "funds"],
    )
    tm.add_trust_boundary("user <-> vault", "user", "vault",
                          assumption="a user cannot mint shares without depositing assets")
    tm.add_assumption("shares are minted only in exchange for assets",
                      depends_on="deposit()", if_false="share/asset accounting breaks")
    tm.add_invariant("INV-1", "redeemable value never exceeds assets held",
                     applies_to=["shares", "funds"],
                     expression="invariant_accounting_consistent()")
    tm.select_impacts(impacts)
    return tm


# --------------------------------------------------------------------------- #
# Impact catalogue (Part 3.B)
# --------------------------------------------------------------------------- #

def test_impact_catalogue_covers_the_mission_impacts():
    # The mission lists these impacts explicitly; the catalogue must include them.
    for required in (
        "unauthorized-fund-transfer", "theft-or-freeze", "unauthorized-execution",
        "privilege-escalation", "auth-bypass", "consensus-failure", "network-dos",
        "remote-code-execution", "signature-verification-failure", "state-corruption",
        "replay-ordering", "cross-component-trust", "incorrect-settlement",
    ):
        assert required in IMPACT_CATALOG
        assert IMPACT_CATALOG[required]["consequence"]


def test_impact_catalog_returns_a_copy():
    a = impact_catalog()
    a["theft-or-freeze"]["title"] = "mutated"
    assert IMPACT_CATALOG["theft-or-freeze"]["title"] != "mutated"


def test_known_impacts_sorted():
    assert known_impacts() == sorted(IMPACT_CATALOG)


# --------------------------------------------------------------------------- #
# Completeness gate
# --------------------------------------------------------------------------- #

def test_empty_model_is_incomplete_with_named_gaps():
    tm = ThreatModel(target="X")
    gaps = tm.missing()
    assert not tm.is_complete()
    for expected in ("summary", "architecture", "critical_assets",
                     "trust_boundaries", "assumptions", "invariants", "selected_impacts"):
        assert expected in gaps


def test_every_critical_asset_must_be_covered_by_an_invariant():
    tm = _complete_model()
    assert tm.is_complete()
    # Add an asset no invariant protects -> the gate must reopen.
    tm.critical_assets.append("governance-token")
    gaps = tm.missing()
    assert any(g.startswith("uncovered_assets:") for g in gaps)
    assert "governance-token" in " ".join(gaps)
    assert not tm.is_complete()


def test_profile_scaffold_is_incomplete_by_design():
    # A profile is not a threat model: the security-relevant fields are left empty
    # and the gate reports them, rather than silently passing.
    tm = model_from_profile(_profile(), selected_impacts=["theft-or-freeze"])
    assert tm.architecture  # transcribed from the profile
    assert tm.critical_assets == ["shares", "funds"]
    assert "assumptions" in tm.missing()
    assert "invariants" in tm.missing()
    assert not tm.is_complete()


def test_unknown_impact_is_rejected():
    tm = ThreatModel(target="X")
    with pytest.raises(ValueError):
        tm.select_impacts(["definitely-not-an-impact"])


# --------------------------------------------------------------------------- #
# Serialisation
# --------------------------------------------------------------------------- #

def test_model_round_trips_through_json():
    tm = _complete_model()
    restored = ThreatModel.from_dict(tm.to_dict())
    assert restored.is_complete()
    assert restored.target == tm.target
    assert restored.invariants[0].statement == tm.invariants[0].statement
    assert restored.trust_boundaries[0].assumption == tm.trust_boundaries[0].assumption
    assert restored.selected_impacts == tm.selected_impacts


# --------------------------------------------------------------------------- #
# Impact-driven steering (Part 3.B)
# --------------------------------------------------------------------------- #

def test_steer_puts_impact_relevant_categories_first():
    tm = _complete_model(impacts=["signature-verification-failure"])
    objectives = generate_objectives(_profile())
    steered = steer_objectives(objectives, tm)
    relevant = categories_for_impacts(tm.selected_impacts)
    # The first objectives must be the ones that can produce the selected impact.
    first_cats = [o.category for o in steered[:len(relevant)]]
    assert set(first_cats) == relevant
    # Nothing is dropped: steering reorders, it does not filter.
    assert len(steered) == len(objectives)


def test_steer_with_no_impacts_is_identity():
    tm = _complete_model()
    tm.selected_impacts = []
    objectives = generate_objectives(_profile())
    assert [o.category for o in steer_objectives(objectives, tm)] == [o.category for o in objectives]


# --------------------------------------------------------------------------- #
# Hunting gate (P1 -> hypothesis engine)
# --------------------------------------------------------------------------- #

def test_incomplete_model_blocks_hunting():
    inc = ThreatModel(target="VaultNoOracle")
    inc.select_impacts(["theft-or-freeze"])
    with pytest.raises(ThreatModelIncomplete):
        HypothesisEngine(_profile(), threat_model=inc).generate()


def test_complete_model_allows_hunting_and_steers():
    tm = _complete_model(impacts=["theft-or-freeze"])
    hyps = HypothesisEngine(_profile(), threat_model=tm).generate()
    assert hyps
    relevant = categories_for_impacts(tm.selected_impacts)
    # The top-ranked hypothesis must belong to an impact-relevant category.
    assert hyps[0].category in relevant


def test_no_threat_model_preserves_previous_behaviour():
    # Without a model the engine behaves exactly as before (no gate).
    hyps = HypothesisEngine(_profile()).generate()
    assert hyps


# --------------------------------------------------------------------------- #
# CLI end-to-end (scaffold -> gate -> gated hypothesis)
# --------------------------------------------------------------------------- #

def test_cli_scaffold_check_and_gated_hypothesis(tmp_path, capsys):
    import json

    from blackheart.cli import main

    profile = tmp_path / "profile.json"
    profile.write_text(json.dumps({
        "name": "VaultNoOracle", "kind": "smart-contract",
        "assets": ["shares", "funds"],
        "entry_points": ["deposit(uint256)", "withdraw(uint256)"],
        "trust_boundaries": ["user <-> vault"], "roles": ["depositor"],
    }), encoding="utf-8")
    model = tmp_path / "model.json"

    # Scaffold: deliberately incomplete -> non-zero, with named gaps.
    rc = main(["threatmodel", "scaffold", "--profile", str(profile),
               "--impact", "theft-or-freeze", "--out", str(model)])
    assert rc == 3
    assert "assumptions" in capsys.readouterr().out

    # check agrees the model is incomplete.
    assert main(["threatmodel", "check", "--model", str(model)]) == 3

    # Hunting against the incomplete model is refused by the CLI (exit 3).
    rc = main(["hypothesis", "--profile", str(profile), "--threat-model", str(model)])
    assert rc == 3
    assert "threat model is incomplete" in capsys.readouterr().err

    # Complete the model, then check + hunt succeed.
    data = json.loads(model.read_text(encoding="utf-8"))
    data["summary"] = "An ERC4626 vault that mints shares for deposited assets."
    data["assumptions"] = [{"statement": "shares minted only for assets",
                            "depends_on": "deposit()", "if_false": "accounting breaks",
                            "testable": True}]
    data["invariants"] = [{"inv_id": "INV-1", "statement": "redeemable <= assets",
                           "applies_to": ["shares", "funds"],
                           "expression": "invariant_accounting_consistent()",
                           "severity_if_broken": "high"}]
    model.write_text(json.dumps(data), encoding="utf-8")

    assert main(["threatmodel", "check", "--model", str(model)]) == 0
    assert main(["hypothesis", "--profile", str(profile), "--threat-model", str(model)]) == 0
