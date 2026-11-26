"""Scanner leads become grounded hypotheses -- and never a finding."""

from __future__ import annotations

from blackheart.cli import main
from blackheart.engines.external import ExternalOutcome
from blackheart.hypothesis.from_leads import (
    classify_lead, lead_to_hypothesis, leads_to_hypotheses,
)
from blackheart.mindset import LEVERS, OUTCOMES
from blackheart.threatmodel import ThreatModel


def test_classify_maps_known_rules_and_returns_none_otherwise():
    cat, outcome, levers = classify_lead({"rule": "reentrancy-eth"})
    assert cat == "reentrancy" and outcome in OUTCOMES
    assert all(lever in LEVERS for lever in levers)
    assert classify_lead({"rule": "style-guide", "message": "naming"}) is None


def test_promoted_lead_is_a_hypothesis_not_a_finding():
    hyp, why = lead_to_hypothesis(
        {"rule": "reentrancy-eth", "message": "reentrant external call",
         "path": "contracts/Vault.sol", "line": 42},
        tool="slither", component="Vault")
    assert why == "promoted"
    assert hyp["attacker_outcome"] in OUTCOMES
    assert all(lever in LEVERS for lever in hyp["attacker_levers"])
    assert hyp["is_finding"] is False and hyp["status"] == "HYPOTHESIS"
    assert "disposition" not in hyp and "confirmed" not in hyp
    assert hyp["component"] == "Vault" and hyp["source"]["line"] == 42


def test_component_falls_back_to_file_stem():
    hyp, _ = lead_to_hypothesis(
        {"rule": "access-control", "path": "a/b/Owner.sol", "line": 1}, tool="x")
    assert hyp["component"] == "Owner"


def test_unmapped_lead_is_refused_with_reason():
    hyp, why = lead_to_hypothesis({"rule": "gas-optimization"}, tool="x")
    assert hyp is None
    assert "no unprivileged-attacker outcome" in why


def test_ungrounded_component_is_refused_against_a_threat_model():
    model = ThreatModel(target="t", architecture=["Vault"])
    hyp, why = lead_to_hypothesis(
        {"rule": "reentrancy", "path": "Other.sol", "line": 1},
        tool="x", component="Other", threat_model=model)
    assert hyp is None and "ungrounded" in why
    grounded, _ = lead_to_hypothesis(
        {"rule": "reentrancy", "path": "Vault.sol", "line": 1},
        tool="x", component="Vault", threat_model=model)
    assert grounded is not None


def test_leads_to_hypotheses_from_an_outcome_dedupes_and_reports():
    outcome = ExternalOutcome("slither", "COMPLETED", "2 lead(s)", leads=[
        {"rule": "reentrancy-eth", "path": "Vault.sol", "line": 5},
        {"rule": "reentrancy-eth", "path": "Vault.sol", "line": 5},   # duplicate
        {"rule": "style-guide", "path": "Vault.sol", "line": 9},      # unmapped
    ])
    promo = leads_to_hypotheses(outcome, component="Vault")
    assert promo.promoted_count == 1
    assert promo.rejected_count == 2
    assert promo.as_dict()["note"].endswith("not findings")


def test_accepts_a_plain_list_of_leads():
    promo = leads_to_hypotheses([{"rule": "arithmetic", "path": "X.sol", "line": 1}],
                                component="X")
    assert promo.promoted_count == 1 and promo.tool == ""


def test_cli_to_hypotheses_without_record_is_fail_closed(tmp_path, capsys):
    rc = main(["external", "--run", "semgrep", "--target", str(tmp_path),
               "--to-hypotheses", "--component", "X"])
    assert rc == 2
    assert "needs --compatibility" in capsys.readouterr().err
