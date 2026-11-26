"""Impact triage: a difference is not a vulnerability; an off-chain claim is a lead."""

from __future__ import annotations

from blackheart.autohunt import Target, bounty_grade
from blackheart.cli import main
from blackheart.hypothesis.from_leads import lead_to_hypothesis
from blackheart.impact import outcome_for_invariant, triage
from blackheart.mindset import OUTCOMES


def test_offchain_surface_is_lead_only():
    r = triage(surface="off-chain", impact="marginTable differs from enforced value",
               identifiers=["marginTable", "notionalMarginTable"])
    assert r.disposition == "LEAD_ONLY" and not r.qualifies
    assert "no executable model" in r.reasons[0]


def test_name_collision_is_informational():
    r = triage(surface="contract", impact="marginTable differs from notionalMarginTable")
    assert r.disposition == "INFORMATIONAL"
    assert "name collision" in r.reasons[0]


def test_no_attacker_outcome_is_informational():
    assert triage(surface="contract", impact="the table value looks different").disposition \
        == "INFORMATIONAL"


def test_receive_more_with_value_movement_surfaces():
    r = triage(surface="contract", impact="reentrant call lets an attacker drain funds")
    assert r.qualifies and r.outcome == OUTCOMES[0]


def test_access_control_bypass_surfaces():
    r = triage(surface="contract", impact="bypass access control to call the admin function")
    assert r.qualifies and r.outcome == OUTCOMES[1]


def test_unknown_surface_fails_closed():
    assert triage(surface="weird", impact="attacker steals funds").disposition == "LEAD_ONLY"


def test_outcome_for_invariant():
    assert outcome_for_invariant(["authorization:owner"]) == OUTCOMES[1]
    assert outcome_for_invariant(["conservation:total"]) == OUTCOMES[0]
    assert outcome_for_invariant(["other:x"]) == ""


def test_offchain_lead_is_refused_at_promotion():
    hyp, why = lead_to_hypothesis(
        {"rule": "access-control", "path": "api/info.py",
         "message": "authorization missing in the /info response"})
    assert hyp is None and "impact triage" in why


def test_contract_lead_still_promotes():
    hyp, why = lead_to_hypothesis(
        {"rule": "reentrancy-eth", "path": "Vault.sol", "message": "reentrant external call"})
    assert hyp is not None and why == "promoted"


def test_bounty_grade_refuses_offchain_finding():
    g = bounty_grade({"reproduced": True, "surface": "off-chain",
                      "hypothesis": "marginTable differs from notionalMarginTable"},
                     Target("T"))
    assert g["disposition"] == "E_INFORMATIONAL"
    assert g["payable"] is False and g["awaiting_review"] is False


def test_bounty_grade_qualifies_a_real_authorization_reproduction():
    g = bounty_grade({"reproduced": True, "surface": "contract",
                      "outcome": OUTCOMES[1], "hypothesis": "C: authorization witness"},
                     Target("C"))
    assert g["disposition"] == "F_NOT_ASSESSED" and g["awaiting_review"] is True


def test_cli_impact_offchain_exits_1(capsys):
    rc = main(["impact", "--surface", "off-chain", "--impact", "marginTable differs",
               "--identifiers", "marginTable", "notionalMarginTable"])
    assert rc == 1
    assert "LEAD_ONLY" in capsys.readouterr().out


def test_cli_impact_qualifying_exits_0(capsys):
    rc = main(["impact", "--impact", "attacker drains funds from the vault"])
    assert rc == 0
    assert "SURFACE" in capsys.readouterr().out
