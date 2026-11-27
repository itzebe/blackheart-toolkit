"""The allowance-reuse class is modelled, certified, and priced."""

from __future__ import annotations

from blackheart.discovery.certify import certify_exhaustive
from blackheart.discovery.corpus import corpus
from blackheart.value import analyse


def _case():
    return {c.case_id: c for c in corpus()}["H29-allowance-reuse"]


def test_the_case_is_a_holdout_authorization_model():
    case = _case()
    assert case.holdout
    assert case.root_cause == "access-control"


def test_the_reused_allowance_is_certified_and_the_guarded_twin_is_not():
    case = _case()
    cert = certify_exhaustive(case.vulnerable(), max_depth=2)
    assert cert.proven
    assert [step.action for step in cert.witness] == ["transferFrom"]
    assert not certify_exhaustive(case.patched(), max_depth=2).proven


def test_the_witness_is_priced_as_attacker_profit_and_victim_loss():
    case = _case()
    cert = certify_exhaustive(case.vulnerable(), max_depth=2)
    account = analyse(case.vulnerable(), cert.witness, cert.invariant_id)
    assert account.attacker_profit > 0
    assert account.victim_loss > 0
