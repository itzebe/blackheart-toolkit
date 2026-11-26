"""The corpus now carries the numeric-window class as a measured holdout case."""

from __future__ import annotations

from blackheart.discovery.certify import certify_exhaustive, certify_numeric
from blackheart.discovery.corpus import corpus


def _case():
    return {c.case_id: c for c in corpus()}["H28-liquidation-window"]


def test_the_case_is_a_holdout_liquidation_model():
    case = _case()
    assert case.holdout
    assert case.root_cause == "liquidation"
    assert case.vulnerable is not None and case.patched is not None


def test_both_certifiers_find_the_window_and_the_ladder_keeps_it():
    case = _case()
    assert certify_exhaustive(case.vulnerable(), max_depth=2).proven
    cert = certify_numeric(case.vulnerable(), max_depth=2)
    assert cert.proven
    assert 750 < int(cert.witness[0].params.get("amount", 0)) <= 800


def test_the_guarded_twin_stays_clean_under_the_ladder():
    assert not certify_numeric(_case().patched(), max_depth=2).proven
