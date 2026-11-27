"""Tests for the passive HyperCore conformance auditor.

These use small, fixed fixtures so the checks are deterministic and offline. The
fixtures mirror the shapes returned by the live ``info`` endpoints.
"""

from blackheart.hyperliquid_audit import (
    Anomaly,
    check_merged_book,
    check_question_no_set,
    check_reserve_ledger,
    check_reserve_utilization,
    outcome_settlement,
    question_no_set_redeems,
    settlement_conserves,
)


def _reserve(balance, borrowed, supplied, util, ltv="0.0", px="1.0"):
    return {
        "balance": str(balance),
        "totalBorrowed": str(borrowed),
        "totalSupplied": str(supplied),
        "utilization": str(util),
        "ltv": ltv,
        "oraclePx": px,
    }


# --------------------------------------------------------------------------- #
# Reserve ledger identity
# --------------------------------------------------------------------------- #

def test_ledger_flags_supplier_claims_exceeding_assets():
    # supplied 100, but only 40 idle + 0 lent available -> 60 deficit.
    states = [(7, _reserve(40, 0, 100, 0.0))]
    out = check_reserve_ledger(states)
    assert len(out) == 1
    assert out[0].invariant == "reserve-fully-backed"
    assert out[0].severity == "deficit"
    assert out[0].observed["deficit"] == 60.0


def test_ledger_does_not_flag_benign_positive_excess():
    # Live data shows balance + borrowed slightly > supplied (uncredited interest).
    # That is the safe direction and must NOT be reported as a finding.
    states = [(1, _reserve(9953.26843, 0.0, 9927.88597, 0.0))]
    assert check_reserve_ledger(states) == []


def test_ledger_flags_are_relative_to_supplied():
    # A 0.5 deficit on a 1_000_000 supply is noise, not a finding.
    states = [(9, _reserve(999_999.5, 0, 1_000_000, 0.0))]
    assert check_reserve_ledger(states) == []


def test_utilization_mismatch_is_info_only():
    states = [(0, _reserve(100, 50, 200, 0.9))]   # real util is 0.25, reported 0.9
    out = check_reserve_utilization(states)
    assert len(out) == 1
    assert out[0].severity == "info"
    assert abs(out[0].observed["expected"] - 0.25) < 1e-12


def test_utilization_ok():
    states = [(0, _reserve(50, 50, 100, 0.5))]
    assert check_reserve_utilization(states) == []


# --------------------------------------------------------------------------- #
# Merged outcome book
# --------------------------------------------------------------------------- #

def _book(coin, bids, asks):
    return {"coin": coin, "levels": [
        [{"px": str(p), "sz": "10"} for p in bids],
        [{"px": str(p), "sz": "10"} for p in asks],
    ]}


def test_merged_book_complementary_ok():
    # Yes bid 0.49 / ask 0.51  <=>  No bid 0.49 / ask 0.51 (the live sample).
    yes = _book("#266090", [0.49], [0.51])
    no = _book("#266091", [0.49], [0.51])
    assert check_merged_book(yes, no) == []


def test_merged_book_flags_non_complementary_quote():
    # No best ask 0.40 should equal 1 - Yes bid 0.49 = 0.51.
    yes = _book("#1", [0.49], [0.51])
    no = _book("#2", [0.60], [0.40])
    out = check_merged_book(yes, no)
    assert any(a.invariant == "merged-book-complementary" for a in out)


def test_merged_book_flags_crossed_book_as_arbitrage():
    # Yes bid 0.55 + No bid 0.55 > 1 -> sell both legs for > guaranteed 1.
    yes = _book("#1", [0.55], [0.60])
    no = _book("#2", [0.55], [0.60])
    out = check_merged_book(yes, no)
    crossed = [a for a in out if a.invariant == "merged-book-not-crossed"]
    assert crossed and crossed[0].severity == "arbitrage"


def test_merged_book_handles_empty_books():
    assert check_merged_book(_book("#1", [], []), _book("#2", [], [])) == []


# --------------------------------------------------------------------------- #
# Settlement and question conservation
# --------------------------------------------------------------------------- #

def test_settlement_conserves_for_any_fraction():
    for f in (0.0, 0.25, 0.5, 1.0):
        assert settlement_conserves(f)
        assert abs(outcome_settlement(f, 1.0, 1.0) - 1.0) < 1e-12


def test_settlement_pays_documented_sides():
    # Binary yes: Yes pays 1, No pays 0.
    assert outcome_settlement(1.0, 3.0, 5.0) == 3.0
    # Binary no: Yes pays 0, No pays 1.
    assert outcome_settlement(0.0, 3.0, 5.0) == 5.0


def test_question_no_set_documented_value():
    assert question_no_set_redeems(2) == 1.0
    assert question_no_set_redeems(3) == 2.0


def test_question_no_set_overpay_is_flagged():
    a = check_question_no_set(n_outcomes=3, redeemed=3.0)
    assert isinstance(a, Anomaly)
    assert a.severity == "arbitrage"


def test_question_no_set_correct_value_not_flagged():
    assert check_question_no_set(n_outcomes=3, redeemed=2.0) is None
