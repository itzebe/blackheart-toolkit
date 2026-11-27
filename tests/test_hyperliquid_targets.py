"""Tests for the spec-derived Hyperliquid models and their executable chains.

These models encode the *documented* portfolio-margin and HIP-4 mechanics (see
``blackheart/invariants/hyperliquid_targets.py``). A violation here is a
hypothesis about the specification, not a claim about the live protocol -- but
the models are still a real, executable part of the engine and must keep the
same vulnerable/guarded contrast as every other target.
"""

from __future__ import annotations

import pytest

from blackheart.attackdb import get_chain, run_chain, run_chain_control, verify_all_chains
from blackheart.invariants import FuzzConfig, StatefulFuzzer
from blackheart.invariants.registry import make_target

PAIRS = [
    ("hl-pm-supply", "hl-pm-supply-guarded"),
    ("hl-pm-liquidation", "hl-pm-liquidation-guarded"),
    ("hl-outcome", "hl-outcome-guarded"),
]


@pytest.mark.parametrize("vuln,guard", PAIRS)
def test_hl_pair_breaks_vulnerable_and_holds_guarded(vuln, guard):
    cfg = FuzzConfig(runs=300, steps_per_run=10, seed=0)
    vr = StatefulFuzzer(make_target(vuln), cfg).run()
    gr = StatefulFuzzer(make_target(guard), cfg).run()
    reachable = [f for f in vr.failures if f.reachable_by_attacker]
    assert reachable, f"{vuln} produced no attacker-reachable violation"
    assert not gr.failures, f"{guard} must not violate any invariant"


def test_all_chains_including_hl_verify():
    report = verify_all_chains()
    assert report["passed"] == report["total"]


@pytest.mark.parametrize(
    "chain_id,invariant",
    [
        ("hl-pm-withdraw-lent-supply", "pm-pool-solvent"),
        ("hl-pm-liquidate-healthy-position", "pm-liquidation-only-past-threshold"),
        ("hl-outcome-merge-unmatched-shares", "outcome-shares-collateralized"),
    ],
)
def test_hl_chain_breaks_vulnerable_not_guarded(chain_id, invariant):
    vuln = run_chain(chain_id)
    guard = run_chain_control(chain_id)
    assert invariant in vuln.broken_invariants
    assert not guard.broken_invariants


def test_pm_supply_run_is_a_bank_run():
    """The documented parameters: 100 USDC idle, a 100 USDC borrow drains idle to 0,
    and the supplier then withdraws the full 100 -- leaving the debt unbacked."""
    target = make_target("hl-pm-supply")
    st = target.reset()
    target.step(st, "borrow", "attacker", {"amount": 100 * 10**6})
    assert st.total_supplied - st.total_borrowed == 0
    target.step(st, "withdraw_supply", "victim", {"amount": 100 * 10**6})
    assert st.total_supplied < st.total_borrowed  # invariant broken


def test_pm_liquidation_threshold_matches_docs():
    """0.5 + 0.5*LTV is 0.825 for HYPE and 0.75 for BTC, per the docs."""
    from blackheart.invariants.hyperliquid_targets import _liq_threshold_bps

    assert _liq_threshold_bps(6500) == 8250
    assert _liq_threshold_bps(5000) == 7500


def test_outcome_merge_conserves_value_when_guarded():
    """A matched merge must return exactly what was locked (no value minted)."""
    target = make_target("hl-outcome-guarded")
    st = target.reset()
    before = st.quote["attacker"]
    target.step(st, "split", "attacker", {"amount": 100 * 10**6})
    target.step(st, "merge", "attacker", {"amount": 100 * 10**6})
    assert st.quote["attacker"] == before  # round-trips exactly
    assert st.locked == 0
    assert st.collateral_in == st.collateral_out
    assert all(i.holds(st) for i in target.invariants())


def test_outcome_merge_mints_value_when_vulnerable():
    target = make_target("hl-outcome")
    st = target.reset()
    target.step(st, "split", "attacker", {"amount": 100 * 10**6})
    # Attacker keeps the No leg, sends the Yes leg to a second controlled account,
    # then both merge. The Yes-only merge still refunds 100 quote, so 100 No shares
    # are left outstanding with zero collateral behind them.
    target.step(st, "transfer", "attacker",
                {"amount": 100 * 10**6, "to": "attacker2", "side": "yes"})
    target.step(st, "merge", "attacker", {"amount": 100 * 10**6})
    target.step(st, "merge", "attacker2", {"amount": 100 * 10**6})
    assert st.locked == 0
    assert sum(st.no.values()) == 100 * 10**6          # unbacked No shares remain
    assert not target.invariants()[0].holds(st)        # backing invariant broken


def test_hl_chains_are_renderable_targets():
    for chain_id in ("hl-pm-withdraw-lent-supply", "hl-outcome-merge-unmatched-shares"):
        get_chain(chain_id)  # must exist


# --------------------------------------------------------------------------- #
# HIP-4 question: negate/merge conservation
# --------------------------------------------------------------------------- #

def test_question_merge_no_set_breaks_conservation_but_guarded_holds():
    from blackheart.attackdb import verify_chain
    res = verify_chain("hl-question-merge-no-set-overpay")
    assert res["vulnerable"]["targeted_invariant_broke"] is True
    assert res["guarded"]["targeted_invariant_broke"] is False
    assert res["verified"] is True


def test_question_guarded_pays_documented_n_minus_1():
    from blackheart.invariants.hyperliquid_targets import (
        GuardedQuestionMarket, QuestionMarket,
    )
    from blackheart.invariants.engine import run_sequence
    from blackheart.attackdb import get_chain
    steps = get_chain("hl-question-merge-no-set-overpay").steps

    vuln = QuestionMarket()
    vres = run_sequence(vuln, steps)
    vst = vres.state
    # The defect pays n quote per No set: redeemed strictly exceeds the fair n-1.
    assert any(vst.redeemed[q] > vst.fair[q] for q in vst.redeemed)

    guard = GuardedQuestionMarket()
    gres = run_sequence(guard, steps)
    gst = gres.state
    assert all(gst.redeemed[q] <= gst.fair[q] for q in gst.redeemed)
