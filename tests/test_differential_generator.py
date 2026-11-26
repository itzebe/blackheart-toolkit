"""Acceptance bar for the differential-fuzz generator.

A divergence must be found when two targets genuinely differ, reported with the
differing field and a minimised sequence; and no divergence must be reported when
they agree. A mismatched alphabet is an error, never an empty "clean" result.
"""

from __future__ import annotations

import pytest

from blackheart.fuzz.differential import (
    DifferentialError,
    compare_sequence,
    differential_fuzz,
)
from blackheart.invariants.engine import OpSpec, PureState


class Bank(PureState):
    """A toy ledger. ``fee`` is charged per withdraw -- the deliberate difference."""

    name = "bank"

    def __init__(self, fee: int = 0, ops_override=None) -> None:
        self._fee = fee
        self._ops_override = ops_override

    def reset(self):
        return {"total": 0, "user": 0, "fee": 0}

    def ops(self):
        if self._ops_override is not None:
            return self._ops_override
        return [
            OpSpec("deposit", ["attacker"], {"amount": [10, 100, 1000]}),
            OpSpec("withdraw", ["attacker"], {"amount": [5, 50]}),
        ]

    def invariants(self):
        return []

    def step(self, state, op_name, actor, params):
        if op_name == "deposit":
            amt = int(params["amount"])
            state["user"] += amt
            state["total"] += amt
        elif op_name == "withdraw":
            amt = min(int(params["amount"]), state["user"])
            state["user"] -= amt
            state["total"] -= amt
            state["fee"] += self._fee

    def snapshot(self, state):
        return dict(state)


def _step(action, amount):
    from blackheart.models import AttackStep

    return AttackStep(index=0, actor="attacker", action=action, params={"amount": amount})


def test_compare_sequence_finds_divergence_on_differing_field():
    ref, cand = Bank(0), Bank(1)
    seq = [_step("deposit", 100), _step("withdraw", 50)]
    div = compare_sequence(ref, cand, seq)
    assert div is not None
    assert "fee" in div.differing_keys
    assert div.step_index == 1  # the withdraw is where the fee appears
    assert div.verdict == "DIVERGENCE"


def test_compare_sequence_clean_when_they_agree():
    ref, cand = Bank(0), Bank(0)
    seq = [_step("deposit", 100), _step("withdraw", 50)]
    assert compare_sequence(ref, cand, seq) is None


def test_differential_fuzz_reports_divergence():
    report = differential_fuzz(Bank(0), Bank(1), runs=40, steps=6, seed=1)
    assert not report.clean
    assert report.divergences
    assert report.to_dict()["verdict"] == "DIVERGENCE"
    # The minimised sequence is short and ends at the diverging step.
    assert len(report.divergences[0].sequence) <= 6


def test_differential_fuzz_clean_when_identical():
    report = differential_fuzz(Bank(0), Bank(0), runs=40, steps=6, seed=1)
    assert report.clean
    assert report.to_dict()["verdict"] == "NO_DIVERGENCE"
    assert "not an equivalence proof" in report.to_dict()["note"]


def test_differential_fuzz_is_deterministic():
    a = differential_fuzz(Bank(0), Bank(1), runs=30, steps=5, seed=7).to_dict()
    b = differential_fuzz(Bank(0), Bank(1), runs=30, steps=5, seed=7).to_dict()
    assert a == b


def test_mismatched_alphabet_is_an_error():
    other = Bank(0, ops_override=[OpSpec("transfer", ["attacker"], {"amount": [1]})])
    with pytest.raises(DifferentialError):
        differential_fuzz(Bank(0), other, runs=5, steps=3)
    with pytest.raises(DifferentialError):
        compare_sequence(Bank(0), other, [_step("deposit", 10)])
