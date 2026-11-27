"""The numeric-window certifier must reach windows boundary analysis misses.

The self-evaluation recorded a real miss (``hl-pm-liquidation``): the planted bug
fires only when a value is pushed past one threshold but kept under another, and
a boundary-value sampler never lands inside that window. These tests pin the
replacement behaviour on a purpose-built target with the same shape -- and the
two honesty properties that must survive: it stays inside the declared domain,
and it never certifies the guarded control.
"""

from __future__ import annotations

from blackheart.discovery.certify import (
    _ladder_values,
    certify_exhaustive,
    certify_numeric,
)
from blackheart.invariants.engine import InvariantSpec, OpSpec
from blackheart.models import AttackStep


class _LiquidationWindow:
    """A position liquidated between its borrow LTV and its liquidation threshold.

    ``borrow`` is capped at 800 (a hard supply limit). The vulnerable ``liquidate``
    fires at the *borrow LTV* (750) instead of the liquidation threshold (800), so
    any debt in (750, 800] is liquidated unfairly. Boundary values for the sample
    domain ``[0, 1, 1000]`` are ``0, 1, 999, 1000`` -- none lands in the window.
    """

    name = "liquidation-window"
    LTV = 750
    THRESHOLD = 800
    HARD_CAP = 800

    def __init__(self, patched: bool = False) -> None:
        self.patched = patched

    def reset(self):
        return {"debt": 0, "seized": 0, "unfair": 0}

    def ops(self):
        return [
            OpSpec("borrow", ["attacker"], {"amount": [0, 1, 1000]}),
            OpSpec("liquidate", ["attacker"], {}),
        ]

    def invariants(self):
        return [InvariantSpec("no-unfair-liquidation", "no unfair liquidation",
                              lambda s: s["unfair"] == 0)]

    def step(self, state, op, actor, params):
        if op == "borrow":
            amount = params.get("amount", 0)
            if not isinstance(amount, int) or amount < 0:
                return
            if state["debt"] + amount > self.HARD_CAP:
                return
            state["debt"] += amount
        elif op == "liquidate":
            trigger = self.THRESHOLD if self.patched else self.LTV
            if state["debt"] > trigger:
                state["seized"] += 100
                if state["debt"] <= self.THRESHOLD:
                    state["unfair"] = 1

    def snapshot(self, state):
        return dict(state)


def test_boundary_values_miss_the_window():
    cert = certify_exhaustive(_LiquidationWindow(), max_depth=2)
    assert not cert.proven, "the fixture is only useful if boundary analysis misses it"


def test_numeric_ladder_finds_the_window():
    cert = certify_numeric(_LiquidationWindow(), max_depth=2)
    assert cert.proven
    assert cert.reproducible
    assert cert.witness
    amounts = [s.params.get("amount") for s in cert.witness if s.action == "borrow"]
    assert any(isinstance(a, int) and 750 < a <= 800 for a in amounts)


def test_numeric_ladder_clears_the_patched_control():
    patched = _LiquidationWindow(patched=True)
    cert = certify_numeric(patched, max_depth=2)
    assert not cert.proven
    assert cert.exhausted


def test_numeric_ladder_uses_a_seed_path():
    seed = [
        AttackStep(0, "attacker", "borrow", {"amount": 1}),
        AttackStep(1, "attacker", "liquidate", {}),
    ]
    cert = certify_numeric(_LiquidationWindow(), max_depth=2, seed_path=seed)
    assert cert.proven


def test_ladder_values_stay_inside_the_declared_domain():
    values = _ladder_values([0, 1, 1000])
    assert values
    assert all(0 <= v <= 1000 for v in values)
    # The ratios that bracket a mid-range window are present.
    assert 750 in values and 800 in values


def test_numeric_certifier_reports_a_bound_when_it_finds_nothing():
    cert = certify_numeric(_LiquidationWindow(patched=True), max_depth=2)
    assert not cert.proven
    assert cert.exhausted
    assert cert.bound.get("max_depth") == 2
    assert "not a proof" in cert.reason.lower()
