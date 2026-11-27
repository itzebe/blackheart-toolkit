"""Executable targets for ordering (MEV) attacks -- the class the step-based
engines cannot express on their own.

A sandwich is not a sequence one party submits; it is an *interleaving* of the
attacker's transactions into a victim's. This module supplies the target those
interleavings run against, so :mod:`blackheart.statespace.mempool` can search them
and the value engine can price them:

  * ``sandwich-slippage`` -- a constant-product pool with a *correct* swap formula,
    where the attack is not in the arithmetic but in the ordering: the attacker
    front-runs the victim's swap to move the price, the victim executes at the
    worse price, and the attacker back-runs to bank the difference. The victim's
    order carries a slippage limit they fixed when they submitted it; the
    vulnerable pool executes the order regardless, the guarded pool refuses it
    (the real fix -- the victim's tx reverts).

The victim's ``min_out`` is an *input* the victim declared at submission time, not
a value re-derived from the pool at execution: that is exactly why a front-run
beats it. Each variant ships a **vulnerable** model (a profitable,
slippage-breaching ordering exists) and a **guarded** model (the limit is
enforced, so no ordering extracts value). They differ *only* in that one control.
Engine fixtures: deterministic, no I/O, no network, no real funds.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .engine import InvariantSpec, OpSpec, PureState, Target


@dataclass
class SandwichState:
    rx: int = 1000
    ry: int = 1000
    bal_a: dict[str, int] = field(default_factory=dict)
    bal_b: dict[str, int] = field(default_factory=dict)
    initial_a: dict[str, int] = field(default_factory=dict)
    victim_out: int = 0
    victim_min_out: int = 0
    last_out: int = 0


class SandwichPool(PureState, Target):
    """A correct constant-product pool whose victim order carries no enforced
    slippage limit.

    The arithmetic is right -- this is deliberately *not* an AMM formula bug. The
    defect is that the victim's ``victim_swap`` executes no matter how far the
    attacker has moved the price first, so a front-run / back-run pair around it
    extracts the victim's price impact. The attacker's value is measured at the
    pool's initial 1:1 price, so ``bal_a + bal_b`` is their A-equivalent worth.
    """

    name = "sandwich-slippage"
    ATTACKER, VICTIM = "attacker", "victim"
    ACTORS = [ATTACKER, VICTIM]

    def reset(self) -> SandwichState:
        st = SandwichState()
        st.rx, st.ry = 1000, 1000
        st.bal_a = {self.ATTACKER: 1000, self.VICTIM: 1000}
        st.bal_b = {self.ATTACKER: 0, self.VICTIM: 0}
        st.initial_a = dict(st.bal_a)
        st.victim_out = 0
        st.victim_min_out = 0
        st.last_out = 0
        return st

    def ops(self) -> list[OpSpec]:
        # The victim's *only* trade is the slippage-protected one; the plain swaps
        # are the attacker's own market operations. That isolates the defect to the
        # victim order, so the guarded control has no unprotected trade to sandwich.
        return [
            OpSpec("swap_a_for_b", [self.ATTACKER], {"amount": [50, 100, 200]}, weight=5,
                   description="sell token A into the pool for token B"),
            OpSpec("swap_b_for_a", [self.ATTACKER], {"amount": [50, 100, 200]}, weight=5,
                   description="sell token B into the pool for token A"),
            OpSpec("victim_swap", [self.VICTIM], {"amount": [100], "min_out": [90]},
                   weight=1,
                   description="the victim's swap with the slippage limit they declared"),
        ]

    def _out_a_for_b(self, amount: int, st: SandwichState) -> int:
        return amount * st.ry // (st.rx + amount)

    def _out_b_for_a(self, amount: int, st: SandwichState) -> int:
        return amount * st.rx // (st.ry + amount)

    # -- the only difference between the vulnerable and guarded models -- #
    def _slippage_enforced(self) -> bool:
        """Vulnerable: no. Guarded: yes (the victim's tx reverts below their limit)."""
        return False

    def invariants(self) -> list[InvariantSpec]:
        return [
            InvariantSpec(
                "victim-slippage-protected",
                "the victim's swap never executes below the slippage limit they set",
                lambda st: st.victim_out == 0 or st.victim_out >= st.victim_min_out,
                severity_if_broken="high",
            ),
            InvariantSpec(
                "no-material-attacker-profit",
                "the attacker's A-equivalent value never exceeds their starting value "
                "by more than 0.1%",
                self._no_attacker_profit,
                severity_if_broken="high",
            ),
        ]

    ATTACKER_MATERIAL_BPS = 10
    BPS = 10_000

    def _no_attacker_profit(self, st: SandwichState) -> bool:
        a = self.ATTACKER
        # At the pool's initial 1:1 price, A-equivalent value is bal_a + bal_b.
        net = st.bal_a.get(a, 0) + st.bal_b.get(a, 0)
        return net - st.initial_a[a] <= (st.initial_a[a] * self.ATTACKER_MATERIAL_BPS) // self.BPS

    def _swap(self, st: SandwichState, actor: str, amount: int, a_for_b: bool) -> int:
        if a_for_b:
            if amount <= 0 or amount > st.bal_a.get(actor, 0):
                return 0
            out = self._out_a_for_b(amount, st)
            if out <= 0 or out > st.ry:
                return 0
            st.bal_a[actor] -= amount
            st.bal_b[actor] = st.bal_b.get(actor, 0) + out
            st.rx += amount
            st.ry -= out
            return out
        if amount <= 0 or amount > st.bal_b.get(actor, 0):
            return 0
        out = self._out_b_for_a(amount, st)
        if out <= 0 or out > st.rx:
            return 0
        st.bal_b[actor] -= amount
        st.bal_a[actor] = st.bal_a.get(actor, 0) + out
        st.ry += amount
        st.rx -= out
        return out

    def step(self, st: SandwichState, op: str, actor: str, params: dict[str, Any]) -> None:
        st.last_out = 0
        if op == "swap_a_for_b":
            st.last_out = self._swap(st, actor, int(params["amount"]), True)
        elif op == "swap_b_for_a":
            st.last_out = self._swap(st, actor, int(params["amount"]), False)
        elif op == "victim_swap":
            amount = int(params["amount"])
            min_out = int(params.get("min_out", 0))
            st.victim_min_out = min_out
            prospective = self._out_a_for_b(amount, st)
            if prospective <= 0 or amount > st.bal_a.get(actor, 0):
                return
            # Decide *before* mutating: a swap below the limit must not move the
            # pool at all (the guarded model: the victim's transaction reverts).
            if self._slippage_enforced() and prospective < min_out:
                return
            st.victim_out = self._swap(st, actor, amount, True)
            st.last_out = st.victim_out

    def snapshot(self, st: SandwichState) -> dict[str, Any]:
        return {
            "rx": st.rx, "ry": st.ry,
            "bal_a": dict(st.bal_a), "bal_b": dict(st.bal_b),
            "victim_out": st.victim_out, "victim_min_out": st.victim_min_out,
            "last_out": st.last_out,
        }


class GuardedSandwichPool(SandwichPool):
    """Same pool, but the victim's declared slippage limit is enforced."""

    name = "sandwich-guarded"

    def _slippage_enforced(self) -> bool:
        return True
