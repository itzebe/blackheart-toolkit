"""Reference model: a wrapper-share token over a rebasing aToken.

Mission section 6 asks specifically whether a *wrapper share* can diverge from the
underlying *aToken* balance in a way that yields unauthorized value extraction.
The real Twyne deployment's Aave wrapper source is not available in this
repository, so this module is an explicit, documented **model** of that accounting
(not a copy of the real code). It exists to test the *hypothesis class* and to
falsify it honestly.

Accounting modelled (the parts that matter for the hypothesis):

  * deposit: underlying -> aToken (1:1 at deposit time) -> wrapper shares, where
        shares = amount * totalShares / totalAtokens      (naive)
        shares = amount * (totalShares+VIRTUAL_SHARES) / (totalAtokens+VIRTUAL_ASSETS)  (guarded)
  * aToken rebase: `accrue_yield` grows totalAtokens without changing share supply
    (this is what an Aave aToken does as interest accrues).
  * unsolicited transfer: `donate` sends aTokens to the wrapper directly, inflating
    totalAtokens with no shares minted.
  * withdraw: burn shares, redeem `shares * totalAtokens / totalShares`.
  * partial withdrawals, multiple actors, and a `transfer_shares` op so users can
    enter and leave in different orders.

The two variants differ only in the virtual-shares/offset defence, exactly as in
the ERC4626 reference harness, so the same invariants can be run against a
vulnerable and a guarded model (non-vacuity).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .engine import InvariantSpec, OpSpec, Target

DECIMALS = 10**18
ACTORS = ["attacker", "victim", "victim2", "depositor"]


@dataclass
class WrapperState:
    atokens: dict[str, int] = field(default_factory=dict)     # per-actor aToken claim
    shares: dict[str, int] = field(default_factory=dict)      # per-actor wrapper shares
    underlying: dict[str, int] = field(default_factory=dict)  # un-deposited underlying
    total_atokens: int = 0
    total_shares: int = 0
    initial: dict[str, int] = field(default_factory=dict)     # starting underlying
    donated: dict[str, int] = field(default_factory=dict)
    # Fair-yield attribution: a yield accrual is *legitimate* income for holders,
    # so it must not be counted as attacker profit. We credit each actor their
    # pro-rata share of every accrual and subtract it when measuring extraction.
    fair_yield: dict[str, int] = field(default_factory=dict)
    # A donation is a *voluntary* transfer to the whole pool; the pro-rata value
    # each holder receives from someone else's donation is a gift, not theft.
    fair_gift: dict[str, int] = field(default_factory=dict)
    # Value an actor voluntarily gave away (donations + share transfers out).
    # An actor who chooses to give value away has not suffered a security loss.
    voluntary_out: dict[str, int] = field(default_factory=dict)
    yield_accrued: int = 0
    last_shares_minted: int = 0
    last_deposit_assets: int = 0


class WrapperTarget(Target):
    """A wrapper-share token over a rebasing aToken.

    ``VIRTUAL_SHARES``/``VIRTUAL_ASSETS`` are 0 in the vulnerable variant and set
    to the ERC4626 offset in the guarded variant.
    """

    name = "wrapper"
    VIRTUAL_SHARES = 0
    VIRTUAL_ASSETS = 0

    def __init__(self, starting_balance: int = 1000 * DECIMALS) -> None:
        self.starting_balance = starting_balance

    # ------------------------------------------------------------------ #
    def reset(self) -> WrapperState:
        st = WrapperState()
        for a in ACTORS:
            st.underlying[a] = self.starting_balance
            st.initial[a] = self.starting_balance
            st.atokens[a] = 0
            st.shares[a] = 0
            st.donated[a] = 0
            st.fair_yield[a] = 0
            st.fair_gift[a] = 0
            st.voluntary_out[a] = 0
        return st

    def ops(self) -> list[OpSpec]:
        return [
            OpSpec("deposit", ACTORS, {"amount": [1, 10, 1000, DECIMALS, 10 * DECIMALS]},
                   weight=3, description="deposit underlying and mint wrapper shares"),
            OpSpec("withdraw", ACTORS, {"shares": [1, 10, 1000, DECIMALS]},
                   weight=3, description="burn wrapper shares and redeem aTokens"),
            OpSpec("donate", ["attacker", "depositor"],
                   {"amount": [1, 10, 1000, DECIMALS, 100 * DECIMALS]},
                   weight=2, description="transfer aTokens directly to the wrapper"),
            OpSpec("accrue_yield", ["aave"], {"amount": [1, 10, DECIMALS, 100 * DECIMALS]},
                   weight=2, description="aToken rebase: grow totalAtokens (not attacker-controlled)"),
            OpSpec("transfer_shares", ACTORS, {"to": ACTORS, "shares": [1, 10, DECIMALS]},
                   weight=1, description="move wrapper shares between actors"),
        ]

    def invariants(self) -> list[InvariantSpec]:
        return [
            InvariantSpec(
                "wrapper-solvency",
                "the sum of every holder's redeemable aTokens never exceeds totalAtokens",
                self._solvent,
                severity_if_broken="critical",
            ),
            InvariantSpec(
                "no-material-attacker-profit",
                "the attacker's net claim never exceeds what they supplied plus their "
                "fair pro-rata share of legitimate yield, by more than 0.1%",
                self._no_material_attacker_profit,
                severity_if_broken="high",
            ),
            InvariantSpec(
                "no-material-victim-loss",
                "no non-donating actor loses more than 1% of their starting underlying",
                self._no_material_victim_loss,
                severity_if_broken="high",
            ),
        ]

    ATTACKER_MATERIAL_BPS = 10
    VICTIM_MATERIAL_BPS = 100
    BPS = 10_000

    # ------------------------------------------------------------------ #
    def _redeemable(self, st: WrapperState, actor: str) -> int:
        return self._convert_to_assets(st, st.shares.get(actor, 0))

    def _convert_to_assets(self, st: WrapperState, shares: int) -> int:
        denom = st.total_shares + self.VIRTUAL_SHARES
        if denom == 0:
            return 0
        return (shares * (st.total_atokens + self.VIRTUAL_ASSETS)) // denom

    def _convert_to_shares(self, st: WrapperState, assets: int) -> int:
        denom = st.total_atokens + self.VIRTUAL_ASSETS
        if denom == 0:
            return assets
        return (assets * (st.total_shares + self.VIRTUAL_SHARES)) // denom

    def _solvent(self, st: WrapperState) -> bool:
        total_redeemable = sum(
            self._convert_to_assets(st, st.shares.get(a, 0)) for a in st.shares
        )
        return total_redeemable <= st.total_atokens

    def _no_material_attacker_profit(self, st: WrapperState) -> bool:
        a = "attacker"
        net = st.underlying.get(a, 0) + self._redeemable(st, a)
        # Legitimate yield the attacker fairly earned, voluntary gifts they were
        # given, and any value they voluntarily gave away are not exploit profit.
        gain = (
            net
            - st.initial[a]
            - st.fair_yield.get(a, 0)
            - st.fair_gift.get(a, 0)
            + st.voluntary_out.get(a, 0)
        )
        return gain <= (st.initial[a] * self.ATTACKER_MATERIAL_BPS) // self.BPS

    def _no_material_victim_loss(self, st: WrapperState) -> bool:
        for a in st.initial:
            if st.donated.get(a, 0) > 0:
                continue
            net = st.underlying.get(a, 0) + self._redeemable(st, a)
            # Fair yield/gifts received offset the shortfall; value the actor
            # voluntarily gave away is not a loss.
            loss = (
                st.initial[a]
                + st.fair_yield.get(a, 0)
                + st.fair_gift.get(a, 0)
                - st.voluntary_out.get(a, 0)
                - net
            )
            if loss > (st.initial[a] * self.VICTIM_MATERIAL_BPS) // self.BPS:
                return False
        return True

    # ------------------------------------------------------------------ #
    def step(self, st: WrapperState, op: str, actor: str, params: dict[str, Any]) -> None:
        st.last_shares_minted = 0
        st.last_deposit_assets = 0
        if op == "deposit":
            self._deposit(st, actor, int(params["amount"]))
        elif op == "withdraw":
            self._withdraw(st, actor, int(params["shares"]))
        elif op == "donate":
            self._donate(st, actor, int(params["amount"]))
        elif op == "accrue_yield":
            self._accrue_yield(st, int(params["amount"]))
        elif op == "transfer_shares":
            self._transfer(st, actor, params["to"], int(params["shares"]))

    def _deposit(self, st: WrapperState, actor: str, amount: int) -> None:
        amount = min(amount, st.underlying.get(actor, 0))
        if amount <= 0:
            return
        shares = self._convert_to_shares(st, amount)
        st.underlying[actor] -= amount
        st.atokens[actor] = st.atokens.get(actor, 0) + amount
        st.total_atokens += amount
        st.shares[actor] = st.shares.get(actor, 0) + shares
        st.total_shares += shares
        st.last_shares_minted = shares
        st.last_deposit_assets = amount

    def _withdraw(self, st: WrapperState, actor: str, shares: int) -> None:
        shares = min(shares, st.shares.get(actor, 0))
        if shares <= 0:
            return
        assets = self._convert_to_assets(st, shares)
        assets = min(assets, st.total_atokens)
        st.shares[actor] -= shares
        st.total_shares -= shares
        st.atokens[actor] = max(0, st.atokens.get(actor, 0) - assets)
        st.total_atokens -= assets
        st.underlying[actor] = st.underlying.get(actor, 0) + assets

    def _donate(self, st: WrapperState, actor: str, amount: int) -> None:
        amount = min(amount, st.underlying.get(actor, 0))
        if amount <= 0:
            return
        st.underlying[actor] -= amount
        # A donation gifts its value to existing share-holders, minus any part the
        # virtual shares absorb (which benefits future depositors, not holders).
        if st.total_shares > 0:
            denom = st.total_shares + self.VIRTUAL_SHARES
            for a, sh in st.shares.items():
                st.fair_gift[a] = st.fair_gift.get(a, 0) + amount * sh // denom
        st.total_atokens += amount
        st.donated[actor] = st.donated.get(actor, 0) + amount

    def _accrue_yield(self, st: WrapperState, amount: int) -> None:
        # Aave aToken rebase: balances grow without new shares being minted.
        if amount <= 0 or st.total_shares == 0:
            return
        # Credit each share-holder their fair slice of the yield. The virtual
        # shares (if any) absorb part of any inflow, so they belong in the
        # denominator; the remainder benefits future depositors, not current ones.
        denom = st.total_shares + self.VIRTUAL_SHARES
        for a, sh in st.shares.items():
            st.fair_yield[a] = st.fair_yield.get(a, 0) + amount * sh // denom
        st.yield_accrued += amount
        prev_total = st.total_atokens
        st.total_atokens += amount
        # aToken balances rebase proportionally for all holders.
        if prev_total > 0:
            for a in st.atokens:
                st.atokens[a] = st.atokens[a] * st.total_atokens // prev_total

    def _transfer(self, st: WrapperState, actor: str, to: str, shares: int) -> None:
        if to == actor:
            return
        shares = min(shares, st.shares.get(actor, 0))
        if shares <= 0:
            return
        # Value the sender voluntarily gives away (measured at the current rate).
        value = self._convert_to_assets(st, shares)
        st.voluntary_out[actor] = st.voluntary_out.get(actor, 0) + value
        # ...and the value the recipient voluntarily receives is a gift, not profit.
        st.fair_gift[to] = st.fair_gift.get(to, 0) + value
        st.shares[actor] -= shares
        st.shares[to] = st.shares.get(to, 0) + shares

    def snapshot(self, st: WrapperState) -> dict[str, Any]:
        return {
            "total_atokens": st.total_atokens,
            "total_shares": st.total_shares,
            "shares": dict(st.shares),
            "redeemable": {a: self._redeemable(st, a) for a in ACTORS},
            "underlying": dict(st.underlying),
        }


class GuardedWrapper(WrapperTarget):
    """Same model with the ERC4626 virtual-shares/offset defence."""

    name = "wrapper-guarded"
    VIRTUAL_SHARES = DECIMALS
    VIRTUAL_ASSETS = 1
