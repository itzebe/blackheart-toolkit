"""Executable models for attack classes that only exist *between* contracts.

The engine's other fixtures model one contract with several operations. That is
enough for share accounting, an oracle, a re-entrant withdraw, and every other
single-contract class -- but it cannot express a class whose whole point is the
boundary between two components:

  * ``cross-contract``     -- a protocol that trusts a price a *second* contract
    it does not control reports, so an attacker who controls that second
    contract moves the first one's collateral valuation.
  * ``cross-protocol-trust`` -- a vault that trusts a strategy contract's
    self-reported holdings, so a dishonest strategy inflates the vault's
    accounting without a matching asset.

Both ship a **vulnerable** and a **guarded** variant that differ in exactly one
place: whether the consumer re-derives the value itself or trusts the report.
That single difference is what makes the pair a real control -- a guarded twin
that differs in more than one method proves nothing about the guard.

Why a separate module instead of another entry in ``defi_targets``: these are the
first targets whose state is *two* contracts, and they carry a ``SystemModel``
that names the trust boundary explicitly (``add_trust_boundary``), so a
hypothesis generated from the model can point at the boundary it crosses rather
than at a function name. Keeping them apart makes the two-contract structure
visible to a reader instead of buried among the single-contract fixtures.

They are engine fixtures: no network, no real funds, no external system.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .engine import InvariantSpec, OpSpec, PureState, Target


# --------------------------------------------------------------------------- #
# 1. A lending market that trusts an external oracle contract's report
# --------------------------------------------------------------------------- #

@dataclass
class OracleConsumerState:
    """Two contracts in one state: the market, and the oracle it consults.

    Naming both halves here -- rather than hiding the oracle behind a scalar --
    is what lets a sequence move the oracle and observe the market react.
    """

    # -- contract A: the lending market ---------------------------------- #
    cash: dict[str, int] = field(default_factory=dict)
    collateral: dict[str, int] = field(default_factory=dict)
    debt: dict[str, int] = field(default_factory=dict)
    initial: dict[str, int] = field(default_factory=dict)
    pool_liquidity: int = 0        # LPs' cash available to lend
    # -- contract B: the oracle the market trusts ------------------------ #
    oracle_price: int = 0
    oracle_updates: int = 0


REFERENCE_PRICE = 100          # true value of one collateral unit, in cash
LTV_NUM, LTV_DEN = 3, 4        # the market lends up to 75% of *true* value


class TrustingMarket(PureState, Target):
    """A market that values collateral at whatever its oracle contract reports.

    The oracle is a second contract. In this variant the market trusts the
    report verbatim, so an attacker who can move the oracle moves the market's
    collateral valuation -- and can borrow against value that does not exist.
    """

    name = "cross-contract-oracle-trust"
    ATTACKER, VICTIM = "attacker", "victim"
    ACTORS = [ATTACKER, VICTIM]

    def reset(self) -> OracleConsumerState:
        st = OracleConsumerState()
        # The market is funded by LPs, so an attacker can borrow real cash
        # without needing a cooperating victim. Only the attacker acts; every
        # violation is therefore attributable to one unprivileged actor.
        st.cash = {self.ATTACKER: 1000}
        st.initial = dict(st.cash)
        st.collateral = {self.ATTACKER: 100}
        st.debt = {self.ATTACKER: 0}
        st.pool_liquidity = 100_000
        st.oracle_price = REFERENCE_PRICE
        st.oracle_updates = 0
        return st

    def ops(self) -> list[OpSpec]:
        return [
            OpSpec("deposit_collateral", [self.ATTACKER], {"amount": [10, 50, 100]},
                   weight=2, description="lock collateral in the market"),
            OpSpec("borrow", [self.ATTACKER], {"amount": [10, 100, 225, 7500]},
                   weight=5,
                   description="borrow cash against collateral the oracle prices"),
            OpSpec("repay", [self.ATTACKER], {"amount": [10, 100]},
                   weight=1, description="repay outstanding debt"),
            # The attack surface: the oracle is a *separate* contract the
            # attacker can push, and the market reads it on the next borrow.
            OpSpec("manipulate_oracle", [self.ATTACKER], {"factor": [10, 100, 1000]},
                   weight=3,
                   description="move the external oracle contract's reported price"),
            OpSpec("restore_oracle", [self.ATTACKER], {},
                   weight=1, description="return the oracle to its reference price"),
        ]

    # -- the only difference between the vulnerable and guarded models -- #
    def _trusted_price(self, st: OracleConsumerState) -> int:
        """Vulnerable: the market believes the oracle contract verbatim."""
        return st.oracle_price

    def _borrow_limit(self, st: OracleConsumerState, actor: str) -> int:
        return st.collateral.get(actor, 0) * self._trusted_price(st) * LTV_NUM // LTV_DEN

    def invariants(self) -> list[InvariantSpec]:
        return [
            InvariantSpec(
                "no-borrow-above-true-collateral-value",
                "no actor borrows more than their collateral is worth at the "
                "manipulation-resistant reference price times the LTV",
                self._within_true_limit,
                severity_if_broken="critical",
            ),
        ]

    def model(self):
        from ..statespace.model import SystemModel

        m = SystemModel(
            target=self.name,
            summary="A lending market (contract A) values collateral at a price "
                    "reported by an external oracle contract (contract B) it does "
                    "not control; the valuation must not follow a manipulated report.",
            assets=["collateral", "cash"],
            trust_boundaries=["lending market (A) <-> external oracle contract (B)"],
            dependencies=["oracle-contract"],
            evidence=["fixture:blackheart/invariants/multicontract_targets.py"
                      "#TrustingMarket"],
        )
        m.add_actor(self.ATTACKER, roles=("user", "oracle-controller"),
                    unprivileged=True,
                    note="ordinary borrower that also controls contract B, the "
                         "external oracle whose report the market trusts")
        m.add_actor(self.VICTIM, roles=("liquidity-provider",), unprivileged=False,
                    note="supplies the market's lendable cash; does not act in "
                         "the attack sequence")
        m.add_operation("deposit_collateral", ("user",), sensitive=False,
                        effect="lock collateral", source="fixture")
        m.add_operation("borrow", ("user",), sensitive=True, asset="collateral",
                        precondition="debt within the collateral limit",
                        effect="move cash to the borrower",
                        guard="collateral valued at a manipulation-resistant price",
                        guard_roles=("user",), source="fixture")
        m.add_operation("manipulate_oracle", ("oracle-controller",), sensitive=True,
                        asset="collateral",
                        effect="change the price the external contract reports",
                        source="fixture")
        m.add_invariant("no-borrow-above-true-collateral-value",
                        "a borrower never owes more than their collateral is "
                        "truly worth times the LTV",
                        applies_to=("collateral",),
                        expression="no-borrow-above-true-collateral-value",
                        severity_if_broken="critical")
        m.intended_behaviours = []
        return m

    def _within_true_limit(self, st: OracleConsumerState) -> bool:
        """The attacker never owes more than their collateral is truly worth."""
        a = self.ATTACKER
        limit = st.collateral.get(a, 0) * REFERENCE_PRICE * LTV_NUM // LTV_DEN
        return st.debt.get(a, 0) <= limit

    def step(self, st: OracleConsumerState, op: str, actor: str,
             params: dict[str, Any]) -> None:
        if op == "deposit_collateral":
            amt = min(int(params["amount"]), st.cash.get(actor, 0))
            if amt <= 0:
                return
            st.cash[actor] -= amt
            st.collateral[actor] = st.collateral.get(actor, 0) + amt
        elif op == "borrow":
            amt = int(params["amount"])
            if amt <= 0:
                return
            if st.debt.get(actor, 0) + amt <= self._borrow_limit(st, actor):
                if amt > st.pool_liquidity:
                    return
                st.pool_liquidity -= amt
                st.debt[actor] = st.debt.get(actor, 0) + amt
                st.cash[actor] = st.cash.get(actor, 0) + amt
        elif op == "repay":
            amt = min(int(params["amount"]), st.debt.get(actor, 0),
                      st.cash.get(actor, 0))
            if amt <= 0:
                return
            st.cash[actor] -= amt
            st.debt[actor] -= amt
            st.pool_liquidity += amt
        elif op == "manipulate_oracle":
            st.oracle_price *= int(params["factor"])
            st.oracle_updates += 1
        elif op == "restore_oracle":
            st.oracle_price = REFERENCE_PRICE
            st.oracle_updates += 1

    def snapshot(self, st: OracleConsumerState) -> dict[str, Any]:
        return {
            "oracle_price": st.oracle_price,
            "reference_price": REFERENCE_PRICE,
            "cash": dict(st.cash),
            "collateral": dict(st.collateral),
            "debt": dict(st.debt),
            "pool_liquidity": st.pool_liquidity,
            "oracle_updates": st.oracle_updates,
        }


class GuardedTrustingMarket(TrustingMarket):
    """Same market, but it re-derives value instead of trusting the oracle report.

    A manipulation-resistant consumer does not use a spot report as the sole
    valuation: it applies its own bound (here, the reference price the market
    itself tracks). The attacker can still move the oracle, but the borrow limit
    no longer follows it.
    """

    name = "cross-contract-oracle-guarded"

    def _trusted_price(self, st: OracleConsumerState) -> int:
        # The guard: never value collateral above the market's own reference
        # price, whatever the external contract reports.
        return min(st.oracle_price, REFERENCE_PRICE)


# --------------------------------------------------------------------------- #
# 2. A vault that trusts a strategy contract's self-reported holdings
# --------------------------------------------------------------------------- #

@dataclass
class StrategyTrustState:
    """A vault (contract A) and the strategy it delegates to (contract B)."""

    # -- contract A: the vault ------------------------------------------- #
    shares: dict[str, int] = field(default_factory=dict)
    vault_idle: int = 0
    initial_wallet: dict[str, int] = field(default_factory=dict)
    wallet: dict[str, int] = field(default_factory=dict)
    # -- contract B: the strategy the vault delegates to ----------------- #
    strategy_real_assets: int = 0
    strategy_reported_assets: int = 0


class StrategyVault(PureState, Target):
    """A vault that redeems against the strategy's self-reported asset total.

    The strategy is a second contract. In this variant the vault trusts
    ``strategy_reported_assets`` when pricing a redemption, so an attacker who
    controls the strategy can inflate the report and redeem shares for more
    underlying than the strategy actually holds.
    """

    name = "cross-protocol-strategy-trust"
    ATTACKER, VICTIM = "attacker", "victim"
    ACTORS = [ATTACKER, VICTIM]

    def reset(self) -> StrategyTrustState:
        st = StrategyTrustState()
        st.wallet = {self.ATTACKER: 1000, self.VICTIM: 1000}
        st.initial_wallet = dict(st.wallet)
        # The vault already holds other depositors' funds: the victim's 10,000
        # shares represent pre-existing TVL sitting in the strategy. Without it
        # the attacker could only ever recover their own capital, and the
        # inflation would have nothing to steal from.
        st.shares = {self.ATTACKER: 0, self.VICTIM: 10_000}
        st.vault_idle = 0
        st.strategy_real_assets = 10_000
        st.strategy_reported_assets = 10_000
        return st

    def ops(self) -> list[OpSpec]:
        return [
            OpSpec("deposit", [self.ATTACKER], {"amount": [100, 500, 1000]},
                   weight=3, description="deposit underlying for vault shares"),
            OpSpec("redeem", [self.ATTACKER], {"amount": [100, 500, 1000]},
                   weight=4, description="redeem shares for underlying"),
            # The attack surface: the strategy is a separate contract whose
            # self-report the vault believes.
            OpSpec("inflate_report", [self.ATTACKER],
                   {"amount": [100, 1000, 10000]}, weight=3,
                   description="inflate the strategy contract's reported assets"),
        ]

    # -- the only difference between the vulnerable and guarded models -- #
    def _pricing_assets(self, st: StrategyTrustState) -> int:
        """Vulnerable: price shares off the strategy's self-reported total."""
        return st.strategy_reported_assets

    def invariants(self) -> list[InvariantSpec]:
        return [
            InvariantSpec(
                "redemption-backed-by-real-assets",
                "underlying paid out never exceeds what the strategy actually holds",
                self._solvent,
                severity_if_broken="critical",
            ),
        ]

    def model(self):
        from ..statespace.model import SystemModel

        m = SystemModel(
            target=self.name,
            summary="A vault (contract A) prices share redemptions off the asset "
                    "total a strategy contract (contract B) reports about itself; "
                    "the payout must follow the assets the strategy really holds.",
            assets=["wallet", "shares"],
            trust_boundaries=["vault (A) <-> strategy contract (B)"],
            dependencies=["strategy-contract"],
            evidence=["fixture:blackheart/invariants/multicontract_targets.py"
                      "#StrategyVault"],
        )
        m.add_actor(self.ATTACKER, roles=("user", "strategy-controller"),
                    unprivileged=True,
                    note="ordinary depositor that also controls contract B, the "
                         "strategy whose self-report the vault trusts")
        m.add_actor(self.VICTIM, roles=("user",), unprivileged=True)
        m.add_operation("deposit", ("user",), sensitive=False,
                        effect="deposit underlying for shares", source="fixture")
        m.add_operation("redeem", ("user",), sensitive=True, asset="wallet",
                        precondition="the vault holds enough underlying",
                        effect="pay underlying for shares",
                        guard="shares priced off real assets, not a self-report",
                        guard_roles=("user",), source="fixture")
        m.add_operation("inflate_report", ("strategy-controller",), sensitive=True,
                        asset="wallet",
                        effect="inflate the strategy contract's reported assets",
                        source="fixture")
        m.add_invariant("redemption-backed-by-real-assets",
                        "underlying paid out never exceeds what the strategy holds",
                        applies_to=("wallet",),
                        expression="redemption-backed-by-real-assets",
                        severity_if_broken="critical")
        m.intended_behaviours = []
        return m

    def _solvent(self, st: StrategyTrustState) -> bool:
        return st.wallet.get(self.ATTACKER, 0) <= st.initial_wallet.get(
            self.ATTACKER, 0)

    def step(self, st: StrategyTrustState, op: str, actor: str,
             params: dict[str, Any]) -> None:
        if op == "deposit":
            amt = min(int(params["amount"]), st.wallet.get(actor, 0))
            if amt <= 0:
                return
            st.wallet[actor] -= amt
            # Deposits are forwarded to the strategy, so real assets grow.
            st.strategy_real_assets += amt
            st.strategy_reported_assets += amt
            st.shares[actor] = st.shares.get(actor, 0) + amt
        elif op == "redeem":
            shares = min(int(params["amount"]), st.shares.get(actor, 0))
            if shares <= 0:
                return
            total_shares = sum(st.shares.values())
            if total_shares <= 0:
                return
            priced = self._pricing_assets(st)
            payout = shares * priced // total_shares
            payout = min(payout, st.strategy_real_assets)
            st.shares[actor] -= shares
            st.strategy_real_assets -= payout
            st.strategy_reported_assets -= payout
            st.wallet[actor] = st.wallet.get(actor, 0) + payout
        elif op == "inflate_report":
            st.strategy_reported_assets += int(params["amount"])

    def snapshot(self, st: StrategyTrustState) -> dict[str, Any]:
        return {
            "wallet": dict(st.wallet),
            "shares": dict(st.shares),
            "strategy_real_assets": st.strategy_real_assets,
            "strategy_reported_assets": st.strategy_reported_assets,
            "vault_idle": st.vault_idle,
        }


class GuardedStrategyVault(StrategyVault):
    """Same vault, but it prices redemptions off the strategy's *real* assets."""

    name = "cross-protocol-strategy-guarded"

    def _pricing_assets(self, st: StrategyTrustState) -> int:
        # The guard: ignore the self-report, read the assets the strategy holds.
        return st.strategy_real_assets


__all__ = [
    "TrustingMarket",
    "GuardedTrustingMarket",
    "StrategyVault",
    "GuardedStrategyVault",
]
