"""Executable targets for the objective classes the engine *names* but could not
previously *run*.

The objectives engine (``blackheart/objectives``) generates goals such as
``oracle-manipulation``, ``replay-forgery``, and ``privilege-escalation`` for any
smart-contract profile, and the chain generator proposes sequences for them. But
the only executable targets were ERC4626-style accounting models, so those
classes could be *described* and never *broken*. This module closes that gap with
small, deterministic, local models for three further classes:

  * ``lending-oracle``      -- borrow against a manipulable spot price.
  * ``permit-replay``       -- a signed authorization that can be replayed.
  * ``proxy-initializer``   -- an initializer that can be called again.

Each class ships a **vulnerable** variant (the modelled attack succeeds, so the
stateful fuzzer finds a genuine invariant violation) and a **guarded** variant
(the attack is prevented, so the same invariants hold -- the non-vacuity control
the rest of the engine already relies on).

They are engine fixtures, not bounty targets: no network, no real funds, no
external system. Their only purpose is to let the fuzzer, the minimiser, the
reachability triage, and the verifier be exercised against attack classes beyond
share accounting.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .engine import InvariantSpec, OpSpec, Target

# --------------------------------------------------------------------------- #
# 1. Lending pool priced by a manipulable spot oracle
# --------------------------------------------------------------------------- #

REFERENCE_PRICE = 100          # cash per collateral unit at the true price
LTV_NUM, LTV_DEN = 3, 4        # 75% loan-to-value


@dataclass
class LendingState:
    cash: dict[str, int] = field(default_factory=dict)
    collateral: dict[str, int] = field(default_factory=dict)
    debt: dict[str, int] = field(default_factory=dict)
    initial: dict[str, int] = field(default_factory=dict)
    spot_price: int = REFERENCE_PRICE


class LendingPool(Target):
    """A lending market that values collateral at a manipulable spot price."""

    name = "lending-oracle"
    ACTORS = ["attacker", "victim"]

    def reset(self) -> LendingState:
        st = LendingState()
        st.cash = {"attacker": 1000, "victim": 1000}
        st.initial = dict(st.cash)
        st.collateral = {"attacker": 100, "victim": 100}
        st.debt = {"attacker": 0, "victim": 0}
        st.spot_price = REFERENCE_PRICE
        return st

    def ops(self) -> list[OpSpec]:
        return [
            OpSpec("deposit_collateral", self.ACTORS, {"amount": [1, 10, 50, 100]},
                   weight=3, description="lock collateral in the market"),
            OpSpec("borrow", self.ACTORS, {"amount": [1, 10, 7500, 100_000]},
                   weight=5, description="borrow cash against collateral valued at the spot price"),
            OpSpec("repay", self.ACTORS, {"amount": [1, 10, 100]},
                   weight=1, description="repay outstanding debt"),
            OpSpec("pump_price", ["attacker"], {"factor": [10, 100, 1000]},
                   weight=2, description="manipulate the spot oracle upward"),
            OpSpec("dump_price", ["attacker"], {"factor": [10, 100, 1000]},
                   weight=2, description="manipulate the spot oracle back down"),
            OpSpec("withdraw_collateral", self.ACTORS, {"amount": [1, 10, 50]},
                   weight=2, description="withdraw collateral that is not securing debt"),
        ]

    # -- the one line that differs between the vulnerable and guarded models -- #
    def _price(self, st: LendingState) -> int:
        return st.spot_price

    def _borrow_limit(self, st: LendingState, actor: str) -> int:
        return st.collateral.get(actor, 0) * self._price(st) * LTV_NUM // LTV_DEN

    def invariants(self) -> list[InvariantSpec]:
        return [
            InvariantSpec(
                "no-actor-over-borrows",
                "no actor's debt exceeds their collateral valued at the "
                "manipulation-resistant reference price times the LTV",
                self._solvent,
                severity_if_broken="critical",
            ),
        ]

    def _solvent(self, st: LendingState) -> bool:
        for a in self.ACTORS:
            limit = st.collateral.get(a, 0) * REFERENCE_PRICE * LTV_NUM // LTV_DEN
            if st.debt.get(a, 0) > limit:
                return False
        return True

    def step(self, st: LendingState, op: str, actor: str, params: dict[str, Any]) -> None:
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
                st.debt[actor] = st.debt.get(actor, 0) + amt
                st.cash[actor] = st.cash.get(actor, 0) + amt
        elif op == "repay":
            amt = min(int(params["amount"]), st.debt.get(actor, 0), st.cash.get(actor, 0))
            if amt <= 0:
                return
            st.cash[actor] -= amt
            st.debt[actor] -= amt
        elif op == "pump_price":
            st.spot_price *= int(params["factor"])
        elif op == "dump_price":
            st.spot_price = max(1, st.spot_price // int(params["factor"]))
        elif op == "withdraw_collateral":
            amt = min(int(params["amount"]), st.collateral.get(actor, 0))
            if amt <= 0:
                return
            # Only collateral not securing debt may leave, judged with the price
            # this variant trusts -- so the sole difference stays the oracle.
            st.collateral[actor] -= amt
            if st.debt.get(actor, 0) > self._borrow_limit(st, actor):
                st.collateral[actor] += amt  # revert: it was still securing debt
                return
            st.cash[actor] += amt

    def snapshot(self, st: LendingState) -> dict[str, Any]:
        return {
            "spot_price": st.spot_price,
            "reference_price": REFERENCE_PRICE,
            "collateral": dict(st.collateral),
            "debt": dict(st.debt),
            "cash": dict(st.cash),
        }


class GuardedLendingPool(LendingPool):
    """Same market, but debt is bounded by the manipulation-resistant price."""

    name = "lending-oracle-guarded"

    def _price(self, st: LendingState) -> int:
        return REFERENCE_PRICE


# --------------------------------------------------------------------------- #
# 2. Permit: a signed authorization that must be usable exactly once
# --------------------------------------------------------------------------- #

@dataclass
class PermitState:
    balances: dict[str, int] = field(default_factory=dict)
    allowance: dict[str, int] = field(default_factory=dict)   # victim -> attacker
    signed_value: int = 0                                     # last value the victim signed
    total_authorized: int = 0                                 # cumulative value ever signed
    spent: int = 0                                            # cumulative value drawn via permits
    consumed: bool = False                                    # guarded model only
    initial: dict[str, int] = field(default_factory=dict)


class PermitToken(Target):
    """An EIP-2612-style permit whose signature carries no single-use binding.

    A permit *sets* the allowance to the signed value (as EIP-2612 does). With no
    single-use binding, the attacker can submit the same signature again to
    re-arm the allowance after spending it, drawing more than the victim ever
    authorized -- the replay the ``authorization-used-once`` invariant catches.
    """

    name = "permit-replay"
    VICTIM, ATTACKER = "victim", "attacker"

    def reset(self) -> PermitState:
        st = PermitState()
        st.balances = {self.VICTIM: 1000, self.ATTACKER: 0}
        st.initial = dict(st.balances)
        st.allowance = {self.ATTACKER: 0}
        st.signed_value = 0
        st.total_authorized = 0
        st.spent = 0
        st.consumed = False
        return st

    def ops(self) -> list[OpSpec]:
        return [
            OpSpec("victim_sign", [self.VICTIM], {"value": [1, 10, 100, 1000]},
                   weight=3, description="the victim signs a permit authorizing an allowance"),
            OpSpec("replay_permit", [self.ATTACKER], {},
                   weight=4, description="submit the signed permit to the token"),
            OpSpec("transfer_from", [self.ATTACKER], {"amount": [1, 10, 100, 1000]},
                   weight=3, description="spend the granted allowance"),
        ]

    # -- the only difference between the models -- #
    def _apply_permit(self, st: PermitState) -> None:
        st.allowance[self.ATTACKER] = st.signed_value

    def invariants(self) -> list[InvariantSpec]:
        return [
            InvariantSpec(
                "authorization-used-once",
                "the cumulative value drawn through permits never exceeds the "
                "cumulative value the victim actually signed",
                self._used_once,
                severity_if_broken="high",
            ),
            InvariantSpec(
                "no-material-victim-loss",
                "the victim never loses more than the value they authorized",
                self._victim_bounded,
                severity_if_broken="high",
            ),
        ]

    def _used_once(self, st: PermitState) -> bool:
        return st.spent <= st.total_authorized

    def _victim_bounded(self, st: PermitState) -> bool:
        lost = st.initial[self.VICTIM] - st.balances.get(self.VICTIM, 0)
        return lost <= st.total_authorized

    def step(self, st: PermitState, op: str, actor: str, params: dict[str, Any]) -> None:
        if op == "victim_sign":
            st.signed_value = int(params["value"])
            st.total_authorized += st.signed_value
        elif op == "replay_permit":
            self._apply_permit(st)
        elif op == "transfer_from":
            amt = min(int(params["amount"]),
                      st.allowance.get(self.ATTACKER, 0),
                      st.balances.get(self.VICTIM, 0))
            if amt <= 0:
                return
            st.allowance[self.ATTACKER] -= amt
            st.balances[self.VICTIM] -= amt
            st.balances[self.ATTACKER] = st.balances.get(self.ATTACKER, 0) + amt
            st.spent += amt

    def snapshot(self, st: PermitState) -> dict[str, Any]:
        return {
            "balances": dict(st.balances),
            "allowance": dict(st.allowance),
            "signed_value": st.signed_value,
            "total_authorized": st.total_authorized,
            "spent": st.spent,
        }


class SafePermitToken(PermitToken):
    """Same token, but each signature is single-use (consumed on first submit)."""

    name = "permit-guarded"

    def _apply_permit(self, st: PermitState) -> None:
        if st.consumed:
            return
        st.allowance[self.ATTACKER] = st.signed_value
        st.consumed = True

    def step(self, st: PermitState, op: str, actor: str, params: dict[str, Any]) -> None:
        if op == "victim_sign":
            st.consumed = False  # a fresh signature re-arms the permit
        super().step(st, op, actor, params)


# --------------------------------------------------------------------------- #
# 3. Proxy vault with a re-callable initializer
# --------------------------------------------------------------------------- #

@dataclass
class ProxyState:
    owner: str = "owner"
    initialized: bool = False
    funds: int = 0
    wallet: dict[str, int] = field(default_factory=dict)
    initial: dict[str, int] = field(default_factory=dict)


class ProxyVault(Target):
    """An upgradeable vault whose ``initialize`` can be called more than once."""

    name = "proxy-initializer"
    DEPLOYER, ATTACKER = "owner", "attacker"

    def reset(self) -> ProxyState:
        st = ProxyState()
        st.owner = self.DEPLOYER
        st.initialized = False
        st.funds = 1000
        st.wallet = {self.DEPLOYER: 0, self.ATTACKER: 0}
        st.initial = dict(st.wallet)
        return st

    def ops(self) -> list[OpSpec]:
        return [
            OpSpec("initialize", [self.DEPLOYER, self.ATTACKER], {},
                   weight=3, description="initialize the vault (sets the owner)"),
            OpSpec("sweep", [self.DEPLOYER, self.ATTACKER], {"amount": [100, 500, 1000]},
                   weight=3, description="owner-only: transfer vault funds out"),
        ]

    # -- the only difference between the models -- #
    def _initialize(self, st: ProxyState, actor: str) -> None:
        st.owner = actor
        st.initialized = True

    def invariants(self) -> list[InvariantSpec]:
        return [
            InvariantSpec(
                "no-material-attacker-profit",
                "an actor who was never the legitimate deployer never gains vault funds",
                self._no_attacker_profit,
                severity_if_broken="critical",
            ),
        ]

    def _no_attacker_profit(self, st: ProxyState) -> bool:
        return st.wallet.get(self.ATTACKER, 0) <= st.initial.get(self.ATTACKER, 0)

    def step(self, st: ProxyState, op: str, actor: str, params: dict[str, Any]) -> None:
        if op == "initialize":
            self._initialize(st, actor)
        elif op == "sweep":
            if actor != st.owner:
                return
            amt = min(int(params["amount"]), st.funds)
            if amt <= 0:
                return
            st.funds -= amt
            st.wallet[actor] = st.wallet.get(actor, 0) + amt

    def snapshot(self, st: ProxyState) -> dict[str, Any]:
        return {"owner": st.owner, "initialized": st.initialized,
                "funds": st.funds, "wallet": dict(st.wallet)}


class GuardedProxyVault(ProxyVault):
    """Same vault, but ``initialize`` runs once and only for the deployer."""

    name = "proxy-guarded"

    def _initialize(self, st: ProxyState, actor: str) -> None:
        if st.initialized or actor != self.DEPLOYER:
            return
        st.owner = actor
        st.initialized = True
