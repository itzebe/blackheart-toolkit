"""Blind holdout cases for the historical-rediscovery benchmark (mission 3.A).

These cases are kept in a **separate module** from the development corpus
(:mod:`blackheart.discovery.corpus`) so the headline recall number is not a
tuned-on result. They use mechanisms that do not appear in the development
corpus, and the discovery engine has never been adjusted against them.

They follow the same contract as the corpus: a vulnerable model and a patched
model that differ by exactly the defence, both implementing the same invariant.
Nothing here executes anything or contacts a network; these are local, in-memory
models.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..invariants.engine import InvariantSpec, OpSpec, PureState, Target
from .corpus import HistoricalCase


# H-H1. Double refund -- a refund path with no single-use binding on the order.

@dataclass
class RefundState:
    escrow: dict[str, int] = field(default_factory=dict)
    refunded: dict[str, int] = field(default_factory=dict)
    refund_count: int = 0


class DoubleRefundMarket(PureState, Target):
    name = "heldout-double-refund-vulnerable"
    ATTACKER = "attacker"

    def reset(self) -> RefundState:
        return RefundState(escrow={self.ATTACKER: 100})

    def ops(self) -> list[OpSpec]:
        return [OpSpec("cancel", [self.ATTACKER], {}, weight=5)]

    def invariants(self) -> list[InvariantSpec]:
        return [InvariantSpec("single-refund",
                              "an order is refunded at most once",
                              lambda st: st.refund_count <= 1,
                              severity_if_broken="high")]

    def step(self, st: RefundState, op: str, actor: str, params: dict[str, Any]) -> None:
        if op == "cancel":
            amt = st.escrow.get(actor, 0)
            if amt:
                # Vulnerable: escrow is credited back but never cleared.
                st.refunded[actor] = st.refunded.get(actor, 0) + amt
                st.refund_count += 1


class SingleRefundMarket(DoubleRefundMarket):
    name = "heldout-double-refund-patched"

    def step(self, st: RefundState, op: str, actor: str, params: dict[str, Any]) -> None:
        if op == "cancel":
            amt = st.escrow.get(actor, 0)
            if amt:
                st.escrow[actor] = 0          # Patched: clear escrow -> single use.
                st.refunded[actor] = st.refunded.get(actor, 0) + amt
                st.refund_count += 1


# H-H2. Stale privilege -- a session captures the role at open and honours it
#       after the user is demoted.

@dataclass
class StalePrivState:
    role: dict[str, str] = field(default_factory=dict)
    session_role: dict[str, str] = field(default_factory=dict)
    session_open: dict[str, bool] = field(default_factory=dict)
    unauthorized_ops: int = 0


class StalePrivilegeSession(PureState, Target):
    name = "heldout-stale-privilege-vulnerable"
    ATTACKER, ADMIN = "attacker", "admin"

    def reset(self) -> StalePrivState:
        # The attacker legitimately starts as an admin, then is demoted.
        return StalePrivState(role={self.ATTACKER: "admin", self.ADMIN: "admin"})

    def ops(self) -> list[OpSpec]:
        return [
            OpSpec("open_session", [self.ATTACKER], {}, weight=3),
            OpSpec("demote", [self.ADMIN], {}, weight=3),
            OpSpec("privileged_action", [self.ATTACKER], {}, weight=5),
        ]

    def invariants(self) -> list[InvariantSpec]:
        return [InvariantSpec("no-stale-privilege",
                              "a demoted user cannot perform a privileged action",
                              lambda st: st.unauthorized_ops == 0,
                              severity_if_broken="high")]

    def step(self, st: StalePrivState, op: str, actor: str, params: dict[str, Any]) -> None:
        if op == "open_session":
            st.session_open[actor] = True
            st.session_role[actor] = st.role.get(actor, "user")
        elif op == "demote":
            st.role[self.ATTACKER] = "user"
        elif op == "privileged_action":
            # Vulnerable: authorizes from the role captured at session open.
            if st.session_role.get(actor) == "admin" and st.role.get(actor) != "admin":
                st.unauthorized_ops += 1


class StalePrivilegeSessionGuarded(StalePrivilegeSession):
    name = "heldout-stale-privilege-patched"

    def step(self, st: StalePrivState, op: str, actor: str, params: dict[str, Any]) -> None:
        if op == "open_session":
            st.session_open[actor] = True
            st.session_role[actor] = st.role.get(actor, "user")
        elif op == "demote":
            st.role[self.ATTACKER] = "user"
        elif op == "privileged_action":
            # Patched: authorizes from the *current* role, so a demoted user is
            # denied and no unauthorized action can occur.
            if st.role.get(actor) != "admin":
                pass


# H-H3. Stale cache after a slash -- a withdrawal settles against a cached total
#       the system already invalidated.

@dataclass
class DesyncState:
    real: int = 100            # the authoritative asset total
    cache: int = 100           # a derived cache the vulnerable path trusts
    over_withdrawals: int = 0  # withdrawals that paid more than the real assets


class DesyncLedger(PureState, Target):
    name = "heldout-desync-ledger-vulnerable"
    ATTACKER = "attacker"

    def reset(self) -> DesyncState:
        return DesyncState()

    def ops(self) -> list[OpSpec]:
        return [
            OpSpec("slash", [self.ATTACKER], {}, weight=3),
            OpSpec("withdraw", [self.ATTACKER], {}, weight=5),
        ]

    def invariants(self) -> list[InvariantSpec]:
        return [InvariantSpec("no-stale-withdraw",
                              "a withdrawal never exceeds the real assets",
                              lambda st: st.over_withdrawals == 0,
                              severity_if_broken="high")]

    def step(self, st: DesyncState, op: str, actor: str, params: dict[str, Any]) -> None:
        if op == "slash":
            st.real = 50              # Vulnerable: the cache is left stale.
        elif op == "withdraw" and st.cache:
            if st.cache > st.real:
                st.over_withdrawals += 1
            st.cache = 0


class DesyncLedgerGuarded(DesyncLedger):
    name = "heldout-desync-ledger-patched"

    def step(self, st: DesyncState, op: str, actor: str, params: dict[str, Any]) -> None:
        if op == "slash":
            st.real = 50
            st.cache = st.real        # Patched: the cache is refreshed on the slash.
        elif op == "withdraw" and st.cache:
            st.cache = 0


# H-H4. Rounding direction -- a redeem rounds up, so repeated redemptions extract
#       more than the vault's assets.

@dataclass
class RoundingState:
    total_shares: int = 3
    total_assets: int = 10
    my_shares: int = 3
    withdrawn: int = 0


class RoundUpRedeem(PureState, Target):
    name = "heldout-round-up-vulnerable"
    ATTACKER = "attacker"

    def reset(self) -> RoundingState:
        return RoundingState()

    def ops(self) -> list[OpSpec]:
        return [OpSpec("redeem_one", [self.ATTACKER], {}, weight=5)]

    def invariants(self) -> list[InvariantSpec]:
        return [InvariantSpec("no-over-redeem",
                              "redeemed assets never exceed the vault's assets",
                              lambda st: st.withdrawn <= 10,
                              severity_if_broken="high")]

    def step(self, st: RoundingState, op: str, actor: str, params: dict[str, Any]) -> None:
        if op == "redeem_one" and st.my_shares > 0:
            # Vulnerable: rounds up -- 10/3 -> 4 per share, 3 times = 12 > 10.
            payout = -(-st.total_assets // st.total_shares)
            st.withdrawn += payout
            st.my_shares -= 1


class RoundDownRedeem(RoundUpRedeem):
    name = "heldout-round-down-patched"

    def step(self, st: RoundingState, op: str, actor: str, params: dict[str, Any]) -> None:
        if op == "redeem_one" and st.my_shares > 0:
            payout = st.total_assets // st.total_shares   # Patched: round down -> 3.
            st.withdrawn += payout
            st.my_shares -= 1


# H-H5. Missing deadline -- a signed order can be executed after it should have
#       expired, so a stale price is honoured.

@dataclass
class DeadlineState:
    now: int = 50
    order_expiry: int = 90
    expired_executions: int = 0


class NoDeadlineOrder(PureState, Target):
    name = "heldout-no-deadline-vulnerable"
    ATTACKER = "attacker"

    def reset(self) -> DeadlineState:
        return DeadlineState()

    def ops(self) -> list[OpSpec]:
        return [OpSpec("advance_time", [self.ATTACKER], {}, weight=2),
                OpSpec("execute_order", [self.ATTACKER], {}, weight=5)]

    def invariants(self) -> list[InvariantSpec]:
        return [InvariantSpec("deadline-respected",
                              "an expired order is never executed",
                              lambda st: st.expired_executions == 0,
                              severity_if_broken="high")]

    def step(self, st: DeadlineState, op: str, actor: str, params: dict[str, Any]) -> None:
        if op == "advance_time":
            st.now += 100
        elif op == "execute_order":
            # Vulnerable: never checks the deadline, so an order past its expiry
            # is still executed.
            if st.now > st.order_expiry:
                st.expired_executions += 1


class DeadlineOrder(NoDeadlineOrder):
    name = "heldout-deadline-patched"

    def step(self, st: DeadlineState, op: str, actor: str, params: dict[str, Any]) -> None:
        if op == "advance_time":
            st.now += 100
        elif op == "execute_order":
            if st.now <= st.order_expiry:   # Patched: an expired order is rejected.
                pass


# H-H6. Reward double-claim -- a claim does not clear the accrual, so the same
#       reward is paid twice.

@dataclass
class RewardState:
    accrued: int = 50
    claimed: int = 0


class DoubleClaimRewards(PureState, Target):
    name = "heldout-double-claim-vulnerable"
    ATTACKER = "attacker"

    def reset(self) -> RewardState:
        return RewardState()

    def ops(self) -> list[OpSpec]:
        return [OpSpec("claim", [self.ATTACKER], {}, weight=5)]

    def invariants(self) -> list[InvariantSpec]:
        return [InvariantSpec("no-double-claim",
                              "rewards are claimed at most once",
                              lambda st: st.claimed <= 50,
                              severity_if_broken="high")]

    def step(self, st: RewardState, op: str, actor: str, params: dict[str, Any]) -> None:
        if op == "claim" and st.accrued:
            st.claimed += st.accrued        # Vulnerable: accrual is not cleared.


class SingleClaimRewards(DoubleClaimRewards):
    name = "heldout-single-claim-patched"

    def step(self, st: RewardState, op: str, actor: str, params: dict[str, Any]) -> None:
        if op == "claim" and st.accrued:
            st.claimed += st.accrued
            st.accrued = 0                  # Patched: clear on claim.


def holdout_cases() -> list[HistoricalCase]:
    return [
        HistoricalCase(
            case_id="HH1-double-refund",
            title="Order refunded twice (no single-use binding)",
            protocol="Order-book refund class",
            root_cause="logic-error",
            year=2022, loss_usd=None,
            invariant_statement="an order is refunded at most once",
            attacker_outcome="receive the same refund more than once",
            reference="Workflow idempotency class",
            advisory="double-refund class",
            vulnerable=DoubleRefundMarket, patched=SingleRefundMarket,
            holdout=True),
        HistoricalCase(
            case_id="HH2-stale-privilege",
            title="Demoted user keeps a session privilege (stale authorization)",
            protocol="Session/authorization class",
            root_cause="state-staleness",
            year=2022, loss_usd=None,
            invariant_statement="a demoted user cannot perform a privileged action",
            attacker_outcome="retain a privilege after it is revoked",
            reference="OWASP session-fixation / stale-authz class",
            advisory="stale-authorization class",
            vulnerable=StalePrivilegeSession, patched=StalePrivilegeSessionGuarded,
            holdout=True),
        HistoricalCase(
            case_id="HH3-stale-cache-slash",
            title="Withdrawal settles against a cache invalidated by a slash",
            protocol="Vault/cache class",
            root_cause="state-staleness",
            year=2021, loss_usd=None,
            invariant_statement="a withdrawal never exceeds the real assets",
            attacker_outcome="withdraw against a cache the system already invalidated",
            reference="Compound governance / cache class",
            advisory="stale-cache class",
            vulnerable=DesyncLedger, patched=DesyncLedgerGuarded,
            holdout=True),
        HistoricalCase(
            case_id="HH4-round-up-redeem",
            title="Redeem rounds up, so repeated redemptions over-extract",
            protocol="Vault accounting class",
            root_cause="accounting-rounding",
            year=2022, loss_usd=None,
            invariant_statement="redeemed assets never exceed the vault's assets",
            attacker_outcome="extract more assets than the shares are worth",
            reference="OpenZeppelin ERC4626 rounding notes; EIP-4626",
            advisory="EIP-4626 rounding-direction class",
            vulnerable=RoundUpRedeem, patched=RoundDownRedeem,
            holdout=True),
        HistoricalCase(
            case_id="HH5-expired-order",
            title="Signed order executed after its deadline (missing expiry)",
            protocol="Order-settlement class",
            root_cause="missing-deadline",
            year=2022, loss_usd=None,
            invariant_statement="an expired order is never executed",
            attacker_outcome="execute a stale order at a favourable old price",
            reference="Uniswap/Seaport deadline class",
            advisory="missing-deadline class",
            vulnerable=NoDeadlineOrder, patched=DeadlineOrder,
            holdout=True),
        HistoricalCase(
            case_id="HH6-double-claim",
            title="Reward claimed twice (accrual not cleared)",
            protocol="Staking rewards class",
            root_cause="logic-error",
            year=2021, loss_usd=None,
            invariant_statement="rewards are claimed at most once",
            attacker_outcome="receive the same reward more than once",
            reference="Synthetix/Compound reward-accounting class",
            advisory="double-claim class",
            vulnerable=DoubleClaimRewards, patched=SingleClaimRewards,
            holdout=True),
    ]
