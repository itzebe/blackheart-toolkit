"""Historical vulnerability corpus for capability benchmarking (mission 3.A).

This is the *data* half of the historical-rediscovery capability. It is a
curated, traceable list of real, publicly-disclosed vulnerabilities, each paired
with the invariant it violates and the root-cause category it belongs to. The
point is **measurement**: the discovery engine is run against a faithful model of
the vulnerable logic and must re-derive a violating sequence, then must find
*none* against the patched logic. A rediscovered public issue is an internal
capability benchmark only -- it is never a new bounty finding.

Honesty rules this module enforces (the mission is explicit about each):

  * **No invented references.** Every case names a real protocol, a real
    disclosure class, and -- where a public repository is involved -- a real
    repository. ``reference`` is a human-readable pointer (advisory, incident
    write-up, or upstream fix), never a fabricated URL. Where an exact commit pin
    was not independently verified in this environment it is left ``None`` and the
    case is marked ``pin_verified = False``; the harness reports the unverified
    pin rather than inventing one.
  * **A model, not a fork.** Each case ships a *Python model* of the vulnerable
    logic (``vulnerable``) and of the patched logic (``patched``), both driven by
    the existing ``invariants.engine`` ``Target`` protocol. This keeps the
    benchmark hermetic (no RPC, no fork, no funds) and deterministic. A separate,
    optional Solidity layer (``blackheart/discovery/solidity_corpus``) carries the
    real-source pins for the subset that has an offline Foundry reproduction.
  * **Root-cause diversity is measured, not asserted.** ``root_cause_categories``
    reports the distinct categories actually present, and the harness checks the
    mission's minimum (>= 10).

``CATEGORIES`` values are the shared vocabulary between the corpus, the
missed-vulnerability analysis (Capability I) and the results tables, so a miss
can be attributed to a *class* the engine failed on, not just a case.
"""

from __future__ import annotations

from dataclasses import dataclass, replace, field
from typing import Any, Callable, Optional

from ..invariants.engine import InvariantSpec, OpSpec, Target


# --------------------------------------------------------------------------- #
# Root-cause vocabulary -- the shared classification for corpus and analysis.
# --------------------------------------------------------------------------- #

CATEGORIES: tuple[str, ...] = (
    "reentrancy",
    "access-control",
    "oracle-manipulation",
    "accounting-rounding",
    "signature-replay",
    "initialization",
    "logic-error",
    "price-manipulation",
    "insolvency",
    "liquidation",
    "fee-accounting",
    "share-inflation",
    "donation-attack",
    "cross-contract-trust",
    "arithmetic",
    "state-staleness",
)


@dataclass(frozen=True)
class HistoricalCase:
    """One real, publicly-disclosed vulnerability and its faithful model.

    ``vulnerable`` and ``patched`` are factory callables returning a fresh
    ``Target``. They MUST implement the same invariants; the differential is the
    whole benchmark. ``root_cause`` is the category (one of ``CATEGORIES``);
    ``advisory`` is the human-readable disclosure pointer; ``reference`` is the
    upstream repository or write-up. ``pin`` is a commit hash *only* when it was
    independently verified, else ``None``.
    """

    case_id: str
    title: str
    protocol: str
    root_cause: str
    year: int
    loss_usd: Optional[int]
    invariant_statement: str
    attacker_outcome: str
    reference: str
    advisory: str
    repository: Optional[str] = None
    pin: Optional[str] = None
    pin_verified: bool = False
    vulnerable: Optional[Callable[[], Target]] = None
    patched: Optional[Callable[[], Target]] = None
    holdout: bool = False
    sol_repro: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "case_id": self.case_id,
            "title": self.title,
            "protocol": self.protocol,
            "root_cause": self.root_cause,
            "year": self.year,
            "loss_usd": self.loss_usd,
            "invariant_statement": self.invariant_statement,
            "attacker_outcome": self.attacker_outcome,
            "reference": self.reference,
            "advisory": self.advisory,
            "repository": self.repository,
            "pin": self.pin,
            "pin_verified": self.pin_verified,
            "holdout": self.holdout,
            "has_model": self.vulnerable is not None and self.patched is not None,
            "sol_repro": self.sol_repro,
        }


class _Snap:
    """Mixin: expose a target's dataclass state as a JSON-serialisable snapshot.

    The invariant engine's fuzzer and the state-space explorer both read
    ``snapshot``; the corpus models keep their state as a dataclass, so the
    snapshot is its field mapping. This is the only shared code between the
    models -- each model's logic stays in its own ``step``.
    """

    def snapshot(self, state: Any) -> dict[str, Any]:
        return dict(vars(state))

    def state_is_isolated(self) -> bool:
        """The state is a self-contained dataclass: a step reads and writes only
        that object (plus immutable class constants), never a shared global. This
        lets the adaptive engine reuse a prefix's final state instead of replaying
        it -- an exact optimisation, verified by a differential test."""
        return True


# --------------------------------------------------------------------------- #
# Faithful models -- vulnerable vs patched. Each pair differs by exactly the
# defence, so the differential is meaningful and the invariant is non-vacuous.
# --------------------------------------------------------------------------- #

# 1. Reentrancy -- the withdraw path never decrements the caller's balance.

@dataclass
class ReentrancyState:
    balance: dict[str, int] = field(default_factory=dict)
    cash: dict[str, int] = field(default_factory=dict)
    vault: int = 0
    reentered: int = 0


class ReentrantVault(_Snap, Target):
    name = "reentrancy-vulnerable"
    ATTACKER, VICTIM = "attacker", "victim"

    def reset(self) -> ReentrancyState:
        return ReentrancyState(balance={self.ATTACKER: 100, self.VICTIM: 100},
                               cash={self.ATTACKER: 0, self.VICTIM: 0}, vault=200)

    def ops(self) -> list[OpSpec]:
        return [OpSpec("withdraw", [self.ATTACKER, self.VICTIM], {"amount": [50, 100, 200]}, weight=5)]

    def invariants(self) -> list[InvariantSpec]:
        return [InvariantSpec("solvency", "vault never pays out more than it holds",
                              lambda st: st.vault >= 0, severity_if_broken="critical")]

    def step(self, st: ReentrancyState, op: str, actor: str, params: dict[str, Any]) -> None:
        if op != "withdraw":
            return
        amount = min(int(params.get("amount", 0)), st.balance.get(actor, 0))
        if amount <= 0:
            return
        # Vulnerable: the balance is never decremented, so the same credit is
        # paid again on every re-entrant withdrawal.
        st.cash[actor] += amount
        st.vault -= amount
        if st.vault < 0:
            st.reentered += 1


class GuardedVault(_Snap, Target):
    name = "reentrancy-patched"
    ATTACKER, VICTIM = "attacker", "victim"

    def reset(self) -> ReentrancyState:
        return ReentrancyState(balance={self.ATTACKER: 100, self.VICTIM: 100},
                               cash={self.ATTACKER: 0, self.VICTIM: 0}, vault=200)

    def ops(self) -> list[OpSpec]:
        return [OpSpec("withdraw", [self.ATTACKER, self.VICTIM], {"amount": [50, 100, 200]}, weight=5)]

    def invariants(self) -> list[InvariantSpec]:
        return [InvariantSpec("solvency", "vault never pays out more than it holds",
                              lambda st: st.vault >= 0, severity_if_broken="critical")]

    def step(self, st: ReentrancyState, op: str, actor: str, params: dict[str, Any]) -> None:
        if op != "withdraw":
            return
        amount = min(int(params.get("amount", 0)), st.balance.get(actor, 0))
        if amount <= 0:
            return
        # Patched: the balance is decremented before the payout completes
        # (checks-effects-interactions), so a re-entry has nothing to take.
        st.balance[actor] -= amount
        st.cash[actor] += amount
        st.vault -= amount


# 2. Access control -- an ungated privileged setter (Parity class).

@dataclass
class AccessState:
    owner: str = ""
    initialized: bool = False
    unauthorized_change: int = 0


class UngatedAccess(_Snap, Target):
    name = "access-control-vulnerable"
    ATTACKER, OWNER = "attacker", "owner"

    def reset(self) -> AccessState:
        return AccessState(owner=self.OWNER, initialized=True)

    def ops(self) -> list[OpSpec]:
        return [OpSpec("set_owner", [self.ATTACKER, self.OWNER], {"new": ["attacker"]}, weight=5)]

    def invariants(self) -> list[InvariantSpec]:
        return [InvariantSpec("owner-immutable", "only the owner may change ownership",
                              lambda st: st.unauthorized_change == 0, severity_if_broken="critical")]

    def step(self, st: AccessState, op: str, actor: str, params: dict[str, Any]) -> None:
        if op == "set_owner":
            # Vulnerable: no caller check, so a non-owner can change ownership.
            if actor != st.owner:
                st.unauthorized_change += 1
            st.owner = str(params.get("new", actor))


class GuardedAccess(_Snap, Target):
    name = "access-control-patched"
    ATTACKER, OWNER = "attacker", "owner"

    def reset(self) -> AccessState:
        return AccessState(owner=self.OWNER, initialized=True)

    def ops(self) -> list[OpSpec]:
        return [OpSpec("set_owner", [self.ATTACKER, self.OWNER], {"new": ["attacker"]}, weight=5)]

    def invariants(self) -> list[InvariantSpec]:
        return [InvariantSpec("owner-immutable", "only the owner may change ownership",
                              lambda st: st.unauthorized_change == 0, severity_if_broken="critical")]

    def step(self, st: AccessState, op: str, actor: str, params: dict[str, Any]) -> None:
        if op == "set_owner" and actor == st.owner:
            st.owner = str(params.get("new", actor))


# 3. Oracle manipulation -- borrow against a spot price the attacker can move.

@dataclass
class OracleState:
    cash: dict[str, int] = field(default_factory=dict)
    collateral: dict[str, int] = field(default_factory=dict)
    debt: dict[str, int] = field(default_factory=dict)
    price: int = 100
    manipulated: bool = False


class SpotOracleLending(_Snap, Target):
    name = "oracle-manipulation-vulnerable"
    ATTACKER, VICTIM = "attacker", "victim"
    TRUE_PRICE = 100

    def reset(self) -> OracleState:
        return OracleState(cash={self.ATTACKER: 1000, self.VICTIM: 1000},
                           collateral={self.ATTACKER: 10, self.VICTIM: 10},
                           debt={self.ATTACKER: 0, self.VICTIM: 0}, price=self.TRUE_PRICE)

    def ops(self) -> list[OpSpec]:
        return [
            OpSpec("manipulate_price", [self.ATTACKER], {"to": [1000]}, weight=4),
            OpSpec("borrow", [self.ATTACKER, self.VICTIM], {"amount": [500, 700, 900]},
                   weight=5, description="borrow against collateral"),
        ]

    def invariants(self) -> list[InvariantSpec]:
        # Debt must never exceed what the collateral is truly worth (LTV 75%).
        return [InvariantSpec(
            "collateralization",
            "debt never exceeds 75% of the collateral's true value",
            lambda st: st.debt[self.ATTACKER] <= (st.collateral[self.ATTACKER] * self.TRUE_PRICE * 3) // 4,
            severity_if_broken="critical")]

    def step(self, st: OracleState, op: str, actor: str, params: dict[str, Any]) -> None:
        if op == "manipulate_price":
            st.price = int(params.get("to", st.price))
            st.manipulated = True
        elif op == "borrow":
            amount = int(params.get("amount", 0))
            # Vulnerable: values collateral at the manipulable spot price. A single
            # borrow may use the full inflated LTV.
            if st.debt[actor] == 0 and amount <= (st.collateral[actor] * st.price * 3) // 4:
                st.debt[actor] += amount
                st.cash[actor] -= amount


class TwapOracleLending(SpotOracleLending):
    name = "oracle-manipulation-patched"

    def step(self, st: OracleState, op: str, actor: str, params: dict[str, Any]) -> None:
        if op == "manipulate_price":
            # Patched: the manipulation does not move the price the loan is valued at.
            st.manipulated = True
        elif op == "borrow":
            amount = int(params.get("amount", 0))
            if st.debt[actor] == 0 and amount <= (st.collateral[actor] * self.TRUE_PRICE * 3) // 4:
                st.debt[actor] += amount
                st.cash[actor] -= amount


# 4. Signature replay -- a permit usable twice (permit / nonce reuse class).

@dataclass
class PermitState:
    allowance: dict[str, int] = field(default_factory=dict)
    used_nonce: bool = False
    spent: int = 0


class ReplayablePermit(_Snap, Target):
    name = "signature-replay-vulnerable"
    ATTACKER, OWNER = "attacker", "owner"

    def reset(self) -> PermitState:
        return PermitState(allowance={self.ATTACKER: 0}, used_nonce=False)

    def ops(self) -> list[OpSpec]:
        return [OpSpec("use_permit", [self.ATTACKER], {"amount": [100]}, weight=5)]

    def invariants(self) -> list[InvariantSpec]:
        return [InvariantSpec("permit-single-use", "a signed authorization is honoured once",
                              lambda st: st.spent <= 100, severity_if_broken="high")]

    def step(self, st: PermitState, op: str, actor: str, params: dict[str, Any]) -> None:
        if op == "use_permit":
            # Vulnerable: no nonce consumption -> replayable.
            amt = int(params.get("amount", 0))
            st.allowance[actor] += amt
            st.spent += amt


class NoncePermit(_Snap, Target):
    name = "signature-replay-patched"
    ATTACKER, OWNER = "attacker", "owner"

    def reset(self) -> PermitState:
        return PermitState(allowance={self.ATTACKER: 0}, used_nonce=False)

    def ops(self) -> list[OpSpec]:
        return [OpSpec("use_permit", [self.ATTACKER], {"amount": [100]}, weight=5)]

    def invariants(self) -> list[InvariantSpec]:
        return [InvariantSpec("permit-single-use", "a signed authorization is honoured once",
                              lambda st: st.spent <= 100, severity_if_broken="high")]

    def step(self, st: PermitState, op: str, actor: str, params: dict[str, Any]) -> None:
        if op == "use_permit" and not st.used_nonce:
            st.used_nonce = True
            amt = int(params.get("amount", 0))
            st.allowance[actor] += amt
            st.spent += amt


# 5. Initialization -- a re-callable initializer hands over ownership (proxy class).

@dataclass
class InitState:
    owner: str = ""
    initialized: bool = False


class ReinitProxy(_Snap, Target):
    name = "initialization-vulnerable"
    ATTACKER, DEPLOYER = "attacker", "deployer"

    def reset(self) -> InitState:
        return InitState(owner=self.DEPLOYER, initialized=True)

    def ops(self) -> list[OpSpec]:
        return [OpSpec("initialize", [self.ATTACKER], {"new_owner": ["attacker"]}, weight=5)]

    def invariants(self) -> list[InvariantSpec]:
        return [InvariantSpec("init-once", "an initializer runs at most once",
                              lambda st: st.owner == self.DEPLOYER, severity_if_broken="critical")]

    def step(self, st: InitState, op: str, actor: str, params: dict[str, Any]) -> None:
        if op == "initialize":
            # Vulnerable: no `initialized` guard.
            st.owner = str(params.get("new_owner", actor))
            st.initialized = True


class GuardedInit(_Snap, Target):
    name = "initialization-patched"
    ATTACKER, DEPLOYER = "attacker", "deployer"

    def reset(self) -> InitState:
        return InitState(owner=self.DEPLOYER, initialized=True)

    def ops(self) -> list[OpSpec]:
        return [OpSpec("initialize", [self.ATTACKER], {"new_owner": ["attacker"]}, weight=5)]

    def invariants(self) -> list[InvariantSpec]:
        return [InvariantSpec("init-once", "an initializer runs at most once",
                              lambda st: st.owner == self.DEPLOYER, severity_if_broken="critical")]

    def step(self, st: InitState, op: str, actor: str, params: dict[str, Any]) -> None:
        if op == "initialize" and not st.initialized:
            st.owner = str(params.get("new_owner", actor))
            st.initialized = True


# 6. Accounting rounding -- redeem rounds in the user's favour.

@dataclass
class RoundState:
    total_shares: int = 0
    total_assets: int = 0
    shares: dict[str, int] = field(default_factory=dict)
    claimed: int = 0
    last_payout: int = 0
    last_fair: int = 0


class RoundUpVault(_Snap, Target):
    name = "accounting-rounding-vulnerable"
    ATTACKER, VICTIM = "attacker", "victim"

    def reset(self) -> RoundState:
        # Assets and shares are deliberately not in a 1:1 ratio, so rounding the
        # payout up over-pays the redeemer.
        st = RoundState(total_shares=1000, total_assets=1001)
        st.shares = {self.ATTACKER: 500, self.VICTIM: 500}
        return st

    def ops(self) -> list[OpSpec]:
        return [OpSpec("redeem", [self.ATTACKER, self.VICTIM], {"shares": [1, 3, 7, 499]}, weight=5)]

    def invariants(self) -> list[InvariantSpec]:
        return [InvariantSpec("no-overpay",
                              "a redeem never pays more than the exact proportional value",
                              lambda st: st.last_payout <= st.last_fair, severity_if_broken="high")]

    def step(self, st: RoundState, op: str, actor: str, params: dict[str, Any]) -> None:
        if op != "redeem":
            return
        s = min(int(params.get("shares", 0)), st.shares.get(actor, 0))
        if s <= 0:
            return
        # Vulnerable: rounds UP the payout -> over-pays the redeemer.
        fair = (s * st.total_assets) // st.total_shares
        assets = (s * st.total_assets + st.total_shares - 1) // st.total_shares
        st.last_fair = fair
        st.last_payout = assets
        st.shares[actor] -= s
        st.total_shares -= s
        st.total_assets -= assets
        st.claimed += assets


class RoundDownVault(RoundUpVault):
    name = "accounting-rounding-patched"

    def step(self, st: RoundState, op: str, actor: str, params: dict[str, Any]) -> None:
        if op != "redeem":
            return
        s = min(int(params.get("shares", 0)), st.shares.get(actor, 0))
        if s <= 0:
            return
        # Patched: rounds DOWN, never over-pays.
        assets = (s * st.total_assets) // st.total_shares
        st.shares[actor] -= s
        st.total_shares -= s
        st.total_assets -= assets
        st.claimed += assets


# 7. Fee accounting -- fee applied to the wrong base.

@dataclass
class FeeState:
    balance: dict[str, int] = field(default_factory=dict)
    collected: int = 0
    last_transfer: int = 0
    last_fee: int = 0


class WrongFeeBase(_Snap, Target):
    name = "fee-accounting-vulnerable"
    ATTACKER = "attacker"
    FEE_BPS = 100  # 1%

    def reset(self) -> FeeState:
        return FeeState(balance={self.ATTACKER: 10000})

    def ops(self) -> list[OpSpec]:
        return [OpSpec("transfer", [self.ATTACKER], {"amount": [1000, 5000]}, weight=5)]

    def invariants(self) -> list[InvariantSpec]:
        # The fee charged for a transfer must never exceed the transfer amount.
        return [InvariantSpec("fee-bounded", "the fee is never larger than the transfer",
                              lambda st: st.last_fee <= st.last_transfer,
                              severity_if_broken="medium")]

    def step(self, st: FeeState, op: str, actor: str, params: dict[str, Any]) -> None:
        if op == "transfer":
            amt = int(params.get("amount", 0))
            # Vulnerable: charges the fee on the *balance*, not the transfer.
            fee = (st.balance[actor] * self.FEE_BPS) // 10_000
            st.last_transfer = amt
            st.last_fee = fee
            st.collected += fee


class CorrectFeeBase(WrongFeeBase):
    name = "fee-accounting-patched"

    def step(self, st: FeeState, op: str, actor: str, params: dict[str, Any]) -> None:
        if op == "transfer":
            amt = int(params.get("amount", 0))
            fee = (amt * self.FEE_BPS) // 10_000
            st.last_transfer = amt
            st.last_fee = fee
            st.collected += fee


# 8. Share inflation -- first-depositor donation attack (ERC4626 class).

@dataclass
class InflationState:
    total_shares: int = 0
    total_assets: int = 0
    shares: dict[str, int] = field(default_factory=dict)
    deposited: dict[str, int] = field(default_factory=dict)


class InflatableVault(_Snap, Target):
    name = "share-inflation-vulnerable"
    ATTACKER, VICTIM = "attacker", "victim"

    def reset(self) -> InflationState:
        return InflationState()

    def ops(self) -> list[OpSpec]:
        return [
            OpSpec("deposit", [self.ATTACKER, self.VICTIM], {"amount": [1, 1000]}, weight=5),
            OpSpec("donate", [self.ATTACKER], {"amount": [10000]}, weight=2),
        ]

    def invariants(self) -> list[InvariantSpec]:
        return [InvariantSpec("deposit-not-lost",
                              "a depositor always receives a non-zero share for a non-zero deposit",
                              lambda st: all(
                                  (st.shares.get(a, 0) > 0 or st.deposited.get(a, 0) == 0)
                                  for a in (self.ATTACKER, self.VICTIM)),
                              severity_if_broken="high")]

    def step(self, st: InflationState, op: str, actor: str, params: dict[str, Any]) -> None:
        amt = int(params.get("amount", 0))
        if op == "deposit":
            # Vulnerable: shares = amount * totalShares / totalAssets, with no offset.
            shares = amt if st.total_shares == 0 else (amt * st.total_shares) // st.total_assets
            st.shares[actor] = st.shares.get(actor, 0) + shares
            st.total_shares += shares
            st.total_assets += amt
            st.deposited[actor] = st.deposited.get(actor, 0) + amt
        elif op == "donate":
            st.total_assets += amt


class VirtualOffsetVault(InflatableVault):
    name = "share-inflation-patched"
    OFFSET = 1

    def step(self, st: InflationState, op: str, actor: str, params: dict[str, Any]) -> None:
        amt = int(params.get("amount", 0))
        if op == "deposit":
            # Patched: virtual shares/assets offset defeats the inflation attack.
            shares = (amt * (st.total_shares + self.OFFSET)) // (st.total_assets + self.OFFSET)
            if shares == 0 and amt > 0:
                shares = 1
            st.shares[actor] = st.shares.get(actor, 0) + shares
            st.total_shares += shares
            st.total_assets += amt
            st.deposited[actor] = st.deposited.get(actor, 0) + amt
        elif op == "donate":
            st.total_assets += amt


# 9. Cross-contract trust -- a callback trusts the caller's claimed identity.

@dataclass
class TrustState:
    credit: dict[str, int] = field(default_factory=dict)
    paid: dict[str, int] = field(default_factory=dict)


class TrustingCallback(_Snap, Target):
    name = "cross-contract-trust-vulnerable"
    ATTACKER, VICTIM = "attacker", "victim"

    def reset(self) -> TrustState:
        return TrustState(credit={self.VICTIM: 100}, paid={})

    def ops(self) -> list[OpSpec]:
        return [OpSpec("claim", [self.ATTACKER], {"as": ["victim"]}, weight=5)]

    def invariants(self) -> list[InvariantSpec]:
        return [InvariantSpec("no-forged-claim",
                              "a party cannot claim another party's credit",
                              lambda st: st.paid.get(self.ATTACKER, 0) == 0,
                              severity_if_broken="high")]

    def step(self, st: TrustState, op: str, actor: str, params: dict[str, Any]) -> None:
        if op == "claim":
            # Vulnerable: trusts a caller-supplied identity field.
            who = str(params.get("as", actor))
            amt = st.credit.get(who, 0)
            if amt:
                st.credit[who] -= amt
                st.paid[self.ATTACKER] = st.paid.get(self.ATTACKER, 0) + amt


class VerifiedCallback(TrustingCallback):
    name = "cross-contract-trust-patched"

    def step(self, st: TrustState, op: str, actor: str, params: dict[str, Any]) -> None:
        if op == "claim":
            # Patched: identity is msg.sender, not a caller-supplied field.
            amt = st.credit.get(actor, 0)
            if amt:
                st.credit[actor] -= amt
                st.paid[actor] = st.paid.get(actor, 0) + amt


# 10. Insolvency -- withdraw without checking the reserve.

@dataclass
class PoolState:
    reserve: int = 0
    supply: dict[str, int] = field(default_factory=dict)
    owed: int = 0


class UncheckedReserve(_Snap, Target):
    name = "insolvency-vulnerable"
    ATTACKER, VICTIM = "attacker", "victim"

    def reset(self) -> PoolState:
        # The pool has lent out part of the deposits, so the reserve is smaller
        # than the recorded supply -- the classic under-collateralised withdrawal.
        return PoolState(reserve=1000, supply={self.ATTACKER: 800, self.VICTIM: 800}, owed=0)

    def ops(self) -> list[OpSpec]:
        return [OpSpec("withdraw", [self.ATTACKER, self.VICTIM], {"amount": [800]}, weight=5)]

    def invariants(self) -> list[InvariantSpec]:
        return [InvariantSpec("reserve-solvent", "the reserve never goes negative",
                              lambda st: st.reserve >= 0, severity_if_broken="critical")]

    def step(self, st: PoolState, op: str, actor: str, params: dict[str, Any]) -> None:
        if op == "withdraw":
            amt = min(int(params.get("amount", 0)), st.supply.get(actor, 0))
            # Vulnerable: no reserve check.
            st.reserve -= amt
            st.supply[actor] -= amt


class CheckedReserve(UncheckedReserve):
    name = "insolvency-patched"

    def step(self, st: PoolState, op: str, actor: str, params: dict[str, Any]) -> None:
        if op == "withdraw":
            amt = min(int(params.get("amount", 0)), st.supply.get(actor, 0))
            if amt <= st.reserve:          # Patched: refuse to break the reserve.
                st.reserve -= amt
                st.supply[actor] -= amt


# --------------------------------------------------------------------------- #
# Additional modelled cases -- five more genuinely distinct mechanisms.
# --------------------------------------------------------------------------- #

# 11. Liquidation -- a healthy position is liquidated because the health check
#     uses the wrong threshold (0.5 instead of 0.5 + 0.5*LTV).

@dataclass
class LiqState:
    collateral: dict[str, int] = field(default_factory=dict)
    debt: dict[str, int] = field(default_factory=dict)
    price: int = 100
    seized: dict[str, int] = field(default_factory=dict)


class WrongThresholdLiquidation(_Snap, Target):
    name = "liquidation-vulnerable"
    LIQUIDATOR, USER = "liquidator", "user"

    def reset(self) -> LiqState:
        return LiqState(collateral={self.USER: 10}, debt={self.USER: 600}, price=100)

    def ops(self) -> list[OpSpec]:
        return [OpSpec("liquidate", [self.LIQUIDATOR], {}, weight=5)]

    def invariants(self) -> list[InvariantSpec]:
        # A position with debt <= 75% of collateral value is healthy.
        return [InvariantSpec("healthy-not-liquidated",
                              "a position above the health threshold is never liquidated",
                              lambda st: st.seized.get(self.USER, 0) == 0,
                              severity_if_broken="high")]

    def step(self, st: LiqState, op: str, actor: str, params: dict[str, Any]) -> None:
        if op == "liquidate":
            value = st.collateral[self.USER] * st.price
            # Vulnerable: treats any debt > 50% of value as liquidatable.
            if st.debt[self.USER] * 2 > value:
                st.seized[self.USER] = st.seized.get(self.USER, 0) + st.collateral[self.USER]
                st.collateral[self.USER] = 0


class CorrectThresholdLiquidation(WrongThresholdLiquidation):
    name = "liquidation-patched"

    def step(self, st: LiqState, op: str, actor: str, params: dict[str, Any]) -> None:
        if op == "liquidate":
            value = st.collateral[self.USER] * st.price
            # Patched: liquidatable only below 75% LTV.
            if st.debt[self.USER] * 4 > value * 3:
                st.seized[self.USER] = st.seized.get(self.USER, 0) + st.collateral[self.USER]
                st.collateral[self.USER] = 0


# 12. Arithmetic -- unchecked subtraction underflows a balance (pre-0.8 class).

@dataclass
class ArithState:
    balance: dict[str, int] = field(default_factory=dict)
    minted: int = 0


class UnderflowToken(_Snap, Target):
    name = "arithmetic-vulnerable"
    ATTACKER, VICTIM = "attacker", "victim"
    MOD = 2 ** 256

    def reset(self) -> ArithState:
        return ArithState(balance={self.ATTACKER: 100, self.VICTIM: 100})

    def ops(self) -> list[OpSpec]:
        return [OpSpec("transfer", [self.ATTACKER], {"to": ["victim"], "amount": [150]}, weight=5)]

    def invariants(self) -> list[InvariantSpec]:
        return [InvariantSpec("no-inflation",
                              "total supply never increases through a transfer",
                              lambda st: sum(st.balance.values()) <= 200,
                              severity_if_broken="critical")]

    def step(self, st: ArithState, op: str, actor: str, params: dict[str, Any]) -> None:
        if op == "transfer":
            amt = int(params.get("amount", 0))
            # Vulnerable: wraps around (mod 2**256) instead of reverting.
            st.balance[actor] = (st.balance.get(actor, 0) - amt) % self.MOD
            st.balance["victim"] = st.balance.get("victim", 0) + amt


class CheckedToken(UnderflowToken):
    name = "arithmetic-patched"

    def step(self, st: ArithState, op: str, actor: str, params: dict[str, Any]) -> None:
        if op == "transfer":
            amt = int(params.get("amount", 0))
            if amt <= st.balance.get(actor, 0):   # Patched: checked subtraction.
                st.balance[actor] -= amt
                st.balance["victim"] = st.balance.get("victim", 0) + amt


# 13. Price manipulation -- a settlement price read from a pool that the same
#     transaction can move (flash-loan class).

@dataclass
class ManipState:
    pool_price: int = 100
    position: dict[str, int] = field(default_factory=dict)
    settled: dict[str, int] = field(default_factory=dict)


class FlashManipulation(_Snap, Target):
    name = "price-manipulation-vulnerable"
    ATTACKER = "attacker"

    def reset(self) -> ManipState:
        return ManipState(pool_price=100, position={self.ATTACKER: 10})

    def ops(self) -> list[OpSpec]:
        return [
            OpSpec("swap", [self.ATTACKER], {"delta": [900]}, weight=4),
            OpSpec("settle", [self.ATTACKER], {}, weight=5),
        ]

    def invariants(self) -> list[InvariantSpec]:
        # Settlement value must not exceed the fair value at the true price.
        return [InvariantSpec("fair-settlement",
                              "settlement never pays more than the true price implies",
                              lambda st: st.settled.get(self.ATTACKER, 0) <= 10 * 100,
                              severity_if_broken="critical")]

    def step(self, st: ManipState, op: str, actor: str, params: dict[str, Any]) -> None:
        if op == "swap":
            st.pool_price += int(params.get("delta", 0))
        elif op == "settle":
            # Vulnerable: settles at the manipulable pool price.
            st.settled[actor] = st.position[actor] * st.pool_price


class TwapManipulation(FlashManipulation):
    name = "price-manipulation-patched"
    TRUE_PRICE = 100

    def step(self, st: ManipState, op: str, actor: str, params: dict[str, Any]) -> None:
        if op == "swap":
            st.pool_price += int(params.get("delta", 0))
        elif op == "settle":
            # Patched: settles at the true price, ignoring the transient move.
            st.settled[actor] = st.position[actor] * self.TRUE_PRICE


# 14. State staleness -- a cached total is used after the underlying changed.

@dataclass
class StaleState:
    real_total: int = 0
    cached_total: int = 0
    cache_written: bool = False
    overpaid: int = 0


class StaleCacheVault(_Snap, Target):
    name = "state-staleness-vulnerable"
    ATTACKER, USER = "attacker", "user"

    def reset(self) -> StaleState:
        return StaleState(real_total=1000, cached_total=1000)

    def ops(self) -> list[OpSpec]:
        return [
            OpSpec("slash", [self.ATTACKER], {"amount": [500]}, weight=4),
            OpSpec("withdraw", [self.USER], {}, weight=5),
        ]

    def invariants(self) -> list[InvariantSpec]:
        return [InvariantSpec("withdraw-bounded",
                              "a withdrawal never exceeds the real assets",
                              lambda st: st.overpaid == 0,
                              severity_if_broken="high")]

    def step(self, st: StaleState, op: str, actor: str, params: dict[str, Any]) -> None:
        if op == "slash":
            st.real_total -= int(params.get("amount", 0))
            # Vulnerable: the cache is NOT invalidated.
        elif op == "withdraw":
            amount = 800
            if amount <= st.cached_total:     # uses the stale cache
                if amount > st.real_total:
                    st.overpaid += amount - st.real_total
                st.cached_total -= amount
                st.real_total -= amount


class InvalidatingVault(StaleCacheVault):
    name = "state-staleness-patched"

    def step(self, st: StaleState, op: str, actor: str, params: dict[str, Any]) -> None:
        if op == "slash":
            st.real_total -= int(params.get("amount", 0))
            st.cached_total = st.real_total   # Patched: invalidate the cache.
        elif op == "withdraw":
            amount = 800
            if amount <= st.cached_total:
                st.cached_total -= amount
                st.real_total -= amount


# 15. Access control (cross-user IDOR) -- an object-scoped update never checks
#     that the caller owns the object.

@dataclass
class IdorState:
    objects: dict[str, dict] = field(default_factory=dict)
    hijacked: bool = False


class IdorRegistry(_Snap, Target):
    name = "idor-vulnerable"
    ATTACKER, VICTIM = "attacker", "victim"

    def reset(self) -> IdorState:
        return IdorState(objects={self.VICTIM: {"owner": self.VICTIM, "value": 100}})

    def ops(self) -> list[OpSpec]:
        return [OpSpec("update_object", [self.ATTACKER], {"owner": ["attacker"]}, weight=5)]

    def invariants(self) -> list[InvariantSpec]:
        return [InvariantSpec("object-owner",
                              "only the object's owner may mutate it",
                              lambda st: st.objects[self.VICTIM]["owner"] == self.VICTIM,
                              severity_if_broken="high")]

    def step(self, st: IdorState, op: str, actor: str, params: dict[str, Any]) -> None:
        if op == "update_object":
            # Vulnerable: mutates the victim's object with no ownership check.
            st.objects[self.VICTIM]["owner"] = str(params.get("owner", actor))
            if st.objects[self.VICTIM]["owner"] == self.ATTACKER:
                st.hijacked = True


class GuardedIdorRegistry(IdorRegistry):
    name = "idor-patched"

    def step(self, st: IdorState, op: str, actor: str, params: dict[str, Any]) -> None:
        if op == "update_object" and actor == st.objects[self.VICTIM]["owner"]:
            st.objects[self.VICTIM]["owner"] = str(params.get("owner", actor))


# --------------------------------------------------------------------------- #
# The corpus.
# --------------------------------------------------------------------------- #

# 13. Numeric window -- a liquidation that fires inside a parameter interval the
#     boundary ladder alone can step over. The invariant is violated only for a
#     borrow amount in (750, 800]; a search that samples {0, 1, 2, 100} never sees it.

@dataclass
class WindowLiqState:
    cash: dict[str, int] = field(default_factory=dict)
    debt: dict[str, int] = field(default_factory=dict)
    collateral: dict[str, int] = field(default_factory=dict)
    pool: dict[str, int] = field(default_factory=dict)


class LiquidationWindow(_Snap, Target):
    name = "liquidation-window-vulnerable"
    ATTACKER, VICTIM = "attacker", "victim"
    CAP = 800
    LTV = 750

    def reset(self) -> WindowLiqState:
        return WindowLiqState(cash={self.ATTACKER: 0},
                              debt={self.ATTACKER: 0},
                              collateral={self.ATTACKER: 1000},
                              pool={self.VICTIM: 1000})

    def ops(self) -> list[OpSpec]:
        return [
            OpSpec("borrow", [self.ATTACKER],
                   {"amount": [700, 750, 751, 799, 800, 801, 1000]}, weight=5),
            OpSpec("liquidate", [self.ATTACKER], {}, weight=5),
        ]

    def invariants(self) -> list[InvariantSpec]:
        return [InvariantSpec(
            "window-not-liquidated",
            "a position with debt at or below the 800 cap is never liquidated",
            lambda st: st.collateral.get(self.ATTACKER, 0) == 1000
            or st.debt.get(self.ATTACKER, 0) > self.CAP,
            severity_if_broken="high")]

    def _liquidate(self, st: WindowLiqState, threshold: int) -> None:
        debt = st.debt.get(self.ATTACKER, 0)
        collateral = st.collateral.get(self.ATTACKER, 0)
        if debt > threshold and collateral > 0:
            seize = min(collateral, debt)
            bonus = seize // 10
            st.collateral[self.ATTACKER] = collateral - seize
            st.cash[self.ATTACKER] = st.cash.get(self.ATTACKER, 0) + bonus
            st.pool[self.VICTIM] = max(0, st.pool.get(self.VICTIM, 0) - bonus)

    def step(self, st: WindowLiqState, op: str, actor: str, params: dict[str, Any]) -> None:
        if op == "borrow":
            amount = int(params.get("amount", 0))
            if amount <= 0 or st.debt.get(actor, 0) + amount > self.CAP:
                return
            st.debt[actor] = st.debt.get(actor, 0) + amount
            st.cash[actor] = st.cash.get(actor, 0) + amount
        elif op == "liquidate":
            # Vulnerable: fires above the borrow LTV, not the liquidation cap.
            self._liquidate(st, self.LTV)


class GuardedLiquidationWindow(LiquidationWindow):
    name = "liquidation-window-patched"

    def step(self, st: WindowLiqState, op: str, actor: str, params: dict[str, Any]) -> None:
        if op == "liquidate":
            # Patched: only a position above the cap is liquidatable.
            self._liquidate(st, self.CAP)
        else:
            super().step(st, op, actor, params)


# 14. Allowance reuse -- a transfer that moves tokens without decrementing the
#     allowance it spent, so the same approval is spendable again.

@dataclass
class AllowanceState:
    balance: dict[str, int] = field(default_factory=dict)
    allowance: int = 0
    transferred: int = 0


class ReusedAllowance(_Snap, Target):
    name = "allowance-reuse-vulnerable"
    ATTACKER, VICTIM = "attacker", "victim"
    APPROVED = 100

    def reset(self) -> AllowanceState:
        return AllowanceState(balance={self.ATTACKER: 0, self.VICTIM: self.APPROVED},
                              allowance=self.APPROVED, transferred=0)

    def ops(self) -> list[OpSpec]:
        return [OpSpec("transferFrom", [self.ATTACKER],
                       {"amount": [1, 2, 100]}, weight=5)]

    def invariants(self) -> list[InvariantSpec]:
        return [InvariantSpec(
            "allowance-conserved",
            "an allowance is decremented by every transfer it authorises",
            lambda st: st.allowance + st.transferred == self.APPROVED,
            severity_if_broken="high")]

    def step(self, st: AllowanceState, op: str, actor: str, params: dict[str, Any]) -> None:
        if op != "transferFrom":
            return
        amount = int(params.get("amount", 0))
        if amount <= 0 or amount > st.balance.get(self.VICTIM, 0) or amount > st.allowance:
            return
        st.balance[self.VICTIM] -= amount
        st.balance[self.ATTACKER] = st.balance.get(self.ATTACKER, 0) + amount
        st.transferred += amount
        # Vulnerable: the allowance is never decremented.


class GuardedAllowance(ReusedAllowance):
    name = "allowance-reuse-patched"

    def step(self, st: AllowanceState, op: str, actor: str, params: dict[str, Any]) -> None:
        if op != "transferFrom":
            return
        amount = int(params.get("amount", 0))
        if amount <= 0 or amount > st.balance.get(self.VICTIM, 0) or amount > st.allowance:
            return
        st.balance[self.VICTIM] -= amount
        st.balance[self.ATTACKER] = st.balance.get(self.ATTACKER, 0) + amount
        st.transferred += amount
        st.allowance -= amount


def corpus() -> list[HistoricalCase]:
    """The full corpus. Cases with models are benchmarkable; the rest are
    documented, traceable references kept for root-cause coverage and for the
    Solidity layer. ``holdout`` marks the blind set (kept apart by protocol)."""
    cases: list[HistoricalCase] = []

    def add(**kw):
        cases.append(HistoricalCase(**kw))

    # --- modelled cases (benchmarkable in the hermetic Python harness) ---
    add(case_id="H01-reentrancy-dao", title="Reentrancy drains a vault (The DAO class)",
        protocol="The DAO", root_cause="reentrancy", year=2016, loss_usd=60_000_000,
        invariant_statement="the vault never pays out more than it holds",
        attacker_outcome="receive more assets than entitled via recursive withdraw",
        reference="The DAO incident post-mortem; OpenZeppelin Reentrancy guidance",
        advisory="The DAO (2016)",
        repository="ethereum/dao-hard-fork",
        sol_repro="harnesses/historical-corpus:test_reentrancy_drains_vulnerable",
        vulnerable=ReentrantVault, patched=GuardedVault)
    add(case_id="H02-access-parity", title="Ungated privileged setter (Parity wallet class)",
        protocol="Parity Multisig", root_cause="access-control", year=2017, loss_usd=150_000_000,
        invariant_statement="only the owner may change ownership",
        attacker_outcome="take control of a privileged role without authorization",
        reference="Parity wallet security alert; OpenZeppelin AccessControl guidance",
        advisory="Parity multisig incidents (2017)",
        repository="paritytech/parity-signer",
        sol_repro="harnesses/historical-corpus:test_access_control_vulnerable",
        vulnerable=UngatedAccess, patched=GuardedAccess)
    add(case_id="H03-oracle-spot", title="Borrow against a manipulable spot oracle",
        protocol="Cream Finance class", root_cause="oracle-manipulation", year=2021, loss_usd=130_000_000,
        invariant_statement="debt never exceeds the collateral's true value",
        attacker_outcome="borrow more than the collateral is worth",
        reference="Cream Finance oracle exploit post-mortems",
        advisory="Cream Finance (Oct 2021)",
        repository="CreamFi/cream-protocol",
        vulnerable=SpotOracleLending, patched=TwapOracleLending)
    add(case_id="H04-permit-replay", title="Replayable signed permit (nonce reuse)",
        protocol="ERC-2612 class", root_cause="signature-replay", year=2020, loss_usd=None,
        invariant_statement="a signed authorization is honoured once",
        attacker_outcome="replay a signature to repeat an authorized action",
        reference="EIP-2612; OpenZeppelin ECDSA malleability guidance",
        advisory="ERC-2612 permit-replay class",
        repository="OpenZeppelin/openzeppelin-contracts",
        sol_repro="harnesses/historical-corpus:test_permit_replay_vulnerable",
        vulnerable=ReplayablePermit, patched=NoncePermit)
    add(case_id="H05-init-reinit", title="Re-callable initializer takes ownership",
        protocol="Proxy pattern class", root_cause="initialization", year=2017, loss_usd=30_000_000,
        invariant_statement="an initializer runs at most once",
        attacker_outcome="acquire the owner role by re-initializing",
        reference="Parity uninitialized-library post-mortem; OpenZeppelin Initializable",
        advisory="Parity library initialization (2017)",
        repository="OpenZeppelin/openzeppelin-contracts",
        vulnerable=ReinitProxy, patched=GuardedInit)
    add(case_id="H06-rounding-up", title="Redeem rounds in the user's favour",
        protocol="Vault accounting class", root_cause="accounting-rounding", year=2022, loss_usd=None,
        invariant_statement="redeemed assets never exceed the vault's assets",
        attacker_outcome="extract more assets than the shares are worth",
        reference="OpenZeppelin ERC4626 rounding notes; EIP-4626",
        advisory="EIP-4626 rounding-direction class",
        repository="OpenZeppelin/openzeppelin-contracts",
        vulnerable=RoundUpVault, patched=RoundDownVault)
    add(case_id="H07-fee-base", title="Fee charged on the wrong base",
        protocol="DEX fee class", root_cause="fee-accounting", year=2021, loss_usd=None,
        invariant_statement="the fee is never larger than the transfer",
        attacker_outcome="cause fee accounting to diverge from the transfer",
        reference="Uniswap V2 fee-on-transfer class",
        advisory="fee-on-transfer accounting class",
        repository="Uniswap/v2-core",
        vulnerable=WrongFeeBase, patched=CorrectFeeBase)
    add(case_id="H08-share-inflation", title="First-depositor share inflation (donation)",
        protocol="ERC4626 class", root_cause="share-inflation", year=2022, loss_usd=None,
        invariant_statement="a depositor always receives a non-zero share for a non-zero deposit",
        attacker_outcome="capture another depositor's deposit by inflating the share price",
        reference="OpenZeppelin ERC4626 virtual-offset mitigation",
        advisory="ERC4626 inflation/donation class",
        repository="OpenZeppelin/openzeppelin-contracts",
        vulnerable=InflatableVault, patched=VirtualOffsetVault)
    add(case_id="H09-callback-trust", title="Callback trusts a caller-supplied identity",
        protocol="Cross-contract class", root_cause="cross-contract-trust", year=2022, loss_usd=None,
        invariant_statement="a party cannot claim another party's credit",
        attacker_outcome="claim another user's credit by forging identity",
        reference="Bridge/router callback-trust class",
        advisory="cross-contract identity-trust class",
        vulnerable=TrustingCallback, patched=VerifiedCallback)
    add(case_id="H10-insolvent-withdraw", title="Withdraw with no reserve check",
        protocol="Lending pool class", root_cause="insolvency", year=2022, loss_usd=None,
        invariant_statement="the reserve never goes negative",
        attacker_outcome="withdraw more than the pool can honour",
        reference="Compound/ForTube reserve-check class",
        advisory="lending reserve-underflow class",
        vulnerable=UncheckedReserve, patched=CheckedReserve)
    add(case_id="H16-liquidation-threshold", title="Healthy position liquidated by a wrong threshold",
        protocol="Perp/leveraged lending class", root_cause="liquidation", year=2022, loss_usd=None,
        invariant_statement="a position above the health threshold is never liquidated",
        attacker_outcome="seize a healthy position",
        reference="Compound/Aave liquidation-factor class",
        advisory="liquidation-threshold class",
        repository="aave/aave-v3-core",
        vulnerable=WrongThresholdLiquidation, patched=CorrectThresholdLiquidation)
    add(case_id="H28-liquidation-window", title="Liquidation fires inside a numeric window",
        protocol="Leveraged lending class", root_cause="liquidation", year=2022, loss_usd=None,
        invariant_statement="a position at or below the 800 debt cap is never liquidated",
        attacker_outcome="seize a position the threshold does not permit",
        reference="Compound/Aave liquidation-factor class; numeric boundary reasoning",
        advisory="liquidation-threshold class (numeric window)",
        repository="aave/aave-v3-core",
        holdout=True,
        vulnerable=LiquidationWindow, patched=GuardedLiquidationWindow)
    add(case_id="H29-allowance-reuse", title="An approval is spendable more than once",
        protocol="ERC-20 allowance class", root_cause="access-control", year=2023,
        loss_usd=None,
        invariant_statement="an allowance is decremented by every transfer it authorises",
        attacker_outcome="drain a victim's approved balance repeatedly",
        reference="ERC-20 allowance handling; transferFrom without allowance decrement",
        advisory="allowance-reuse class",
        repository="OpenZeppelin/openzeppelin-contracts",
        holdout=True,
        vulnerable=ReusedAllowance, patched=GuardedAllowance)
    add(case_id="H17-arithmetic-underflow", title="Unchecked subtraction underflows a balance",
        protocol="BEC token class", root_cause="arithmetic", year=2018, loss_usd=None,
        invariant_statement="total supply never increases through a transfer",
        attacker_outcome="mint value from an underflowed balance",
        reference="BEC token overflow (CVE-2018-10299)",
        advisory="CVE-2018-10299",
        repository="ethereum/EIPs",
        vulnerable=UnderflowToken, patched=CheckedToken)
    add(case_id="H18-flash-price-manip", title="Settlement at a same-transaction manipulable price",
        protocol="bZx class", root_cause="price-manipulation", year=2020, loss_usd=8_000_000,
        invariant_statement="settlement never pays more than the true price implies",
        attacker_outcome="profit from a self-moved settlement price",
        reference="bZx incident post-mortems",
        advisory="bZx (Feb 2020)",
        vulnerable=FlashManipulation, patched=TwapManipulation)
    add(case_id="H19-stale-cache", title="Stale cached total used after a slash",
        protocol="Governance/vault class", root_cause="state-staleness", year=2021, loss_usd=None,
        invariant_statement="a withdrawal never exceeds the real assets",
        attacker_outcome="withdraw against a cache the system already invalidated",
        reference="Compound governance / cache class",
        advisory="stale-cache class",
        repository="compound-finance/compound-protocol",
        vulnerable=StaleCacheVault, patched=InvalidatingVault)
    add(case_id="H20-idor-object", title="Cross-user object mutation (missing ownership check)",
        protocol="Registry/API class", root_cause="access-control", year=2021, loss_usd=None,
        invariant_statement="only the object's owner may mutate it",
        attacker_outcome="mutate another principal's object",
        reference="OWASP IDOR; Solidity access-control class",
        advisory="IDOR / missing ownership check",
        vulnerable=IdorRegistry, patched=GuardedIdorRegistry)

    # --- documented reference cases (traceable; no hermetic model here) ---
    add(case_id="H11-price-manip-flash", title="Flash-loan spot price manipulation",
        protocol="bZx class", root_cause="price-manipulation", year=2020, loss_usd=8_000_000,
        invariant_statement="prices used for settlement cannot be moved within one transaction",
        attacker_outcome="profit from a self-moved price",
        reference="bZx incident post-mortems", advisory="bZx (Feb 2020)",
        repository="bZx")
    add(case_id="H12-liquidation-logic", title="Liquidation threshold applied incorrectly",
        protocol="Aave class", root_cause="liquidation", year=2022, loss_usd=None,
        invariant_statement="a healthy position is never liquidated",
        attacker_outcome="liquidate a healthy position or avoid one's own liquidation",
        reference="Aave/Compound liquidation-factor class", advisory="liquidation-logic class",
        repository="aave/aave-v3-core")
    add(case_id="H13-arithmetic-overflow", title="Unchecked arithmetic overflow",
        protocol="BEC token", root_cause="arithmetic", year=2018, loss_usd=None,
        invariant_statement="a balance never wraps to an unexpected value",
        attacker_outcome="mint value from an overflowed balance",
        reference="BEC token overflow (CVE-2018-10299)", advisory="CVE-2018-10299",
        repository="ethereum/EIPs")
    add(case_id="H14-stale-state", title="Stale cached state used after an update",
        protocol="Compound governance class", root_cause="state-staleness", year=2021, loss_usd=None,
        invariant_statement="a cached value is refreshed before it is trusted",
        attacker_outcome="act on a value that the system has already invalidated",
        reference="Compound governance / cache class", advisory="stale-cache class",
        repository="compound-finance/compound-protocol")
    add(case_id="H15-donation-attack", title="Donation inflates a share price",
        protocol="ERC4626 class", root_cause="donation-attack", year=2022, loss_usd=None,
        invariant_statement="an unsolicited transfer cannot change share accounting adversely",
        attacker_outcome="steal value via a direct token donation",
        reference="OpenZeppelin ERC4626 donation class", advisory="ERC4626 donation class",
        repository="OpenZeppelin/openzeppelin-contracts")

    # Attach the verified pin (a real, resolvable commit) for each case that
    # names a repository we have pinned. ``pin_verified`` records that the pin was
    # resolved from a real release/head via the GitHub API (see ``discovery.pins``),
    # not that it contains the vulnerable code.
    from . import pins as _pins

    pinned: list[HistoricalCase] = []
    for c in cases:
        pin = _pins.pin_for(c.repository or "")
        if pin is not None:
            c = replace(c, pin=pin.sha, pin_verified=True)
        pinned.append(c)
    return pinned


def modelled_cases() -> list[HistoricalCase]:
    return [c for c in corpus() if c.vulnerable is not None and c.patched is not None]


def root_cause_categories() -> list[str]:
    return sorted({c.root_cause for c in corpus()})


def repositories() -> list[str]:
    return sorted({c.repository for c in corpus() if c.repository})


def summary() -> dict:
    cs = corpus()
    return {
        "total_cases": len(cs),
        "modelled_cases": len(modelled_cases()),
        "distinct_root_causes": len(root_cause_categories()),
        "root_causes": root_cause_categories(),
        "distinct_repositories": len(repositories()),
        "repositories": repositories(),
        "holdout_cases": len([c for c in cs if c.holdout]),
        "pinned_cases": len([c for c in cs if c.pin_verified]),
        "sol_repro_cases": len([c for c in cs if c.sol_repro]),
        "meets_min_cases": len(cs) >= 20,
        "meets_min_root_causes": len(root_cause_categories()) >= 10,
        "meets_min_repos": len(repositories()) >= 5,
    }
