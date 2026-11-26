"""Blind hold-out fixtures for the Mission-06 adaptive-discovery benchmark.

These are **new** cases, authored *after* the adaptive engine and its parameters
were frozen, and kept in a separate module from the development corpus
(:mod:`blackheart.discovery.corpus`) and the earlier hold-out set
(:mod:`blackheart.discovery.heldout`). The engine was never tuned against them;
the benchmark reports the result whatever it is.

Every case is a plain :class:`~blackheart.invariants.engine.Target`: the engine
sees only ``ops()`` / ``invariants()`` / ``step()`` / ``reset()`` / ``snapshot()``,
so nothing here can be special-cased by name.

Vulnerability classes here are deliberately *not* in the development corpus:

  * ``approval-double-spend`` -- a spend path that checks the allowance but never
    decrements it, so the same allowance is spent twice (cross-actor).
  * ``fee-on-transfer`` -- the ledger credits the requested amount while the token
    transfers less, so the ledger over-states the balance.
  * ``expiry-not-enforced`` -- a deadline parameter that is ignored, so an expired
    authorisation is still accepted (parameter-boundary).
  * ``liquidation-boundary`` -- a liquidation guard that is off by one at the
    healthy threshold, so a keeper can seize a position that is not liquidatable
    (parameter-boundary).

Plus two **clean negative controls** whose invariant genuinely holds for every
sequence the engine can build; any "violation" the engine reports on them is a
false positive and is counted as one.

Nothing here executes a network, a real contract, or real funds.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..invariants.engine import InvariantSpec, OpSpec, Target


class _Snap:
    def snapshot(self, state: Any) -> dict[str, Any]:
        return dict(vars(state))

    def state_is_isolated(self) -> bool:
        return True


# ======================================================================= #
# BL-01. Approval double-spend (cross-actor; allowance never decremented).
# ======================================================================= #

@dataclass
class AllowanceState:
    approved: int = 0
    remaining: int = 0
    spent: int = 0
    transferred: int = 0


class ApprovalDoubleSpend(_Snap, Target):
    name = "blind-approval-double-spend-vulnerable"
    OWNER, ATTACKER = "owner", "attacker"

    def reset(self) -> AllowanceState:
        return AllowanceState(approved=50, remaining=50, spent=0, transferred=0)

    def ops(self) -> list[OpSpec]:
        return [
            OpSpec("approve", [self.OWNER], {"amount": [50, 100]}, weight=1),
            OpSpec("spend", [self.ATTACKER], {"amount": [1, 50, 100]}, weight=3),
        ]

    def invariants(self) -> list[InvariantSpec]:
        return [InvariantSpec(
            "allowance-respected", "spent within an approval epoch never exceeds it",
            lambda st: st.spent <= st.approved, severity_if_broken="high")]

    def step(self, st: AllowanceState, op: str, actor: str, params: dict[str, Any]) -> None:
        if op == "approve":
            amt = int(params.get("amount", 0))
            st.approved = amt
            st.remaining = amt
            st.spent = 0
        elif op == "spend":
            amt = int(params.get("amount", 0))
            # Vulnerable: checks the remaining allowance but never decrements it,
            # so the same allowance is spent repeatedly.
            if amt <= st.remaining:
                st.spent += amt
                st.transferred += amt


class ApprovalDoubleSpendPatched(ApprovalDoubleSpend):
    name = "blind-approval-double-spend-patched"

    def step(self, st: AllowanceState, op: str, actor: str, params: dict[str, Any]) -> None:
        if op == "approve":
            amt = int(params.get("amount", 0))
            st.approved = amt
            st.remaining = amt
            st.spent = 0
        elif op == "spend":
            amt = int(params.get("amount", 0))
            if amt <= st.remaining:
                st.remaining -= amt
                st.spent += amt
                st.transferred += amt


# ======================================================================= #
# BL-02. Fee-on-transfer accounting mismatch (ledger over-credits).
# ======================================================================= #

@dataclass
class FeeTransferState:
    ledger: dict[str, int] = field(default_factory=dict)
    token: dict[str, int] = field(default_factory=dict)


class FeeOnTransferMismatch(_Snap, Target):
    name = "blind-fee-on-transfer-vulnerable"
    USER = "attacker"
    FEE_BPS = 100  # 1%

    def reset(self) -> FeeTransferState:
        return FeeTransferState(ledger={}, token={})

    def ops(self) -> list[OpSpec]:
        return [OpSpec("deposit", [self.USER], {"amount": [100, 1000]}, weight=5)]

    def invariants(self) -> list[InvariantSpec]:
        return [InvariantSpec(
            "ledger-backed", "the ledger never claims more than the token actually holds",
            lambda st: st.ledger.get(self.USER, 0) <= st.token.get(self.USER, 0),
            severity_if_broken="high")]

    def step(self, st: FeeTransferState, op: str, actor: str, params: dict[str, Any]) -> None:
        if op == "deposit":
            amt = int(params.get("amount", 0))
            fee = (amt * self.FEE_BPS) // 10_000
            # Vulnerable: the ledger is credited the full amount, the token less.
            st.ledger[actor] = st.ledger.get(actor, 0) + amt
            st.token[actor] = st.token.get(actor, 0) + (amt - fee)


class FeeOnTransferMismatchPatched(FeeOnTransferMismatch):
    name = "blind-fee-on-transfer-patched"

    def step(self, st: FeeTransferState, op: str, actor: str, params: dict[str, Any]) -> None:
        if op == "deposit":
            amt = int(params.get("amount", 0))
            fee = (amt * self.FEE_BPS) // 10_000
            received = amt - fee
            st.ledger[actor] = st.ledger.get(actor, 0) + received
            st.token[actor] = st.token.get(actor, 0) + received


# ======================================================================= #
# BL-03. Expiry not enforced (parameter-boundary: a deadline of 0/1).
# ======================================================================= #

@dataclass
class DeadlineState:
    now: int = 5
    accepted: int = 0
    bad_accepts: int = 0
    last_deadline: int = 0


class ExpiryNotEnforced(_Snap, Target):
    name = "blind-expiry-not-enforced-vulnerable"
    ATTACKER = "attacker"

    def reset(self) -> DeadlineState:
        return DeadlineState()

    def ops(self) -> list[OpSpec]:
        return [OpSpec("submit", [self.ATTACKER], {"deadline": [0, 1, 100]}, weight=5)]

    def invariants(self) -> list[InvariantSpec]:
        return [InvariantSpec(
            "no-expired-accept", "an operation is never accepted after its deadline",
            lambda st: st.bad_accepts == 0, severity_if_broken="high")]

    def _accept(self, st: DeadlineState, deadline: int) -> None:
        st.last_deadline = deadline
        st.accepted += 1
        if deadline < st.now:
            st.bad_accepts += 1

    def step(self, st: DeadlineState, op: str, actor: str, params: dict[str, Any]) -> None:
        if op == "submit":
            # Vulnerable: the deadline is recorded but never enforced.
            self._accept(st, int(params.get("deadline", 0)))


class ExpiryNotEnforcedPatched(ExpiryNotEnforced):
    name = "blind-expiry-not-enforced-patched"

    def step(self, st: DeadlineState, op: str, actor: str, params: dict[str, Any]) -> None:
        if op == "submit":
            deadline = int(params.get("deadline", 0))
            if st.now <= deadline:
                self._accept(st, deadline)


# ======================================================================= #
# BL-04. Liquidation boundary off-by-one (parameter-boundary).
# ======================================================================= #

@dataclass
class LiqBoundaryState:
    collateral: int = 0
    debt: int = 0
    liquidated_healthy: int = 0


class LiquidationBoundaryOffByOne(_Snap, Target):
    name = "blind-liquidation-boundary-vulnerable"
    ATTACKER, KEEPER = "attacker", "user"  # liquidation is permissionless: an unprivileged caller
    THRESHOLD_PCT = 75

    def reset(self) -> LiqBoundaryState:
        return LiqBoundaryState(collateral=100, debt=0, liquidated_healthy=0)

    def ops(self) -> list[OpSpec]:
        return [
            OpSpec("borrow", [self.ATTACKER], {"amount": [50, 75, 90]}, weight=3),
            OpSpec("liquidate", [self.KEEPER], {}, weight=1),
        ]

    def _healthy(self, st: LiqBoundaryState) -> bool:
        # A position is healthy while debt <= collateral * threshold.
        return st.debt <= (st.collateral * self.THRESHOLD_PCT) // 100

    def invariants(self) -> list[InvariantSpec]:
        return [InvariantSpec(
            "no-liquidation-of-healthy", "a healthy position is never liquidated",
            lambda st: st.liquidated_healthy == 0, severity_if_broken="high")]

    def step(self, st: LiqBoundaryState, op: str, actor: str, params: dict[str, Any]) -> None:
        if op == "borrow":
            st.debt += int(params.get("amount", 0))
        elif (op == "liquidate"
              # Vulnerable: liquidates a healthy position at the boundary too, so an
              # unprivileged keeper can seize a position that is not liquidatable.
              and st.debt <= (st.collateral * self.THRESHOLD_PCT) // 100
              and self._healthy(st)):
            st.liquidated_healthy += 1


class LiquidationBoundaryPatched(LiquidationBoundaryOffByOne):
    name = "blind-liquidation-boundary-patched"

    def step(self, st: LiqBoundaryState, op: str, actor: str, params: dict[str, Any]) -> None:
        if op == "borrow":
            st.debt += int(params.get("amount", 0))
        elif op == "liquidate" and not self._healthy(st):
            # Patched: only an unhealthy position may be liquidated.
            st.debt = 0


# ======================================================================= #
# Clean negative controls -- the invariant holds for every sequence.
# ======================================================================= #

@dataclass
class CleanVaultState:
    shares: dict[str, int] = field(default_factory=dict)
    total: int = 0


class CleanVault(_Snap, Target):
    """A correct share vault: shares are conserved. No vulnerability exists."""

    name = "blind-clean-vault"
    ATTACKER, VICTIM = "attacker", "victim"

    def reset(self) -> CleanVaultState:
        return CleanVaultState(shares={}, total=0)

    def ops(self) -> list[OpSpec]:
        return [
            OpSpec("deposit", [self.ATTACKER, self.VICTIM], {"amount": [1, 100, 1000]}, weight=5),
            OpSpec("withdraw", [self.ATTACKER, self.VICTIM], {"amount": [1, 100]}, weight=3),
        ]

    def invariants(self) -> list[InvariantSpec]:
        return [InvariantSpec(
            "shares-conserved", "the sum of shares equals the recorded total",
            lambda st: sum(st.shares.values()) == st.total, severity_if_broken="high")]

    def step(self, st: CleanVaultState, op: str, actor: str, params: dict[str, Any]) -> None:
        amt = int(params.get("amount", 0))
        if op == "deposit":
            st.shares[actor] = st.shares.get(actor, 0) + amt
            st.total += amt
        elif op == "withdraw":
            held = st.shares.get(actor, 0)
            take = min(amt, held)
            st.shares[actor] = held - take
            st.total -= take


@dataclass
class CleanApprovalState:
    approved: int = 0
    remaining: int = 0
    spent: int = 0


class CleanApproval(_Snap, Target):
    """A correct allowance system: spend never exceeds the approved amount."""

    name = "blind-clean-approval"
    OWNER, ATTACKER = "owner", "attacker"

    def reset(self) -> CleanApprovalState:
        return CleanApprovalState(approved=50, remaining=50, spent=0)

    def ops(self) -> list[OpSpec]:
        return [
            OpSpec("approve", [self.OWNER], {"amount": [50, 100]}, weight=1),
            OpSpec("spend", [self.ATTACKER], {"amount": [1, 50, 100]}, weight=3),
        ]

    def invariants(self) -> list[InvariantSpec]:
        return [InvariantSpec(
            "allowance-respected", "spent within an approval epoch never exceeds it",
            lambda st: st.spent <= st.approved, severity_if_broken="high")]

    def step(self, st: CleanApprovalState, op: str, actor: str, params: dict[str, Any]) -> None:
        if op == "approve":
            amt = int(params.get("amount", 0))
            st.approved = amt
            st.remaining = amt
            st.spent = 0
        elif op == "spend":
            amt = int(params.get("amount", 0))
            if amt <= st.remaining:
                st.remaining -= amt
                st.spent += amt


# ======================================================================= #
# Registry
# ======================================================================= #

@dataclass(frozen=True)
class BlindPair:
    case_id: str
    root_cause: str
    description: str
    vulnerable: type
    patched: type
    invariant: str


BLIND_PAIRS: tuple[BlindPair, ...] = (
    BlindPair("BL01-approval-double-spend", "approval-double-spend",
              "allowance checked but never decremented (cross-actor)",
              ApprovalDoubleSpend, ApprovalDoubleSpendPatched, "allowance-respected"),
    BlindPair("BL02-fee-on-transfer", "fee-on-transfer",
              "ledger credited the gross amount, token transferred the net",
              FeeOnTransferMismatch, FeeOnTransferMismatchPatched, "ledger-backed"),
    BlindPair("BL03-expiry-not-enforced", "expiry-not-enforced",
              "an expired authorisation is still accepted (deadline ignored)",
              ExpiryNotEnforced, ExpiryNotEnforcedPatched, "no-expired-accept"),
    BlindPair("BL04-liquidation-boundary", "liquidation-boundary",
              "a healthy position can be liquidated (off-by-one guard)",
              LiquidationBoundaryOffByOne, LiquidationBoundaryPatched,
              "no-liquidation-of-healthy"),
)

NEGATIVE_CONTROLS: tuple[type, ...] = (CleanVault, CleanApproval)


def blind_pairs() -> list[BlindPair]:
    return list(BLIND_PAIRS)


def negative_controls() -> list[Target]:
    return [cls() for cls in NEGATIVE_CONTROLS]
