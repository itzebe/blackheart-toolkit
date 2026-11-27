"""Executable targets for two more attack classes the engine should be able to
*break*, not merely describe:

  * ``callback-reentrancy`` -- a vault that credits a withdrawal before it
    decrements the caller's balance, so a re-entrant withdrawal sees the stale
    balance and drains the vault (the classic checks-effects-interactions bug).
  * ``access-control``     -- privileged state that a non-owner can overwrite
    because the write is not gated on the caller's role.

Each ships a **vulnerable** variant (the modelled attack succeeds, so the stateful
fuzzer finds a genuine invariant violation) and a **guarded** variant (the attack
is prevented, so the same invariants hold -- the non-vacuity control).

Modelling note: reentrancy is a *single* call that re-enters itself, which the
step-based engine cannot express as two independent steps. The vulnerable and
guarded variants therefore differ only in the order of the credit and the balance
update inside one ``withdraw``-with-callback operation, exactly as the real
checks-effects-interactions fix does. They are engine fixtures: no network, no
real funds.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .engine import InvariantSpec, OpSpec, Target


# --------------------------------------------------------------------------- #
# 1. Reentrant withdrawal (checks-effects-interactions)
# --------------------------------------------------------------------------- #

@dataclass
class CallbackState:
    balances: dict[str, int] = field(default_factory=dict)   # vault claim per actor
    wallet: dict[str, int] = field(default_factory=dict)     # liquid underlying
    vault_total: int = 0
    initial_total: int = 0
    initial: dict[str, int] = field(default_factory=dict)
    last_credit: int = 0


class CallbackVault(Target):
    """A vault whose ``withdraw`` credits the caller before updating state."""

    name = "callback-reentrancy"
    ATTACKER, VICTIM = "attacker", "victim"
    ACTORS = [ATTACKER, VICTIM]

    def reset(self) -> CallbackState:
        st = CallbackState()
        st.wallet = {self.ATTACKER: 1000, self.VICTIM: 1000}
        st.initial = dict(st.wallet)
        st.balances = {a: 0 for a in self.ACTORS}
        st.vault_total = 0
        st.initial_total = 0
        st.last_credit = 0
        return st

    def ops(self) -> list[OpSpec]:
        return [
            OpSpec("deposit", self.ACTORS, {"amount": [10, 50, 100]},
                   weight=3, description="deposit underlying into the vault"),
            OpSpec("withdraw_reentrant", [self.ATTACKER], {"amount": [10, 50, 100]},
                   weight=5, description="withdraw with a callback that re-enters withdraw"),
            OpSpec("withdraw", self.ACTORS, {"amount": [10, 50, 100]},
                   weight=2, description="a normal, non-reentrant withdrawal"),
        ]

    # -- the only difference between the vulnerable and guarded models -- #
    def _withdraw_reentrant(self, st: CallbackState, actor: str, amount: int) -> None:
        """Vulnerable ordering: credit first (twice), then decrement once."""
        bal = st.balances.get(actor, 0)
        credit = min(amount, bal)
        if credit <= 0:
            return
        # First (outer) call credits before updating state...
        st.wallet[actor] = st.wallet.get(actor, 0) + credit
        # ...the callback re-enters while the balance is still stale...
        st.wallet[actor] = st.wallet.get(actor, 0) + credit
        # ...and the outer call decrements only once.
        st.balances[actor] = bal - credit
        st.vault_total -= credit
        st.last_credit = 2 * credit

    def invariants(self) -> list[InvariantSpec]:
        return [
            InvariantSpec(
                "no-material-attacker-profit",
                "the attacker's net value never exceeds their starting value by more "
                "than 0.1%",
                self._no_attacker_profit,
                severity_if_broken="critical",
            ),
            InvariantSpec(
                "vault-solvency",
                "the vault always holds enough underlying to cover every claim",
                self._solvent,
                severity_if_broken="critical",
            ),
        ]

    ATTACKER_MATERIAL_BPS = 10
    BPS = 10_000

    def _no_attacker_profit(self, st: CallbackState) -> bool:
        a = self.ATTACKER
        net = st.wallet.get(a, 0) + st.balances.get(a, 0)
        return net - st.initial[a] <= (st.initial[a] * self.ATTACKER_MATERIAL_BPS) // self.BPS

    def _solvent(self, st: CallbackState) -> bool:
        return sum(st.balances.values()) <= st.vault_total

    def step(self, st: CallbackState, op: str, actor: str, params: dict[str, Any]) -> None:
        st.last_credit = 0
        if op == "deposit":
            amt = min(int(params["amount"]), st.wallet.get(actor, 0))
            if amt <= 0:
                return
            st.wallet[actor] -= amt
            st.balances[actor] = st.balances.get(actor, 0) + amt
            st.vault_total += amt
        elif op == "withdraw_reentrant":
            self._withdraw_reentrant(st, actor, int(params["amount"]))
        elif op == "withdraw":
            amt = min(int(params["amount"]), st.balances.get(actor, 0))
            if amt <= 0:
                return
            st.balances[actor] -= amt
            st.vault_total -= amt
            st.wallet[actor] = st.wallet.get(actor, 0) + amt

    def snapshot(self, st: CallbackState) -> dict[str, Any]:
        return {
            "balances": dict(st.balances),
            "wallet": dict(st.wallet),
            "vault_total": st.vault_total,
            "last_credit": st.last_credit,
        }


class GuardedCallbackVault(CallbackVault):
    """Same vault, but state is updated *before* any credit (checks-effects)."""

    name = "callback-guarded"

    def _withdraw_reentrant(self, st: CallbackState, actor: str, amount: int) -> None:
        bal = st.balances.get(actor, 0)
        first = min(amount, bal)
        if first <= 0:
            return
        # Effects first: the balance drops before anything is credited...
        st.balances[actor] = bal - first
        st.vault_total -= first
        st.wallet[actor] = st.wallet.get(actor, 0) + first
        # ...so the re-entrant call sees the already-reduced balance.
        second = min(amount, st.balances.get(actor, 0))
        st.balances[actor] -= second
        st.vault_total -= second
        st.wallet[actor] = st.wallet.get(actor, 0) + second
        st.last_credit = first + second


# --------------------------------------------------------------------------- #
# 2. Access control on privileged state
# --------------------------------------------------------------------------- #

@dataclass
class AccessState:
    owner: str = "owner"
    fee: int = 0
    owner_set_fee: int = 0
    attacker_set_fee: int = 0
    privileged_writes_by_non_owner: int = 0


class AccessRegistry(Target):
    """A registry whose privileged setter is not gated on the caller's role."""

    name = "access-control"
    OWNER, ATTACKER = "owner", "attacker"
    ACTORS = [OWNER, ATTACKER]

    def reset(self) -> AccessState:
        st = AccessState()
        st.owner = self.OWNER
        st.fee = 0
        st.owner_set_fee = 0
        st.attacker_set_fee = 0
        st.privileged_writes_by_non_owner = 0
        return st

    def ops(self) -> list[OpSpec]:
        return [
            OpSpec("set_fee", self.ACTORS, {"value": [1, 100, 9999]},
                   weight=4, description="set the protocol fee (owner-only)"),
        ]

    # -- the only difference between the vulnerable and guarded models -- #
    def _authorized(self, st: AccessState, actor: str) -> bool:
        return True

    def invariants(self) -> list[InvariantSpec]:
        return [
            InvariantSpec(
                "privileged-state-only-by-owner",
                "privileged state only ever takes a value the owner actually set",
                self._only_owner_writes,
                severity_if_broken="high",
            ),
        ]

    def _only_owner_writes(self, st: AccessState) -> bool:
        return st.fee == st.owner_set_fee

    def step(self, st: AccessState, op: str, actor: str, params: dict[str, Any]) -> None:
        if op != "set_fee":
            return
        if not self._authorized(st, actor):
            if actor != st.owner:
                st.attacker_set_fee = int(params["value"])
            return
        value = int(params["value"])
        st.fee = value
        if actor == st.owner:
            st.owner_set_fee = value
        else:
            st.privileged_writes_by_non_owner += 1
            st.attacker_set_fee = value

    def snapshot(self, st: AccessState) -> dict[str, Any]:
        return {
            "owner": st.owner,
            "fee": st.fee,
            "owner_set_fee": st.owner_set_fee,
            "privileged_writes_by_non_owner": st.privileged_writes_by_non_owner,
        }


class GuardedAccessRegistry(AccessRegistry):
    """Same registry, but only the owner may change privileged state."""

    name = "access-guarded"

    def _authorized(self, st: AccessState, actor: str) -> bool:
        return actor == st.owner
