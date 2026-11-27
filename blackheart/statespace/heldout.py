"""Held-out multi-step scenarios for the benchmark's held-out discovery metric.

These are deliberately kept in a **separate module** from the development fixtures
(:mod:`blackheart.statespace.fixtures`) so the benchmark can honestly report a
*held-out* discovery rate: cases the engine was not tuned against. They cover two
multi-step classes the development fixtures do not:

  * ``heldout-double-refund`` -- a refund path with no single-use binding, so the
    same order can be refunded twice (a replay / idempotency bug in a workflow).
  * ``heldout-permission-cache`` -- a permission evaluated once and cached, then
    used after the permission is downgraded (a stale-state privilege bug).

Same rules as the development fixtures: local, no network, no real funds; a
vulnerable variant and a guarded control; the engine must break the vulnerable one
and hold on the control.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .model import SystemModel
from ..invariants.engine import InvariantSpec, OpSpec, Target


# ======================================================================= #
# H1. Double refund (replay in a workflow)
# ======================================================================= #

@dataclass
class RefundState:
    wallet: int = 0
    paid: int = 0
    refunded: int = 0
    refunds: int = 0
    order_open: bool = False
    initial: int = 0


class DoubleRefund(Target):
    """A refund path that does not mark the order refunded, so it can be reused."""

    name = "heldout-double-refund"
    ACTOR = "attacker"
    ACTORS = [ACTOR]

    def reset(self) -> RefundState:
        st = RefundState()
        st.wallet = 1000
        st.initial = 1000
        return st

    def model(self) -> SystemModel:
        m = SystemModel(
            target=self.name,
            summary="An order/refund workflow: an order is paid, then refunded. A refund "
                    "must be usable at most once for the amount actually paid.",
            assets=["user-value"],
            trust_boundaries=["payment ledger <-> refund service"],
            evidence=["fixture:blackheart/statespace/heldout.py#DoubleRefund"],
        )
        m.add_actor(self.ACTOR, roles=("user",), unprivileged=True)
        m.add_operation("pay", ("user",), sensitive=True, asset="user-value",
                        effect="move wallet -> paid", guard="", source="fixture")
        m.add_operation("refund", ("user",), sensitive=True, asset="user-value",
                        precondition="the order was paid",
                        effect="move paid -> wallet", guard="single-use refund token",
                        guard_roles=("user",), source="fixture")
        m.add_transition("issue-refund", "order must be paid and not yet refunded",
                         ("user",), operation="refund", description="refund a paid order")
        m.add_invariant("refund-at-most-once",
                        "the wallet never ends with more value than it started with "
                        "(a refund is usable at most once)",
                        applies_to=("user-value",), expression="refund-at-most-once")
        return m

    def ops(self) -> list[OpSpec]:
        return [
            OpSpec("pay", [self.ACTOR], {"amount": [100, 500, 1000]}, weight=3,
                   description="pay for an order"),
            OpSpec("refund", [self.ACTOR], {}, weight=3, description="refund a paid order"),
        ]

    def _mark_refunded(self, st: RefundState) -> None:
        """The guarded control marks the order refunded; the vulnerable one does not."""

    def invariants(self) -> list[InvariantSpec]:
        return [InvariantSpec(
            "refund-at-most-once",
            "the wallet never exceeds its starting value",
            lambda st: st.wallet <= st.initial,
            severity_if_broken="high",
        )]

    def step(self, st: RefundState, op: str, actor: str, params: dict[str, Any]) -> None:
        if op == "pay":
            amount = min(int(params.get("amount", 0)), st.wallet)
            st.wallet -= amount
            st.paid += amount
            st.order_open = True
        elif op == "refund":
            if not st.order_open or st.paid <= 0:
                return
            st.wallet += st.paid
            st.refunded += st.paid
            st.refunds += 1
            self._mark_refunded(st)

    def snapshot(self, st: RefundState) -> dict[str, Any]:
        return {"wallet": st.wallet, "paid": st.paid, "refunded": st.refunded,
                "refunds": st.refunds, "initial": st.initial}


class GuardedDoubleRefund(DoubleRefund):
    """Same workflow, but a refund is single-use: it clears the payable balance."""

    name = "heldout-double-refund-guarded"

    def _mark_refunded(self, st: RefundState) -> None:
        st.paid = 0
        st.order_open = False


# ======================================================================= #
# H2. Cached permission used after downgrade
# ======================================================================= #

@dataclass
class PermCacheState:
    level: dict = field(default_factory=dict)     # per-actor permission level
    shared_cache: int = -1                        # a single shared "last seen" level
    high_actions_by_low: int = 0


class SharedPermissionCache(Target):
    """A service that caches the last-seen permission level in a *shared* field.

    The classic "authorization cached in a static/shared variable" bug: once a
    privileged caller warms the cache, an unprivileged caller is evaluated against
    the privileged caller's level. It is multi-step and cross-user -- a privileged
    actor's benign action is the setup, and the attacker's action is the exploit.
    """

    name = "heldout-permission-cache"
    ADMIN, USER = "admin", "attacker"
    ACTORS = [ADMIN, USER]

    def reset(self) -> PermCacheState:
        st = PermCacheState()
        st.level = {self.ADMIN: 2, self.USER: 0}
        st.shared_cache = -1
        st.high_actions_by_low = 0
        return st

    def model(self) -> SystemModel:
        m = SystemModel(
            target=self.name,
            summary="A service that caches the last-seen permission level in a shared field; "
                    "a privileged action must be evaluated against the caller's own level.",
            assets=["privileged-action"],
            trust_boundaries=["authorization service <-> shared permission cache"],
            evidence=["fixture:blackheart/statespace/heldout.py#SharedPermissionCache"],
        )
        m.add_actor(self.USER, roles=("user",), unprivileged=True)
        m.add_actor(self.ADMIN, roles=("admin",), unprivileged=False)
        m.add_operation("authorize", (), sensitive=False,
                        effect="evaluate and cache the caller's level", source="fixture")
        m.add_operation("privileged_action", (), sensitive=True, asset="privileged-action",
                        precondition="the caller's own level is high",
                        effect="perform a privileged action",
                        guard="the caller's own permission level",
                        guard_roles=("user", "admin"), source="fixture")
        m.add_transition("grant-privileged-action", "caller's own level must be high",
                         ("user", "admin"), operation="privileged_action",
                         description="privileged action gated on the caller's own level")
        m.add_invariant("no-privileged-action-by-unprivileged-caller",
                        "a caller whose own level is low never performs a privileged action",
                        applies_to=("privileged-action",),
                        expression="no-privileged-action-by-unprivileged-caller")
        return m

    def ops(self) -> list[OpSpec]:
        return [
            OpSpec("authorize", [self.USER, self.ADMIN], {}, weight=2,
                   description="evaluate and cache the caller's level"),
            OpSpec("privileged_action", [self.USER, self.ADMIN], {}, weight=4,
                   description="perform a privileged action"),
        ]

    def _effective_level(self, st: PermCacheState, actor: str) -> int:
        """The vulnerable service evaluates against the shared cache."""
        return st.shared_cache if st.shared_cache >= 0 else st.level.get(actor, 0)

    def _record(self, st: PermCacheState, actor: str, level: int) -> None:
        st.shared_cache = level

    def invariants(self) -> list[InvariantSpec]:
        return [InvariantSpec(
            "no-privileged-action-by-unprivileged-caller",
            "no low-level caller performs a privileged action",
            lambda st: st.high_actions_by_low == 0,
            severity_if_broken="high",
        )]

    def step(self, st: PermCacheState, op: str, actor: str, params: dict[str, Any]) -> None:
        if op == "authorize":
            self._record(st, actor, st.level.get(actor, 0))
        elif op == "privileged_action":
            if self._effective_level(st, actor) < 2:
                return
            if st.level.get(actor, 0) < 2:
                st.high_actions_by_low += 1

    def snapshot(self, st: PermCacheState) -> dict[str, Any]:
        return {"level": dict(st.level), "shared_cache": st.shared_cache,
                "high_actions_by_low": st.high_actions_by_low}


class GuardedSharedPermissionCache(SharedPermissionCache):
    """Same service, but the level is cached per caller, never shared."""

    name = "heldout-permission-cache-guarded"

    def _effective_level(self, st: PermCacheState, actor: str) -> int:
        return st.level.get(actor, 0)

    def _record(self, st: PermCacheState, actor: str, level: int) -> None:
        # A per-caller cache would be keyed by actor; here we simply do not retain
        # a shared value, so the shared_cache stays at its initial -1.
        st.shared_cache = -1


# ----------------------------------------------------------------------- #

HELDOUT_PAIRS: list[tuple[str, str, str, str]] = [
    ("heldout-double-refund", "heldout-double-refund-guarded", "refund-at-most-once",
     "a refund path is not single-use, so the same order is refunded twice"),
    ("heldout-permission-cache", "heldout-permission-cache-guarded",
     "no-privileged-action-by-unprivileged-caller",
     "a shared permission cache lets a privileged caller's level authorize an unprivileged caller"),
]

_HELDOUT: dict[str, type] = {
    "heldout-double-refund": DoubleRefund,
    "heldout-double-refund-guarded": GuardedDoubleRefund,
    "heldout-permission-cache": SharedPermissionCache,
    "heldout-permission-cache-guarded": GuardedSharedPermissionCache,
}


def heldout_names() -> list[str]:
    return list(_HELDOUT)


def make_heldout(name: str) -> Target:
    if name not in _HELDOUT:
        raise KeyError(f"unknown held-out fixture: {name} (known: {', '.join(heldout_names())})")
    return _HELDOUT[name]()
