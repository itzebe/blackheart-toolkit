"""Controlled, deliberately-vulnerable local applications for evaluation.

These are real, runnable HTTP applications (served by
:mod:`blackheart.statespace.runtime.harness_server`) that the execution adapter
drives over loopback. They exist so the engine can be shown to discover a
multi-step flaw in *actual application behaviour*, not in a hand-modelled fixture.

Each app ships a **vulnerable** variant and a **secure control** that differs by
exactly the defence, so the evaluation is a differential: the engine must break
the vulnerable app and must NOT report the control.

Two apps, deliberately in different flaw classes so the held-out case is not a
re-skin of the development case:

  * ``orders`` -- **stale authorization**: a session captures an access grant when
    it opens; the grant is revoked, but the session still honours it. (Development
    target -- the adapter is built and tuned against this app.)
  * ``market`` -- **non-atomic settlement**: ``cancel`` refunds escrow but leaves
    the recorded credit, so a later ``withdraw`` pays the same value twice.
    (Held-out target -- never used to develop or tune the adapter.)

Neither app is told to the engine: the engine derives its model from the app's
declared operations and searches for a sequence that breaks a stated invariant.

The vulnerable sequence is *not* encoded anywhere in the engine. Each app states
what it protects (its invariants) and exposes its operations; what breaks is left
for the search to find.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from ..model import SystemModel


@dataclass
class AppInvariant:
    """A security property the app states it must uphold (over observable state)."""

    inv_id: str
    title: str
    predicate: Callable[[dict], bool]
    severity: str = "high"


@dataclass
class Op:
    """One application operation: the roles allowed to invoke it and its handler."""

    name: str
    roles: tuple[str, ...]                 # roles allowed; empty = any authenticated actor
    handler: Callable[[dict, str, dict], tuple[int, dict]]
    entry: str = ""                        # "METHOD /path" (defaults to POST /<name>)


# --------------------------------------------------------------------------- #
# App 1 (development): stale authorization
# --------------------------------------------------------------------------- #

class OrdersApp:
    """A resource-sharing service whose session captures a grant once.

    ``victim`` owns ``r1`` and has shared it with ``attacker``. ``attacker`` opens
    a session (which captures the grant), the victim revokes the share, and the
    attacker writes anyway -- because the *vulnerable* app honours the captured
    grant instead of the live one.
    """

    name = "orders"
    resource = "r1"

    def roles(self) -> dict[str, tuple[str, ...]]:
        return {"attacker": ("user",), "victim": ("user",), "admin": ("admin",)}

    def initial_state(self) -> dict:
        return {
            "resources": {self.resource: {"owner": "victim", "value": 0}},
            "shared": {self.resource: ["attacker"]},
            "sessions": {},
            "writes": 0,
            "unauthorized_writes": 0,
        }

    # -- authorization the app itself enforces --------------------------- #

    def _granted(self, state: dict, actor: str) -> bool:
        """The VULNERABLE grant check: trusts the grant captured at session open."""
        return bool(state["sessions"].get(actor, {}).get("grants", {}).get(self.resource, False))

    def _live_shared(self, state: dict, actor: str) -> bool:
        res = state["resources"][self.resource]
        return actor == res["owner"] or actor in state["shared"].get(self.resource, [])

    # -- handlers -------------------------------------------------------- #

    def op_open_session(self, state: dict, actor: str, params: dict) -> tuple[int, dict]:
        grants = {rid: (actor in state["shared"].get(rid, []) or state["resources"][rid]["owner"] == actor)
                  for rid in state["resources"]}
        state["sessions"][actor] = {"grants": grants}
        return 200, {"session": actor, "grants": grants}

    def op_revoke_share(self, state: dict, actor: str, params: dict) -> tuple[int, dict]:
        res = state["resources"][self.resource]
        if actor != res["owner"] and "admin" not in self.roles().get(actor, ()):
            return 403, {"error": "only the owner may revoke a share"}
        state["shared"][self.resource] = [a for a in state["shared"][self.resource] if a == res["owner"]]
        return 200, {"shared": list(state["shared"][self.resource])}

    def op_write(self, state: dict, actor: str, params: dict) -> tuple[int, dict]:
        if not self._granted(state, actor):
            return 403, {"error": "no grant for this resource"}
        live = self._live_shared(state, actor)
        state["resources"][self.resource]["value"] += 1
        state["writes"] += 1
        if not live:
            state["unauthorized_writes"] += 1
        return 200, {"value": state["resources"][self.resource]["value"], "authorized": live}

    # -- contract -------------------------------------------------------- #

    def ops(self) -> list[Op]:
        return [
            Op("open_session", (), self.op_open_session),
            Op("revoke_share", ("user", "admin"), self.op_revoke_share),
            Op("write", ("user",), self.op_write),
        ]

    def invariants(self) -> list[AppInvariant]:
        return [AppInvariant(
            "revoked-access-not-exercised",
            "an access grant that has been revoked cannot be exercised",
            lambda st: st.get("unauthorized_writes", 0) == 0,
        )]

    def snapshot(self, state: dict) -> dict:
        return {
            "resources": {k: dict(v) for k, v in state["resources"].items()},
            "shared": {k: list(v) for k, v in state["shared"].items()},
            "sessions": {k: dict(v) for k, v in state["sessions"].items()},
            "writes": state["writes"],
            "unauthorized_writes": state["unauthorized_writes"],
        }

    def model(self) -> SystemModel:
        m = SystemModel(
            target=self.name,
            summary="A resource-sharing service: a session captures the caller's access "
                    "grant when it opens, and a write must honour the *live* grant, so a "
                    "revoked grant can never be exercised.",
            assets=["resource-value"],
            trust_boundaries=["session layer <-> authorization store"],
            evidence=[f"app:blackheart/statespace/runtime/harness_apps.py#{type(self).__name__}"],
        )
        m.add_actor("attacker", roles=("user",), unprivileged=True)
        m.add_actor("victim", roles=("user",), unprivileged=True)
        m.add_actor("admin", roles=("admin",), unprivileged=False)
        m.add_operation("open_session", ("user", "admin"), sensitive=False,
                        effect="capture the caller's current grants",
                        entry_point="POST /open_session", source="app:orders")
        m.add_operation("revoke_share", ("user", "admin"), sensitive=True, asset="resource-value",
                        guard="owner-or-admin", guard_roles=("user",),
                        effect="revoke another principal's access grant",
                        entry_point="POST /revoke_share", source="app:orders")
        m.add_operation("write", ("user",), sensitive=True, asset="resource-value",
                        precondition="a live access grant", guard="live-grant", guard_roles=("user",),
                        effect="write the resource value",
                        entry_point="POST /write", source="app:orders")
        m.add_transition("open-session", "authenticated", ("user",), operation="open_session",
                         description="capture the current grant into a session")
        m.add_transition("revoke-grant", "owner-only", ("user",), operation="revoke_share",
                         description="revoke a shared grant")
        m.add_transition("write-resource", "live-grant", ("user",), operation="write",
                         description="write a resource that requires a live grant")
        m.add_invariant("revoked-access-not-exercised",
                        "an access grant that has been revoked cannot be exercised",
                        applies_to=("resource-value",),
                        expression="revoked-access-not-exercised")
        return m


class GuardedOrdersApp(OrdersApp):
    """The same service, but a write always re-checks the *live* grant."""

    name = "orders-guarded"

    def _granted(self, state: dict, actor: str) -> bool:
        return self._live_shared(state, actor)


# --------------------------------------------------------------------------- #
# App 2 (held-out): non-atomic settlement -> value duplication
# --------------------------------------------------------------------------- #

class MarketApp:
    """A two-phase settlement whose ``cancel`` is not atomic.

    ``initiate`` escrows value and records a credit; ``cancel`` must undo *both*
    atomically. The vulnerable app refunds the escrow but leaves the credit, so a
    later ``withdraw`` pays the same value a second time. The secure control clears
    the credit on cancel and never refunds value already withdrawn.
    """

    name = "market"

    def roles(self) -> dict[str, tuple[str, ...]]:
        return {"attacker": ("user",), "admin": ("admin",)}

    def initial_state(self) -> dict:
        return {"wallet": 1000, "escrow": 0, "credit": 0, "initial": 1000,
                "payout": 0, "orders": 0}

    def _cancel(self, state: dict) -> None:
        """VULNERABLE: refund the escrow but leave the recorded credit intact."""
        state["wallet"] += state["escrow"]
        state["escrow"] = 0

    def op_initiate(self, state: dict, actor: str, params: dict) -> tuple[int, dict]:
        amount = int(params.get("amount", 100))
        amount = max(0, min(amount, state["wallet"]))
        state["wallet"] -= amount
        state["escrow"] += amount
        state["credit"] += amount
        state["orders"] += 1
        return 200, {"escrow": state["escrow"], "credit": state["credit"]}

    def op_cancel(self, state: dict, actor: str, params: dict) -> tuple[int, dict]:
        self._cancel(state)
        return 200, {"wallet": state["wallet"], "credit": state["credit"]}

    def op_withdraw(self, state: dict, actor: str, params: dict) -> tuple[int, dict]:
        amount = state["credit"]
        state["wallet"] += amount
        state["payout"] += amount
        state["credit"] = 0
        return 200, {"wallet": state["wallet"], "payout": state["payout"]}

    def ops(self) -> list[Op]:
        return [
            Op("initiate", ("user",), self.op_initiate),
            Op("cancel", ("user",), self.op_cancel),
            Op("withdraw", ("user",), self.op_withdraw),
        ]

    def invariants(self) -> list[AppInvariant]:
        return [AppInvariant(
            "no-value-duplication",
            "a settlement never lets the wallet exceed the initial deposit",
            lambda st: st.get("wallet", 0) <= st.get("initial", 0),
        )]

    def snapshot(self, state: dict) -> dict:
        return {k: state[k] for k in ("wallet", "escrow", "credit", "initial", "payout", "orders")}

    def model(self) -> SystemModel:
        m = SystemModel(
            target=self.name,
            summary="A two-phase settlement: initiate escrows value and records a credit; "
                    "cancel must undo the credit atomically, or a later withdraw duplicates it.",
            assets=["user-value"],
            trust_boundaries=["settlement escrow <-> user credit ledger"],
            evidence=[f"app:blackheart/statespace/runtime/harness_apps.py#{type(self).__name__}"],
        )
        m.add_actor("attacker", roles=("user",), unprivileged=True)
        m.add_actor("admin", roles=("admin",), unprivileged=False)
        m.add_operation("initiate", ("user",), sensitive=True, asset="user-value",
                        effect="move wallet -> escrow and record a credit",
                        entry_point="POST /initiate", source="app:market")
        m.add_operation("cancel", ("user",), sensitive=True, asset="user-value",
                        precondition="value is escrowed", effect="refund the escrow",
                        entry_point="POST /cancel", source="app:market")
        m.add_operation("withdraw", ("user",), sensitive=True, asset="user-value",
                        precondition="a credit is recorded", effect="move credit -> wallet",
                        entry_point="POST /withdraw", source="app:market")
        m.add_transition("initiate-settlement", "state must be settled", ("user",),
                         operation="initiate", description="start a settlement")
        m.add_transition("cancel-settlement", "state must be escrowed", ("user",),
                         operation="cancel", description="refund a pending settlement")
        m.add_transition("withdraw-credit", "a credit is recorded", ("user",),
                         operation="withdraw", description="withdraw recorded credit")
        m.add_invariant("no-value-duplication",
                        "value is never withdrawn more than once",
                        applies_to=("user-value",), expression="no-value-duplication")
        return m


class GuardedMarketApp(MarketApp):
    """The same settlement, but cancel is atomic and never refunds withdrawn value."""

    name = "market-guarded"

    def _cancel(self, state: dict) -> None:
        refundable = min(state["escrow"], state["credit"])
        state["wallet"] += refundable
        state["escrow"] -= refundable
        state["credit"] -= refundable


# --------------------------------------------------------------------------- #
# Registry
# --------------------------------------------------------------------------- #

_APPS: dict[str, type] = {
    "orders": OrdersApp,
    "orders-guarded": GuardedOrdersApp,
    "market": MarketApp,
    "market-guarded": GuardedMarketApp,
}

#: (vulnerable, control, invariant, class) -- one row per evaluation pair.
APP_PAIRS: list[tuple[str, str, str, str]] = [
    ("orders", "orders-guarded", "revoked-access-not-exercised",
     "stale authorization after revocation"),
    ("market", "market-guarded", "no-value-duplication",
     "non-atomic settlement value duplication"),
]

#: Development vs held-out separation (mission Phase 5).
DEVELOPMENT_APPS = ("orders", "orders-guarded")
HELDOUT_APPS = ("market", "market-guarded")


def app_names() -> list[str]:
    return list(_APPS)


def make_app(name: str) -> "OrdersApp | MarketApp":
    if name not in _APPS:
        raise KeyError(f"unknown harness app: {name} (known: {', '.join(app_names())})")
    return _APPS[name]()
