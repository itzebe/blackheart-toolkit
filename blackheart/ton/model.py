"""A small executable TON (The Open Network) reference model.

BLACKHEART's invariant engine speaks one language: a ``Target`` with operations,
actors, parameter domains and invariants. TON is an asynchronous actor chain with
cell storage and message-based entry points, so the EVM models cannot express it.
This module supplies the missing reference model for the three bug classes TON
contracts most often get wrong:

* **authorization** -- a jetton (fungible token) mint that does not check the
  admin, so any wallet can mint itself tokens;
* **conservation** -- a jetton transfer that credits the destination without a
  matching debit;
* **replay** -- a wallet whose internal message handler does not advance its
  ``seqno``, so a signed transfer can be replayed.

It is deliberately a *reference model*, not a TVM simulator: it models the subset
an unprivileged account can reach through ordinary messages and says what it does
not model. A violation here is a lead about the message/accounting shape, never a
finding against a deployed contract.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ..invariants.engine import InvariantSpec, OpSpec, PureState

ACCOUNTS = ("attacker", "victim", "admin")
AMOUNTS = (0, 1, 10, 100)
SEQNOS = (0, 1)

#: Operations this reference model deliberately does not simulate. They are
#: reported so a clean certificate is never read as covering them.
UNMODELLED = (
    "TVM gas accounting, cell serialisation and boc (bag-of-cells) layout",
    "asynchronous message delivery order and bounce handling",
    "the masterchain / workchain split and sharding",
    "TEP-74 jetton forward payloads and excess-message returns",
    "get-method (off-chain) queries and the Tact runtime checks",
)


@dataclass(frozen=True)
class TonOp:
    name: str
    actors: tuple[str, ...]
    params: tuple[str, ...]
    description: str


TON_OPS: tuple[TonOp, ...] = (
    TonOp("mint", ACCOUNTS, ("to", "amount"), "admin mints new jettons"),
    TonOp("transfer", ACCOUNTS, ("to", "amount"), "jetton transfer between wallets"),
    TonOp("burn", ACCOUNTS, ("amount",), "burn jettons held by the caller"),
    TonOp("change_admin", ACCOUNTS, ("new_admin",), "set the jetton admin"),
    TonOp("wallet_send", ACCOUNTS, ("to", "amount", "seqno"),
          "send from a TON wallet, replay-protected by seqno"),
)


def _initial_jettons() -> dict[str, int]:
    return {"admin": 500, "attacker": 500, "victim": 0}


class TONTarget(PureState):
    """A reference TON target with one deliberate bug switch.

    ``vulnerable=True`` makes ``mint`` skip the admin check, ``transfer`` credit
    the destination twice, and ``wallet_send`` leave ``seqno`` unadvanced. Those
    are the three shapes a TON jetton/wallet bug most often takes; the guarded
    twin does the check/debit/increment, so a differential run proves the model
    can tell them apart.
    """

    name = "ton-reference"

    def __init__(self, *, vulnerable: bool = False, name: str = "") -> None:
        self.vulnerable = vulnerable
        if name:
            self.name = name

    def _admin_bypass(self, op_name: str) -> bool:
        """Whether ``op_name`` skips the admin check.

        The reference model's deliberate bug makes every privileged op bypass the
        check. A *derived* target overrides this to bypass only the ops the source
        left unguarded.
        """
        return self.vulnerable

    def reset(self) -> dict[str, Any]:
        jettons = _initial_jettons()
        return {
            "jettons": dict(jettons),
            "wallets": {a: {"balance": 1000, "seqno": 0} for a in ACCOUNTS},
            "sent": {a: 0 for a in ACCOUNTS},
            "admin": "admin",
            "total_minted": sum(jettons.values()),
            "burned": 0,
            "minted_by_other": 0,
            "events": [],
        }

    def ops(self) -> list[OpSpec]:
        specs: list[OpSpec] = []
        for op in TON_OPS:
            domain: dict[str, list[Any]] = {}
            for param in op.params:
                if param in ("to", "new_admin"):
                    domain[param] = list(ACCOUNTS)
                elif param == "seqno":
                    domain[param] = list(SEQNOS)
                else:
                    domain[param] = list(AMOUNTS)
            specs.append(OpSpec(op.name, list(op.actors), domain,
                                description=op.description))
        return specs

    def invariants(self) -> list[InvariantSpec]:
        return [
            InvariantSpec(
                "ton:supply-conservation",
                "sum(jetton balances) + burned equals total minted",
                lambda s: (sum(s["jettons"].values()) + s["burned"]
                           == s["total_minted"]),
                "critical",
            ),
            InvariantSpec(
                "ton:no-negative-balance",
                "no jetton or wallet balance is negative",
                lambda s: all(v >= 0 for v in s["jettons"].values())
                and all(w["balance"] >= 0 for w in s["wallets"].values()),
                "high",
            ),
            InvariantSpec(
                "ton:admin-only-mint",
                "no jetton is minted by a non-admin account",
                lambda s: s["minted_by_other"] == 0,
                "critical",
            ),
            InvariantSpec(
                "ton:wallet-seqno-advanced",
                "every processed wallet message advanced its seqno",
                lambda s: all(s["wallets"][a]["seqno"] == s["sent"][a]
                              for a in s["wallets"]),
                "high",
            ),
        ]

    def snapshot(self, state: dict[str, Any]) -> dict[str, Any]:
        return {
            "jettons": dict(sorted(state["jettons"].items())),
            "wallets": {k: dict(v) for k, v in sorted(state["wallets"].items())},
            "sent": dict(sorted(state["sent"].items())),
            "admin": state["admin"],
            "total_minted": state["total_minted"],
            "burned": state["burned"],
            "minted_by_other": state["minted_by_other"],
        }

    def step(self, state: dict[str, Any], op_name: str, actor: str,
             params: dict[str, Any]) -> None:
        jettons = state["jettons"]
        jettons.setdefault(actor, 0)
        amount = int(params.get("amount", 0) or 0)
        if amount < 0:
            state["events"].append(f"{actor}:{op_name}:negative-amount")
            return

        if op_name == "mint":
            to = str(params.get("to", ""))
            jettons.setdefault(to, 0)
            if not self._admin_bypass("mint") and actor != state["admin"]:
                return
            jettons[to] += amount
            state["total_minted"] += amount
            if actor != state["admin"]:
                state["minted_by_other"] += amount
            return

        if op_name == "transfer":
            to = str(params.get("to", ""))
            jettons.setdefault(to, 0)
            if jettons[actor] >= amount:
                jettons[actor] -= amount
                jettons[to] += amount
                if self.vulnerable:
                    # the destination is credited a second time with no second
                    # debit, so the jetton sum no longer matches the supply.
                    jettons[to] += amount
            return

        if op_name == "burn":
            if jettons[actor] >= amount:
                jettons[actor] -= amount
                state["burned"] += amount
            return

        if op_name == "change_admin":
            new_admin = str(params.get("new_admin", ""))
            if ((actor == state["admin"] or self._admin_bypass("change_admin"))
                    and new_admin in ACCOUNTS):
                state["admin"] = new_admin
            return

        if op_name == "wallet_send":
            to = str(params.get("to", ""))
            seqno = int(params.get("seqno", 0) or 0)
            wallet = state["wallets"].setdefault(
                actor, {"balance": 0, "seqno": 0})
            state["wallets"].setdefault(to, {"balance": 0, "seqno": 0})
            if seqno == wallet["seqno"] and wallet["balance"] >= amount:
                wallet["balance"] -= amount
                state["wallets"][to]["balance"] += amount
                state["sent"][actor] = state["sent"].get(actor, 0) + 1
                if not self.vulnerable:
                    wallet["seqno"] += 1
            return
