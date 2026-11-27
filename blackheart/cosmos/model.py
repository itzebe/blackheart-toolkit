"""A small executable Cosmos SDK accounting model.

BLACKHEART's invariant engine speaks one language: a ``Target`` with operations,
actors, parameter domains and invariants. A Cosmos chain is not a Solidity
contract, so the EVM models cannot express it. This module supplies the missing
reference model for the value-accounting invariants every Cosmos module must
hold: supply conservation, non-negative balances, the self-bond floor and locked
coins that cannot be spent twice.

It is deliberately a *reference model*, not a chain simulator. It models the
subset an unprivileged account can reach through ordinary messages, and it says
which operations it does not model. A violation here is a lead about the
accounting shape, not a finding against a deployed chain.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..invariants.engine import InvariantSpec, OpSpec, PureState

ACCOUNTS = ("attacker", "victim", "validator")
VALIDATORS = ("v1", "v2")
AMOUNTS = (0, 1, 10, 100, 1000)
PROPOSALS = (1, 2)

#: Operations this reference model deliberately does not simulate. They are
#: reported so a clean certificate is never read as covering them.
UNMODELLED = (
    "BeginBlock / EndBlock module hooks",
    "IBC packet lifecycle and light-client verification",
    "governance proposal execution and parameter changes",
    "EVM lane execution and precompile calls",
    "cgo / FFI to native PQ or SVM libraries",
    "slashing fractions and distribution rounding",
)


@dataclass(frozen=True)
class CosmosOp:
    name: str
    actors: tuple[str, ...]
    params: tuple[str, ...]
    description: str


COSMOS_OPS: tuple[CosmosOp, ...] = (
    CosmosOp("send", ACCOUNTS, ("to", "amount"), "bank send between accounts"),
    CosmosOp("delegate", ("attacker", "victim"), ("validator", "amount"),
             "delegate liquid stake to a validator"),
    CosmosOp("undelegate", ("attacker", "victim"), ("validator", "amount"),
             "begin unbonding of delegated stake"),
    CosmosOp("redelegate", ("attacker", "victim"),
             ("from_validator", "to_validator", "amount"),
             "move delegation between validators"),
    CosmosOp("unjail", ("validator",), ("validator",),
             "return a jailed validator to the set"),
    CosmosOp("deposit", ACCOUNTS, ("proposal", "amount"),
             "deposit into a governance proposal"),
    CosmosOp("withdraw_deposit", ACCOUNTS, ("proposal", "amount"),
             "withdraw a governance deposit"),
    CosmosOp("lock", ACCOUNTS, ("amount",), "lock liquid coins"),
    CosmosOp("unlock", ACCOUNTS, ("amount",), "unlock previously locked coins"),
    CosmosOp("slash", ("governance",), ("validator", "amount"),
             "slash a validator"),
)


def _accounts() -> dict[str, dict[str, int]]:
    return {a: {"liquid": 1000, "staked": 0, "unbonding": 0, "locked": 0}
            for a in ACCOUNTS}


class CosmosTarget(PureState):
    """A reference Cosmos accounting target with one deliberate bug switch.

    ``vulnerable=True`` makes ``undelegate``, ``unlock`` and ``withdraw_deposit``
    credit the caller without debiting the source. Those are the three shapes a
    module-level accounting bug most often takes; the guarded twin does the
    debit, so a differential run proves the model can tell them apart.
    """

    name = "cosmos-reference"

    def __init__(self, *, vulnerable: bool = False, name: str = "") -> None:
        self.vulnerable = vulnerable
        if name:
            self.name = name

    def reset(self) -> dict[str, Any]:
        return {
            "accounts": _accounts(),
            "delegations": {a: {v: 0 for v in VALIDATORS} for a in ACCOUNTS},
            "validators": {
                "v1": {"tokens": 500, "self_bond": 500, "jailed": False},
                "v2": {"tokens": 100, "self_bond": 100, "jailed": False},
            },
            "module": {"escrow": 0, "fee_pool": 0},
            "proposals": {1: {"amount": 0, "owner": ""},
                          2: {"amount": 0, "owner": ""}},
            "supply": 3000,
            "burned": 0,
            "height": 0,
            "events": [],
        }

    def ops(self) -> list[OpSpec]:
        specs: list[OpSpec] = []
        for op in COSMOS_OPS:
            domain: dict[str, list[Any]] = {}
            for param in op.params:
                if param == "to":
                    domain[param] = list(ACCOUNTS)
                elif param in ("validator", "from_validator", "to_validator"):
                    domain[param] = list(VALIDATORS)
                elif param == "proposal":
                    domain[param] = list(PROPOSALS)
                else:
                    domain[param] = list(AMOUNTS)
            specs.append(OpSpec(op.name, list(op.actors), domain,
                                description=op.description))
        return specs

    def invariants(self) -> list[InvariantSpec]:
        return [
            InvariantSpec(
                "cosmos:supply-conservation",
                "liquid + staked + unbonding + locked + module + burned equals supply",
                lambda s: (sum(a["liquid"] + a["staked"] + a["unbonding"] + a["locked"]
                               for a in s["accounts"].values())
                           + s["module"]["escrow"] + s["module"]["fee_pool"]
                           + s["burned"] == s["supply"]),
                "critical",
            ),
            InvariantSpec(
                "cosmos:no-negative-balance",
                "no account or module balance is negative",
                lambda s: all(v >= 0 for a in s["accounts"].values() for v in a.values())
                and all(v >= 0 for v in s["module"].values()),
                "high",
            ),
            InvariantSpec(
                "cosmos:self-bond-floor",
                "every validator in the active set meets the self-bond floor",
                lambda s: all(v["self_bond"] >= 100 for v in s["validators"].values()
                              if not v["jailed"]),
                "medium",
            ),
            InvariantSpec(
                "cosmos:locked-is-backed",
                "locked coins are still held by the locking account",
                lambda s: all(a["locked"] <= a["liquid"] + a["locked"]
                              for a in s["accounts"].values()),
                "medium",
            ),
        ]

    def snapshot(self, state: dict[str, Any]) -> dict[str, Any]:
        return {
            "accounts": {k: dict(v) for k, v in sorted(state["accounts"].items())},
            "validators": {k: dict(v) for k, v in sorted(state["validators"].items())},
            "delegations": {k: dict(v) for k, v in sorted(state["delegations"].items())},
            "module": dict(state["module"]),
            "proposals": {k: dict(v) for k, v in sorted(state["proposals"].items())},
            "supply": state["supply"],
            "burned": state["burned"],
            "height": state["height"],
        }

    def step(self, state: dict[str, Any], op_name: str, actor: str,
             params: dict[str, Any]) -> None:
        state["height"] += 1
        account = state["accounts"].setdefault(
            actor, {"liquid": 0, "staked": 0, "unbonding": 0, "locked": 0})
        amount = int(params.get("amount", 0) or 0)
        if amount < 0:
            state["events"].append(f"{actor}:{op_name}:negative-amount")
            return

        if op_name == "send":
            to = str(params.get("to", ""))
            if to in state["accounts"] and account["liquid"] >= amount:
                account["liquid"] -= amount
                state["accounts"][to]["liquid"] += amount
            return

        if op_name == "delegate":
            val = str(params.get("validator", ""))
            if val in state["validators"] and account["liquid"] >= amount:
                account["liquid"] -= amount
                account["staked"] += amount
                state["delegations"][actor][val] += amount
                state["validators"][val]["tokens"] += amount
            return

        if op_name == "undelegate":
            val = str(params.get("validator", ""))
            if (val in state["validators"] and account["staked"] >= amount
                    and state["delegations"][actor][val] >= amount):
                account["staked"] -= amount
                account["unbonding"] += amount
                state["delegations"][actor][val] -= amount
                state["validators"][val]["tokens"] -= amount
                if self.vulnerable:
                    account["liquid"] += amount
            return

        if op_name == "redelegate":
            src = str(params.get("from_validator", ""))
            dst = str(params.get("to_validator", ""))
            if src in state["validators"] and dst in state["validators"] and src != dst:
                if (state["delegations"][actor][src] >= amount
                        and state["validators"][src]["tokens"] >= amount):
                    state["delegations"][actor][src] -= amount
                    state["delegations"][actor][dst] += amount
                    state["validators"][src]["tokens"] -= amount
                    state["validators"][dst]["tokens"] += amount
            return

        if op_name == "unjail":
            val = str(params.get("validator", ""))
            if val in state["validators"] and state["validators"][val]["self_bond"] >= 100:
                state["validators"][val]["jailed"] = False
            return

        if op_name == "deposit":
            proposal = int(params.get("proposal", 1) or 1)
            if proposal in state["proposals"] and account["liquid"] >= amount:
                record = state["proposals"][proposal]
                if record["owner"] in ("", actor):
                    record["owner"] = actor
                    record["amount"] += amount
                    account["liquid"] -= amount
                    state["module"]["escrow"] += amount
            return

        if op_name == "withdraw_deposit":
            proposal = int(params.get("proposal", 1) or 1)
            if proposal in state["proposals"]:
                record = state["proposals"][proposal]
                if record["owner"] == actor and record["amount"] >= amount:
                    record["amount"] -= amount
                    state["module"]["escrow"] -= amount
                    account["liquid"] += amount
                    if self.vulnerable:
                        account["liquid"] += amount
            return

        if op_name == "lock":
            if account["liquid"] >= amount:
                account["liquid"] -= amount
                account["locked"] += amount
            return

        if op_name == "unlock":
            if account["locked"] >= amount:
                account["locked"] -= amount
                account["liquid"] += amount
                if self.vulnerable:
                    account["liquid"] += amount
            return

        if op_name == "slash":
            val = str(params.get("validator", ""))
            if val in state["validators"]:
                slashed = min(amount, state["validators"][val]["tokens"])
                state["validators"][val]["tokens"] -= slashed
                state["validators"][val]["self_bond"] = max(
                    0, state["validators"][val]["self_bond"] - slashed)
                # Slashing burns bonded value. The reference model debits the
                # validator's liquid account by the same amount so the supply
                # invariant stays meaningful; a real chain debits delegations.
                debit = min(slashed, account["liquid"])
                account["liquid"] -= debit
                state["burned"] += debit
                state["supply"] -= debit
                if state["validators"][val]["self_bond"] < 100:
                    state["validators"][val]["jailed"] = True
            return


@dataclass(frozen=True)
class CosmosOpCandidate:
    """One message handler recovered from Go source, with its guard state."""

    name: str
    receiver: str
    path: str
    line: int
    message: str
    writes_state: bool
    guarded: bool
    reason: str = ""
    delegated_to: tuple[str, ...] = ()
    unresolved_dispatch: tuple[str, ...] = ()


@dataclass
class CosmosSurface:
    root: str
    handlers: list[CosmosOpCandidate] = field(default_factory=list)
    stubs: int = 0
    boundaries: list[str] = field(default_factory=list)
    unmodelled: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "root": self.root,
            "handlers": [h.__dict__ for h in self.handlers],
            "stubs": self.stubs,
            "boundaries": list(self.boundaries),
            "unmodelled": list(self.unmodelled),
            "errors": list(self.errors),
        }


def model_from_go(report) -> CosmosSurface:
    """Recover Cosmos message handlers from a :class:`GoSurfaceReport`.

    The result is a *surface*, not a model: it names the messages an
    unprivileged account can reach and whether the handler checks an authority.
    It never invents the handler's accounting semantics; those must be read and
    modelled, or reproduced on a devnet.
    """
    import re

    from ..ingest.golang_calls import (
        AUTHORITY_GUARD_PATTERN,
        STATE_WRITE_PATTERN,
        GoCallGraph,
    )

    graph = GoCallGraph(report)
    surface = CosmosSurface(
        root=report.root,
        stubs=len(report.stubs),
        boundaries=[f"{b.path}:{b.line} {b.kind} {b.detail}" for b in report.boundaries],
        unmodelled=list(UNMODELLED),
    )
    for func in report.functions:
        if func.stub or func.path.endswith(".pb.go"):
            continue
        if func.receiver.startswith("Unimplemented") or func.name.startswith("New"):
            continue
        message = ""
        m = re.search(r"\*?types\.(Msg[A-Za-z0-9_]+)", func.signature)
        if m:
            message = m.group(1)
        is_handler = func.is_handler and not func.is_consensus
        if not is_handler:
            continue
        direct_write = bool(re.search(STATE_WRITE_PATTERN, func.body))
        edges = graph.reachable(func)
        delegated_calls = [e.callee for e in edges if e.callee is not None]
        delegated = graph.delegated_writes(func)
        writes = direct_write or bool(delegated)
        guarded = bool(re.search(AUTHORITY_GUARD_PATTERN, func.body))
        if not guarded and graph.delegated_guards(func):
            guarded = True
        unresolved = tuple(sorted({
            edge.expression for edge in edges
            if edge.callee is None and edge.detail
        }))
        reason = ""
        if writes and not guarded:
            if delegated:
                callee = delegated[0]
                reason = (f"delegates to {callee.receiver}.{callee.name} "
                          f"({callee.path}:{callee.line}) which writes state "
                          f"with no signer/authority token")
            else:
                reason = "writes state with no signer/authority token"
        elif not writes:
            stubs = [c for c in delegated_calls if c.stub]
            if stubs:
                reason = ("delegates to public-build stub(s) "
                          + ", ".join(f"{c.receiver}.{c.name}" for c in stubs[:3])
                          + "; the implementation is not in this tree")
            elif unresolved:
                reason = ("no direct write and unresolved delegated call(s): "
                          + ", ".join(unresolved[:3]))
        surface.handlers.append(CosmosOpCandidate(
            name=func.name,
            receiver=func.receiver,
            path=func.path,
            line=func.line,
            message=message or func.name,
            writes_state=writes,
            guarded=guarded,
            reason=reason,
            delegated_to=tuple(f"{c.receiver}.{c.name}" for c in delegated_calls),
            unresolved_dispatch=unresolved,
        ))
    surface.errors.extend(report.errors)
    return surface
