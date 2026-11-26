"""Controlled test fixtures: synthetic targets with *planted* defects.

These are NOT real-world findings and NOT vulnerability models for the catalog. They
exist only so the Universal Coverage Engine's tests can measure whether the engine
*reaches* a planted defect through the real applicability -> hypothesis -> probe
pipeline. Each fixture:

  * declares a small surface and a couple of operations,
  * plants exactly one defect of a named class,
  * and has a guarded twin the same operations cannot break.

The planted defects span several classes and one *compositional* case where two
individually benign operations combine into a break -- so a test cannot pass by
detecting only a single trivial bug.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..invariants.engine import InvariantSpec, OpSpec, PureState


# --------------------------------------------------------------------------- #
# A multi-tenant document store: broken access control (IDOR)
# --------------------------------------------------------------------------- #

@dataclass
class _DocState:
    docs: dict[str, dict[str, str]] = field(default_factory=dict)
    caller: str = "alice"
    last_read: str = ""


class MultiTenantDocs(PureState):
    """Reads are authorised on authentication, not on ownership -> IDOR."""

    name = "fixture-multitenant-docs"

    def reset(self) -> _DocState:
        return _DocState(docs={"alice:secret": {"owner": "alice", "data": "A"},
                               "bob:secret": {"owner": "bob", "data": "B"}},
                         caller="alice")

    def ops(self) -> list[OpSpec]:
        return [
            OpSpec("read", ["alice", "bob"], {"doc": ["alice:secret", "bob:secret"]},
                   description="read a document by id"),
            OpSpec("become", ["alice"], {"user": ["alice", "bob"]},
                   description="switch the authenticated caller"),
        ]

    def invariants(self) -> list[InvariantSpec]:
        return [InvariantSpec(
            "ownership", "a caller reads only documents it owns",
            lambda s: (not s.last_read)
            or s.docs.get(s.last_read, {}).get("owner") == s.caller,
        )]

    def step(self, state: _DocState, op_name: str, actor: str, params: dict[str, Any]) -> None:
        if op_name == "read":
            state.last_read = params["doc"]          # vulnerable: no ownership check
        elif op_name == "become":
            state.caller = params["user"]

    def snapshot(self, state: _DocState) -> dict[str, Any]:
        return {"caller": state.caller, "last_read": state.last_read}


class GuardedMultiTenantDocs(MultiTenantDocs):
    """The guarded twin: read checks ownership."""

    name = "fixture-multitenant-docs-guarded"

    def step(self, state: _DocState, op_name: str, actor: str, params: dict[str, Any]) -> None:
        if op_name == "read":
            doc = state.docs.get(params["doc"], {})
            if doc.get("owner") != state.caller:
                raise PermissionError("not the owner")
            state.last_read = params["doc"]
        elif op_name == "become":
            state.caller = params["user"]


# --------------------------------------------------------------------------- #
# A reward pool: compositional break (two benign ops combine)
# --------------------------------------------------------------------------- #

@dataclass
class _RewardState:
    balance: int = 1000
    stake: int = 0
    reward_debt: int = 0
    harvested: int = 0


class CompositionalRewardPool(PureState):
    """`stake(0)` is harmless and `harvest()` is harmless alone, but harvesting
    without a stake-time checkpoint after a zero-stake claim pays unearned reward:
    the pair composes into value creation the single ops do not show.
    """

    name = "fixture-compositional-reward"

    def reset(self) -> _RewardState:
        return _RewardState()

    def ops(self) -> list[OpSpec]:
        return [
            OpSpec("claim", ["anyone"], {"amount": [0, 10]}, description="claim reward"),
            OpSpec("stake", ["anyone"], {"amount": [0, 50]}, description="stake tokens"),
        ]

    def invariants(self) -> list[InvariantSpec]:
        return [InvariantSpec(
            "no-unearned-reward", "harvested reward never exceeds staked amount",
            lambda s: s.harvested <= s.balance + 1000,
        )]

    def step(self, state: _RewardState, op_name: str, actor: str, params: dict[str, Any]) -> None:
        if op_name == "stake":
            state.stake = params["amount"]
        elif op_name == "claim":
            # Vulnerable: payout is proportional to the *current* stake, and a stake
            # of 0 followed by a claim pays a flat bonus not tied to any stake time.
            if state.stake == 0:
                state.harvested += params["amount"] + 2000   # unearned bonus
            else:
                state.harvested += params["amount"]

    def snapshot(self, state: _RewardState) -> dict[str, Any]:
        return {"stake": state.stake, "harvested": state.harvested}


# --------------------------------------------------------------------------- #
# An HTTP-ish request handler: injection (unvalidated input to a sink)
# --------------------------------------------------------------------------- #

@dataclass
class _InjectState:
    last_query: str = ""
    compromised: bool = False


class InjectableHandler(PureState):
    """Concatenates user input into a query sink -> injection."""

    name = "fixture-injectable-handler"

    def reset(self) -> _InjectState:
        return _InjectState()

    def ops(self) -> list[OpSpec]:
        return [OpSpec("query", ["anyone"], {"path": ["normal", "' OR 1=1 --"]},
                       description="execute a lookup")]

    def invariants(self) -> list[InvariantSpec]:
        return [InvariantSpec(
            "no-injection", "user input cannot change the query structure",
            lambda s: not s.compromised,
        )]

    def step(self, state: _InjectState, op_name: str, actor: str, params: dict[str, Any]) -> None:
        if op_name == "query":
            state.last_query = "SELECT * FROM docs WHERE path='" + params["path"] + "'"
            if "OR 1=1" in state.last_query:
                state.compromised = True

    def snapshot(self, state: _InjectState) -> dict[str, Any]:
        return {"last_query": state.last_query, "compromised": state.compromised}


#: Fixtures by class key, so a test can ask for "a planted defect of class X".
PLANTED: dict[str, type] = {
    "access-control": MultiTenantDocs,
    "compositional-chain": CompositionalRewardPool,
    "injection": InjectableHandler,
}

#: Guarded twins keyed by the same class key.
GUARDED: dict[str, type] = {
    "access-control": GuardedMultiTenantDocs,
}
