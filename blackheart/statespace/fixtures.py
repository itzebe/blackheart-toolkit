"""Deliberately-vulnerable multi-step fixtures and their secure controls.

These are the engine's own local test fixtures -- no network, no real funds, no
production system. Each is a *multi-step* scenario: the vulnerability is not
visible in any single operation, only in a sequence. That is the whole point --
it is the class of bug a per-function scanner misses.

Every fixture ships a **vulnerable** variant and a **guarded** control that
differs by exactly the defence. The engine must reproduce a violation on the
vulnerable variant and find *none* on the control (the non-vacuity / differential
test). A fixture that the control also "breaks" would be a badly specified
invariant, and the verifier rejects it -- so the controls are load-bearing.

Scenarios (chosen to be genuinely different from the existing fixtures, which
cover ERC4626 inflation, oracle, permit, proxy-init, reentrancy and access
control):

  * ``stale-authorization`` -- a right captured when a session opens is used after
    the right is revoked (a stale-state / privilege-change bug).
  * ``partial-failure``      -- a cancel refunds an escrow but leaves the credit
    recorded, so a later withdraw pays the same value twice (a non-atomic
    multi-step write).
  * ``cross-user-idor``      -- an object-scoped update never checks the caller
    owns the object, so one principal mutates another's object.

Each fixture implements the existing :class:`blackheart.invariants.engine.Target`
protocol (so the random baseline fuzzer can run it for a fair ablation) and adds
:meth:`model`, the richer description the state-space engine reads.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .model import SystemModel
from ..invariants.engine import InvariantSpec, OpSpec, PureState, Target


# ======================================================================= #
# 1. Stale authorization
# ======================================================================= #

@dataclass
class StaleAuthState:
    grant: dict[str, bool] = field(default_factory=dict)      # live right per actor
    session_grant: dict[str, bool] = field(default_factory=dict)  # right captured at open
    session_open: dict[str, bool] = field(default_factory=dict)
    balance: dict[str, int] = field(default_factory=dict)
    wallet: dict[str, int] = field(default_factory=dict)
    revoked: set = field(default_factory=set)
    revoked_withdrawals: int = 0


class StaleAuthVault(PureState, Target):
    """A vault whose session captures the withdraw right once and never refreshes it."""

    name = "stale-authorization"
    ATTACKER, OWNER = "attacker", "owner"
    ACTORS = [ATTACKER, OWNER]

    def reset(self) -> StaleAuthState:
        st = StaleAuthState()
        st.grant = {self.ATTACKER: True, self.OWNER: True}
        st.session_grant = {}
        st.session_open = {}
        st.balance = {self.ATTACKER: 1000, self.OWNER: 1000}
        st.wallet = {self.ATTACKER: 0, self.OWNER: 0}
        st.revoked = set()
        st.revoked_withdrawals = 0
        return st

    def model(self) -> SystemModel:
        m = SystemModel(
            target=self.name,
            summary="A vault where a withdrawal right is captured when a session opens; "
                    "the session must not remain usable after the right is revoked.",
            assets=["vault-balance"],
            trust_boundaries=["session layer <-> authorization store"],
            evidence=["fixture:blackheart/statespace/fixtures.py#StaleAuthVault"],
        )
        m.add_actor(self.ATTACKER, roles=("user",), unprivileged=True)
        m.add_actor(self.OWNER, roles=("owner",), unprivileged=False)
        m.add_operation("open_session", (), sensitive=False, effect="capture the current right",
                        guard="", source="fixture")
        m.add_operation("revoke", ("owner",), sensitive=True, asset="vault-balance",
                        effect="revoke the user's right", guard="owner-only", guard_roles=("owner",),
                        source="fixture")
        m.add_operation("withdraw", (), sensitive=True, asset="vault-balance",
                        precondition="the session holds a withdraw right",
                        effect="move balance to the wallet", guard="an active withdraw right",
                        guard_roles=("user", "owner"), source="fixture")
        m.add_transition("revoke-right", "owner-only", ("owner",), operation="revoke",
                         description="privileged revocation of a right")
        m.add_invariant("no-withdrawal-after-revoke",
                        "a right that has been revoked cannot be exercised afterwards",
                        applies_to=("vault-balance",), expression="no-withdrawal-after-revoke")
        m.intended_behaviours = []
        return m

    def ops(self) -> list[OpSpec]:
        return [
            OpSpec("open_session", [self.ATTACKER], {}, weight=2,
                   description="open a session, capturing the current right"),
            OpSpec("grant", [self.OWNER], {}, weight=1, description="grant the right"),
            OpSpec("revoke", [self.OWNER], {}, weight=3, description="revoke the right"),
            OpSpec("withdraw", [self.ATTACKER, self.OWNER], {"amount": [10, 100, 1000]},
                   weight=4, description="withdraw balance"),
        ]

    def _grant_is_live(self, st: StaleAuthState, actor: str) -> bool:
        """The vulnerable vault trusts the right captured at session open."""
        return bool(st.session_grant.get(actor, False))

    def invariants(self) -> list[InvariantSpec]:
        return [InvariantSpec(
            "no-withdrawal-after-revoke",
            "a revoked right is never exercised",
            lambda st: st.revoked_withdrawals == 0,
            severity_if_broken="high",
        )]

    def step(self, st: StaleAuthState, op: str, actor: str, params: dict[str, Any]) -> None:
        if op == "open_session":
            st.session_open[actor] = True
            st.session_grant[actor] = st.grant.get(actor, False)
        elif op == "revoke":
            # The owner revokes the *user's* withdrawal right (a privileged
            # action against another principal's permission).
            st.grant[self.ATTACKER] = False
            st.revoked.add(self.ATTACKER)
        elif op == "withdraw":
            amount = int(params.get("amount", 0))
            if not self._grant_is_live(st, actor):
                return
            amount = min(amount, st.balance.get(actor, 0))
            st.balance[actor] = st.balance.get(actor, 0) - amount
            st.wallet[actor] = st.wallet.get(actor, 0) + amount
            if actor in st.revoked:
                st.revoked_withdrawals += 1

    def snapshot(self, st: StaleAuthState) -> dict[str, Any]:
        return {
            "balance": dict(st.balance),
            "wallet": dict(st.wallet),
            "revoked": sorted(st.revoked),
            "revoked_withdrawals": st.revoked_withdrawals,
        }


class GuardedStaleAuthVault(StaleAuthVault):
    """Same vault, but a withdrawal always re-checks the *live* right."""

    name = "stale-authorization-guarded"

    def _grant_is_live(self, st: StaleAuthState, actor: str) -> bool:
        return bool(st.grant.get(actor, False))


# ======================================================================= #
# 2. Partial failure -> value duplication
# ======================================================================= #

@dataclass
class TwoPhaseState:
    wallet: int = 0
    escrow: int = 0
    credit: int = 0
    initial: int = 0
    withdrawn: int = 0
    cancelled: bool = False


class TwoPhaseSettlement(PureState, Target):
    """A settlement whose cancel refunds the escrow but leaves the credit recorded."""

    name = "partial-failure"
    ACTOR = "attacker"
    ACTORS = [ACTOR]

    def reset(self) -> TwoPhaseState:
        st = TwoPhaseState()
        st.wallet = 1000
        st.initial = 1000
        return st

    def model(self) -> SystemModel:
        m = SystemModel(
            target=self.name,
            summary="A two-phase settlement: initiate escrows value and records a credit; "
                    "cancel must undo the credit atomically or value is duplicated.",
            assets=["user-value"],
            trust_boundaries=["settlement escrow <-> user credit ledger"],
            evidence=["fixture:blackheart/statespace/fixtures.py#TwoPhaseSettlement"],
        )
        m.add_actor(self.ACTOR, roles=("user",), unprivileged=True)
        m.add_operation("initiate", ("user",), sensitive=True, asset="user-value",
                        effect="move wallet -> escrow and record a credit", guard="",
                        source="fixture")
        m.add_operation("cancel", ("user",), sensitive=True, asset="user-value",
                        effect="refund escrow -> wallet", guard="", source="fixture")
        m.add_operation("withdraw", ("user",), sensitive=True, asset="user-value",
                        precondition="a credit is recorded",
                        effect="move credit -> wallet", guard="", source="fixture")
        m.add_transition("cancel-settlement", "state must be escrowed", ("user",), operation="cancel",
                         description="refund a pending settlement")
        m.add_invariant("no-value-duplication",
                        "value is never withdrawn more than once (wallet never exceeds the initial deposit)",
                        applies_to=("user-value",), expression="no-value-duplication")
        return m

    def ops(self) -> list[OpSpec]:
        return [
            OpSpec("initiate", [self.ACTOR], {"amount": [100, 500, 1000]}, weight=3,
                   description="initiate a settlement"),
            OpSpec("cancel", [self.ACTOR], {}, weight=3, description="cancel the settlement"),
            OpSpec("withdraw", [self.ACTOR], {}, weight=3, description="withdraw recorded credit"),
        ]

    def _cancel(self, st: TwoPhaseState) -> None:
        """The vulnerable cancel refunds the escrow unconditionally and leaves the
        recorded credit intact, so a later withdraw pays the same value again."""
        st.wallet += st.escrow
        st.escrow = 0
        st.cancelled = True

    def invariants(self) -> list[InvariantSpec]:
        return [InvariantSpec(
            "no-value-duplication",
            "the wallet never exceeds the initial deposit",
            lambda st: st.wallet <= st.initial,
            severity_if_broken="high",
        )]

    def step(self, st: TwoPhaseState, op: str, actor: str, params: dict[str, Any]) -> None:
        if op == "initiate":
            amount = int(params.get("amount", 0))
            amount = min(amount, st.wallet)
            st.wallet -= amount
            st.escrow += amount
            st.credit += amount
            st.cancelled = False
        elif op == "cancel":
            self._cancel(st)
        elif op == "withdraw":
            st.wallet += st.credit
            st.withdrawn += st.credit
            st.credit = 0

    def snapshot(self, st: TwoPhaseState) -> dict[str, Any]:
        return {"wallet": st.wallet, "escrow": st.escrow, "credit": st.credit,
                "withdrawn": st.withdrawn, "initial": st.initial}


class GuardedTwoPhaseSettlement(TwoPhaseSettlement):
    """Same settlement, but cancel is atomic: it clears the recorded credit, and it
    only refunds escrow that is still held (never value already withdrawn)."""

    name = "partial-failure-guarded"

    def _cancel(self, st: TwoPhaseState) -> None:
        refundable = min(st.escrow, st.credit)
        st.wallet += refundable
        st.escrow -= refundable
        st.credit -= refundable
        st.cancelled = True


# ======================================================================= #
# 3. Cross-user object access (IDOR)
# ======================================================================= #

@dataclass
class ObjectState:
    owner: dict[str, str] = field(default_factory=dict)   # object id -> owner
    value: dict[str, int] = field(default_factory=dict)
    foreign_writes: int = 0


class CrossUserObjects(PureState, Target):
    """An object store whose update never checks the caller owns the object."""

    name = "cross-user-idor"
    VICTIM, ATTACKER = "victim", "attacker"
    ACTORS = [VICTIM, ATTACKER]

    def reset(self) -> ObjectState:
        st = ObjectState()
        st.owner = {}
        st.value = {}
        st.foreign_writes = 0
        return st

    def model(self) -> SystemModel:
        m = SystemModel(
            target=self.name,
            summary="An object store: objects belong to a principal, and only that "
                    "principal may update them.",
            assets=["object-value"],
            trust_boundaries=["principal identity <-> object ownership"],
            evidence=["fixture:blackheart/statespace/fixtures.py#CrossUserObjects"],
        )
        m.add_actor(self.VICTIM, roles=("user",), unprivileged=True)
        m.add_actor(self.ATTACKER, roles=("user",), unprivileged=True)
        m.add_operation("create_object", ("user",), sensitive=False,
                        effect="create an object owned by the caller", source="fixture")
        m.add_operation("update_object", ("user",), sensitive=True, asset="object-value",
                        precondition="the object exists and is owned by the caller",
                        effect="write the object's value",
                        guard="object-ownership", guard_roles=("user",), source="fixture")
        m.add_invariant("object-writes-only-by-owner",
                        "only an object's owner may write it",
                        applies_to=("object-value",), expression="object-writes-only-by-owner")
        return m

    def ops(self) -> list[OpSpec]:
        return [
            OpSpec("create_object", [self.VICTIM, self.ATTACKER], {}, weight=2,
                   description="create an object owned by the caller"),
            OpSpec("update_object", [self.VICTIM, self.ATTACKER],
                   {"obj": [1, 2], "value": [1, 100, 9999]},
                   weight=4, description="update an object's value"),
        ]

    def _check_owner(self, st: ObjectState, actor: str, obj: str) -> bool:
        """The vulnerable store accepts the write regardless of owner."""
        return True

    def invariants(self) -> list[InvariantSpec]:
        return [InvariantSpec(
            "object-writes-only-by-owner",
            "no non-owner writes an object",
            lambda st: st.foreign_writes == 0,
            severity_if_broken="high",
        )]

    def step(self, st: ObjectState, op: str, actor: str, params: dict[str, Any]) -> None:
        if op == "create_object":
            oid = f"obj-{len(st.owner) + 1}"
            st.owner[oid] = actor
            st.value[oid] = 0
        elif op == "update_object":
            oid = f"obj-{int(params.get('obj', 1))}"
            if oid not in st.owner:
                return
            if not self._check_owner(st, actor, oid):
                return
            st.value[oid] = int(params.get("value", 0))
            if st.owner[oid] != actor:
                st.foreign_writes += 1

    def snapshot(self, st: ObjectState) -> dict[str, Any]:
        return {"owner": dict(st.owner), "value": dict(st.value),
                "foreign_writes": st.foreign_writes}


class GuardedCrossUserObjects(CrossUserObjects):
    """Same store, but update enforces object ownership."""

    name = "cross-user-idor-guarded"

    def _check_owner(self, st: ObjectState, actor: str, obj: str) -> bool:
        return st.owner.get(obj) == actor


# ======================================================================= #
# Registry of fixture pairs
# ======================================================================= #

# (vulnerable, guarded, invariant, description) -- one row per scenario.
FIXTURE_PAIRS: list[tuple[str, str, str, str]] = [
    ("stale-authorization", "stale-authorization-guarded", "no-withdrawal-after-revoke",
     "a right captured at session open is exercised after revocation"),
    ("partial-failure", "partial-failure-guarded", "no-value-duplication",
     "cancel refunds the escrow but leaves the credit, so value is withdrawn twice"),
    ("cross-user-idor", "cross-user-idor-guarded", "object-writes-only-by-owner",
     "an object-scoped update never checks the caller owns the object"),
]

_FIXTURES: dict[str, type] = {
    "stale-authorization": StaleAuthVault,
    "stale-authorization-guarded": GuardedStaleAuthVault,
    "partial-failure": TwoPhaseSettlement,
    "partial-failure-guarded": GuardedTwoPhaseSettlement,
    "cross-user-idor": CrossUserObjects,
    "cross-user-idor-guarded": GuardedCrossUserObjects,
}


def fixture_names() -> list[str]:
    return list(_FIXTURES)


def make_fixture(name: str) -> Target:
    if name not in _FIXTURES:
        raise KeyError(f"unknown fixture: {name} (known: {', '.join(fixture_names())})")
    return _FIXTURES[name]()
