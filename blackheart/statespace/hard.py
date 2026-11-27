"""Hard scenarios with decoy operations, for the budget-controlled ablation.

The development and held-out fixtures are small: a random fuzzer stumbles onto
their 3-step bugs within a few hundred sequences, so they do not separate
*model-guided* search from *random* search. These scenarios do.

Each hard scenario is the same kind of multi-step bug, but embedded among many
**decoy operations** that are individually plausible and never participate in the
exploit. Random selection must land on the exact ordered subsequence out of the
much larger operation set; model-guided search enumerates the sensitive operations
and their orderings directly. The gap between the two on these scenarios is the
honest, measurable value of the model guidance -- and the benchmark reports it as
sequences-to-detection, not as a rate that both engines reach given unlimited
budget.

Same rules: local, no network, no real funds; a vulnerable variant and a guarded
control.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .model import SystemModel
from ..invariants.engine import InvariantSpec, OpSpec, PureState, Target

# The decoy operations: each looks like a normal workflow action and is harmless.
_DECOYS: list[tuple[str, dict[str, list[Any]]]] = [
    ("view_balance", {}),
    ("update_profile", {"field": [1, 2, 3]}),
    ("list_history", {}),
    ("set_preference", {"value": [1, 2, 3]}),
    ("ping", {}),
    ("export_csv", {}),
    ("refresh_token", {}),
    ("log_event", {"kind": [1, 2]}),
]


# ======================================================================= #
# Hard A: stale authorization hidden among decoys
# ======================================================================= #

@dataclass
class HardStaleState:
    grant: dict = field(default_factory=dict)
    session_grant: dict = field(default_factory=dict)
    balance: dict = field(default_factory=dict)
    wallet: dict = field(default_factory=dict)
    revoked: set = field(default_factory=set)
    revoked_withdrawals: int = 0


class HardStaleAuth(PureState, Target):
    """Stale-authorization bug with eight decoy operations around it."""

    name = "hard-stale-authorization"
    ATTACKER, OWNER = "attacker", "owner"
    ACTORS = [ATTACKER, OWNER]

    def reset(self) -> HardStaleState:
        st = HardStaleState()
        st.grant = {self.ATTACKER: True, self.OWNER: True}
        st.session_grant = {}
        st.balance = {self.ATTACKER: 1000, self.OWNER: 1000}
        st.wallet = {self.ATTACKER: 0, self.OWNER: 0}
        st.revoked = set()
        return st

    def model(self) -> SystemModel:
        m = SystemModel(
            target=self.name,
            summary="A stale-authorization vault embedded among decoy operations.",
            assets=["vault-balance"],
            trust_boundaries=["session layer <-> authorization store"],
            evidence=["fixture:blackheart/statespace/hard.py#HardStaleAuth"],
        )
        m.add_actor(self.ATTACKER, roles=("user",), unprivileged=True)
        m.add_actor(self.OWNER, roles=("owner",), unprivileged=False)
        m.add_operation("open_session", (), sensitive=False,
                        effect="capture the current right", source="fixture")
        m.add_operation("revoke", ("owner",), sensitive=True, asset="vault-balance",
                        effect="revoke the user's right", guard="owner-only",
                        guard_roles=("owner",), source="fixture")
        m.add_operation("withdraw", (), sensitive=True, asset="vault-balance",
                        precondition="the session holds a withdraw right",
                        effect="move balance to the wallet", guard="an active withdraw right",
                        guard_roles=("user", "owner"), source="fixture")
        for name, domain in _DECOYS:
            m.add_operation(name, (), sensitive=False, effect="decoy (no security effect)",
                            source="fixture")
        m.add_transition("revoke-right", "owner-only", ("owner",), operation="revoke",
                         description="privileged revocation")
        m.add_invariant("no-withdrawal-after-revoke",
                        "a revoked right is never exercised",
                        applies_to=("vault-balance",), expression="no-withdrawal-after-revoke")
        return m

    def ops(self) -> list[OpSpec]:
        ops = [
            OpSpec("open_session", [self.ATTACKER], {}, weight=1, description="open session"),
            OpSpec("revoke", [self.OWNER], {}, weight=1, description="revoke right"),
            OpSpec("withdraw", [self.ATTACKER, self.OWNER], {"amount": [10, 100, 1000]},
                   weight=1, description="withdraw"),
        ]
        ops += [OpSpec(n, [self.ATTACKER, self.OWNER], dict(d), weight=1, description="decoy")
                for n, d in _DECOYS]
        return ops

    def _grant_is_live(self, st: HardStaleState, actor: str) -> bool:
        return bool(st.session_grant.get(actor, False))

    def invariants(self) -> list[InvariantSpec]:
        return [InvariantSpec("no-withdrawal-after-revoke", "a revoked right is never used",
                              lambda st: st.revoked_withdrawals == 0, severity_if_broken="high")]

    def step(self, st: HardStaleState, op: str, actor: str, params: dict[str, Any]) -> None:
        if op == "open_session":
            st.session_grant[actor] = st.grant.get(actor, False)
        elif op == "revoke":
            st.grant[self.ATTACKER] = False
            st.revoked.add(self.ATTACKER)
        elif op == "withdraw":
            if not self._grant_is_live(st, actor):
                return
            amount = min(int(params.get("amount", 0)), st.balance.get(actor, 0))
            st.balance[actor] -= amount
            st.wallet[actor] = st.wallet.get(actor, 0) + amount
            if actor in st.revoked:
                st.revoked_withdrawals += 1

    def snapshot(self, st: HardStaleState) -> dict[str, Any]:
        return {"balance": dict(st.balance), "wallet": dict(st.wallet),
                "revoked": sorted(st.revoked), "revoked_withdrawals": st.revoked_withdrawals}


class GuardedHardStaleAuth(HardStaleAuth):
    name = "hard-stale-authorization-guarded"

    def _grant_is_live(self, st: HardStaleState, actor: str) -> bool:
        return bool(st.grant.get(actor, False))


# ======================================================================= #
# Hard B: partial-failure duplication hidden among decoys
# ======================================================================= #

@dataclass
class HardTwoPhaseState:
    wallet: int = 0
    escrow: int = 0
    credit: int = 0
    initial: int = 0


class HardTwoPhase(PureState, Target):
    """Partial-failure duplication with eight decoy operations around it."""

    name = "hard-partial-failure"
    ACTOR = "attacker"
    ACTORS = [ACTOR]

    def reset(self) -> HardTwoPhaseState:
        st = HardTwoPhaseState()
        st.wallet = 1000
        st.initial = 1000
        return st

    def model(self) -> SystemModel:
        m = SystemModel(
            target=self.name,
            summary="A two-phase settlement with the duplication bug hidden among decoys.",
            assets=["user-value"],
            trust_boundaries=["escrow <-> credit ledger"],
            evidence=["fixture:blackheart/statespace/hard.py#HardTwoPhase"],
        )
        m.add_actor(self.ACTOR, roles=("user",), unprivileged=True)
        m.add_operation("initiate", ("user",), sensitive=True, asset="user-value",
                        effect="wallet -> escrow, record credit", source="fixture")
        m.add_operation("cancel", ("user",), sensitive=True, asset="user-value",
                        effect="refund escrow", source="fixture")
        m.add_operation("withdraw", ("user",), sensitive=True, asset="user-value",
                        precondition="a credit is recorded", effect="credit -> wallet",
                        source="fixture")
        for name, domain in _DECOYS:
            m.add_operation(name, (), sensitive=False, effect="decoy", source="fixture")
        m.add_invariant("no-value-duplication",
                        "the wallet never exceeds the initial deposit",
                        applies_to=("user-value",), expression="no-value-duplication")
        return m

    def ops(self) -> list[OpSpec]:
        ops = [
            OpSpec("initiate", [self.ACTOR], {"amount": [100, 500, 1000]}, weight=1,
                   description="initiate"),
            OpSpec("cancel", [self.ACTOR], {}, weight=1, description="cancel"),
            OpSpec("withdraw", [self.ACTOR], {}, weight=1, description="withdraw"),
        ]
        ops += [OpSpec(n, [self.ACTOR], dict(d), weight=1, description="decoy") for n, d in _DECOYS]
        return ops

    def _cancel(self, st: HardTwoPhaseState) -> None:
        st.wallet += st.escrow
        st.escrow = 0

    def invariants(self) -> list[InvariantSpec]:
        return [InvariantSpec("no-value-duplication", "wallet never exceeds initial",
                              lambda st: st.wallet <= st.initial, severity_if_broken="high")]

    def step(self, st: HardTwoPhaseState, op: str, actor: str, params: dict[str, Any]) -> None:
        if op == "initiate":
            amount = min(int(params.get("amount", 0)), st.wallet)
            st.wallet -= amount
            st.escrow += amount
            st.credit += amount
        elif op == "cancel":
            self._cancel(st)
        elif op == "withdraw":
            st.wallet += st.credit
            st.credit = 0

    def snapshot(self, st: HardTwoPhaseState) -> dict[str, Any]:
        return {"wallet": st.wallet, "escrow": st.escrow, "credit": st.credit,
                "initial": st.initial}


class GuardedHardTwoPhase(HardTwoPhase):
    name = "hard-partial-failure-guarded"

    def _cancel(self, st: HardTwoPhaseState) -> None:
        refundable = min(st.escrow, st.credit)
        st.wallet += refundable
        st.escrow -= refundable
        st.credit -= refundable


# ======================================================================= #
# Deep, state-gated escalation -- the scenario coverage guidance wins on.
# ======================================================================= #

#: The ordered escalation chain: each step only advances the stage if the
#: previous one already ran, so the exploit is reachable *only* by the exact
#: ordered subsequence. This is the shape a shallow random walk cannot reach and
#: a coverage-guided one can -- the point of the corpus fuzzer.
_ESCALATION = ["register", "verify", "upgrade", "open_vault", "set_delegate",
               "raise_limit", "bypass_guard", "withdraw_all"]

#: Ten decoy operations, so random selection must land on an 8-step ordered
#: subsequence out of eighteen operations -- the dilution that makes this a
#: genuine separation test.
_ESCALATION_DECOYS = [f"escalation_decoy{i}" for i in range(10)]


class DeepGatedState:
    stage: dict = field(default_factory=dict)          # actor -> steps completed
    balance: dict = field(default_factory=dict)
    withdrawn: dict = field(default_factory=dict)


class DeepGatedEscalation(PureState, Target):
    """An 8-step ordered escalation among decoys, guarded by stage order.

    The bug is a missing cap on the final withdrawal: an actor who has completed
    the whole escalation may withdraw more than their balance. It is *only*
    reachable by performing the eight operations in order -- any wrong-order step
    resets the actor's stage -- so the search must build the chain one transition
    at a time.
    """

    name = "deep-gated-escalation"
    ATTACKER, OWNER = "attacker", "owner"
    ACTORS = [ATTACKER, OWNER]

    def reset(self) -> DeepGatedState:
        st = DeepGatedState()
        st.stage = {self.ATTACKER: 0, self.OWNER: 0}
        st.balance = {self.ATTACKER: 100, self.OWNER: 100}
        st.withdrawn = {self.ATTACKER: 0, self.OWNER: 0}
        return st

    def model(self) -> SystemModel:
        m = SystemModel(
            target=self.name,
            summary="An 8-step ordered escalation among decoy operations.",
            assets=["vault-balance"],
            trust_boundaries=["staged onboarding <-> withdrawal authority"],
            evidence=["fixture:blackheart/statespace/hard.py#DeepGatedEscalation"],
        )
        m.add_actor(self.ATTACKER, roles=("user",), unprivileged=True)
        m.add_actor(self.OWNER, roles=("owner",), unprivileged=False)
        for i, name in enumerate(_ESCALATION):
            m.add_operation(name, ("user",), sensitive=(i == len(_ESCALATION) - 1),
                            asset="vault-balance",
                            effect=f"escalation step {i + 1} of {len(_ESCALATION)}",
                            precondition="the previous step completed", source="fixture")
        for name in _ESCALATION_DECOYS:
            m.add_operation(name, (), sensitive=False, effect="decoy", source="fixture")
        m.add_invariant("no-overdraw",
                        "a withdrawal never exceeds the actor's balance",
                        applies_to=("vault-balance",), expression="no-overdraw")
        return m

    def ops(self) -> list[OpSpec]:
        ops = [OpSpec(n, [self.ATTACKER], {}) for n in _ESCALATION]
        ops += [OpSpec(n, list(self.ACTORS), {}) for n in _ESCALATION_DECOYS]
        return ops

    def _advance(self, st: DeepGatedState, actor: str, op: str) -> None:
        idx = _ESCALATION.index(op)
        if st.stage.get(actor, 0) == idx:
            st.stage[actor] = idx + 1
            if op == _ESCALATION[-1]:
                # The bug: the final withdrawal is uncapped.
                st.withdrawn[actor] += 1000
        else:
            st.stage[actor] = 0

    def invariants(self) -> list[InvariantSpec]:
        return [InvariantSpec("no-overdraw", "withdrawal never exceeds balance",
                              lambda st: all(st.withdrawn[a] <= st.balance[a]
                                             for a in st.balance),
                              severity_if_broken="critical")]

    def step(self, st: DeepGatedState, op: str, actor: str, params: dict[str, Any]) -> None:
        if op in _ESCALATION:
            self._advance(st, actor, op)

    def snapshot(self, st: DeepGatedState) -> dict[str, Any]:
        return {"stage": dict(st.stage), "balance": dict(st.balance),
                "withdrawn": dict(st.withdrawn)}


class GuardedDeepGatedEscalation(DeepGatedEscalation):
    name = "deep-gated-escalation-guarded"

    def _advance(self, st: DeepGatedState, actor: str, op: str) -> None:
        idx = _ESCALATION.index(op)
        if st.stage.get(actor, 0) == idx:
            st.stage[actor] = idx + 1
            if op == _ESCALATION[-1]:
                # Guarded: the withdrawal is capped at the balance.
                st.withdrawn[actor] += min(1000, st.balance[actor])
        else:
            st.stage[actor] = 0


HARD_PAIRS: list[tuple[str, str, str, str]] = [
    ("hard-stale-authorization", "hard-stale-authorization-guarded",
     "no-withdrawal-after-revoke",
     "stale-authorization bug among 8 decoy operations"),
    ("hard-partial-failure", "hard-partial-failure-guarded",
     "no-value-duplication",
     "partial-failure duplication among 8 decoy operations"),
]

#: Fixtures whose bug is reachable *only* by a deep, ordered sequence, so the
#: enumerating explorer does not find them and the coverage-guided fuzzer is what
#: reaches them. Kept separate from :data:`HARD_PAIRS` -- whose contract is that
#: the explorer detects every vulnerable variant -- so the two contracts never
#: conflict. The coverage-guided ablation in ``blackheart/fuzz/benchmark.py``
#: runs over these.
DEEP_PAIRS: list[tuple[str, str, str, str]] = [
    ("deep-gated-escalation", "deep-gated-escalation-guarded",
     "no-overdraw",
     "8-step ordered escalation among 10 decoy operations (coverage-guided)"),
]

_HARD: dict[str, type] = {
    "hard-stale-authorization": HardStaleAuth,
    "hard-stale-authorization-guarded": GuardedHardStaleAuth,
    "hard-partial-failure": HardTwoPhase,
    "hard-partial-failure-guarded": GuardedHardTwoPhase,
    "deep-gated-escalation": DeepGatedEscalation,
    "deep-gated-escalation-guarded": GuardedDeepGatedEscalation,
}


def hard_names() -> list[str]:
    return list(_HARD)


def make_hard(name: str) -> Target:
    if name not in _HARD:
        raise KeyError(f"unknown hard fixture: {name} (known: {', '.join(hard_names())})")
    return _HARD[name]()
