"""Executable targets for three logic classes the engine must be able to
*break*, not merely describe:

  * ``rounding-precision``  -- a vault whose deposit mints shares with a
    **ceiling** instead of a floor, so an attacker deposits a hair many times,
    each deposit rounding up to a whole share worth far more than it paid, then
    redeems and drains the pool (the classic rounding-direction bug).
  * ``ordering-timing``     -- a settlement pool whose ``claim`` ignores the
    obligations it has already recognised, so an attacker front-runs the
    settlement and drains the pool before the owed party is paid (the classic
    "drain before the debt is booked" ordering bug).
  * ``info-disclosure``     -- an object store whose read is gated on being
    *authenticated* rather than on *owning the object*, so any caller can read
    another principal's record (the classic IDOR / object-level authorization
    gap).

Each ships a **vulnerable** variant (the modelled attack succeeds, so the
stateful fuzzer finds a genuine invariant violation) and a **guarded** variant
(the single missing control is restored, so the same invariants hold -- the
non-vacuity control). The two variants differ *only* in that one control, so the
contrast isolates the defect.

These close the three objective categories that previously existed only as prose
in :mod:`blackheart.objectives`; see :mod:`blackheart.invariants.coverage`. They
are engine fixtures -- deterministic, no I/O, no network, no real funds.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .engine import InvariantSpec, OpSpec, PureState, Target


# --------------------------------------------------------------------------- #
# 1. Rounding precision -- deposit mints shares with a ceiling
# --------------------------------------------------------------------------- #

@dataclass
class RoundingState:
    total_shares: int = 0
    total_assets: int = 0
    shares: dict[str, int] = field(default_factory=dict)      # vault shares per actor
    wallet: dict[str, int] = field(default_factory=dict)      # liquid underlying
    initial: dict[str, int] = field(default_factory=dict)     # starting net capital
    deposited: dict[str, int] = field(default_factory=dict)
    last_shares: int = 0

    def redeemable(self, who: str) -> int:
        if self.total_shares == 0:
            return 0
        return (self.shares.get(who, 0) * self.total_assets) // self.total_shares


class RoundingVault(PureState, Target):
    """A vault whose ``deposit`` rounds share issuance *up* (in the user's favour).

    A correctly-rounded vault floors the shares it issues, so a sub-share deposit
    buys nothing and the residual stays with the pool. Rounding up lets an
    attacker buy a whole share for a fraction of its value, repeat it, and redeem.
    """

    name = "rounding-precision"
    ACTORS = ["attacker", "victim"]

    def reset(self) -> RoundingState:
        st = RoundingState()
        # A pre-existing pool with accrued yield: 1000 shares backing 100000
        # underlying (share price 100). The victim holds the whole pool.
        st.total_shares = 1000
        st.total_assets = 100000
        st.shares = {"attacker": 0, "victim": 1000}
        st.wallet = {"attacker": 1000, "victim": 0}
        st.initial = {"attacker": 1000, "victim": 100000}
        st.deposited = {a: 0 for a in self.ACTORS}
        st.last_shares = 0
        return st

    def ops(self) -> list[OpSpec]:
        return [
            OpSpec("deposit", self.ACTORS, {"amount": [1, 2, 5, 10, 100]},
                   weight=5, description="deposit underlying, receive shares"),
            OpSpec("withdraw", self.ACTORS, {"shares": [1, 2, 5, 10, 500]},
                   weight=4, description="redeem shares for underlying"),
        ]

    # -- the only difference between the vulnerable and guarded models -- #
    def _shares_for(self, amount: int, st: RoundingState) -> int:
        """Vulnerable: round the issued shares UP, over-crediting the depositor."""
        if st.total_shares == 0:
            return amount
        return -(-(amount * st.total_shares) // st.total_assets)   # ceil

    def invariants(self) -> list[InvariantSpec]:
        return [
            InvariantSpec(
                "no-material-attacker-profit",
                "the attacker's net value never exceeds their starting value by more "
                "than 0.1% (dust-level rounding is ignored; real extraction is not)",
                self._no_material_attacker_profit,
                severity_if_broken="high",
            ),
            InvariantSpec(
                "no-material-victim-loss",
                "no actor who never deposited loses more than 1% of their starting value",
                self._no_material_victim_loss,
                severity_if_broken="high",
            ),
        ]

    ATTACKER_MATERIAL_BPS = 10    # 0.1% of attacker capital counts as profit
    VICTIM_MATERIAL_BPS = 100     # 1% of victim capital counts as loss
    BPS_DENOM = 10_000

    def _no_material_attacker_profit(self, st: RoundingState) -> bool:
        a = "attacker"
        net = st.wallet.get(a, 0) + st.redeemable(a)
        gain = net - st.initial[a]
        threshold = (st.initial[a] * self.ATTACKER_MATERIAL_BPS) // self.BPS_DENOM
        return gain <= threshold

    def _no_material_victim_loss(self, st: RoundingState) -> bool:
        for a in st.initial:
            if st.deposited.get(a, 0) > 0:
                continue
            net = st.wallet.get(a, 0) + st.redeemable(a)
            loss = st.initial[a] - net
            threshold = (st.initial[a] * self.VICTIM_MATERIAL_BPS) // self.BPS_DENOM
            if loss > threshold:
                return False
        return True

    def step(self, st: RoundingState, op: str, actor: str, params: dict[str, Any]) -> None:
        st.last_shares = 0
        if op == "deposit":
            amount = min(int(params["amount"]), st.wallet.get(actor, 0))
            if amount <= 0:
                return
            shares = self._shares_for(amount, st)
            if shares <= 0:
                # A correctly-guarded vault refuses a deposit that would mint no
                # shares; the vulnerable one never reaches here.
                return
            st.wallet[actor] -= amount
            st.total_assets += amount
            st.total_shares += shares
            st.shares[actor] = st.shares.get(actor, 0) + shares
            st.deposited[actor] = st.deposited.get(actor, 0) + amount
            st.last_shares = shares
        elif op == "withdraw":
            shares = min(int(params["shares"]), st.shares.get(actor, 0))
            if shares <= 0 or st.total_shares == 0:
                return
            assets = (shares * st.total_assets) // st.total_shares
            st.shares[actor] -= shares
            st.total_shares -= shares
            st.total_assets -= assets
            st.wallet[actor] = st.wallet.get(actor, 0) + assets

    def snapshot(self, st: RoundingState) -> dict[str, Any]:
        return {
            "total_shares": st.total_shares,
            "total_assets": st.total_assets,
            "shares": dict(st.shares),
            "wallet": dict(st.wallet),
            "redeemable": {a: st.redeemable(a) for a in st.initial},
            "last_shares": st.last_shares,
        }


class GuardedRoundingVault(RoundingVault):
    """Same vault, but share issuance is floored and a zero-share deposit is refused."""

    name = "rounding-guarded"

    def _shares_for(self, amount: int, st: RoundingState) -> int:
        if st.total_shares == 0:
            return amount
        return (amount * st.total_shares) // st.total_assets   # floor


# --------------------------------------------------------------------------- #
# 2. Ordering / timing -- an offer accepted after its deadline
# --------------------------------------------------------------------------- #

@dataclass
class OfferState:
    clock: int = 0
    deadline: int = 1
    pool: int = 1000
    wallet: dict[str, int] = field(default_factory=dict)
    expired_accepts: int = 0        # acceptances made after the deadline
    valid_accepts: int = 0
    last_accept: int = 0


class ExpiringOffer(PureState, Target):
    """A pool offer whose ``accept`` ignores the deadline.

    The offer is valid only while ``clock <= deadline``. A correct ``accept``
    checks the clock; the vulnerable one lets an attacker race the deadline and
    accept a *stale* offer after it has expired, draining the pool. The clock is
    advanced by a ``tick`` any actor may perform, so the deadline is a genuine
    ordering/timing lever rather than a fixed constant.
    """

    name = "timing-expiry"
    ACTORS = ["attacker", "victim"]

    def reset(self) -> OfferState:
        st = OfferState()
        st.clock = 0
        st.deadline = 1
        st.pool = 1000
        st.wallet = {a: 0 for a in self.ACTORS}
        st.expired_accepts = 0
        st.valid_accepts = 0
        st.last_accept = 0
        return st

    def ops(self) -> list[OpSpec]:
        return [
            OpSpec("tick", self.ACTORS, {}, weight=5,
                   description="advance the clock toward the offer deadline"),
            OpSpec("accept_offer", ["attacker"], {}, weight=4,
                   description="accept the offer and take the pool"),
        ]

    # -- the only difference between the vulnerable and guarded models -- #
    def _accept_allowed(self, st: OfferState) -> bool:
        """Vulnerable: the deadline is never checked."""
        return st.pool > 0

    def invariants(self) -> list[InvariantSpec]:
        return [
            InvariantSpec(
                "no-expired-acceptance",
                "an offer is never accepted after its deadline has passed",
                lambda st: st.expired_accepts == 0,
                severity_if_broken="high",
            ),
        ]

    def step(self, st: OfferState, op: str, actor: str, params: dict[str, Any]) -> None:
        st.last_accept = 0
        if op == "tick":
            st.clock += 1
        elif op == "accept_offer":
            if not self._accept_allowed(st):
                return
            expired = st.clock > st.deadline
            amount = st.pool
            st.pool = 0
            st.wallet[actor] = st.wallet.get(actor, 0) + amount
            st.last_accept = amount
            if expired:
                st.expired_accepts += 1
            else:
                st.valid_accepts += 1

    def snapshot(self, st: OfferState) -> dict[str, Any]:
        return {
            "clock": st.clock,
            "deadline": st.deadline,
            "pool": st.pool,
            "wallet": dict(st.wallet),
            "expired_accepts": st.expired_accepts,
            "valid_accepts": st.valid_accepts,
            "last_accept": st.last_accept,
        }


class GuardedExpiringOffer(ExpiringOffer):
    """Same offer, but ``accept`` is refused once the deadline has passed."""

    name = "timing-guarded"

    def _accept_allowed(self, st: OfferState) -> bool:
        return st.clock <= st.deadline and st.pool > 0


# --------------------------------------------------------------------------- #
# 3. Info disclosure -- object read gated on authentication, not ownership
# --------------------------------------------------------------------------- #

@dataclass
class IdorState:
    objects: dict[str, dict[str, Any]] = field(default_factory=dict)
    unauthorized_reads: int = 0
    authorized_reads: int = 0
    last_read_id: str = ""
    last_read_secret: int = 0


class ObjectStore(PureState, Target):
    """A record store whose read checks *who you are*, not *what you own*.

    Any authenticated caller may read any object by id, so an attacker enumerates
    ids and reads another principal's record -- the classic IDOR.
    """

    name = "info-disclosure"
    ACTORS = ["attacker", "victim"]

    def reset(self) -> IdorState:
        st = IdorState()
        st.objects = {
            "1": {"owner": "victim", "secret": 424242},
            "2": {"owner": "attacker", "secret": 111},
        }
        st.unauthorized_reads = 0
        st.authorized_reads = 0
        st.last_read_id = ""
        st.last_read_secret = 0
        return st

    def ops(self) -> list[OpSpec]:
        return [
            OpSpec("read", self.ACTORS, {"object_id": ["1", "2"]},
                   weight=5, description="read an object's record by id"),
        ]

    # -- the only difference between the vulnerable and guarded models -- #
    def _may_read(self, st: IdorState, actor: str, object_id: str) -> bool:
        """Vulnerable: any authenticated caller may read any object."""
        return object_id in st.objects

    def invariants(self) -> list[InvariantSpec]:
        return [
            InvariantSpec(
                "object-read-only-by-owner",
                "a principal only ever reads records that belong to them",
                lambda st: st.unauthorized_reads == 0,
                severity_if_broken="high",
            ),
        ]

    def step(self, st: IdorState, op: str, actor: str, params: dict[str, Any]) -> None:
        if op != "read":
            return
        object_id = str(params["object_id"])
        if not self._may_read(st, actor, object_id):
            return
        record = st.objects.get(object_id)
        if record is None:
            return
        st.last_read_id = object_id
        st.last_read_secret = int(record["secret"])
        if record["owner"] == actor:
            st.authorized_reads += 1
        else:
            st.unauthorized_reads += 1

    def snapshot(self, st: IdorState) -> dict[str, Any]:
        return {
            "objects": {k: dict(v) for k, v in st.objects.items()},
            "unauthorized_reads": st.unauthorized_reads,
            "authorized_reads": st.authorized_reads,
            "last_read_id": st.last_read_id,
            "last_read_secret": st.last_read_secret,
        }


class GuardedObjectStore(ObjectStore):
    """Same store, but a read is gated on owning the object (object-level authz)."""

    name = "info-guarded"

    def _may_read(self, st: IdorState, actor: str, object_id: str) -> bool:
        record = st.objects.get(object_id)
        return record is not None and record["owner"] == actor
