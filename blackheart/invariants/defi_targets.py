"""Executable targets for eight more attack classes the engine must be able to
*break*, not merely describe:

  * ``cross-chain-replay``      -- a cross-domain message bridge that neither
    marks a message executed nor checks its destination domain, so an attacker
    replays an authorized message and executes it on the wrong chain.
  * ``amm-slippage``            -- an automated market maker whose swap output
    divides by the reserve instead of the reserve *plus the input*, overpaying
    the trader; a round trip extracts value from the pool.
  * ``silent-transfer-failure`` -- a bridge that credits a deposit regardless of
    whether the token transfer actually moved funds (unchecked return / non-standard
    token), minting credit that was never backed.
  * ``flashloan-governance``    -- a governor that counts a voter's *current*
    balance instead of a pre-proposal snapshot, so an attacker flash-borrows
    voting power, passes a proposal, and repays.
  * ``griefing-dos``            -- a liquidator whose liquidation path is blocked
    by any frozen position, so an attacker freezes their own position and
    permanently blocks liquidations (accruing bad debt).
  * ``reward-manipulation``     -- a rewards pool that fails to checkpoint a
    staker's reward debt on ``stake``, so an attacker stakes after a distribution
    and claims rewards they never accrued.
  * ``storage-collision``       -- a proxy whose implementation can write the
    reserved admin slot, letting unprivileged logic overwrite the owner.
  * ``decimals-mismatch``       -- a vault that assumes every token has 6 decimals,
    so an 18-decimal deposit is credited 1e12x its real value.

Each ships a **vulnerable** variant (the modelled attack succeeds, so the
stateful fuzzer finds a genuine invariant violation) and a **guarded** variant
(the single missing control is restored, so the same invariants hold -- the
non-vacuity control). The two variants differ *only* in that one control, so the
contrast isolates the defect.

These close objective categories that previously existed only as prose; see
:mod:`blackheart.invariants.coverage`. They are engine fixtures -- deterministic,
no I/O, no network, no real funds.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .engine import InvariantSpec, OpSpec, PureState, Target


# --------------------------------------------------------------------------- #
# 1. Cross-chain replay -- a message replayed, or executed on the wrong domain
# --------------------------------------------------------------------------- #

@dataclass
class BridgeState:
    domain: int = 1
    pending: dict[str, dict[str, Any]] = field(default_factory=dict)
    executed: dict[str, bool] = field(default_factory=dict)
    credited: dict[str, int] = field(default_factory=dict)
    replays: int = 0
    wrong_domain: int = 0
    last_credit: int = 0


class CrossDomainBridge(PureState, Target):
    """A bridge that executes an authorized message without binding it to a chain.

    A correct bridge marks a message executed (so it runs once) and refuses a
    message whose declared destination is not this chain. The vulnerable bridge
    does neither, so an attacker replays a message -- or executes one addressed to
    another chain -- and is credited each time.
    """

    name = "cross-chain-replay"
    ACTORS = ["attacker", "victim"]
    DOMAIN = 1

    def reset(self) -> BridgeState:
        st = BridgeState()
        st.domain = self.DOMAIN
        st.pending = {
            "m1": {"dst": 1, "amount": 100, "recipient": "attacker"},
            "m2": {"dst": 2, "amount": 500, "recipient": "attacker"},
        }
        st.executed = {"m1": False, "m2": False}
        st.credited = {"attacker": 0, "victim": 0}
        st.replays = 0
        st.wrong_domain = 0
        st.last_credit = 0
        return st

    def ops(self) -> list[OpSpec]:
        return [
            OpSpec("execute", ["attacker"], {"msg_id": ["m1", "m2"]}, weight=5,
                   description="execute an authorized cross-domain message"),
        ]

    # -- the only difference between the vulnerable and guarded models -- #
    def _allowed(self, st: BridgeState, msg_id: str) -> bool:
        """Vulnerable: neither replay nor destination-domain is checked."""
        return msg_id in st.pending

    def invariants(self) -> list[InvariantSpec]:
        return [
            InvariantSpec(
                "message-executed-at-most-once",
                "a cross-domain message is executed at most once",
                lambda st: st.replays == 0,
                severity_if_broken="high",
            ),
            InvariantSpec(
                "message-only-on-destination-domain",
                "a cross-domain message is only executed on its declared destination",
                lambda st: st.wrong_domain == 0,
                severity_if_broken="high",
            ),
        ]

    def step(self, st: BridgeState, op: str, actor: str, params: dict[str, Any]) -> None:
        st.last_credit = 0
        if op != "execute":
            return
        msg_id = str(params["msg_id"])
        if not self._allowed(st, msg_id):
            return
        msg = st.pending[msg_id]
        if st.executed.get(msg_id):
            st.replays += 1
        if msg["dst"] != st.domain:
            st.wrong_domain += 1
        st.credited[msg["recipient"]] = st.credited.get(msg["recipient"], 0) + msg["amount"]
        st.executed[msg_id] = True
        st.last_credit = msg["amount"]

    def snapshot(self, st: BridgeState) -> dict[str, Any]:
        return {
            "domain": st.domain,
            "credited": dict(st.credited),
            "replays": st.replays,
            "wrong_domain": st.wrong_domain,
            "last_credit": st.last_credit,
        }


class GuardedCrossDomainBridge(CrossDomainBridge):
    """Same bridge, but a message runs once and only on its destination domain."""

    name = "cross-chain-guarded"

    def _allowed(self, st: BridgeState, msg_id: str) -> bool:
        return (
            msg_id in st.pending
            and not st.executed.get(msg_id)
            and st.pending[msg_id]["dst"] == st.domain
        )


# --------------------------------------------------------------------------- #
# 2. AMM slippage -- a swap that divides by the reserve, not the reserve + input
# --------------------------------------------------------------------------- #

@dataclass
class AmmState:
    rx: int = 1000
    ry: int = 1000
    bal_a: dict[str, int] = field(default_factory=dict)
    bal_b: dict[str, int] = field(default_factory=dict)
    k0: int = 1_000_000
    last_out: int = 0


class SlippageAmm(PureState, Target):
    """A constant-product pool whose swap output ignores the input it takes in.

    The correct constant-product output is ``dx * ry / (rx + dx)``. The vulnerable
    pool computes ``dx * ry / rx`` -- it forgets the ``+ dx`` -- so it pays out too
    much and the pool invariant ``k = rx * ry`` *decreases* on every swap: the
    trader drains value from the pool (and from the other liquidity providers).
    """

    name = "amm-slippage"
    ACTORS = ["attacker"]

    def reset(self) -> AmmState:
        st = AmmState()
        st.rx, st.ry = 1000, 1000
        st.bal_a = {"attacker": 1000}
        st.bal_b = {"attacker": 0}
        st.k0 = st.rx * st.ry
        st.last_out = 0
        return st

    def ops(self) -> list[OpSpec]:
        return [
            OpSpec("swap_a_for_b", self.ACTORS, {"amount": [10, 50, 100]}, weight=5,
                   description="sell token A into the pool for token B"),
            OpSpec("swap_b_for_a", self.ACTORS, {"amount": [10, 50, 100]}, weight=5,
                   description="sell token B into the pool for token A"),
        ]

    # -- the only difference between the vulnerable and guarded models -- #
    def _out_a_for_b(self, amount: int, st: AmmState) -> int:
        """Vulnerable: divides by the reserve, not the reserve plus the input."""
        return amount * st.ry // st.rx

    def _out_b_for_a(self, amount: int, st: AmmState) -> int:
        return amount * st.rx // st.ry

    def invariants(self) -> list[InvariantSpec]:
        return [
            InvariantSpec(
                "constant-product-non-decreasing",
                "the pool's invariant k = rx * ry never decreases across a swap",
                lambda st: st.rx * st.ry >= st.k0,
                severity_if_broken="high",
            ),
        ]

    def step(self, st: AmmState, op: str, actor: str, params: dict[str, Any]) -> None:
        st.last_out = 0
        amount = int(params["amount"])
        if op == "swap_a_for_b":
            if amount <= 0 or amount > st.bal_a.get(actor, 0):
                return
            out = self._out_a_for_b(amount, st)
            if out <= 0 or out > st.ry:
                return
            st.bal_a[actor] -= amount
            st.bal_b[actor] = st.bal_b.get(actor, 0) + out
            st.rx += amount
            st.ry -= out
            st.last_out = out
        elif op == "swap_b_for_a":
            if amount <= 0 or amount > st.bal_b.get(actor, 0):
                return
            out = self._out_b_for_a(amount, st)
            if out <= 0 or out > st.rx:
                return
            st.bal_b[actor] -= amount
            st.bal_a[actor] = st.bal_a.get(actor, 0) + out
            st.ry += amount
            st.rx -= out
            st.last_out = out

    def snapshot(self, st: AmmState) -> dict[str, Any]:
        return {
            "rx": st.rx, "ry": st.ry, "k": st.rx * st.ry,
            "bal_a": dict(st.bal_a), "bal_b": dict(st.bal_b),
            "last_out": st.last_out,
        }


class GuardedSlippageAmm(SlippageAmm):
    """Same pool, but the swap output is the correct constant-product formula."""

    name = "amm-guarded"

    def _out_a_for_b(self, amount: int, st: AmmState) -> int:
        return amount * st.ry // (st.rx + amount)

    def _out_b_for_a(self, amount: int, st: AmmState) -> int:
        return amount * st.rx // (st.ry + amount)


# --------------------------------------------------------------------------- #
# 3. Silent transfer failure -- credit regardless of the transfer result
# --------------------------------------------------------------------------- #

@dataclass
class BridgeTokenState:
    vault: int = 0
    credited: dict[str, int] = field(default_factory=dict)
    token_capacity: int = 500
    false_credits: int = 0
    last_credit: int = 0


class SilentFailBridge(PureState, Target):
    """A bridge that credits a deposit even when the token transfer moved nothing.

    A token that silently fails (returns false / moves nothing) above a cap is a
    real hazard. The vulnerable bridge credits the full amount regardless; the
    guarded bridge credits only what the transfer actually moved.
    """

    name = "silent-transfer-failure"
    ACTORS = ["attacker", "victim"]

    def reset(self) -> BridgeTokenState:
        st = BridgeTokenState()
        st.vault = 0
        st.credited = {"attacker": 0, "victim": 0}
        st.token_capacity = 500
        st.false_credits = 0
        st.last_credit = 0
        return st

    def ops(self) -> list[OpSpec]:
        return [
            OpSpec("deposit", ["attacker"], {"amount": [10, 100, 1000]}, weight=5,
                   description="deposit tokens; the token silently fails above its cap"),
        ]

    # -- the only difference between the vulnerable and guarded models -- #
    def _credit(self, st: BridgeTokenState, actor: str, amount: int, moved: int) -> None:
        """Vulnerable: credits the full amount even when nothing moved."""
        st.credited[actor] = st.credited.get(actor, 0) + amount

    def _transferred(self, amount: int, st: BridgeTokenState) -> int:
        return amount if amount <= st.token_capacity else 0

    def invariants(self) -> list[InvariantSpec]:
        return [
            InvariantSpec(
                "credit-matches-real-transfer",
                "the sum of credited balances never exceeds the tokens actually held",
                lambda st: sum(st.credited.values()) <= st.vault,
                severity_if_broken="high",
            ),
        ]

    def step(self, st: BridgeTokenState, op: str, actor: str, params: dict[str, Any]) -> None:
        st.last_credit = 0
        if op != "deposit":
            return
        amount = int(params["amount"])
        moved = self._transferred(amount, st)
        st.vault += moved
        self._credit(st, actor, amount, moved)
        if moved < amount:
            st.false_credits += 1
        st.last_credit = amount

    def snapshot(self, st: BridgeTokenState) -> dict[str, Any]:
        return {
            "vault": st.vault,
            "credited": dict(st.credited),
            "false_credits": st.false_credits,
            "last_credit": st.last_credit,
        }


class GuardedSilentFailBridge(SilentFailBridge):
    """Same bridge, but a deposit is credited only for the funds actually moved."""

    name = "silent-transfer-guarded"

    def _credit(self, st: BridgeTokenState, actor: str, amount: int, moved: int) -> None:
        if moved != amount:
            return
        st.credited[actor] = st.credited.get(actor, 0) + amount


# --------------------------------------------------------------------------- #
# 4. Flash-loan governance -- voting power taken from the current balance
# --------------------------------------------------------------------------- #

@dataclass
class GovState:
    balance: dict[str, int] = field(default_factory=dict)
    snapshot: dict[str, int] = field(default_factory=dict)
    votes: int = 0
    snapshot_power: int = 0
    quorum: int = 150
    bad_passes: int = 0
    passed: int = 0


class Governor(PureState, Target):
    """A governor that counts a voter's *current* balance, not a snapshot.

    A correct governor snapshots voting power at proposal creation. The vulnerable
    governor reads the current balance, so an attacker flash-borrows voting power,
    votes, and passes a proposal without ever holding it.
    """

    name = "flashloan-governance"
    ACTORS = ["attacker", "victim"]
    QUORUM = 150

    def reset(self) -> GovState:
        st = GovState()
        st.balance = {"attacker": 0, "victim": 100}
        st.snapshot = {}
        st.votes = 0
        st.snapshot_power = 0
        st.quorum = self.QUORUM
        st.bad_passes = 0
        st.passed = 0
        return st

    def ops(self) -> list[OpSpec]:
        # The exploit path is attacker-driven: the attacker creates the proposal,
        # flash-borrows voting power, votes, and executes. Restricting these to the
        # attacker keeps every violation attributable to an unprivileged actor (a
        # victim borrowing to pass its own proposal is the same bug, not a
        # different one, and would muddy the attacker-reachability signal).
        return [
            OpSpec("propose", ["attacker"], {}, weight=3,
                   description="create a proposal and snapshot voting power"),
            OpSpec("borrow", ["attacker"], {"amount": [50, 100, 200, 300]}, weight=5,
                   description="flash-borrow voting tokens"),
            OpSpec("repay", ["attacker"], {"amount": [50, 100, 200, 300]}, weight=2,
                   description="return the flash loan"),
            OpSpec("vote", ["attacker"], {}, weight=5,
                   description="vote on the active proposal"),
            OpSpec("execute", ["attacker"], {}, weight=3,
                   description="execute the proposal if quorum is met"),
        ]

    # -- the only difference between the vulnerable and guarded models -- #
    def _vote_power(self, st: GovState, actor: str) -> int:
        """Vulnerable: voting power is the current (flash-loanable) balance."""
        return st.balance.get(actor, 0)

    def invariants(self) -> list[InvariantSpec]:
        return [
            InvariantSpec(
                "no-pass-without-snapshot-power",
                "a proposal only passes when its voters held quorum power at snapshot",
                lambda st: st.bad_passes == 0,
                severity_if_broken="high",
            ),
        ]

    def step(self, st: GovState, op: str, actor: str, params: dict[str, Any]) -> None:
        if op == "propose":
            st.snapshot = dict(st.balance)
            st.votes = 0
            st.snapshot_power = 0
        elif op == "borrow":
            st.balance[actor] = st.balance.get(actor, 0) + int(params["amount"])
        elif op == "repay":
            st.balance[actor] = max(0, st.balance.get(actor, 0) - int(params["amount"]))
        elif op == "vote":
            st.votes += self._vote_power(st, actor)
            st.snapshot_power += st.snapshot.get(actor, 0)
        elif op == "execute":
            if st.votes >= st.quorum:
                st.passed += 1
                if st.snapshot_power < st.quorum:
                    st.bad_passes += 1
                st.votes = 0
                st.snapshot_power = 0

    def snapshot(self, st: GovState) -> dict[str, Any]:
        return {
            "balance": dict(st.balance),
            "snapshot": dict(st.snapshot),
            "votes": st.votes,
            "snapshot_power": st.snapshot_power,
            "bad_passes": st.bad_passes,
            "passed": st.passed,
        }


class GuardedGovernor(Governor):
    """Same governor, but voting power is read from the proposal snapshot."""

    name = "flashloan-governance-guarded"

    def _vote_power(self, st: GovState, actor: str) -> int:
        return st.snapshot.get(actor, 0)


# --------------------------------------------------------------------------- #
# 5. Griefing DoS -- an attacker blocks a critical path for everyone
# --------------------------------------------------------------------------- #

@dataclass
class LiquidatorState:
    frozen: dict[str, bool] = field(default_factory=dict)
    bad_debt: int = 0
    liquidations: int = 0
    blocked: int = 0


class Liquidator(PureState, Target):
    """A liquidator whose path is blocked by any frozen position.

    A correct liquidator skips a frozen position and liquidates the rest. The
    vulnerable one refuses to liquidate *anything* while any position is frozen,
    so an attacker freezes their own position and permanently blocks liquidation,
    letting bad debt accrue -- a griefing denial of service.
    """

    name = "griefing-dos"
    ACTORS = ["attacker", "victim"]

    def reset(self) -> LiquidatorState:
        st = LiquidatorState()
        st.frozen = {"attacker": False, "victim": False}
        st.bad_debt = 0
        st.liquidations = 0
        st.blocked = 0
        return st

    def ops(self) -> list[OpSpec]:
        return [
            OpSpec("freeze", ["attacker"], {}, weight=5,
                   description="freeze the caller's own position"),
            OpSpec("liquidate", ["attacker"], {}, weight=5,
                   description="liquidate the unhealthy positions"),
        ]

    # -- the only difference between the vulnerable and guarded models -- #
    def _can_liquidate(self, st: LiquidatorState) -> bool:
        """Vulnerable: any frozen position blocks the whole liquidation path."""
        return not any(st.frozen.values())

    def invariants(self) -> list[InvariantSpec]:
        return [
            InvariantSpec(
                "liquidation-never-blocked",
                "an attacker cannot permanently block the liquidation path",
                lambda st: st.blocked == 0,
                severity_if_broken="high",
            ),
        ]

    def step(self, st: LiquidatorState, op: str, actor: str, params: dict[str, Any]) -> None:
        if op == "freeze":
            st.frozen[actor] = True
        elif op == "liquidate":
            if not self._can_liquidate(st):
                st.blocked += 1
                st.bad_debt += 1
            else:
                st.liquidations += 1

    def snapshot(self, st: LiquidatorState) -> dict[str, Any]:
        return {
            "frozen": dict(st.frozen),
            "bad_debt": st.bad_debt,
            "liquidations": st.liquidations,
            "blocked": st.blocked,
        }


class GuardedLiquidator(Liquidator):
    """Same liquidator, but a frozen position is skipped, never blocks the path."""

    name = "griefing-guarded"

    def _can_liquidate(self, st: LiquidatorState) -> bool:
        return True


# --------------------------------------------------------------------------- #
# 6. Reward manipulation -- no reward-debt checkpoint on stake
# --------------------------------------------------------------------------- #

@dataclass
class RewardState:
    stake: dict[str, int] = field(default_factory=dict)
    reward_debt: dict[str, int] = field(default_factory=dict)
    claimed: dict[str, int] = field(default_factory=dict)
    reward_index: int = 0                 # scaled by SCALE
    distributed_total: int = 0
    paid_total: int = 0


class RewardPool(PureState, Target):
    """A rewards pool that fails to checkpoint a staker's debt on ``stake``.

    A correct pool records ``rewardDebt = stake * rewardIndex`` when a stake is
    added, so a new staker cannot claim rewards distributed before they joined.
    The vulnerable pool leaves the debt at zero, so an attacker stakes *after* a
    distribution and claims rewards they never accrued.
    """

    name = "reward-manipulation"
    ACTORS = ["attacker", "victim"]
    SCALE = 1_000_000

    def reset(self) -> RewardState:
        st = RewardState()
        st.stake = {"attacker": 0, "victim": 0}
        st.reward_debt = {"attacker": 0, "victim": 0}
        st.claimed = {"attacker": 0, "victim": 0}
        st.reward_index = 0
        st.distributed_total = 0
        st.paid_total = 0
        return st

    def ops(self) -> list[OpSpec]:
        return [
            OpSpec("stake", self.ACTORS, {"amount": [100, 1000]}, weight=5,
                   description="stake tokens into the rewards pool"),
            OpSpec("distribute", self.ACTORS, {"amount": [100, 1000]}, weight=5,
                   description="distribute rewards to current stakers"),
            OpSpec("claim", self.ACTORS, {}, weight=5,
                   description="claim accrued rewards"),
        ]

    # -- the only difference between the vulnerable and guarded models -- #
    def _checkpoint(self, st: RewardState, actor: str) -> None:
        """Vulnerable: no reward-debt checkpoint when a stake is added."""
        return

    def invariants(self) -> list[InvariantSpec]:
        return [
            InvariantSpec(
                "no-over-distribution",
                "the pool never pays out more rewards than it has distributed",
                lambda st: st.paid_total <= st.distributed_total,
                severity_if_broken="high",
            ),
        ]

    def step(self, st: RewardState, op: str, actor: str, params: dict[str, Any]) -> None:
        if op == "stake":
            st.stake[actor] = st.stake.get(actor, 0) + int(params["amount"])
            self._checkpoint(st, actor)
        elif op == "distribute":
            total = sum(st.stake.values())
            if total <= 0:
                return
            amount = int(params["amount"])
            st.reward_index += amount * self.SCALE // total
            st.distributed_total += amount
        elif op == "claim":
            owed = st.stake[actor] * st.reward_index // self.SCALE - st.reward_debt.get(actor, 0)
            if owed <= 0:
                return
            st.claimed[actor] = st.claimed.get(actor, 0) + owed
            st.paid_total += owed
            st.reward_debt[actor] = st.stake[actor] * st.reward_index // self.SCALE

    def snapshot(self, st: RewardState) -> dict[str, Any]:
        return {
            "stake": dict(st.stake),
            "reward_index": st.reward_index,
            "distributed_total": st.distributed_total,
            "paid_total": st.paid_total,
            "claimed": dict(st.claimed),
        }


class GuardedRewardPool(RewardPool):
    """Same pool, but a stake checkpoints the staker's reward debt."""

    name = "reward-guarded"

    def _checkpoint(self, st: RewardState, actor: str) -> None:
        st.reward_debt[actor] = st.stake[actor] * st.reward_index // self.SCALE


# --------------------------------------------------------------------------- #
# 7. Storage collision -- the implementation can write the admin slot
# --------------------------------------------------------------------------- #

@dataclass
class ProxyStorageState:
    slots: dict[int, int] = field(default_factory=dict)
    owner_id: int = 1
    collisions: int = 0
    initial_owner: int = 1


class ProxyStorage(PureState, Target):
    """A proxy whose implementation can write the reserved admin slot.

    A correct proxy reserves the admin slot and refuses implementation writes to
    it. The vulnerable proxy lets unprivileged logic write any slot, so an
    attacker overwrites the admin slot and takes ownership.
    """

    name = "storage-collision"
    ACTORS = ["attacker", "victim"]
    ADMIN_SLOT = 0

    def reset(self) -> ProxyStorageState:
        st = ProxyStorageState()
        st.slots = {0: 1, 1: 0, 2: 0}      # slot 0 holds the admin/owner id
        st.owner_id = 1
        st.collisions = 0
        st.initial_owner = 1
        return st

    def ops(self) -> list[OpSpec]:
        return [
            OpSpec("write_slot", ["attacker"], {"slot": [0, 1, 2], "value": [1, 2]}, weight=5,
                   description="implementation writes a storage slot through the proxy"),
        ]

    # -- the only difference between the vulnerable and guarded models -- #
    def _write_allowed(self, slot: int) -> bool:
        """Vulnerable: no slot is reserved against implementation writes."""
        return True

    def invariants(self) -> list[InvariantSpec]:
        return [
            InvariantSpec(
                "admin-slot-unwritable-by-logic",
                "implementation logic can never overwrite the proxy's admin slot",
                lambda st: st.collisions == 0,
                severity_if_broken="high",
            ),
        ]

    def step(self, st: ProxyStorageState, op: str, actor: str, params: dict[str, Any]) -> None:
        if op != "write_slot":
            return
        slot = int(params["slot"])
        value = int(params["value"])
        if not self._write_allowed(slot):
            return
        st.slots[slot] = value
        if slot == self.ADMIN_SLOT:
            st.owner_id = value
            if value != st.initial_owner:
                st.collisions += 1

    def snapshot(self, st: ProxyStorageState) -> dict[str, Any]:
        return {
            "slots": dict(st.slots),
            "owner_id": st.owner_id,
            "collisions": st.collisions,
        }


class GuardedProxyStorage(ProxyStorage):
    """Same proxy, but the admin slot is reserved against implementation writes."""

    name = "storage-guarded"

    def _write_allowed(self, slot: int) -> bool:
        return slot != self.ADMIN_SLOT


# --------------------------------------------------------------------------- #
# 8. Decimals mismatch -- the vault assumes every token has 6 decimals
# --------------------------------------------------------------------------- #

@dataclass
class DecimalState:
    credit: dict[str, int] = field(default_factory=dict)          # 18-dec credit
    deposited_value: dict[str, int] = field(default_factory=dict)  # 18-dec value in
    last_credit: int = 0


class DecimalVault(PureState, Target):
    """A vault that assumes every token has 6 decimals.

    A correct vault scales a token amount to a common 18-decimal value by its real
    decimals. The vulnerable vault scales *every* token as if it were 6-decimal, so
    an 18-decimal deposit is credited 1e12x its real value.
    """

    name = "decimals-mismatch"
    ACTORS = ["attacker", "victim"]
    SCALE = 1_000_000_000_000    # 1e12: the 6-dec -> 18-dec factor

    def reset(self) -> DecimalState:
        st = DecimalState()
        st.credit = {"attacker": 0, "victim": 0}
        st.deposited_value = {"attacker": 0, "victim": 0}
        st.last_credit = 0
        return st

    def ops(self) -> list[OpSpec]:
        return [
            OpSpec("deposit", ["attacker"], {"token": ["six", "eighteen"],
                                             "amount": [1, 1000]}, weight=5,
                   description="deposit a token; the vault assumes it has 6 decimals"),
        ]

    # -- the only difference between the vulnerable and guarded models -- #
    def _credit_for(self, token: str, amount: int, st: DecimalState) -> int:
        """Vulnerable: scales every token as if it were 6-decimal."""
        return amount * self.SCALE

    def _value_of(self, token: str, amount: int) -> int:
        return amount * self.SCALE if token == "six" else amount

    def invariants(self) -> list[InvariantSpec]:
        return [
            InvariantSpec(
                "credit-never-exceeds-deposited-value",
                "the credited (18-dec) value never exceeds the value actually deposited",
                self._credit_within_value,
                severity_if_broken="high",
            ),
        ]

    def _credit_within_value(self, st: DecimalState) -> bool:
        for a in st.credit:
            if st.credit[a] > st.deposited_value[a]:
                return False
        return True

    def step(self, st: DecimalState, op: str, actor: str, params: dict[str, Any]) -> None:
        st.last_credit = 0
        if op != "deposit":
            return
        token = str(params["token"])
        amount = int(params["amount"])
        credit = self._credit_for(token, amount, st)
        st.credit[actor] = st.credit.get(actor, 0) + credit
        st.deposited_value[actor] = st.deposited_value.get(actor, 0) + self._value_of(token, amount)
        st.last_credit = credit

    def snapshot(self, st: DecimalState) -> dict[str, Any]:
        return {
            "credit": dict(st.credit),
            "deposited_value": dict(st.deposited_value),
            "last_credit": st.last_credit,
        }


class GuardedDecimalVault(DecimalVault):
    """Same vault, but each token is scaled by its real decimals."""

    name = "decimals-guarded"

    def _credit_for(self, token: str, amount: int, st: DecimalState) -> int:
        return self._value_of(token, amount)
