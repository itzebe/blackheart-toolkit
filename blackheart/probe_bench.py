"""Benchmark for the unprivileged-surface probe, by bug *class*, not by project.

The corpus encodes shapes that occur in any contract, so the score measures
generalisation rather than memorisation of one target:

* ``unprivileged-write``   -- no auth, any caller reaches a state write -> a LEAD.
* ``owner-gated``          -- ``CALLER == owner`` gate reverts an outsider -> CLEAR.
* ``caller-source-revert`` -- reverts naming the caller as the subject (an
  ``InsufficientBalance(msg.sender, ...)`` shape): caller-source, not a
  cross-account move -> CLEAR, and the probe must flag the caller as subject.
* ``always-revert``        -- a business revert with no auth signal -> CLEAR.
* ``token-balance-write``  -- an unprivileged caller reaches a balance-slot write;
  the probe must attribute the exact slot -> LEAD + slot attributed.
* ``delegatecall-write``   -- a proxy: the caller reaches a write *through*
  delegatecall, and the probe must attribute it to the caller's storage
  (delegatecall semantics) -> LEAD + slot attributed.

Recall = must-flag shapes flagged; specificity = must-clear shapes cleared;
attribution = cases that require a named slot actually attributed; passed = all
cases correct (verdict *and* attribution).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Optional

from .evmworld import Account, World
from .probe import UNPRIVILEGED, mapping_slot, probe, probe_eth_drain, probe_over_entitlement, probe_sequence, probe_world

LEAD = "LEAD"
CLEAR = "CLEAR"


@dataclass(frozen=True)
class ProbeCase:
    name: str
    bytecode: bytes
    selectors: tuple[str, ...]
    expect: str  # LEAD or CLEAR
    note: str
    #: When set, the call must change this storage slot to ``expect_value``.
    expect_slot: Optional[int] = None
    expect_value: Optional[int] = None
    #: A factory for a fresh multi-account world (delegatecall / proxy targets).
    world: Optional[Callable[[], World]] = None
    address: Optional[int] = None
    sender: int = UNPRIVILEGED
    gain_slot: Optional[int] = None
    expected_gain: Optional[int] = None
    sequence: Optional[tuple[str, ...]] = None
    entitlement_wei: Optional[int] = None
    expect_over: Optional[bool] = None


@dataclass
class CaseResult:
    name: str
    expect: str
    flagged: bool
    outcomes: list[str]
    revert_names_caller: bool
    note: str
    slot_attributed: bool = True
    requires_attribution: bool = False
    over_entitlement: Optional[bool] = None
    expect_over: Optional[bool] = None

    @property
    def correct(self) -> bool:
        if self.flagged != (self.expect == LEAD):
            return False
        if self.requires_attribution and not self.slot_attributed:
            return False
        if self.expect_over is not None:
            return self.over_entitlement == self.expect_over
        return self.over_entitlement is not False

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "expect": self.expect,
            "flagged": self.flagged,
            "outcomes": self.outcomes,
            "revert_names_caller": self.revert_names_caller,
            "slot_attributed": self.slot_attributed,
            "requires_attribution": self.requires_attribution,
            "correct": self.correct,
            "note": self.note,
        }


@dataclass
class ProbeBenchmark:
    cases: list[CaseResult] = field(default_factory=list)

    @property
    def recall(self) -> float:
        must = [c for c in self.cases if c.expect == LEAD]
        return sum(1 for c in must if c.flagged) / len(must) if must else 1.0

    @property
    def specificity(self) -> float:
        clean = [c for c in self.cases if c.expect == CLEAR]
        return sum(1 for c in clean if not c.flagged) / len(clean) if clean else 1.0

    @property
    def attribution(self) -> float:
        need = [c for c in self.cases if c.requires_attribution]
        return sum(1 for c in need if c.slot_attributed) / len(need) if need else 1.0

    @property
    def passed(self) -> bool:
        return all(c.correct for c in self.cases)

    def to_dict(self) -> dict:
        return {
            "passed": self.passed,
            "recall": self.recall,
            "specificity": self.specificity,
            "attribution": self.attribution,
            "cases": [c.to_dict() for c in self.cases],
        }


# --------------------------------------------------------------------------- #
# Bytecode fixtures (hand-assembled; each is the smallest shape of its class)
# --------------------------------------------------------------------------- #

def _unprivileged_write() -> bytes:
    """SSTORE(0, 1); STOP -- no caller check, any EOA writes."""
    return bytes([0x60, 0x01, 0x60, 0x00, 0x55, 0x00])


def _owner_gated(owner: int = 1) -> bytes:
    """CALLER == owner ? SSTORE(0,1) : REVERT -- an outsider is refused."""
    return (
        bytes([0x33, 0x73])                 # CALLER; PUSH20
        + owner.to_bytes(20, "big")
        + bytes([
            0x14,                           # EQ
            0x60, 0x1F,                     # PUSH1 0x1f (dest)
            0x57,                           # JUMPI
            0x60, 0x00, 0x60, 0x00, 0xFD,   # PUSH1 0; PUSH1 0; REVERT
            0x5B,                           # JUMPDEST @ 0x1f
            0x60, 0x01, 0x60, 0x00, 0x55,   # SSTORE(0, 1)
            0x00,                           # STOP
        ])
    )


def _caller_source_revert(err_selector: int = 0xAABBCCDD) -> bytes:
    """REVERT with ``Err(caller)`` -- the caller is the subject, not a victim."""
    return (
        bytes([0x63]) + err_selector.to_bytes(4, "big")  # PUSH4 err
        + bytes([
            0x60, 0xE0, 0x1B, 0x60, 0x00, 0x52,          # PUSH1 0xE0; SHL; PUSH1 0; MSTORE
            0x33, 0x60, 0x04, 0x52,                      # CALLER; PUSH1 4; MSTORE
            0x60, 0x24, 0x60, 0x00, 0xFD,                # PUSH1 0x24; PUSH1 0; REVERT
        ])
    )


def _always_revert() -> bytes:
    """REVERT(0, 0) -- a business revert with no auth signal."""
    return bytes([0x60, 0x00, 0x60, 0x00, 0xFD])


#: A mapping-like slot (stands in for ``balances[caller]``).
TOKEN_SLOT = 0xC0FFEE


def _token_balance_write(slot: int = TOKEN_SLOT, value: int = 1) -> bytes:
    """SSTORE(slot, value); STOP -- an unauthorised balance write."""
    return bytes([0x60, value, 0x7F]) + slot.to_bytes(32, "big") + bytes([0x55, 0x00])


#: A real Solidity mapping slot: ``balances[UNPRIVILEGED]`` at BALANCES_SLOT.
BALANCES_SLOT = 3
MAPPING_BALANCE_SLOT = mapping_slot(UNPRIVILEGED, BALANCES_SLOT)


def _mapping_balance_write(value: int = 1) -> bytes:
    """SSTORE(keccak(addr, slot), value); STOP -- a keccak-derived balance slot."""
    return bytes([0x60, value, 0x7F]) + MAPPING_BALANCE_SLOT.to_bytes(32, "big") + bytes([0x55, 0x00])


_MAIN = 0xC0DE
_LOGIC = 0xA11CE


def _delegatecall_world() -> World:
    """A proxy whose DELEGATECALL writes into the caller's own storage."""
    logic = bytes([0x60, 0x01, 0x60, 0x00, 0x55, 0x00])  # SSTORE(0,1); STOP
    main = (
        bytes([0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x73])  # retSize/Off/argsSize/Off; PUSH20
        + _LOGIC.to_bytes(20, "big")
        + bytes([0x5A, 0xF4, 0x00])  # GAS; DELEGATECALL; STOP
    )
    return World({_MAIN: Account(code=main), _LOGIC: Account(code=logic)})


_REENTRY_TARGET = 0x1000
_REENTRY_ATTACKER = 0x2000


def _reentrancy_world() -> World:
    """A target that calls the caller; the caller re-enters, doubling the write."""
    target = bytes([
        0x60, 0x00, 0x54, 0x60, 0x01, 0x01, 0x60, 0x00, 0x55,  # slot0 += 1
        0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x60, 0x00,  # ret/args; value 0
        0x33, 0x5A, 0xF1, 0x50, 0x00,  # CALL(gas, CALLER, 0); POP; STOP
    ])
    attacker = (
        bytes([0x60, 0x00, 0x54, 0x60, 0x2D, 0x57,  # if flag(slot0) != 0 jump to end
               0x60, 0x01, 0x60, 0x00, 0x55,          # flag = 1
               0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x60, 0x00,  # ret/args; value 0
               0x73])                                # PUSH20 target
        + _REENTRY_TARGET.to_bytes(20, "big")
        + bytes([0x5A, 0xF1, 0x50, 0x5B, 0x00])      # CALL; POP; JUMPDEST(end); STOP
    )
    return World({_REENTRY_TARGET: Account(code=target), _REENTRY_ATTACKER: Account(code=attacker)})


_REVERTER = 0x5000
_VICTIM = 0x6000
_PROXY = 0x7000
_IMPL = 0x8000


def _call_world(checked: bool) -> World:
    """An external call to a reverting target; the result is ignored or checked."""
    reverter = bytes([0x60, 0x00, 0x60, 0x00, 0xFD])
    pre = (bytes([0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x73])
           + _REVERTER.to_bytes(20, "big") + bytes([0x5A, 0xF1]))
    if checked:
        body = bytes([0x60, 0x29, 0x57, 0x60, 0x00, 0x60, 0x00, 0xFD, 0x5B,
                      0x60, 0x01, 0x60, 0x00, 0x55, 0x00])
    else:
        body = bytes([0x50, 0x60, 0x01, 0x60, 0x00, 0x55, 0x00])
    return World({_VICTIM: Account(code=pre + body), _REVERTER: Account(code=reverter)})


def _proxy_collision_world() -> World:
    """A proxy whose implementation delegatecalls a write into the proxy's admin slot."""
    impl = bytes([0x33, 0x60, 0x00, 0x55, 0x00])  # SSTORE(0, CALLER)
    proxy = (bytes([0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x73])
             + _IMPL.to_bytes(20, "big") + bytes([0x5A, 0xF4, 0x00]))
    return World({_PROXY: Account(code=proxy, storage={0: 1}), _IMPL: Account(code=impl)})


_INIT_VICTIM = 0x9000


def _init_takeover_world() -> World:
    """step(): if owner==0 { owner=CALLER } else { require(owner==CALLER); slot1=1 }."""
    step = bytes([0x60, 0x00, 0x54, 0x80, 0x15, 0x60, 0x1A, 0x57, 0x80, 0x33, 0x14, 0x60, 0x13, 0x57,
                  0x60, 0x00, 0x60, 0x00, 0xFD, 0x5B, 0x60, 0x01, 0x60, 0x01, 0x55, 0x00,
                  0x5B, 0x33, 0x60, 0x00, 0x55, 0x00])
    return World({_INIT_VICTIM: Account(code=step)})


_ETH_VAULT = 0x3A00
_ETH_ATTACKER = 0x4A00
_ETH_WITHDRAW = bytes([0x33, 0x60, 0x00, 0x52, 0x60, 0x00, 0x60, 0x20, 0x52, 0x60, 0x40, 0x60, 0x00, 0x20,
                       0x80, 0x60, 0x40, 0x52, 0x54, 0x60, 0x60, 0x52,
                       0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x60, 0x00,
                       0x60, 0x60, 0x51, 0x33, 0x5A, 0xF1, 0x50,
                       0x60, 0x40, 0x51, 0x60, 0x00, 0x90, 0x55, 0x00])
_ETH_REENTER = (bytes([0x60, 0x00, 0x54, 0x60, 0x2D, 0x57, 0x60, 0x01, 0x60, 0x00, 0x55,
                       0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x73])
                + _ETH_VAULT.to_bytes(20, "big") + bytes([0x5A, 0xF1, 0x50, 0x5B, 0x00]))


def _eth_drain_world() -> World:
    """A vault that sends ETH before zeroing its ledger; the attacker re-enters once."""
    slot = mapping_slot(_ETH_ATTACKER, 0)
    return World({_ETH_VAULT: Account(code=_ETH_WITHDRAW, storage={slot: 1}, balance=10),
                  _ETH_ATTACKER: Account(code=_ETH_REENTER, balance=0)})


_ORACLE_POOL = 0x7000
_ORACLE_STEP = bytes([0x60, 0x00, 0x54, 0x80, 0x15, 0x60, 0x10, 0x57, 0x60, 0x02, 0x54, 0x02,
                       0x60, 0x01, 0x55, 0x00, 0x5B, 0x61, 0x03, 0xE8, 0x60, 0x00, 0x55, 0x00])


def _oracle_world() -> World:
    """step(): if price(slot0)==0 { price=1000 } else { loan(slot1)=collateral(slot2)*price }."""
    return World({_ORACLE_POOL: Account(code=_ORACLE_STEP, storage={2: 10})})


_REPLAY_CONTRACT = 0x8000
_REPLAY_STEP = bytes([0x60, 0x00, 0x54, 0x15, 0x60, 0x08, 0x57, 0x00,
                      0x5B, 0x60, 0x01, 0x54, 0x60, 0x01, 0x01, 0x60, 0x01, 0x55, 0x00])


def _replay_world() -> World:
    """redeem(): if used(slot0)==0 { paid(slot1) += 1 } -- used is never set, so it replays."""
    return World({_REPLAY_CONTRACT: Account(code=_REPLAY_STEP)})


_INIT_STEP = bytes([0x60, 0x00, 0x54, 0x80, 0x15, 0x60, 0x1A, 0x57, 0x80, 0x33, 0x14, 0x60, 0x13, 0x57,
                    0x60, 0x00, 0x60, 0x00, 0xFD, 0x5B, 0x60, 0x01, 0x60, 0x01, 0x55, 0x00,
                    0x5B, 0x33, 0x60, 0x00, 0x55, 0x00])


def _guarded_init_world() -> World:
    """Same step() but owner is already a real (non-attacker) address, so the unprivileged
    init branch is unreachable and the action is owner-gated: the attacker's call reverts."""
    return World({_INIT_VICTIM: Account(code=_INIT_STEP, storage={0: 0xAAAA})})


_ETH_CEI_VAULT = 0x3100
_ETH_CEI_ATTACKER = 0x4100
_ETH_CEI_WITHDRAW = bytes([0x33, 0x60, 0x00, 0x52, 0x60, 0x00, 0x60, 0x20, 0x52, 0x60, 0x40, 0x60, 0x00, 0x20,
                           0x80, 0x60, 0x40, 0x52, 0x54, 0x60, 0x60, 0x52,
                           0x60, 0x40, 0x51, 0x60, 0x00, 0x90, 0x55,
                           0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x60, 0x00,
                           0x60, 0x60, 0x51, 0x33, 0x5A, 0xF1, 0x50, 0x00])
_ETH_CEI_REENTER = (bytes([0x60, 0x00, 0x54, 0x60, 0x2D, 0x57, 0x60, 0x01, 0x60, 0x00, 0x55,
                           0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x73])
                    + _ETH_CEI_VAULT.to_bytes(20, "big") + bytes([0x5A, 0xF1, 0x50, 0x5B, 0x00]))


def _eth_drain_cei_world() -> World:
    """CEI withdraw: zeros the ledger BEFORE the CALL, so a reentry reads 0 and cannot double-draw."""
    slot = mapping_slot(_ETH_CEI_ATTACKER, 0)
    return World({_ETH_CEI_VAULT: Account(code=_ETH_CEI_WITHDRAW, storage={slot: 1}, balance=10),
                  _ETH_CEI_ATTACKER: Account(code=_ETH_CEI_REENTER, balance=0)})


_ORACLE_MC = 0x7100
_POOL_MC = 0x7200
_ORACLE_GETPRICE = bytes([0x60, 0x00, 0x54, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xF3])
_POOL_BORROW = (bytes([0x60, 0x20, 0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x73])
                + _ORACLE_MC.to_bytes(20, "big")
                + bytes([0x5A, 0xFA, 0x50, 0x60, 0x00, 0x51, 0x60, 0x00, 0x54, 0x02, 0x60, 0x01, 0x55, 0x00]))


def _oracle_multicontract_world() -> World:
    """Pool reads the spot price from a SEPARATE oracle contract via STATICCALL; an inflated
    oracle price (1000) over-borrows: loan = 10 collateral * 1000 = 10000 (true value 10)."""
    return World({_ORACLE_MC: Account(code=_ORACLE_GETPRICE, storage={0: 1000}),
                  _POOL_MC: Account(code=_POOL_BORROW, storage={0: 10})})


CASES: tuple[ProbeCase, ...] = (
    ProbeCase("unprivileged-write", _unprivileged_write(), ("0x00000000",), LEAD,
              "no auth: any caller reaches SSTORE -> missing access control"),
    ProbeCase("owner-gated", _owner_gated(), ("0x00000000",), CLEAR,
              "CALLER==owner gate refuses an unprivileged caller"),
    ProbeCase("caller-source-revert", _caller_source_revert(), ("0x00000000",), CLEAR,
              "revert names the caller as subject -> caller-source, not cross-account theft"),
    ProbeCase("always-revert", _always_revert(), ("0x00000000",), CLEAR,
              "business revert with no auth signal"),
    ProbeCase("token-balance-write", _token_balance_write(), ("0x00000000",), LEAD,
              "unauthorised balance-slot write", expect_slot=TOKEN_SLOT, expect_value=1),
    ProbeCase("mapping-balance-write", _mapping_balance_write(), ("0x00000000",), LEAD,
              "keccak-derived balances[caller] slot (real Solidity mapping slot)",
              expect_slot=MAPPING_BALANCE_SLOT, expect_value=1),
    ProbeCase("delegatecall-write", b"", ("0x00000000",), LEAD,
              "proxy: write through delegatecall lands in the caller's storage",
              world=_delegatecall_world, address=_MAIN, expect_slot=0, expect_value=1),
    ProbeCase("reentrancy-double-write", b"", ("0x00000000",), LEAD,
              "caller re-enters: one call yields a doubled state write (slot 0 == 2)",
              world=_reentrancy_world, address=_REENTRY_TARGET, sender=_REENTRY_ATTACKER,
              expect_slot=0, expect_value=2),
    ProbeCase("reentrancy-over-credit", b"", ("0x00000000",), LEAD,
              "reentry credits the slot twice for one call -> over-entitlement (2 > 1)",
              world=_reentrancy_world, address=_REENTRY_TARGET, sender=_REENTRY_ATTACKER,
              gain_slot=0, expected_gain=1),
    ProbeCase("unchecked-call", b"", ("0x00000000",), LEAD,
              "failed external call is swallowed (POP), then a credit still lands",
              world=lambda: _call_world(False), address=_VICTIM, expect_slot=0, expect_value=1),
    ProbeCase("checked-call", b"", ("0x00000000",), CLEAR,
              "same call, success checked: failure reverts before any credit",
              world=lambda: _call_world(True), address=_VICTIM),
    ProbeCase("proxy-storage-collision", b"", ("0x00000000",), LEAD,
              "impl delegatecall overwrites the proxy's admin slot 0 with the caller",
              world=_proxy_collision_world, address=_PROXY, expect_slot=0, expect_value=UNPRIVILEGED),
    ProbeCase("unprotected-init-takeover", b"", (), LEAD,
              "unprotected init then a guarded action: only the 2-call sequence reaches slot 1",
              world=_init_takeover_world, address=_INIT_VICTIM, sequence=("0x00000000", "0x00000000"),
              expect_slot=1, expect_value=1),
    ProbeCase("eth-drain-reentrancy", b"", ("0x00000000",), LEAD,
              "reentrant withdraw pays out ETH twice for a 1-wei entitlement",
              world=_eth_drain_world, address=_ETH_VAULT, sender=_ETH_ATTACKER, entitlement_wei=1),
    ProbeCase("oracle-manipulation-overborrow", b"", (), LEAD,
              "a spot price movable in one call, then a loan priced off it: 10 collateral borrows 1000x its true value",
              world=_oracle_world, address=_ORACLE_POOL, sequence=("0x00000000", "0x00000000"),
              expect_slot=1, expect_value=10000),
    ProbeCase("authorization-replay", b"", (), LEAD,
              "a one-shot authorization whose consumed flag is never advanced: two calls pay twice",
              world=_replay_world, address=_REPLAY_CONTRACT, sequence=("0x00000000", "0x00000000"),
              expect_slot=1, expect_value=2),
    ProbeCase("initialized-init-gated", b"", (), CLEAR,
              "the same step() with a real owner seeded: the unprivileged sequence reverts, no takeover",
              world=_guarded_init_world, address=_INIT_VICTIM, sequence=("0x00000000", "0x00000000")),
    ProbeCase("eth-drain-cei-guarded", b"", ("0x00000000",), LEAD,
              "same vault with checks-effects-interactions: the reentry reads 0, gain=1 (no over-payment)",
              world=_eth_drain_cei_world, address=_ETH_CEI_VAULT, sender=_ETH_CEI_ATTACKER,
              entitlement_wei=1, expect_over=False),
    ProbeCase("oracle-multicontract-overborrow", b"", ("0x00000000",), LEAD,
              "pool trusts a spot price read from a separate oracle contract: loan=10000 vs true 10",
              world=_oracle_multicontract_world, address=_POOL_MC, expect_slot=1, expect_value=10000),
)


def benchmark(cases: Optional[tuple[ProbeCase, ...]] = None) -> ProbeBenchmark:
    """Run the probe over each case and score it against its expected verdict."""
    chosen = CASES if cases is None else cases
    results: list[CaseResult] = []
    for case in chosen:
        over = None
        if case.gain_slot is not None:
            result, _gain, over = probe_over_entitlement(
                case.world(), case.address, case.selectors[0],
                sender=case.sender, gain_slot=case.gain_slot,
                expected_gain=case.expected_gain if case.expected_gain is not None else 1,
            )
            outcomes = [result]
        elif case.entitlement_wei is not None:
            result, _g, over = probe_eth_drain(case.world(), case.address, case.selectors[0],
                                               sender=case.sender, entitlement=case.entitlement_wei)
            outcomes = [result]
        elif case.sequence is not None:
            outcomes = probe_sequence(case.world(), case.address, [(case.sender, x) for x in case.sequence])
        elif case.world is not None:
            outcomes = [probe_world(case.world(), case.address, s, sender=case.sender) for s in case.selectors]
        else:
            outcomes = probe(case.bytecode, case.selectors)

        requires = case.expect_slot is not None
        slot_ok = True
        if requires:
            slot_ok = any(
                int(slot["slot"]) == case.expect_slot
                and (case.expect_value is None or slot["to"] == case.expect_value)
                for r in outcomes
                for change in r.state_diff
                for slot in change["storage"]
            )
        results.append(
            CaseResult(
                name=case.name,
                expect=case.expect,
                flagged=any(r.writes for r in outcomes),
                outcomes=[r.outcome for r in outcomes],
                revert_names_caller=any(r.revert_names_caller for r in outcomes),
                note=case.note,
                slot_attributed=slot_ok,
                requires_attribution=requires,
                over_entitlement=over,
                expect_over=case.expect_over,
            )
        )
    return ProbeBenchmark(results)
