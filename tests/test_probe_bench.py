"""Acceptance bar for the probe benchmark: it must separate reach from auth."""

from __future__ import annotations

from blackheart.deployed import keccak256
from blackheart.evmworld import Account
from blackheart.probe import UNPRIVILEGED, mapping_slot, probe_over_entitlement, probe_sequence
from blackheart.probe_bench import (
    CASES, LEAD, CLEAR, _INIT_VICTIM, _REENTRY_ATTACKER, _REENTRY_TARGET,
    _init_takeover_world, _reentrancy_world, benchmark,
)


def test_benchmark_is_perfect_on_the_builtin_corpus():
    result = benchmark()
    assert result.passed, [(c.name, c.expect, c.flagged) for c in result.cases if not c.correct]
    assert result.recall == 1.0
    assert result.specificity == 1.0


def test_the_corpus_covers_both_directions():
    expects = {c.expect for c in CASES}
    assert expects == {LEAD, CLEAR}
    # At least one of each direction, so a trivial all-flag or all-clear cannot pass.
    assert sum(1 for c in CASES if c.expect == LEAD) >= 1
    assert sum(1 for c in CASES if c.expect == CLEAR) >= 1


def test_caller_source_case_names_the_caller_and_is_not_a_lead():
    result = benchmark()
    case = next(c for c in result.cases if c.name == "caller-source-revert")
    assert case.flagged is False
    assert case.revert_names_caller is True


def test_owner_gate_is_cleared_not_flagged():
    result = benchmark()
    case = next(c for c in result.cases if c.name == "owner-gated")
    assert case.flagged is False
    assert case.outcomes == ["REVERT"]


def test_attribution_is_perfect_on_the_corpus():
    result = benchmark()
    assert result.attribution == 1.0


def test_token_and_delegatecall_cases_are_leads_with_attributed_slots():
    result = benchmark()
    for name in ("token-balance-write", "delegatecall-write"):
        case = next(c for c in result.cases if c.name == name)
        assert case.flagged is True
        assert case.slot_attributed is True


def test_keccak_is_ethereum_keccak():
    assert keccak256(b"").hex() == "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"


def test_mapping_slot_is_pad32_then_keccak():
    key, slot = 0x1234, 3
    expected = int.from_bytes(keccak256(key.to_bytes(32, "big") + slot.to_bytes(32, "big")), "big")
    assert mapping_slot(key, slot) == expected


def test_mapping_balance_case_attributes_the_derived_slot():
    result = benchmark()
    case = next(c for c in result.cases if c.name == "mapping-balance-write")
    assert case.flagged is True
    assert case.slot_attributed is True


def test_reentrancy_case_shows_a_doubled_write():
    result = benchmark()
    case = next(c for c in result.cases if c.name == "reentrancy-double-write")
    assert case.flagged is True
    assert case.slot_attributed is True


def test_reentrancy_over_credit_flags_over_entitlement():
    result = benchmark()
    case = next(c for c in result.cases if c.name == "reentrancy-over-credit")
    assert case.flagged is True
    assert case.over_entitlement is True


def test_over_entitlement_needs_reentry():
    world = _reentrancy_world()
    world.accounts[_REENTRY_ATTACKER] = Account(code=b"", balance=0)  # plain EOA, no re-entry
    _r, gain, over = probe_over_entitlement(
        world, _REENTRY_TARGET, "0x00000000",
        sender=_REENTRY_ATTACKER, gain_slot=0, expected_gain=1,
    )
    assert gain == 1
    assert over is False


def test_unchecked_call_is_lead_and_checked_call_is_clear():
    result = benchmark()
    u = next(c for c in result.cases if c.name == "unchecked-call")
    ck = next(c for c in result.cases if c.name == "checked-call")
    assert u.flagged is True and u.slot_attributed is True
    assert ck.flagged is False


def test_proxy_storage_collision_overwrites_admin_slot():
    result = benchmark()
    c = next(c for c in result.cases if c.name == "proxy-storage-collision")
    assert c.flagged is True and c.slot_attributed is True


def test_sequence_reaches_state_a_single_call_cannot():
    w1 = _init_takeover_world()
    probe_sequence(w1, _INIT_VICTIM, [(UNPRIVILEGED, "0x00000000")])
    assert w1.get_storage(_INIT_VICTIM, 1) == 0
    w2 = _init_takeover_world()
    probe_sequence(w2, _INIT_VICTIM, [(UNPRIVILEGED, "0x00000000"), (UNPRIVILEGED, "0x00000000")])
    assert w2.get_storage(_INIT_VICTIM, 1) == 1


def test_init_takeover_case_is_lead():
    r = benchmark()
    c = next(c for c in r.cases if c.name == "unprotected-init-takeover")
    assert c.flagged is True and c.slot_attributed is True


def test_expect_over_distinguishes_guarded_drain():
    r = benchmark()
    vuln = next(c for c in r.cases if c.name == "eth-drain-reentrancy")
    guard = next(c for c in r.cases if c.name == "eth-drain-cei-guarded")
    assert vuln.over_entitlement is True and vuln.correct is True
    assert guard.over_entitlement is False and guard.correct is True
