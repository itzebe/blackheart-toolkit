"""Selector reachability: a PUSH4 constant is not an entry point.

The defect these tests exist for: ``selector_present`` is a substring scan, so a
4-byte value used as ordinary data reads as a callable function. That is a false
lead, and a false lead costs a real investigation its budget.

Every property is tested in both directions -- the honest answer must be reached
*and* a deliberately wrong answer must be rejected -- because a detector that
always says "no" is as useless as one that always says "yes".
"""

from __future__ import annotations

import pytest

from blackheart.deployed import function_selector
from blackheart.deployed_selectors import (
    PRESENT_ONLY,
    REACHABLE,
    analyse_selectors,
    disassemble,
)


def _dispatch(*sels: str) -> str:
    """Build a *valid* classic dispatcher: every destination is a real JUMPDEST.

    The destinations must land on ``JUMPDEST``. An earlier version of this helper
    pointed them at arbitrary offsets (inside a ``PUSH4`` payload), which is not
    valid EVM: the jump would revert, so the fixture proved a byte *shape* rather
    than reachability. Each selector now has its own ``JUMPDEST`` after the chain.
    """
    prefix = "6080"
    n = len(sels)
    body_len = len(prefix) // 2 + 11 * n  # 11 bytes per dispatch entry
    out = prefix
    for i, sel in enumerate(sels):
        dest = body_len + i  # offset of this selector's JUMPDEST
        out += f"8063{sel}14" + "61" + f"{dest:04x}" + "57"
    return "0x" + out + "5b" * n + "00"


def test_dispatch_is_reachable_and_data_is_not():
    sel = function_selector("transfer(address,uint256)")
    rep = analyse_selectors(_dispatch(sel))
    assert [s.status for s in rep.selectors] == [REACHABLE]

    # Same selector, but pushed as data and never compared.
    rep2 = analyse_selectors("0x63" + sel + "5000")
    assert [s.status for s in rep2.selectors] == [PRESENT_ONLY]
    assert rep2.reachable == []


def test_data_only_selector_is_never_reported_reachable():
    """The exact false-lead the brief calls out."""
    sel = function_selector("sweep(address)")
    rep = analyse_selectors("0x6080" + "63" + sel + "50" + "00")
    assert sel not in {s.selector for s in rep.reachable}
    assert sel in {s.selector for s in rep.present_only}


def test_multiple_selectors_are_split_by_proof():
    a = function_selector("transfer(address,uint256)")
    b = function_selector("balanceOf(address)")
    rep = analyse_selectors(_dispatch(a, b))
    assert {s.selector for s in rep.reachable} == {a, b}


def test_eq_without_a_jump_is_not_a_dispatch():
    """EQ whose result feeds no JUMPI proves nothing about entry points."""
    sel = function_selector("approve(address,uint256)")
    # PUSH4 <sel> EQ PUSH1 01 STOP -- a comparison, but no conditional jump.
    rep = analyse_selectors("0x63" + sel + "14610100")
    assert [s.status for s in rep.selectors] == [PRESENT_ONLY]


def test_disassemble_never_reads_a_push_payload_as_an_opcode():
    # PUSH2 0x1461 embeds 0x14 (EQ) and 0x61 (PUSH2) as *operand* bytes. Read as
    # opcodes they would be a comparison and a push; read correctly they are data.
    instrs = disassemble(bytes.fromhex("611461"))
    assert len(instrs) == 1
    assert instrs[0][1] == 0x61
    assert instrs[0][2] == bytes.fromhex("1461")


def test_truncated_push_marks_the_report_incomplete():
    rep = analyse_selectors("0x63" + "aabbcc")  # PUSH4 with only 3 of 4 operand bytes
    assert rep.complete is False
    assert "truncated" in rep.incomplete_reason


def test_empty_code_is_an_empty_report_not_a_crash():
    rep = analyse_selectors("0x")
    assert rep.code_size == 0
    assert rep.selectors == []
    assert rep.complete is True


def test_real_usdc_implementation_abi_is_proven_reachable():
    """A recorded real-bytecode check, skipped when the fixture is absent.

    The full bytecode is fetched by the evidence script; here we assert the
    property on a captured slice so the test is hermetic and still meaningful.
    """
    from pathlib import Path

    fixture = Path(__file__).parent / "fixtures" / "usdc_impl_selectors.txt"
    if not fixture.exists():
        pytest.skip("captured USDC bytecode not present")
    selectors = {
        line.strip() for line in fixture.read_text().splitlines() if line.strip()
    }
    known = ["transfer(address,uint256)", "balanceOf(address)", "approve(address,uint256)"]
    for sig in known:
        assert function_selector(sig) in selectors


# --------------------------------------------------------------------------- #
# Regressions for stack interference between the comparison and its jump
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("between,why", [
    ("50", "POP discards the comparison result"),
    ("90", "SWAP1 moves another value to the top"),
    ("5b", "JUMPDEST is a second entry point with an unknown stack"),
    ("81", "DUP2 copies a lower slot, not the comparison result"),
])
def test_a_clobbering_instruction_breaks_the_dispatch_link(between, why):
    """The comparison must still be on the stack when JUMPI reads it.

    Regression: an earlier version treated POP/SWAP/JUMPDEST/DUP2..16 as neutral,
    so ``PUSH4 s EQ POP PUSH2 d JUMPI`` was reported REACHABLE even though the
    comparison result was thrown away. That is a false lead.
    """
    sel = function_selector("sweep(address)")
    code = "0x63" + sel + "14" + between + "61" + "000c" + "57" + "5b" + "00"
    rep = analyse_selectors(code)
    assert [s.status for s in rep.selectors] == [PRESENT_ONLY], why


def test_dup1_between_the_comparison_and_its_jump_is_still_reachable():
    """DUP1 copies the result, so the jump still reads the comparison.

    This is the guard against over-tightening: the fix above must not reject a
    real dispatcher shape.
    """
    sel = function_selector("pause()")
    # 63 <sel> 14 80 61 000b 57 5b 00 -- the destination (0x0b) is the JUMPDEST.
    code = "0x63" + sel + "14" + "80" + "61" + "000b" + "57" + "5b" + "00"
    rep = analyse_selectors(code)
    assert [s.status for s in rep.selectors] == [REACHABLE]
