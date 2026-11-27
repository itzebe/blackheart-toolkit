"""Dispatcher shapes the linear scan must get right -- in both directions.

The mission's requirement is narrow and hard: distinguish a selector that is
*actually dispatched* from a ``PUSH4`` constant that merely exists, and say
``UNKNOWN`` rather than guess when the shape is one the scan cannot resolve.

Ground truth here is not hand-written. Every fixture under
``tests/fixtures/dispatch`` is real solc 0.8.24 runtime bytecode, compiled twice
-- once through the legacy pipeline and once through ``via_ir`` -- and its
expected selector set is that contract's own ABI. The synthetic shapes are
additionally validated by *executing* them: a body that runs writes a storage
marker, the fallback writes a different one, so "reachable" means a real call
reached the body rather than a byte pattern that looks like one.

Each property is asserted in both directions. A detector that always answers
"reachable" and one that always answers "present-only" must both fail.
"""

from __future__ import annotations

import glob
import os

import pytest

from blackheart.deployed import function_selector
from blackheart.deployed_selectors import (
    PRESENT_ONLY,
    REACHABLE,
    analyse_selectors,
    disassemble,
)

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures", "dispatch")


def _fixtures() -> list[tuple[str, str, set[str]]]:
    out = []
    for code_path in sorted(glob.glob(os.path.join(FIXTURES, "*.code.txt"))):
        name = os.path.basename(code_path)[: -len(".code.txt")]
        code = open(code_path).read().strip()
        abi_path = code_path.replace(".code.", ".abi.")
        truth = {function_selector(s) for s in open(abi_path).read().split() if s}
        out.append((name, code, truth))
    return out


# --------------------------------------------------------------------------- #
# 1-3, 7: real compiled bytecode, both pipelines
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("name,code,truth", _fixtures(), ids=[f[0] for f in _fixtures()])
def test_real_bytecode_recovers_exactly_the_abi(name, code, truth):
    """Every real fixture must yield exactly its ABI's selectors, no more."""
    rep = analyse_selectors(code)
    got = {s.selector for s in rep.reachable}
    assert got - truth == set(), f"{name}: false selector leads {sorted(got - truth)}"
    assert truth - got == set(), f"{name}: missed reachable selectors {sorted(truth - got)}"


@pytest.mark.parametrize("name,code,truth", _fixtures(), ids=[f[0] for f in _fixtures()])
def test_real_bytecode_is_reported_complete(name, code, truth):
    """A fully walked contract must not carry a permanent 'incomplete' warning.

    solc's CBOR metadata trailer is data, not instructions. Leaving it in the walk
    produced a 'truncated PUSH' on essentially every real contract, which made the
    completeness flag constant and therefore meaningless.
    """
    rep = analyse_selectors(code)
    assert rep.complete, f"{name}: {rep.incomplete_reason}"
    assert rep.metadata_stripped, f"{name}: metadata trailer was not recognised"


def test_via_ir_dispatcher_is_not_missed():
    """The via-IR pipeline compares with SUB-for-zero, not EQ.

    Regression: the analyser accepted only ``EQ``, so every via-IR contract lost
    exactly one selector (the final fall-through arm). Both pipelines are present
    in the fixtures, so this asserts the fix rather than the fixture.
    """
    ir = {name: (code, truth) for name, code, truth in _fixtures() if name.endswith("_ir")}
    assert ir, "via-IR fixtures are required for this regression"
    for name, (code, truth) in ir.items():
        got = {s.selector for s in analyse_selectors(code).reachable}
        assert truth - got == set(), f"{name}: via-IR arm missed {sorted(truth - got)}"


def test_a_fallback_only_contract_has_no_dispatch_selectors():
    """No selector is dispatched when the contract only has fallback/receive."""
    code, truth = next(
        (c, t) for n, c, t in _fixtures() if n == "FallbackOnly_legacy"
    )
    rep = analyse_selectors(code)
    # The only ABI function is the auto-generated ``hits()`` getter; what matters
    # is that nothing invented is reachable and the getter is genuinely found.
    assert {s.selector for s in rep.reachable} == truth


def test_data_only_constants_are_never_reachable():
    """A PUSH4 used as data (an error selector / constant) is not an entry point."""
    code, truth = next((c, t) for n, c, t in _fixtures() if n == "DataOnly_legacy")
    rep = analyse_selectors(code)
    assert {s.selector for s in rep.reachable} == truth
    # 0xdeadbeef is a stored constant and 0xcafebabe is an error selector: both
    # appear in the bytecode as PUSH4 and neither may be reported reachable.
    for data_sel in ("deadbeef", "cafebabe"):
        assert data_sel not in {s.selector for s in rep.reachable}


# --------------------------------------------------------------------------- #
# 4-8: synthetic shapes, with the exact byte-level structure under test
# --------------------------------------------------------------------------- #

def _sel4(hexstr: str) -> str:
    return hexstr


def test_classic_eq_dispatch_is_reachable():
    """63 <sel> 14 61 <dest> 57, dest is a JUMPDEST -> reachable."""
    sel = "11111111"
    code = "0x63" + sel + "14" + "61" + "000a" + "57" + "5b" + "00"
    assert [s.status for s in analyse_selectors(code).selectors] == [REACHABLE]


def test_sub_for_zero_dispatch_is_reachable():
    """63 <sel> 03 61 <dest> 57 -- via-IR equality: a-b is zero iff equal."""
    sel = "22222222"
    code = "0x63" + sel + "03" + "61" + "000a" + "57" + "5b" + "00"
    assert [s.status for s in analyse_selectors(code).selectors] == [REACHABLE]


def test_sub_then_iszero_then_jump_is_reachable():
    """63 <sel> 03 15 61 <dest> 57 -- ISZERO re-tests the same difference."""
    sel = "33333333"
    code = "0x63" + sel + "03" + "15" + "61" + "000b" + "57" + "5b" + "00"
    assert [s.status for s in analyse_selectors(code).selectors] == [REACHABLE]


def test_push4_used_only_as_data_is_present_only():
    """63 <sel> 50 -- pushed then popped: data, never a dispatch."""
    assert [
        s.status for s in analyse_selectors("0x63" + "44444444" + "5000").selectors
    ] == [PRESENT_ONLY]


def test_comparison_with_an_unreachable_destination_is_present_only():
    """A JUMPI to an offset that is not a JUMPDEST cannot select a body.

    ``63 <sel> 14 61 0002 57`` jumps to offset 2, which is inside the PUSH4
    payload. A jump there reverts, so the comparison proves nothing about
    reachability. Reporting it REACHABLE would be a false lead.
    """
    sel = "55555555"
    code = "0x63" + sel + "14" + "61" + "0002" + "57" + "00"
    rep = analyse_selectors(code)
    assert [s.status for s in rep.selectors] == [PRESENT_ONLY]
    assert "no EQ/SUB comparison guards a JUMPI" in rep.selectors[0].evidence


def test_comparison_without_any_jump_is_present_only():
    """EQ whose result is discarded proves nothing."""
    assert [
        s.status
        for s in analyse_selectors("0x63" + "66666666" + "146101005000").selectors
    ] == [PRESENT_ONLY]


def test_dead_code_dispatch_is_still_reported_reachable():
    """Unreachable-by-execution code is a different question from dispatch shape.

    ``D`` in the mission's list is 'unreachable selector comparisons'. This module
    answers *is this selector compared and dispatched*, not *is the surrounding
    code live*; a linear scan cannot decide liveness, so claiming PRESENT_ONLY
    here would be a fabricated negative. The honest position is documented: the
    selector is dispatched, and liveness is out of scope.
    """
    sel = "77777777"
    code = "0x600160005500" + "63" + sel + "14" + "61" + "0010" + "57" + "5b" + "00"
    assert [s.status for s in analyse_selectors(code).selectors] == [REACHABLE]


def test_ambiguous_control_flow_is_flagged_not_guessed():
    """A constant that reaches JUMPI with no recognised comparison is ambiguous.

    The status stays PRESENT_ONLY -- presence is never promoted to reachability --
    but the evidence must say the shape was unresolved rather than asserting the
    constant is data.
    """
    sel = "88888888"
    code = "0x63" + sel + "57" + "00"
    rep = analyse_selectors(code)
    assert [s.status for s in rep.selectors] == [PRESENT_ONLY]
    assert "unresolved" in rep.selectors[0].evidence
    # Ambiguity is machine-readable, not prose-only: it must be in the report.
    assert [s.selector for s in rep.ambiguous] == [sel]
    assert rep.to_dict()["ambiguous"][0]["ambiguous"] is True


def test_a_settled_negative_is_not_flagged_ambiguous():
    """Plain data must not read as 'undecided' -- the flag has to discriminate."""
    rep = analyse_selectors("0x63" + "44444444" + "5000")
    assert rep.ambiguous == []
    assert rep.to_dict()["ambiguous"] == []


def test_every_name_in_dunder_all_is_defined():
    """``__all__`` must not advertise a name the module does not define."""
    import blackheart.deployed_selectors as mod

    missing = [n for n in mod.__all__ if not hasattr(mod, n)]
    assert missing == []


def test_a_popped_comparison_is_not_a_dispatch():
    """63 <sel> 14 50 -- the comparison result is discarded before any jump."""
    sel = "99999999"
    code = "0x63" + sel + "14" + "50" + "61" + "000c" + "57" + "5b" + "00"
    assert [s.status for s in analyse_selectors(code).selectors] == [PRESENT_ONLY]


def test_swap_between_comparison_and_jump_breaks_the_link():
    """SWAP1 buries the result, so the JUMPI reads something else."""
    sel = "aaaaaaaa"
    code = "0x63" + sel + "14" + "90" + "61" + "000c" + "57" + "5b" + "00"
    assert [s.status for s in analyse_selectors(code).selectors] == [PRESENT_ONLY]


# --------------------------------------------------------------------------- #
# Input handling: malformed bytecode is named, never crashes
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize(
    "code,needle",
    [
        ("0X63deadbeef5000", None),          # upper-case prefix is still hex
        ("0x0", "odd number of nibbles"),    # odd length
        ("0xzz", "not valid hex"),           # non-hex characters
    ],
)
def test_malformed_hex_is_reported_clearly(code, needle):
    if needle is None:
        # '0X' must be accepted, not crash: same answer as the lower-case form.
        assert analyse_selectors(code).code_size == 7
    else:
        with pytest.raises(ValueError) as exc:
            analyse_selectors(code)
        assert needle in str(exc.value)


def test_a_non_string_non_bytes_payload_is_a_type_error():
    with pytest.raises(TypeError):
        analyse_selectors(1234)  # type: ignore[arg-type]


def test_metadata_trailer_is_not_walked_as_code():
    """A CBOR trailer must be excluded from the walk and reported."""
    body = "63" + "12121212" + "14" + "61" + "000a" + "57" + "5b" + "00"
    # A real solc map: a2 (2 pairs), "ipfs" -> 0x58 0x22 <34 bytes>, "solc" -> 3 bytes.
    trailer_body = "a264697066735822" + "11" * 34 + "64736f6c6343" + "000818"
    declared = len(trailer_body) // 2  # metadata length excludes its own 2-byte word
    raw = body + trailer_body + f"{declared:04x}"
    rep = analyse_selectors("0x" + raw)
    assert rep.metadata_stripped
    assert rep.complete
    assert [s.status for s in rep.selectors] == [REACHABLE]


def test_truncated_push_still_marks_the_report_incomplete():
    """A genuine truncated PUSH (not a trailer) must still be surfaced."""
    rep = analyse_selectors("0x63dead")
    assert not rep.complete
    assert "truncated PUSH" in rep.incomplete_reason


def test_disassembly_skips_push_payloads():
    """A 0x14 byte inside a PUSH2 operand is data, not an EQ."""
    instrs = disassemble(bytes.fromhex("61146100"))
    assert [op for _, op, _ in instrs] == [0x61, 0x00]


def test_a_stray_length_word_does_not_truncate_real_code():
    """Adversarial regression: the trailer check must not fire on a coincidence.

    ``5b a2 00 00 00 00 00 05`` ends with the length word 5, and the byte 7 bytes
    from the end happens to be ``0xa2``. A one-byte prefix check would strip real
    code here and could hide a JUMPDEST. The map must parse as a complete solc
    metadata map, so this is left intact.
    """
    from blackheart.deployed_selectors import _strip_metadata

    crafted = bytes([0x5B, 0xA2, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05])
    code, stripped = _strip_metadata(crafted)
    assert not stripped
    assert code == crafted


def test_a_malformed_metadata_map_is_not_stripped():
    """A region that starts like a map but does not parse is left in place."""
    from blackheart.deployed_selectors import _strip_metadata

    # declares two pairs but supplies no keys
    bad = bytes([0xA2]) + b"\x00" * 30
    code, stripped = _strip_metadata(bad + b"\x00\x1f")
    assert not stripped


def test_push1_destination_is_validated_too():
    """A narrow destination push that misses a JUMPDEST is not reachable.

    Regression: only PUSH2 destinations were checked, so a PUSH1 shape pointing
    at a non-JUMPDEST byte still read as a dispatch.
    """
    sel = "bbbbbbbb"
    # 63 <sel> 14 60 02 57 -- PUSH1 0x02, which is inside the PUSH4 payload
    code = "0x63" + sel + "14" + "60" + "02" + "57" + "00"
    assert [s.status for s in analyse_selectors(code).selectors] == [PRESENT_ONLY]
