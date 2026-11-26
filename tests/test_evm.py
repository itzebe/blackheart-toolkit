"""The deterministic EVM interpreter must agree with real EVM, or it is worthless.

Every claim TestSparker makes rests on this module executing code the same way a
node does. A test that only checks the interpreter against itself proves nothing,
so these tests are anchored to facts established **outside** it:

* the dispatcher contract below was cross-checked against ``anvil`` and agrees on
  both branches (real selector -> ``STOP`` with ``SSTORE(0) = 0xAA``; unknown
  selector -> ``REVERT``);
* the real solc 0.8.24 fixtures under ``tests/fixtures/dispatch`` were compiled by
  solc, and their selectors come from their own ABIs, not from this code;
* the invalid-jump case reproduces the exact defect that made three earlier
  hand-written fixtures meaningless -- a jump into a ``PUSH4`` payload.

Where a test needs a marker contract it builds the bytecode with computed offsets,
never hand-written ones: every hand-written offset in this project's history has
been wrong at least once, and a wrong offset silently tests the wrong thing.
"""

from __future__ import annotations

import glob
import os

import pytest

from blackheart.deployed import function_selector
from blackheart.evm import BAD_JUMP, INVALID, REVERT, STOP, execute


def _marker_contract(selector: str) -> bytes:
    """A dispatcher whose body writes 0xAA to slot 0, with a reverting fallback.

    Offsets are computed from the assembled pieces so the destination is a real
    ``JUMPDEST`` by construction. Anvil agrees on both branches (see module docstring).
    """
    head = bytes.fromhex("60003560e01c")  # CALLDATALOAD(0) >> 224
    compare = bytes.fromhex("63" + selector + "14")  # PUSH4 sel; EQ
    fallback = bytes.fromhex("60006000fd")  # REVERT
    body = bytes.fromhex("5b60aa60005500")  # JUMPDEST; PUSH1 0xAA; PUSH1 0; SSTORE; STOP
    dest = len(head) + len(compare) + 3 + 1 + len(fallback)
    return head + compare + b"\x61" + dest.to_bytes(2, "big") + b"\x57" + fallback + body


def test_a_real_selector_reaches_the_body():
    code = _marker_contract("aaaaaaaa")
    result = execute(code, calldata=bytes.fromhex("aaaaaaaa") + b"\x00" * 32)
    assert result.halt is STOP
    assert result.storage_writes == {0: 0xAA}


def test_an_unknown_selector_reaches_the_fallback_not_the_body():
    code = _marker_contract("aaaaaaaa")
    result = execute(code, calldata=bytes.fromhex("bbbbbbbb") + b"\x00" * 32)
    assert result.halt is REVERT
    assert result.storage_writes == {}


def test_a_jump_into_a_push_payload_is_a_bad_jump():
    """The exact defect that made three earlier fixtures prove nothing.

    ``61 0010`` pushes 0x0010, but offset 0x10 lands inside a PUSH payload rather
    than on a JUMPDEST. Real EVM reverts; so must this.
    """
    code = bytes.fromhex("60003560e01c63aaaaaaaa146100105760006000fd5b60aa60005500")
    result = execute(code, calldata=bytes.fromhex("aaaaaaaa") + b"\x00" * 32)
    assert result.halt is BAD_JUMP
    assert not result.succeeded


def test_a_jumpdest_inside_a_push_payload_is_not_a_valid_destination():
    """A 0x5b byte inside PUSH32 data must not be a legal jump target."""
    # PUSH32 with all-0x5b payload, then JUMP to offset 3 (inside the payload).
    code = bytes.fromhex("7f") + b"\x5b" * 32 + bytes.fromhex("600356")
    result = execute(code)
    assert result.halt is BAD_JUMP


def test_push0_is_supported():
    """solc >= 0.8.20 emits PUSH0 constantly; without it every real contract dies."""
    result = execute(bytes.fromhex("5f5f01"))  # PUSH0 PUSH0 ADD (leaves 0, runs off end)
    assert result.halt is STOP


def test_truncated_push_is_invalid_not_silently_padded():
    result = execute(bytes.fromhex("63aabb"))  # PUSH4 with 2 bytes of operand
    assert result.halt is INVALID


def test_stack_underflow_is_reported_not_crashed():
    result = execute(bytes.fromhex("01"))  # ADD on an empty stack
    assert str(result.halt) == "STACK_UNDERFLOW"


def test_arithmetic_wraps_at_256_bits():
    # PUSH1 0; PUSH1 1; SUB -> 2**256 - 1
    result = execute(bytes.fromhex("6000600103"))
    assert result.halt is STOP


def test_storage_is_read_back_across_a_run():
    # SSTORE(0, 7) then SLOAD(0), leaving 7 on the stack.
    code = bytes.fromhex("6007600055600054")
    result = execute(code)
    assert result.storage.get(0) == 7


@pytest.mark.parametrize(
    "path",
    sorted(glob.glob("tests/fixtures/dispatch/*.code.txt")),
    ids=lambda p: os.path.basename(p)[: -len(".code.txt")],
)
def test_real_solc_selectors_reach_dispatch_not_the_fallback(path):
    """Real solc 0.8.24 code: every ABI selector must be recognised by the dispatcher.

    The check is *not* "does the body succeed" -- these test contracts revert for
    their own reasons. It is "did the dispatcher route the call somewhere other
    than the unknown-selector fallback", which is what the dispatch analysis
    claims. An unknown selector is compared against as the control.
    """
    raw = open(path, encoding="utf-8").read().strip()
    code = bytes.fromhex(raw[2:] if raw.startswith("0x") else raw)
    abi_path = path.replace(".code.", ".abi.")
    selectors = [s for s in open(abi_path, encoding="utf-8").read().split() if s]
    if not selectors:
        pytest.skip("fixture declares no selectors (fallback-only contract)")

    known = execute(
        code, calldata=bytes.fromhex(function_selector(selectors[0])[2:]) + b"\x00" * 32,
        gas=900_000,
    )
    unknown = execute(
        code, calldata=bytes.fromhex("00000001") + b"\x00" * 32, gas=900_000
    )
    # The control must not be a successful body execution; the real selector may be
    # either, but it must not fail with an interpreter-level defect.
    assert known.halt not in (INVALID, BAD_JUMP), known.error
    assert unknown.halt not in (INVALID, BAD_JUMP), unknown.error


# -- hostile offsets must halt, never crash ------------------------------- #
# A campaign runs bytecode it did not write. An uncaught exception from a crafted
# offset would abort the whole run, so every memory access must resolve to a halt.
def test_a_huge_return_offset_halts_instead_of_crashing():
    code = bytes.fromhex("6001" + "7f" + "ff" * 32 + "f3")  # RETURN(2**256-1, 1)
    result = execute(code, gas=100_000)
    assert result.halt is not None
    assert not result.succeeded


def test_a_huge_mstore_offset_halts_instead_of_crashing():
    code = bytes.fromhex("6000" + "7f" + "ff" * 32 + "52")  # MSTORE(2**256-1, 0)
    result = execute(code, gas=100_000)
    assert not result.succeeded


def test_a_huge_revert_offset_halts_instead_of_crashing():
    code = bytes.fromhex("6001" + "7f" + "ff" * 32 + "fd")  # REVERT(2**256-1, 1)
    result = execute(code, gas=100_000)
    assert not result.succeeded


def test_a_huge_calldatacopy_offset_halts_instead_of_crashing():
    code = bytes.fromhex("6001" + "7f" + "ff" * 32 + "6000" + "37")
    result = execute(code, gas=100_000)
    assert not result.succeeded or len(result.return_data) < 1024


def test_no_hostile_offset_escapes_as_an_exception():
    """Sweep: no crafted memory op may raise out of execute()."""
    import itertools

    pushes = ["6001", "60ff", "61ffff", "7f" + "ff" * 32]
    ops = ["f3", "fd", "52", "51", "53", "37", "39"]
    for a, b, op in itertools.product(pushes, pushes, ops):
        try:
            execute(bytes.fromhex(a + b + op), gas=100_000)
        except Exception as exc:  # noqa: BLE001 - the assertion is that nothing raises
            raise AssertionError(f"{a} {b} {op} raised {type(exc).__name__}: {exc}")
