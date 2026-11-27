"""The bytecode symbolic executor must reach a numeric window and clear its twin."""

from __future__ import annotations

from blackheart.deployed import keccak256
from blackheart.evmworld import Account, World, execute_message
from blackheart.symbolic.evm import MASK, explore, find_witness
from blackheart.symbolic.expr import Const, Var, gt, le


def _window_code() -> bytes:
    """Revert iff 750 < calldata[0] <= 800."""
    return bytes([
        0x60, 0x00,              # PUSH1 0
        0x35,                    # CALLDATALOAD     [x]
        0x61, 0x02, 0xEE,        # PUSH2 750        [x, 750]
        0x10,                    # LT               [750 < x]
        0x60, 0x00,              # PUSH1 0
        0x35,                    # CALLDATALOAD     [cond, x]
        0x61, 0x03, 0x20,        # PUSH2 800        [cond, x, 800]
        0x10,                    # LT               [cond, 800 < x]
        0x15,                    # ISZERO           [cond, x <= 800]
        0x16,                    # AND
        0x60, 0x14,              # PUSH1 20
        0x57,                    # JUMPI
        0x00,                    # STOP
        0x5B,                    # JUMPDEST (20)
        0x60, 0x00,              # PUSH1 0
        0x60, 0x00,              # PUSH1 0
        0xFD,                    # REVERT
    ])


def _guarded_code() -> bytes:
    """Revert iff calldata[0] > 800."""
    return bytes([
        0x60, 0x00,              # PUSH1 0
        0x35,                    # CALLDATALOAD
        0x61, 0x03, 0x20,        # PUSH2 800
        0x10,                    # LT               -> 800 < x
        0x60, 0x0B,              # PUSH1 11
        0x57,                    # JUMPI
        0x00,                    # STOP
        0x5B,                    # JUMPDEST (11)
        0x60, 0x00,
        0x60, 0x00,
        0xFD,                    # REVERT
    ])


def _window_goal():
    return [gt(Var("cd0"), 750), le(Var("cd0"), 800)]


def test_the_ladder_finds_a_concrete_input_inside_the_window():
    result = explore(_window_code(), inputs={"cd0": (0, 1000)})
    witnesses = find_witness(result, reverted=True, extra=_window_goal())
    assert witnesses, "the symbolic executor must reach the revert window"
    value = witnesses[0]["cd0"]
    assert 750 < value <= 800


def test_the_guarded_twin_is_unreachable_for_the_same_goal():
    result = explore(_guarded_code(), inputs={"cd0": (0, 1000)})
    assert find_witness(result, reverted=True, extra=_window_goal()) == []


def test_the_witness_reproduces_on_the_concrete_interpreter():
    value = find_witness(explore(_window_code(), inputs={"cd0": (0, 1000)}),
                         reverted=True, extra=_window_goal())[0]["cd0"]
    calldata = int(value).to_bytes(32, "big")

    vuln = World({0x1: Account(code=_window_code())})
    assert not execute_message(vuln, caller=0x2, to=0x1, calldata=calldata).succeeded

    guarded = World({0x1: Account(code=_guarded_code())})
    assert execute_message(guarded, caller=0x2, to=0x1, calldata=calldata).succeeded


def test_an_unsupported_opcode_is_reported_not_treated_as_safe():
    result = explore(bytes([0x20]))  # SHA3 with no concrete offset/size
    assert any("0x20" in item or "sha3" in item for item in result.unsupported)
    assert result.paths and result.paths[0].halt.startswith("unsupported")


def _final(code: bytes) -> Const:
    result = explore(code)
    assert result.paths and result.paths[0].halt == "stop"
    return result.paths[0].stack[-1]


def test_constant_arithmetic_wraps_at_256_bits():
    code = bytes([0x7F]) + b"\xff" * 32 + bytes([0x60, 0x01, 0x01, 0x00])
    assert _final(code) == Const(0)
    # 0 - 1 wraps to 2^256 - 1
    assert _final(bytes([0x60, 0x01, 0x60, 0x00, 0x03, 0x00])) == Const(MASK)


def test_shifts_byte_signextend_and_modular_ops_fold():
    assert _final(bytes([0x60, 0x01, 0x60, 0x04, 0x1B, 0x00])) == Const(16)      # 1 << 4
    assert _final(bytes([0x60, 0x20, 0x60, 0x03, 0x1C, 0x00])) == Const(4)      # 32 >> 3
    assert _final(bytes([0x61, 0x12, 0x34, 0x60, 0x1F, 0x1A, 0x00])) == Const(0x34)  # BYTE 31
    assert _final(bytes([0x60, 0xFF, 0x60, 0x00, 0x0B, 0x00])) == Const(MASK)   # SIGNEXTEND
    assert _final(bytes([0x60, 0x05, 0x60, 0x07, 0x60, 0x0A, 0x08, 0x00])) == Const(2)  # ADDMOD
    assert _final(bytes([0x60, 0x03, 0x60, 0x02, 0x0A, 0x00])) == Const(8)      # 2 ** 3


def test_sha3_of_concrete_memory_matches_keccak():
    empty = _final(bytes([0x60, 0x00, 0x60, 0x00, 0x20, 0x00]))
    assert empty == Const(int.from_bytes(keccak256(b""), "big"))
    # MSTORE 42 at offset 0, then SHA3(0, 32)
    code = bytes([0x60, 0x2A, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0x20, 0x00])
    expected = int.from_bytes(keccak256((42).to_bytes(32, "big")), "big")
    assert _final(code) == Const(expected)


def test_sha3_with_symbolic_memory_is_reported_not_guessed():
    # MSTORE calldata word, then SHA3(0, 32)
    code = bytes([0x60, 0x00, 0x35, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0x20, 0x00])
    result = explore(code, inputs={"cd0": (0, 10)})
    assert "sha3(symbolic memory)" in result.unsupported


def test_constant_bitwise_folds_and_symbolic_masks_are_carried():
    folded = explore(bytes([0x60, 0x0F, 0x60, 0xFF, 0x16, 0x00]))
    assert folded.paths and folded.paths[0].halt == "stop"
    assert folded.paths[0].stack[-1] == Const(15)

    masked = explore(bytes([0x60, 0x00, 0x35, 0x60, 0xFF, 0x16, 0x00]),
                     inputs={"cd0": (0, 255)})
    assert "0x16" not in masked.unsupported
    assert masked.paths and masked.paths[0].halt == "stop"


def test_a_symbolic_mask_reaches_a_concrete_witness():
    # Revert iff (cd0 & 0x0f) == 0x0a.
    code = bytes([
        0x60, 0x00, 0x35,        # PUSH1 0; CALLDATALOAD
        0x60, 0x0F, 0x16,        # PUSH1 15; AND
        0x60, 0x0A, 0x14,        # PUSH1 10; EQ
        0x60, 0x0D, 0x57,        # PUSH1 13; JUMPI
        0x00,                    # STOP
        0x5B,                    # JUMPDEST (13)
        0x60, 0x00, 0x60, 0x00, 0xFD,
    ])
    witness = find_witness(explore(code, inputs={"cd0": (0, 255)}), reverted=True)
    assert witness and witness[0]["cd0"] & 0x0F == 0x0A


def test_symbolic_or_and_xor_are_not_reported_unsupported():
    for opcode in (0x17, 0x18):
        result = explore(bytes([0x60, 0x00, 0x35]) + bytes([0x60, 0x01, opcode, 0x00]),
                         inputs={"cd0": (0, 255)})
        assert not result.unsupported
        assert result.paths and result.paths[0].halt == "stop"


def test_an_undecidable_path_yields_no_witness():
    # Revert iff x*x == 2: no integer solution, and the solver must not guess.
    code = bytes([
        0x60, 0x00, 0x35,        # PUSH1 0 CALLDATALOAD
        0x80, 0x02,              # DUP1 MUL
        0x60, 0x02, 0x14,        # PUSH1 2 EQ
        0x60, 0x0A, 0x57,        # PUSH1 10 JUMPI
        0x00,                    # STOP
        0x5B,                    # JUMPDEST (10)
        0x60, 0x00, 0x60, 0x00, 0xFD,
    ])
    result = explore(code, inputs={"cd0": (0, 100)})
    assert find_witness(result, reverted=True) == []


def _overflow_add_code() -> bytes:
    """Revert iff ``cd0 + 2**256-1`` wraps and the wrapped result is zero."""
    return bytes([0x7F]) + MASK.to_bytes(32, "big") + bytes([
        0x60, 0x00, 0x35,        # PUSH1 0; CALLDATALOAD
        0x01,                    # ADD
        0x60, 0x00, 0x14,        # PUSH1 0; EQ
        0x60, 0x2C, 0x57,        # PUSH1 44; JUMPI
        0x00,                    # STOP
        0x5B,                    # JUMPDEST (44)
        0x60, 0x00, 0x60, 0x00, 0xFD,
    ])


def _underflow_sub_code() -> bytes:
    """Revert iff ``cd0 - 1`` underflows to ``2**256-1``."""
    return bytes([
        0x60, 0x01,              # PUSH1 1
        0x60, 0x00, 0x35,        # PUSH1 0; CALLDATALOAD
        0x03,                    # SUB  (cd0 - 1)
    ]) + bytes([0x7F]) + MASK.to_bytes(32, "big") + bytes([
        0x14,                    # EQ
        0x60, 0x2C, 0x57,        # PUSH1 44; JUMPI
        0x00,                    # STOP
        0x5B,                    # JUMPDEST (44)
        0x60, 0x00, 0x60, 0x00, 0xFD,
    ])


def test_wrap_symbolic_reaches_the_overflow_path():
    result = explore(_overflow_add_code(), inputs={"cd0": (0, 10)},
                     wrap_symbolic=True)
    witness = find_witness(result, reverted=True)
    assert witness and witness[0]["cd0"] == 1


def test_default_arithmetic_has_no_overflow_witness():
    result = explore(_overflow_add_code(), inputs={"cd0": (0, 10)})
    assert find_witness(result, reverted=True) == []


def test_wrap_symbolic_reaches_the_underflow_path():
    result = explore(_underflow_sub_code(), inputs={"cd0": (0, 10)},
                     wrap_symbolic=True)
    witness = find_witness(result, reverted=True)
    assert witness and witness[0]["cd0"] == 0


def test_default_arithmetic_has_no_underflow_witness():
    result = explore(_underflow_sub_code(), inputs={"cd0": (0, 10)})
    assert find_witness(result, reverted=True) == []


def _overflow_mul_code() -> bytes:
    """Revert iff ``cd0 * 2**255`` wraps to zero while ``cd0`` is non-zero."""
    return bytes([0x7F]) + (1 << 255).to_bytes(32, "big") + bytes([
        0x60, 0x00, 0x35,        # PUSH1 0; CALLDATALOAD
        0x02,                    # MUL
        0x60, 0x00, 0x14,        # PUSH1 0; EQ
        0x60, 0x00, 0x35,        # PUSH1 0; CALLDATALOAD
        0x15,                    # ISZERO (cd0 == 0)
        0x15,                    # ISZERO (cd0 != 0)
        0x16,                    # AND
        0x60, 0x32, 0x57,        # PUSH1 50; JUMPI
        0x00,                    # STOP
        0x5B,                    # JUMPDEST (50)
        0x60, 0x00, 0x60, 0x00, 0xFD,
    ])


def test_wrap_symbolic_reaches_the_multiplication_overflow_path():
    result = explore(_overflow_mul_code(), inputs={"cd0": (0, 10)},
                     wrap_symbolic=True)
    witness = find_witness(result, reverted=True)
    assert witness and witness[0]["cd0"] in (2, 4, 6, 8, 10)


def test_default_arithmetic_has_no_multiplication_overflow_witness():
    result = explore(_overflow_mul_code(), inputs={"cd0": (0, 10)})
    assert find_witness(result, reverted=True) == []
