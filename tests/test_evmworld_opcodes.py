"""The multi-frame EVM must execute the modern opcode set, not halt on it.

``evmworld`` treats an unsupported opcode as ``INVALID`` rather than a no-op, which
is correct but means a bytecode that uses a newer instruction silently becomes
untestable. These tests pin the opcodes added for EIP-1153 (TLOAD/TSTORE),
EIP-5656 (MCOPY), EIP-4844 (BLOBHASH) and EIP-7516 (BLOBBASEFEE), including the
two semantics that are easy to get wrong: transient storage is per-transaction,
and a copy must read before it writes so overlap is handled like the spec.
"""

from __future__ import annotations

from blackheart.evmworld import Account, Machine, STATIC_VIOLATION, World

UINT256_MASK = (1 << 256) - 1
TARGET = 0xB
CALLER = 0xA


def _run(code: bytes, *, env=None, static: bool = False):
    world = World({TARGET: Account(code=code)})
    machine = Machine(world, env=env)
    result = machine.message_call(
        caller=CALLER, to=TARGET, gas=1_000_000, static=static
    )
    return result, machine, world


def _push1(value: int) -> bytes:
    return bytes([0x60, value])


def _push32(value: int) -> bytes:
    return bytes([0x7F]) + value.to_bytes(32, "big")


# --------------------------------------------------------------------------- #
# EIP-1153 -- transient storage
# --------------------------------------------------------------------------- #

def test_tstore_then_tload_roundtrips():
    code = (
        _push1(0x2A) + _push1(0x01) + bytes([0x5D])   # TSTORE(1, 0x2a)
        + _push1(0x01) + bytes([0x5C])                 # TLOAD(1)
        + _push1(0x00) + bytes([0x55])                 # SSTORE(0, value)
        + bytes([0x00])
    )
    result, _, world = _run(code)
    assert result.succeeded, result.halt
    assert world.get_storage(TARGET, 0) == 0x2A


def test_transient_storage_is_cleared_between_transactions():
    write = (
        _push1(0x2A) + _push1(0x01) + bytes([0x5D])
        + _push1(0x01) + bytes([0x5C])
        + _push1(0x00) + bytes([0x55])
        + bytes([0x00])
    )
    world = World({TARGET: Account(code=write)})
    machine = Machine(world)
    first = machine.message_call(caller=CALLER, to=TARGET, gas=1_000_000)
    assert first.succeeded
    assert world.get_storage(TARGET, 0) == 0x2A

    # A second transaction must not see the first transaction's transient slot.
    read = _push1(0x01) + bytes([0x5C]) + _push1(0x00) + bytes([0x55]) + bytes([0x00])
    world.account(TARGET).code = read
    second = machine.message_call(caller=CALLER, to=TARGET, gas=1_000_000)
    assert second.succeeded
    assert world.get_storage(TARGET, 0) == 0


def test_tstore_in_a_static_frame_is_a_static_violation():
    code = _push1(0x2A) + _push1(0x01) + bytes([0x5D]) + bytes([0x00])
    result, _, _ = _run(code, static=True)
    assert not result.succeeded
    assert result.halt == STATIC_VIOLATION


# --------------------------------------------------------------------------- #
# EIP-5656 -- MCOPY
# --------------------------------------------------------------------------- #

def test_mcopy_copies_memory():
    value = int.from_bytes(bytes(range(1, 33)), "big")
    code = (
        _push32(value) + _push1(0x00) + bytes([0x52])          # MSTORE(0, value)
        + _push1(0x20) + _push1(0x00) + _push1(0x20) + bytes([0x5E])  # MCOPY(0x20, 0, 0x20)
        + _push1(0x20) + bytes([0x51])                          # MLOAD(0x20)
        + _push1(0x00) + bytes([0x55])                          # SSTORE(0, word)
        + bytes([0x00])
    )
    result, _, world = _run(code)
    assert result.succeeded, result.halt
    assert world.get_storage(TARGET, 0) == value


def test_mcopy_handles_overlapping_regions_like_the_spec():
    value = int.from_bytes(bytes(range(1, 33)), "big")
    code = (
        _push32(value) + _push1(0x00) + bytes([0x52])          # MSTORE(0, value)
        + _push1(0x20) + _push1(0x10) + _push1(0x00) + bytes([0x5E])  # MCOPY(0, 0x10, 0x20)
        + _push1(0x00) + bytes([0x51])                          # MLOAD(0)
        + _push1(0x00) + bytes([0x55])
        + bytes([0x00])
    )
    result, _, world = _run(code)
    assert result.succeeded, result.halt
    expected = (value & ((1 << 128) - 1)) << 128
    assert world.get_storage(TARGET, 0) == expected


# --------------------------------------------------------------------------- #
# EIP-4844 / EIP-7516 -- blob environment
# --------------------------------------------------------------------------- #

def test_blobhash_and_blobbasefee_read_the_environment():
    code = (
        _push1(0x00) + bytes([0x49]) + _push1(0x00) + bytes([0x55])  # SSTORE(0, BLOBHASH(0))
        + bytes([0x4A]) + _push1(0x01) + bytes([0x55])               # SSTORE(1, BLOBBASEFEE)
        + bytes([0x00])
    )
    result, _, world = _run(
        code, env={"blobhashes": [0xABC], "blobbasefee": 7}
    )
    assert result.succeeded, result.halt
    assert world.get_storage(TARGET, 0) == 0xABC
    assert world.get_storage(TARGET, 1) == 7


def test_blobhash_out_of_range_is_zero():
    code = (
        _push1(0x05) + bytes([0x49]) + _push1(0x00) + bytes([0x55]) + bytes([0x00])
    )
    result, _, world = _run(code, env={"blobhashes": [0xABC]})
    assert result.succeeded, result.halt
    assert world.get_storage(TARGET, 0) == 0
