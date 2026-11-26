"""A symbolic witness is proved on the concrete EVM or reported as diverged."""

from __future__ import annotations

from blackheart.bytecode import verify_runtime_hex, verify_runtime_witness


def test_a_revert_witness_is_reproduced_on_runtime_bytecode():
    result = verify_runtime_hex("0x60006000fd", {"_halt": "revert"})
    assert result.status == "VERIFIED"
    assert result.observed_revert is True


def test_a_success_witness_is_reproduced():
    result = verify_runtime_hex("0x00", {})
    assert result.status == "VERIFIED"
    assert result.observed_revert is False


def test_a_storage_effect_is_checked_concretely():
    # PUSH1 1; PUSH1 0; SSTORE; STOP
    result = verify_runtime_hex("0x600160005500", {}, expected_storage={0: 1})
    assert result.status == "VERIFIED"
    assert result.storage_ok


def test_a_wrong_expectation_diverges_instead_of_passing():
    result = verify_runtime_hex("0x00", {"_halt": "revert"})
    assert result.status == "DIVERGED"
    assert not result.verified


def test_invalid_hex_is_incomplete_not_a_proof():
    result = verify_runtime_hex("0xzz", {})
    assert result.status == "INCOMPLETE"


def test_empty_runtime_is_incomplete():
    assert verify_runtime_witness(b"", {}) .status == "INCOMPLETE"
