"""A witness becomes a runnable test, not a paragraph of prose."""

from __future__ import annotations

from blackheart.symbolic.evm import explore, find_witness
from blackheart.symbolic.poc import (MASK, DivergencePoc, WitnessPoc,
                                     calldata_from_witness, witness_poc)


def _window_code() -> bytes:
    """Revert iff 750 < calldata[0] <= 800."""
    return bytes([
        0x60, 0x00, 0x35,
        0x61, 0x02, 0xEE,
        0x10,
        0x60, 0x00, 0x35,
        0x61, 0x03, 0x20,
        0x10,
        0x15,
        0x16,
        0x60, 0x14,
        0x57,
        0x00,
        0x5B,
        0x60, 0x00, 0x60, 0x00, 0xFD,
    ])


def test_calldata_encodes_words_in_order_and_masks_to_256_bits():
    data = calldata_from_witness({"cd0": 751, "cd1": -1, "_halt": "revert"})
    assert data[:32] == (751).to_bytes(32, "big")
    assert data[32:64] == MASK.to_bytes(32, "big")


def test_calldata_pads_to_the_requested_word_count():
    assert calldata_from_witness({"cd0": 1}, words=3) == (1).to_bytes(32, "big") + b"\x00" * 64


def test_render_is_a_real_forge_test_with_the_runtime_and_calldata():
    poc = WitnessPoc(runtime_code=b"\x60\x00", calldata=b"\x01\x02",
                     expect_revert=True, value=7)
    text = poc.render()
    assert "vm.etch(target, hex\"6000\")" in text
    assert "target.call{value: 7}(hex\"0102\")" in text
    assert 'assertFalse(ok, "witness did not revert");' in text
    assert "contract BlackheartWitnessTest {" in text


def test_render_asserts_a_successful_return_when_asked():
    text = WitnessPoc(b"\x00", b"", expect_revert=False).render()
    assert "assertTrue(ok, \"witness did not return\");" in text


def test_witness_poc_defaults_the_expectation_to_the_halt_reason():
    assert witness_poc(b"\x00", {"cd0": 1, "_halt": "revert"}).expect_revert is True
    assert witness_poc(b"\x00", {"cd0": 1, "_halt": "stop"}).expect_revert is False


def test_a_real_witness_renders_the_same_calldata_the_solver_found():
    result = explore(_window_code(), inputs={"cd0": (0, 1000)})
    witness = find_witness(result, reverted=True)[0]
    poc = witness_poc(_window_code(), witness)
    assert poc.calldata == calldata_from_witness(witness)
    assert int.from_bytes(poc.calldata, "big") in range(751, 801)
    assert 'assertFalse' in poc.render()


def test_divergence_poc_etches_both_twins_and_compares_their_results():
    poc = DivergencePoc(vulnerable=b"\x60\x00", guarded=b"\x60\x01",
                        calldata=b"\x02")
    text = poc.render()
    assert "vm.etch(vulnerable, hex\"6000\")" in text
    assert "vm.etch(guarded, hex\"6001\")" in text
    assert "okVulnerable != okGuarded" in text
    assert "keccak256(outVulnerable) != keccak256(outGuarded)" in text
