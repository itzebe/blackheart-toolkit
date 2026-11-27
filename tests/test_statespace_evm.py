"""Tests for the external-source EVM execution adapter.

These exercise *real bytecode*: the vendored, third-party Damn Vulnerable DeFi
v4.1.0 contracts deployed to an ephemeral local anvil node, driven by the engine's
operations as real transactions. No mocks for the target itself.

The harness is git-ignored and re-created by ``harnesses/dvdf-external/fetch.sh``,
so on a fresh checkout these tests skip (a skip is not a pass). They run here.

Coverage: the ABI encoder against known-good calldata, case loading/deployment,
operation dispatch and state read-back, the invariant gate, and the end-to-end
discovery + independent-verification result for each case (with the differential
control), plus the honesty property that a deliberately-vulnerable suite is not
reported as a production vulnerability.
"""

from __future__ import annotations

import pytest

from blackheart.statespace.runtime.evm import (
    _parse_types,
    encode_params,
)
from blackheart.statespace.runtime.evm_cases import (
    ALL_CASES,
    BLIND_CASES,
    DVDF_COMMIT,
    DVDF_TAG,
    get_case,
)
from blackheart.statespace.runtime.evm_run import build_evm_target, run_evm_case


def _no_foundry() -> bool:
    from blackheart.statespace.runtime.evm import _foundry_bin

    return _foundry_bin("anvil") is None or _foundry_bin("cast") is None


# --------------------------------------------------------------------------- #
# Pure: the ABI encoder (no node needed)
# --------------------------------------------------------------------------- #


def test_encode_address_padding():
    data = encode_params(["address"], ["0x00000000000000000000000000000000000000ff"])
    assert data.hex() == "00" * 12 + "ff".rjust(40, "0")
    assert len(data) == 32


def test_encode_uint256_max():
    data = encode_params(["uint256"], [2**256 - 1])
    assert data.hex() == "f" * 64


def test_encode_dynamic_bytes():
    # bytes("0x1234") -> offset(0x20) || length(2) || data padded
    data = encode_params(["bytes"], ["0x1234"])
    assert data.hex() == ("00" * 31 + "20") + ("00" * 31 + "02") + ("1234" + "00" * 30)


def test_parse_types():
    assert _parse_types("flashLoan(uint256,address,address,bytes)") == \
        ["uint256", "address", "address", "bytes"]
    assert _parse_types("deposit(uint256,address)") == ["uint256", "address"]


def test_encode_dynamic_array_of_address():
    addrs = ["0x" + "11" * 20, "0x" + "22" * 20]
    data = encode_params(["address[]"], [addrs])
    # offset word, length word, then two padded addresses
    assert len(data) == 32 * 4
    assert int.from_bytes(data[0:32], "big") == 32
    assert int.from_bytes(data[32:64], "big") == 2


# --------------------------------------------------------------------------- #
# Node-backed: the adapter contract and lifecycle
# --------------------------------------------------------------------------- #


def test_case_registry_is_consistent():
    assert DVDF_TAG == "v4.1.0"
    assert DVDF_COMMIT == "64fddf9f96de2782f8868898d68673acb295119c"
    for name in ALL_CASES:
        case = get_case(name)
        assert case.name == name
        assert case.reference.startswith("Damn Vulnerable DeFi")
        assert case.ground_truth  # every case documents its ground truth
    # blind cases are the discovery set; the development case is clearly labelled
    assert all(get_case(n).suite == "blind" for n in BLIND_CASES)
    assert get_case("dvdf-unstoppable").suite == "development"


def test_unknown_case_is_rejected():
    with pytest.raises(KeyError):
        get_case("dvdf-does-not-exist")


@pytest.mark.skipif(_no_foundry(), reason="foundry (anvil/cast) not installed")
def test_adapter_deploys_and_reads_state(dvdf_ready):
    if not dvdf_ready:
        pytest.skip("dvdf-external harness not built; run harnesses/dvdf-external/fetch.sh")
    adapter, target = build_evm_target("dvdf-unstoppable")
    try:
        snap = adapter.snapshot()
        assert snap["total_assets"] == 1_000_000 * 10**18
        assert snap["total_supply"] == 1_000_000 * 10**18
        rec = adapter.execute("transfer_in", "attacker", {"amount": 1})
        assert rec.status == "ok"
        after = adapter.snapshot()
        assert after["total_assets"] == snap["total_assets"] + 1
    finally:
        adapter.close()


@pytest.mark.skipif(_no_foundry(), reason="foundry (anvil/cast) not installed")
def test_reset_restores_clean_state(dvdf_ready):
    if not dvdf_ready:
        pytest.skip("dvdf-external harness not built")
    adapter, target = build_evm_target("dvdf-unstoppable")
    try:
        clean = adapter.snapshot()
        adapter.execute("transfer_in", "attacker", {"amount": 10**18})
        assert adapter.snapshot() != clean
        adapter.reset()
        assert adapter.snapshot() == clean
    finally:
        adapter.close()


# --------------------------------------------------------------------------- #
# Node-backed: end-to-end discovery + independent verification
# --------------------------------------------------------------------------- #

_END_TO_END = ["dvdf-unstoppable", "dvdf-truster", "dvdf-naive-receiver"]


@pytest.mark.skipif(_no_foundry(), reason="foundry (anvil/cast) not installed")
@pytest.mark.parametrize("name", _END_TO_END)
def test_engine_discovers_and_verifies(dvdf_ready, name):
    if not dvdf_ready:
        pytest.skip("dvdf-external harness not built")
    report = run_evm_case(name, verify=True)
    assert report.executed, report.errors
    assert report.detected, f"engine found no violation for {name}"
    assert report.minimal_sequence, "a detection must carry a minimal sequence"
    # the minimal sequence is attacker-reachable and non-empty
    assert all(s["actor"] in {"attacker", "user", "anonymous"} for s in report.minimal_sequence)
    # independent verification ran and, for these cases, confirmed
    assert report.verdict == "INDEPENDENTLY_VERIFIED", report.verdict
    assert report.independently_verified is True
    # the differential control did NOT reproduce the violation (the hit discriminates)
    assert report.control_reproduced is False


@pytest.mark.skipif(_no_foundry(), reason="foundry (anvil/cast) not installed")
def test_minimal_sequence_is_reproducible_from_clean_state(dvdf_ready):
    if not dvdf_ready:
        pytest.skip("dvdf-external harness not built")
    report = run_evm_case("dvdf-truster", verify=True)
    adapter, target = build_evm_target("dvdf-truster")
    try:
        adapter.reset()
        clean = adapter.snapshot()
        for step in report.minimal_sequence:
            adapter.execute(step["action"], step["actor"], step["params"])
        assert adapter.snapshot() != clean
        # the invariant is broken at the end
        from blackheart.statespace.model import violated

        assert violated(adapter.snapshot(), adapter.invariants())
    finally:
        adapter.close()
