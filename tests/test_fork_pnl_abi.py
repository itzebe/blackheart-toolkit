import pytest
"""ABI-driven candidate generation: verified ABI -> per-function calldata (pure, no network)."""

from blackheart.fork_pnl import candidates_from_abi

_WETH9_ABI = [
    {"type": "function", "name": "deposit", "inputs": []},
    {"type": "function", "name": "withdraw", "inputs": [{"name": "wad", "type": "uint256"}]},
    {"type": "function", "name": "balanceOf", "inputs": [{"name": "", "type": "address"}]},
    {"type": "function", "name": "transfer",
     "inputs": [{"name": "to", "type": "address"}, {"name": "v", "type": "uint256"}]},
    {"type": "function", "name": "approve",
     "inputs": [{"name": "s", "type": "address"}, {"name": "v", "type": "uint256"}]},
    {"type": "function", "name": "name", "inputs": []},
    {"type": "function", "name": "transferFrom",
     "inputs": [{"name": "f", "type": "address"}, {"name": "t", "type": "address"},
                {"name": "v", "type": "uint256"}]},
]


def test_candidates_from_abi_known_selectors():
    out, skipped = candidates_from_abi(_WETH9_ABI)
    by = {c["signature"]: c["calldata"] for c in out}
    assert by["deposit()"] == "0xd0e30db0"
    assert by["withdraw(uint256)"] == "0x2e1a7d4d" + "0" * 64
    assert by["balanceOf(address)"] == "0x70a08231" + "0" * 64
    assert by["transfer(address,uint256)"] == "0xa9059cbb" + "0" * 128
    assert by["approve(address,uint256)"] == "0x095ea7b3" + "0" * 128
    assert by["name()"] == "0x06fdde03"
    assert by["transferFrom(address,address,uint256)"] == "0x23b872dd" + "0" * 192
    assert skipped == []


def test_candidates_from_abi_skips_dynamic_types():
    out, skipped = candidates_from_abi(
        [{"type": "function", "name": "foo", "inputs": [{"name": "x", "type": "bytes"}]}])
    assert out == [] and skipped == ["foo(bytes)"]


def test_candidates_from_abi_boundary_values():
    from blackheart.fork_pnl import candidates_from_abi
    abi = [{"type": "function", "name": "withdraw",
            "inputs": [{"name": "w", "type": "uint256"}]}]
    out, _ = candidates_from_abi(abi, boundary=True)
    datas = [c["calldata"] for c in out]
    assert len(datas) == 3
    assert datas[0] == "0x2e1a7d4d" + "0" * 64          # 0
    assert datas[1] == "0x2e1a7d4d" + "0" * 63 + "1"     # 1
    assert datas[2] == "0x2e1a7d4d" + "f" * 64           # max uint256


@pytest.mark.network
def test_boundary_generation_real_abi():
    from blackheart.fork_pnl import candidates_from_abi, fetch_abi
    abi = fetch_abi(1, "0x6B175474E89094C44Da98b954EedeAC495271d0F")
    assert abi
    cands, _ = candidates_from_abi(abi, boundary=True)
    assert len(cands) >= 30
    tf = [c for c in cands if c["signature"].startswith("transfer(")]
    assert len(tf) == 3
    tails = {c["calldata"][-64:] for c in tf}
    assert "0" * 64 in tails and "f" * 64 in tails
