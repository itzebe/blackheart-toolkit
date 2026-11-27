"""Fork-run PnL harness smoke: deposit ETH into real WETH9 on a fork and price the attacker."""

import json
import os
import shutil
import socket
import subprocess
import time
import urllib.request

import pytest

from blackheart.fork_pnl import (
    _rpc,
    _token_balance,
    _wait_receipt,
    run_fork_sequence,
    screen_candidates,
)

_WETH9 = "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2"
_FORK_RPC = "https://ethereum-rpc.publicnode.com"
_DEPOSIT = "0xd0e30db0"


def _anvil():
    for p in (os.path.expanduser("~/.foundry/bin/anvil"), shutil.which("anvil")):
        if p and os.path.exists(p):
            return p
    return None


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _rpc(url, method, params):
    payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    req = urllib.request.Request(
        url, data=payload,
        headers={"content-type": "application/json", "User-Agent": "blackheart-fork/1"},
    )
    return json.loads(urllib.request.urlopen(req, timeout=20).read())


@pytest.mark.slow
@pytest.mark.network
def test_fork_pnl_measures_eth_and_token_delta():
    anvil = _anvil()
    if not anvil:
        pytest.skip("anvil not installed")
    port = _free_port()
    url = f"http://127.0.0.1:{port}"
    proc = subprocess.Popen(
        [anvil, "--fork-url", _FORK_RPC, "--port", str(port)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        for _ in range(40):
            try:
                _rpc(url, "eth_chainId", [])
                break
            except Exception:
                time.sleep(0.5)
        else:
            pytest.skip("anvil fork did not start (no network?)")
        attacker = _rpc(url, "eth_accounts", [])["result"][0]
        pnl = run_fork_sequence(url, attacker, [(_WETH9, _DEPOSIT, 10**18)], token=_WETH9)
        assert pnl.token_delta == 10**18  # received 1 WETH for 1 ETH
        assert pnl.eth_delta < 0          # paid 1 ETH + gas -> net negative
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()


@pytest.mark.slow
@pytest.mark.network
def test_screen_candidates_independent():
    anvil = _anvil()
    if not anvil:
        pytest.skip("anvil not installed")
    port = _free_port()
    url = f"http://127.0.0.1:{port}"
    proc = subprocess.Popen([anvil, "--fork-url", _FORK_RPC, "--port", str(port)],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        for _ in range(40):
            try:
                _rpc(url, "eth_chainId", [])
                break
            except Exception:
                time.sleep(0.5)
        else:
            pytest.skip("anvil fork did not start")
        attacker = _rpc(url, "eth_accounts", [])["result"][0]
        res = screen_candidates(url, _WETH9, attacker,
                                [(_DEPOSIT, 10**18), (_DEPOSIT, 10**18)], token=_WETH9)
        assert len(res) == 2
        for r in res:
            assert r["token_delta"] == 10**18  # independent runs, not 2e18
            assert r["eth_delta"] < 0
            assert r["extracts_eth"] is False
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()


_WETH9_ABI_MIN = [
    {"type": "function", "name": "deposit", "inputs": []},
    {"type": "function", "name": "withdraw", "inputs": [{"name": "wad", "type": "uint256"}]},
    {"type": "function", "name": "balanceOf", "inputs": [{"name": "", "type": "address"}]},
]


@pytest.mark.network
def test_fetch_abi_from_sourcify():
    from blackheart.fork_pnl import fetch_abi
    abi = fetch_abi(1, _WETH9)
    assert abi, "Sourcify returned no ABI"
    names = {e.get("name") for e in abi if e.get("type") == "function"}
    assert "deposit" in names and "balanceOf" in names


@pytest.mark.slow
@pytest.mark.network
def test_screen_target_fork_weth9():
    from blackheart.fork_pnl import screen_target_fork
    anvil = _anvil()
    if not anvil:
        pytest.skip("anvil not installed")
    port = _free_port()
    url = f"http://127.0.0.1:{port}"
    proc = subprocess.Popen([anvil, "--fork-url", _FORK_RPC, "--port", str(port)],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        for _ in range(40):
            try:
                _rpc(url, "eth_chainId", [])
                break
            except Exception:
                time.sleep(0.5)
        else:
            pytest.skip("anvil fork did not start")
        attacker = _rpc(url, "eth_accounts", [])["result"][0]
        res = screen_target_fork(url, _WETH9, attacker, abi=_WETH9_ABI_MIN, token=_WETH9)
        assert len(res) == 3  # deposit, withdraw, balanceOf
        assert any(r["data"].startswith("0x70a08231") for r in res)  # balanceOf(address)
        assert any(r["data"].startswith("0xd0e30db0") for r in res)  # deposit()
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()


_DRAIN = "0x600060006000600047335af100"
_GUARD = "0x60006000fd"
_VULN = "0x000000000000000000000000000000000000d00d"
_GUARDED = "0x000000000000000000000000000000000000dead"


@pytest.mark.slow
@pytest.mark.network
def test_fork_extraction_differential():
    anvil = _anvil()
    if not anvil:
        pytest.skip("anvil not installed")
    port = _free_port()
    url = f"http://127.0.0.1:{port}"
    proc = subprocess.Popen([anvil, "--port", str(port)],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        for _ in range(40):
            try:
                _rpc(url, "eth_chainId", [])
                break
            except Exception:
                time.sleep(0.5)
        else:
            pytest.skip("anvil fork did not start")
        attacker = _rpc(url, "eth_accounts", [])["result"][0]
        _rpc(url, "anvil_setCode", [_VULN, _DRAIN])
        _rpc(url, "anvil_setCode", [_GUARDED, _GUARD])
        _rpc(url, "anvil_setBalance", [_VULN, hex(5 * 10**18)])
        _rpc(url, "anvil_setBalance", [_GUARDED, hex(5 * 10**18)])
        pv = run_fork_sequence(url, attacker, [(_VULN, "0x", 0)])
        pg = run_fork_sequence(url, attacker, [(_GUARDED, "0x", 0)])
        assert pv.eth_delta > 0
        assert pg.eth_delta <= 0
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()


_DAI = "0x6B175474E89094C44Da98b954EedeAC495271d0F"


@pytest.mark.slow
@pytest.mark.network
def test_screen_real_token_dai_on_fork():
    from blackheart.fork_pnl import fetch_abi, screen_target_fork
    anvil = _anvil()
    if not anvil:
        pytest.skip("anvil not installed")
    port = _free_port()
    url = f"http://127.0.0.1:{port}"
    proc = subprocess.Popen([anvil, "--fork-url", _FORK_RPC, "--port", str(port)],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        for _ in range(40):
            try:
                _rpc(url, "eth_chainId", [])
                break
            except Exception:
                time.sleep(0.5)
        else:
            pytest.skip("anvil fork did not start")
        attacker = _rpc(url, "eth_accounts", [])["result"][0]
        abi = fetch_abi(1, _DAI)
        assert len(abi) >= 15  # DAI's real verified ABI
        res = screen_target_fork(url, _DAI, attacker, abi=abi, token=_DAI)
        assert len(res) >= 15  # the real ABI's functions were screened on the fork
        for r in res:
            assert {"data", "eth_delta", "token_delta", "extracts_eth"} <= set(r)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()


_WETH = "0xC02aaa39b223FE8D0A0e5C4F27eAD9083C756Cc2"
_WHALE = "0xB4e16d0168e52d35CaCD2c6185b44281Ec28C9Dc"  # Uniswap V2 WETH/USDC pair
# WETH.transfer(CALLER, 5e18) -- a vault that hands its whole WETH balance to any caller
_VAULT_BYTECODE = ("0x63a9059cbb60e01b60005233600452"
                   "674563918244f40000602452"
                   "6000600060446000600073c02aaa39b223fe8d0a0e5c4f27ead9083c756cc25af100")
_GUARD_BYTECODE = "0x60006000fd"  # always revert


def _whale_fund(url, whale, token, to, amount):
    data = "0xa9059cbb" + "0" * 24 + to[2:].lower() + hex(amount)[2:].rjust(64, "0")
    h = _rpc(url, "eth_sendTransaction",
             [{"from": whale, "to": token, "data": data, "gas": hex(200000)}])["result"]
    _wait_receipt(url, h)
    for _ in range(60):
        if _token_balance(url, token, to) >= amount:
            return
        time.sleep(0.1)
    raise AssertionError("whale funding did not settle")


@pytest.mark.slow
@pytest.mark.network
def test_fork_real_erc20_extraction_differential():
    anvil = _anvil()
    if not anvil:
        pytest.skip("anvil not installed")
    port = _free_port()
    url = f"http://127.0.0.1:{port}"
    proc = subprocess.Popen([anvil, "--fork-url", _FORK_RPC, "--port", str(port)],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        for _ in range(40):
            try:
                _rpc(url, "eth_chainId", [])
                break
            except Exception:
                time.sleep(0.5)
        else:
            pytest.skip("anvil fork did not start")
        attacker = _rpc(url, "eth_accounts", [])["result"][0]
        vuln = "0x000000000000000000000000000000000000d00d"
        guard = "0x000000000000000000000000000000000000dead"
        _rpc(url, "anvil_setCode", [vuln, _VAULT_BYTECODE])
        _rpc(url, "anvil_setCode", [guard, _GUARD_BYTECODE])
        _rpc(url, "anvil_impersonateAccount", [_WHALE])
        _rpc(url, "anvil_setBalance", [_WHALE, hex(10**18)])
        _whale_fund(url, _WHALE, _WETH, vuln, 5 * 10**18)
        _whale_fund(url, _WHALE, _WETH, guard, 5 * 10**18)
        pv = run_fork_sequence(url, attacker, [(vuln, "0x", 0)], token=_WETH)
        pg = run_fork_sequence(url, attacker, [(guard, "0x", 0)], token=_WETH)
        assert pv.token_delta > 0   # vulnerable vault hands its WETH to the attacker
        assert pg.token_delta <= 0  # guarded vault gives nothing
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
