"""Fork EXECUTION smoke (#1): anvil forks mainnet and reads REAL WETH9 state.

Skips when anvil is absent or the fork can't start (no network); marked slow+network so CI
(`-m "not slow"`) skips it. Run locally with `-m network`. Proves the anvil fork path that
fork-replay-first (#1) executes on, not just read-only RPC.
"""

import json
import os
import shutil
import socket
import subprocess
import time
import urllib.request

import pytest

_WETH9 = "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"
_FORK_RPC = "https://ethereum-rpc.publicnode.com"


def _anvil() -> str | None:
    for p in (os.path.expanduser("~/.foundry/bin/anvil"), shutil.which("anvil")):
        if p and os.path.exists(p):
            return p
    return None


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _rpc(url: str, method: str, params: list) -> dict:
    payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    req = urllib.request.Request(
        url, data=payload,
        headers={"content-type": "application/json", "User-Agent": "blackheart-smoke/1"},
    )
    return json.loads(urllib.request.urlopen(req, timeout=10).read())


@pytest.mark.slow
@pytest.mark.network
def test_anvil_fork_executes_and_reads_real_weth9_state():
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
        block = int(_rpc(url, "eth_blockNumber", [])["result"], 16)
        assert block > 0
        # real WETH9 totalSupply() on the forked state
        res = _rpc(url, "eth_call", [{"to": _WETH9, "data": "0x18160ddd"}, "latest"])
        assert int(res["result"], 16) > 0
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
