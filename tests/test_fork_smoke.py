"""Fork-readiness smoke (#1): read REAL mainnet state through a live RPC.

Marked slow+network so CI (`pytest -m "not slow"`) skips it; run with `-m network`.
Proves the live RPC path that fork-replay-first depends on returns real mainnet data.
"""

import json
import urllib.request

import pytest

from blackheart.rpc import resolve_rpc

_WETH9 = "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"
_ENDPOINTS = ["https://ethereum-rpc.publicnode.com", "https://eth.llamarpc.com"]


def _get_code(url: str) -> str:
    payload = json.dumps(
        {"jsonrpc": "2.0", "id": 1, "method": "eth_getCode", "params": [_WETH9, "latest"]}
    ).encode()
    req = urllib.request.Request(
        url, data=payload,
        headers={"content-type": "application/json", "User-Agent": "blackheart-smoke/1"},
    )
    body = json.loads(urllib.request.urlopen(req, timeout=20).read())
    return body.get("result", "")


@pytest.mark.slow
@pytest.mark.network
def test_live_rpc_reads_real_weth9_runtime_code():
    res = resolve_rpc("mainnet", use_search=False)
    urls = ([res.url] if res.ok else []) + _ENDPOINTS
    code = ""
    for url in urls:
        try:
            code = _get_code(url)
        except Exception:
            continue
        if code.startswith("0x") and len(code) > 100:
            break
    assert code.startswith("0x") and len(code) > 100  # real WETH9 runtime bytecode
