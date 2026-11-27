"""Tests for structured, verified discovery over You.com.

The search is mocked (no network, no spend) and the RPC probe is mocked by a
local HTTP server that speaks JSON-RPC. The tests prove the core discipline:
external text is a *lead*, and only a call that runs promotes it to a fact.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

import blackheart.intelligence.discover as disc
from blackheart.intelligence.discover import (
    DiscoveryResult,
    _extract_urls,
    _rpc_like,
    discover_chain,
    discover_contract,
    discover_rpc_endpoints,
)
from blackheart.intelligence.youcom import IntelResult, Source


@pytest.fixture(autouse=True)
def no_registry(monkeypatch):
    """Keep the keyless chain registry out of the tests (no network)."""
    monkeypatch.setattr(disc, "_registry_entries", lambda timeout=15: [])


class _FakeClient:
    """A You.com stand-in that returns a fixed result set for any query."""

    def __init__(self, sources, *, ok=True, error=""):
        self._sources = sources
        self._ok = ok
        self._error = error

    def search(self, query, **kwargs):
        r = IntelResult(operation="search", query=query, provider="you.com")
        r.ok = self._ok
        r.error = self._error
        r.sources = list(self._sources)
        return r


def _src(url, *snippets):
    return Source(url=url, title=url, snippets=list(snippets), provider="you.com")


# --------------------------------------------------------------------------- #
# Pure helpers
# --------------------------------------------------------------------------- #

def test_extract_urls_strips_trailing_punctuation():
    urls = _extract_urls("see https://a.test/rpc, and https://b.test/x).")
    assert "https://a.test/rpc" in urls
    assert "https://b.test/x" in urls


def test_rpc_like_accepts_endpoint_shapes_rejects_assets():
    assert _rpc_like("https://mainnet.example.com/rpc")
    assert _rpc_like("https://node.example.com/json-rpc")
    assert not _rpc_like("https://example.com/logo.png")
    assert not _rpc_like("https://example.com/style.css")


# --------------------------------------------------------------------------- #
# RPC discovery: verification is a real call
# --------------------------------------------------------------------------- #

def test_search_failure_is_reported_not_faked():
    res = discover_rpc_endpoints("ethereum", client=_FakeClient([], ok=False, error="boom"))
    assert res.ok is False and res.error == "boom" and res.verified == []


def test_no_probe_returns_candidates_only():
    client = _FakeClient([_src("https://docs.test/page", "rpc: https://node.test/rpc")])
    res = discover_rpc_endpoints("ethereum", client=client, probe=False)
    assert res.ok is False and res.verified == []
    assert any("node.test/rpc" in c["url"] for c in res.candidates)
    assert any("probing disabled" in n for n in res.notes)


def test_endpoints_are_verified_by_a_real_chainid_call():
    srv, base = _rpc_server({"/rpc": 1})
    try:
        client = _FakeClient([_src("https://docs.test/p", f"rpc {base}/rpc")])
        res = discover_rpc_endpoints("ethereum", client=client, expect_chain_id=1)
        assert res.ok is True
        assert res.verified and res.verified[0]["chain_id"] == 1
        assert res.verified[0]["verified"] is True
    finally:
        srv.shutdown()


def test_wrong_chain_id_is_not_verified():
    srv, base = _rpc_server({"/rpc": 137})
    try:
        client = _FakeClient([_src("https://docs.test/p", f"rpc {base}/rpc")])
        res = discover_rpc_endpoints("ethereum", client=client, expect_chain_id=1)
        assert res.ok is False
        assert res.verified == []
        assert any("!= expected 1" in c["error"] for c in res.candidates)
    finally:
        srv.shutdown()


def test_unreachable_endpoint_is_a_candidate_with_an_error():
    client = _FakeClient([_src("https://docs.test/p", "rpc http://127.0.0.1:1/rpc")])
    res = discover_rpc_endpoints("ethereum", client=client, timeout=1)
    assert res.ok is False
    assert res.candidates and res.candidates[0]["error"]


def test_registry_endpoints_are_used_and_verified(monkeypatch):
    srv, base = _rpc_server({"/rpc": 8453})
    try:
        monkeypatch.setattr(disc, "_registry_rpc_urls",
                            lambda chain, timeout=15: [f"{base}/rpc"])
        client = _FakeClient([])  # search returns nothing; registry must carry it
        res = discover_rpc_endpoints("base", client=client, expect_chain_id=8453)
        assert res.ok is True
        assert res.verified[0]["chain_id"] == 8453
        assert any("keyless chain registry" in n for n in res.notes)
    finally:
        srv.shutdown()


def test_registry_failure_with_search_failure_is_honest(monkeypatch):
    monkeypatch.setattr(disc, "_registry_rpc_urls", lambda chain, timeout=15: [])
    res = discover_rpc_endpoints("nope", client=_FakeClient([], ok=False, error="down"))
    assert res.ok is False and res.error == "down" and res.candidates == []


def test_registry_match_accepts_a_numeric_chain_id(monkeypatch):
    entries = [{"name": "Lisk", "shortName": "lisk", "chain": ["lisk"],
                "chainId": 1135, "rpc": ["https://rpc.lisk.example"]}]
    monkeypatch.setattr(disc, "_registry_entries", lambda timeout=15: entries)
    assert disc._registry_match(1135) == entries
    assert disc._registry_match("1135") == entries
    assert disc._registry_rpc_urls(1135) == ["https://rpc.lisk.example"]
    assert disc._registry_match(999999) == []


# --------------------------------------------------------------------------- #
# Contract + chain discovery
# --------------------------------------------------------------------------- #

def test_contract_without_rpc_is_unverified_candidates():
    addr = "0x" + "ab" * 20
    client = _FakeClient([_src("https://etherscan.io/address/x", f"deployed at {addr}")])
    res = discover_contract("Example", client=client)
    assert res.ok is False
    assert any(c["address"].lower() == addr for c in res.candidates)
    assert any("no rpc_url" in n for n in res.notes)


def test_contract_verified_by_getcode():
    addr = "0x" + "cd" * 20
    srv, base = _rpc_server({"/rpc": 1, "code": "0x60806040"})
    try:
        client = _FakeClient([_src("https://etherscan.io/address/x", f"deployed at {addr}")])
        res = discover_contract("Example", rpc_url=f"{base}/rpc", client=client)
        assert res.ok is True
        assert res.verified[0]["address"].lower() == addr
        assert res.verified[0]["code_size"] == 4
    finally:
        srv.shutdown()


def test_chain_id_unique_is_verified_ambiguous_is_not():
    uniq = _FakeClient([_src("https://chainlist.org/x", "Chain ID 10")])
    assert discover_chain("optimism", client=uniq).verified == [{"chain_id": 10, "source": "search"}]

    amb = _FakeClient([_src("https://chainlist.org/x", "Chain ID 10 and Chain ID 11")])
    res = discover_chain("mystery", client=amb)
    assert res.ok is False
    assert any("ambiguous" in n for n in res.notes)


# --------------------------------------------------------------------------- #
# A JSON-RPC mock server
# --------------------------------------------------------------------------- #

class _RpcHandler(BaseHTTPRequestHandler):
    routes: dict = {}

    def log_message(self, *a):
        pass

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        req = json.loads(self.rfile.read(length) or b"{}")
        method = req.get("method")
        key = self.path
        if method == "eth_chainId":
            cid = _RpcHandler.routes.get(key)
            return self._ok(hex(cid) if cid is not None else "0x0")
        if method == "eth_getCode":
            return self._ok(_RpcHandler.routes.get("code", "0x"))
        return self._ok("0x0")

    def _ok(self, result):
        body = json.dumps({"jsonrpc": "2.0", "id": 1, "result": result}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def _rpc_server(routes):
    _RpcHandler.routes = routes
    srv = HTTPServer(("127.0.0.1", 0), _RpcHandler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}"
