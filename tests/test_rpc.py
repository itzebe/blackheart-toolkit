"""Tests for the universal RPC resolver.

The resolver exists so no fork test silently depends on one hardcoded endpoint.
The properties that matter, and are asserted here with no network:

  * the operator's explicit value always wins and is never replaced;
  * only an endpoint that *answered* is returned -- a dead one is never returned
    as if it were live;
  * the resolution order is explicit -> registry -> You.com -> probed fallback;
  * when nothing answers, the result is honest (``ok=False``, a reason, a trail).
"""

from __future__ import annotations

import blackheart.rpc as rpc


def _fake_probe(live: dict[str, int], *, default_ok: bool = False):
    def probe(url: str, *, timeout: int = 15):
        if url in live:
            return True, live[url], ""
        return default_ok, 0, f"{url}: refused"
    return probe


def test_explicit_override_wins_and_is_used_verbatim(monkeypatch):
    monkeypatch.setattr(rpc, "probe_rpc", _fake_probe({"http://mine": 1}))
    res = rpc.resolve_rpc("mainnet", explicit="http://mine")
    assert res.ok and res.url == "http://mine"
    assert res.source == "explicit" and res.chain_id == 1
    # No other source is consulted once the operator's choice answers.
    assert [t["source"] for t in res.tried] == ["explicit"]


def test_env_var_is_the_explicit_override(monkeypatch):
    monkeypatch.setenv(rpc.ENV_VAR, "http://from-env")
    monkeypatch.setattr(rpc, "probe_rpc", _fake_probe({"http://from-env": 1}))
    res = rpc.resolve_rpc("mainnet")
    assert res.ok and res.url == "http://from-env" and res.source == "explicit"


def test_explicit_that_does_not_answer_is_reported_not_replaced(monkeypatch):
    monkeypatch.setattr(rpc, "probe_rpc", _fake_probe({}))
    res = rpc.resolve_rpc("mainnet", explicit="http://dead")
    assert res.ok is False and res.url == ""
    assert "did not answer" in res.error
    # It did not fall through to another endpoint behind the operator's back.
    assert len(res.tried) == 1


def test_registry_answers_before_search(monkeypatch):
    monkeypatch.setattr(rpc, "probe_rpc", _fake_probe({"http://reg": 1}))
    import blackheart.intelligence.discover as disc

    monkeypatch.setattr(disc, "_registry_rpc_urls",
                        lambda chain, timeout=15: ["http://reg"])
    called = {"search": False}

    def _no_search(*a, **k):
        called["search"] = True
        raise AssertionError("You.com search must not run when the registry answers")

    monkeypatch.setattr(disc, "discover_rpc_endpoints", _no_search)
    res = rpc.resolve_rpc("mainnet")
    assert res.ok and res.source == "registry" and res.url == "http://reg"
    assert called["search"] is False


def test_youcom_search_is_used_when_registry_is_empty(monkeypatch):
    monkeypatch.setattr(rpc, "probe_rpc", _fake_probe({}))
    import blackheart.intelligence.discover as disc

    monkeypatch.setattr(disc, "_registry_rpc_urls", lambda chain, timeout=15: [])

    class _Found:
        verified = [{"url": "http://you", "chain_id": 1}]
        candidates = []

    monkeypatch.setattr(disc, "discover_rpc_endpoints",
                        lambda chain, **k: _Found())
    res = rpc.resolve_rpc("mainnet")
    assert res.ok and res.source == "you.com" and res.url == "http://you"


def test_fallback_only_after_registry_and_search_fail(monkeypatch):
    monkeypatch.setattr(rpc, "probe_rpc", _fake_probe({rpc.FALLBACKS[0]: 1}))
    import blackheart.intelligence.discover as disc

    monkeypatch.setattr(disc, "_registry_rpc_urls", lambda chain, timeout=15: [])

    class _Empty:
        verified: list = []
        candidates: list = []

    monkeypatch.setattr(disc, "discover_rpc_endpoints", lambda chain, **k: _Empty())
    res = rpc.resolve_rpc("mainnet")
    assert res.ok and res.source == "fallback" and res.url == rpc.FALLBACKS[0]


def test_no_endpoint_answering_is_an_honest_failure(monkeypatch):
    monkeypatch.setattr(rpc, "probe_rpc", _fake_probe({}))
    import blackheart.intelligence.discover as disc

    monkeypatch.setattr(disc, "_registry_rpc_urls", lambda chain, timeout=15: [])

    class _Empty:
        verified: list = []
        candidates: list = []

    monkeypatch.setattr(disc, "discover_rpc_endpoints", lambda chain, **k: _Empty())
    res = rpc.resolve_rpc("mainnet")
    assert res.ok is False and res.url == ""
    assert res.error
    assert res.tried, "a failure must still carry the trail of what was tried"


def test_wrong_chain_id_is_not_accepted(monkeypatch):
    # A live endpoint on the wrong chain is not a mainnet endpoint.
    monkeypatch.setattr(rpc, "probe_rpc", _fake_probe({"http://reg": 137}))
    import blackheart.intelligence.discover as disc

    monkeypatch.setattr(disc, "_registry_rpc_urls",
                        lambda chain, timeout=15: ["http://reg"])

    class _Empty:
        verified: list = []
        candidates: list = []

    monkeypatch.setattr(disc, "discover_rpc_endpoints", lambda chain, **k: _Empty())
    res = rpc.resolve_rpc("mainnet", expect_chain_id=1)
    assert res.ok is False


def test_probe_rpc_parses_hex_and_decimal_and_never_raises(monkeypatch):
    from blackheart.deployed import ChainClient, RpcUnavailable

    monkeypatch.setattr(ChainClient, "call", lambda self, m, p: "0x1")
    ok, cid, err = rpc.probe_rpc("http://x")
    assert ok and cid == 1 and err == ""

    monkeypatch.setattr(ChainClient, "call", lambda self, m, p: "1")
    ok, cid, err = rpc.probe_rpc("http://x")
    assert ok and cid == 1

    def _boom(self, m, p):
        raise RpcUnavailable("nope")

    monkeypatch.setattr(ChainClient, "call", _boom)
    ok, cid, err = rpc.probe_rpc("http://x")
    assert ok is False and cid == 0 and "nope" in err


def test_probe_rpc_unparseable_id_is_a_failure(monkeypatch):
    from blackheart.deployed import ChainClient

    monkeypatch.setattr(ChainClient, "call", lambda self, m, p: "not-a-number")
    ok, cid, err = rpc.probe_rpc("http://x")
    assert ok is False and "unparseable" in err


def test_resolve_mainnet_rpc_returns_empty_string_when_unavailable(monkeypatch):
    monkeypatch.setattr(rpc, "probe_rpc", _fake_probe({}))
    monkeypatch.delenv(rpc.ENV_VAR, raising=False)
    import blackheart.intelligence.discover as disc

    monkeypatch.setattr(disc, "_registry_rpc_urls", lambda chain, timeout=15: [])

    class _Empty:
        verified: list = []
        candidates: list = []

    monkeypatch.setattr(disc, "discover_rpc_endpoints", lambda chain, **k: _Empty())
    assert rpc.resolve_mainnet_rpc() == ""


def test_numeric_chain_never_returns_another_chain(monkeypatch):
    """A request for chain 1135 must not be satisfied by a mainnet endpoint."""
    monkeypatch.setattr(rpc, "probe_rpc", _fake_probe({"http://eth": 1}))
    monkeypatch.setattr(rpc, "FALLBACKS", ["http://eth"])
    import blackheart.intelligence.discover as disc

    monkeypatch.setattr(disc, "_registry_rpc_urls", lambda chain, timeout=15: [])
    res = rpc.resolve_rpc(1135, use_search=False)
    assert res.ok is False and res.url == ""
    assert "no endpoint answered" in res.error


def test_numeric_chain_accepts_the_matching_chain(monkeypatch):
    monkeypatch.setattr(rpc, "probe_rpc", _fake_probe({"http://lisk": 1135}))
    monkeypatch.setattr(rpc, "FALLBACKS", ["http://lisk"])
    import blackheart.intelligence.discover as disc

    monkeypatch.setattr(disc, "_registry_rpc_urls", lambda chain, timeout=15: [])
    res = rpc.resolve_rpc(1135, use_search=False)
    assert res.ok and res.url == "http://lisk" and res.chain_id == 1135
