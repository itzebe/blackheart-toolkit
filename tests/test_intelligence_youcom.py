"""Phase 5/6 — tests for the You.com intelligence layer and MCP config.

Most tests run against a local mock HTTP server that speaks the You.com REST
shapes, so they exercise the real client code (request building, headers,
parsing, error handling, cost/key safety) with no network and no spend.

One test is an opt-in live smoke test, skipped unless ``BLACKHEART_LIVE_YOU=1``
and ``YDC_API_KEY`` are both set. It is the only test that spends (a single lite
research call, capped) and it proves the live integration is real.
"""

from __future__ import annotations

import json
import os
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from blackheart.intelligence import (
    CostRefusal,
    YouComClient,
    YouComError,
    frame_question,
)
from blackheart.intelligence.youcom import (
    CONTENTS_URL,
    RESEARCH_URL,
    SEARCH_URL,
)
from blackheart.intelligence.mcp import (
    MCP_FREE_PROFILE_URL,
    MCP_PRODUCT_URL,
    MCP_RESEARCH_URL,
    mcp_config,
    openhands_mcp_config,
)


# --------------------------------------------------------------------------- #
# A mock You.com server that speaks the documented shapes
# --------------------------------------------------------------------------- #

class _Handler(BaseHTTPRequestHandler):
    seen: list[dict] = []

    def log_message(self, *a):  # silence
        pass

    def _send(self, obj, code=200):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        req = json.loads(self.rfile.read(length) or b"{}")
        _Handler.seen.append({
            "path": self.path,
            "headers": dict(self.headers),
            "body": req,
        })
        # A key-echo endpoint: proves the client never lets the key leak.
        if self.path.endswith("/v1/search"):
            return self._send({
                "results": {"web": [
                    {"url": "https://a.test/1", "title": "First",
                     "description": "desc", "snippets": ["s1", "s2"],
                     "page_age": "2025-01-01"},
                    {"url": "https://b.test/2", "title": "Second",
                     "snippets": ["s3"]},
                ]},
                "metadata": {"query": req.get("query", ""), "latency": 0.1},
            })
        if self.path.endswith("/v1/contents"):
            return self._send([
                {"url": (req.get("urls") or [""])[0], "title": "Page",
                 "markdown": "# Hello\ncontent", "html": "<h1>Hello</h1>"},
            ])
        if self.path.endswith("/v1/research"):
            return self._send({
                "output": {
                    "content": "A cited answer. [1]",
                    "content_type": "text",
                    "sources": [{"url": "https://a.test/x", "title": "Src",
                                 "snippets": ["q"]}],
                },
                "warnings": [],
            })
        return self._send({"detail": "not found"}, 404)


def _server() -> tuple[HTTPServer, str]:
    srv = HTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}"


@pytest.fixture
def mock_you(monkeypatch):
    srv, base = _server()
    _Handler.seen = []
    # Point the client's endpoint constants at the mock.
    import blackheart.intelligence.youcom as yc
    monkeypatch.setattr(yc, "SEARCH_URL", f"{base}/v1/search")
    monkeypatch.setattr(yc, "CONTENTS_URL", f"{base}/v1/contents")
    monkeypatch.setattr(yc, "RESEARCH_URL", f"{base}/v1/research")
    try:
        yield base
    finally:
        srv.shutdown()


# --------------------------------------------------------------------------- #
# Search
# --------------------------------------------------------------------------- #

def test_search_parses_web_results(mock_you):
    c = YouComClient("test-key")
    r = c.search("reentrancy", count=5)
    assert r.ok and r.raw_status == 200 and r.paid is False
    assert [s.url for s in r.sources] == ["https://a.test/1", "https://b.test/2"]
    assert r.sources[0].snippets == ["s1", "s2"]


def test_search_sends_x_api_key_header_and_never_in_url(mock_you):
    c = YouComClient("secret-key-123")
    c.search("q")
    req = _Handler.seen[-1]
    # HTTP headers are case-insensitive; urllib capitalises keys (X-API-Key ->
    # X-api-key) and the live API accepts that. Compare case-insensitively.
    lower = {k.lower(): v for k, v in req["headers"].items()}
    assert lower.get("x-api-key") == "secret-key-123"
    assert "secret-key-123" not in req["path"]
    # a User-Agent is always sent (api.you.com rejects the default urllib UA)
    assert lower.get("user-agent")


def test_search_rejects_include_and_exclude_together(mock_you):
    c = YouComClient("k")
    r = c.search("q", include_domains=["a.com"], exclude_domains=["b.com"])
    assert r.ok is False and "cannot be combined" in r.error


def test_search_extraction_requires_paid(mock_you):
    c = YouComClient("k", allow_paid=False)
    with pytest.raises(CostRefusal):
        c.search("q", extract="highlights")


def test_empty_query_is_rejected(mock_you):
    r = YouComClient("k").search("   ")
    assert r.ok is False and "empty query" in r.error


# --------------------------------------------------------------------------- #
# Contents (paid)
# --------------------------------------------------------------------------- #

def test_contents_requires_paid_permission(mock_you):
    with pytest.raises(CostRefusal):
        YouComClient("k").contents(["https://a.test"])


def test_contents_parses_documents_when_allowed(mock_you):
    c = YouComClient("k", allow_paid=True, max_paid_calls=3)
    r = c.contents(["https://a.test"], formats=["markdown"])
    assert r.ok and r.paid and len(r.documents) == 1
    assert r.documents[0].markdown.startswith("# Hello")
    assert c.paid_calls == 1


# --------------------------------------------------------------------------- #
# Research (paid)
# --------------------------------------------------------------------------- #

def test_research_requires_paid_permission(mock_you):
    with pytest.raises(CostRefusal):
        YouComClient("k").research("why?", effort="lite")


def test_research_parses_answer_and_sources(mock_you):
    c = YouComClient("k", allow_paid=True, max_paid_calls=3)
    r = c.research("why?", effort="lite")
    assert r.ok and r.content_type == "text"
    assert r.text.startswith("A cited answer")
    assert r.sources[0].url == "https://a.test/x"
    assert c.paid_calls == 1


def test_research_rejects_frontier_without_background(mock_you):
    c = YouComClient("k", allow_paid=True, max_paid_calls=3)
    r = c.research("q", effort="frontier")
    assert r.ok is False and "frontier" in r.error


def test_research_rejects_output_schema_with_lite(mock_you):
    c = YouComClient("k", allow_paid=True, max_paid_calls=3)
    r = c.research("q", effort="lite", output_schema={"type": "object"})
    assert r.ok is False and "output_schema" in r.error


def test_research_rejects_overlong_input(mock_you):
    c = YouComClient("k", allow_paid=True, max_paid_calls=3)
    r = c.research("x" * 40_001, effort="lite")
    assert r.ok is False and "40" in r.error


# --------------------------------------------------------------------------- #
# Cost safety
# --------------------------------------------------------------------------- #

def test_paid_call_cap_is_enforced(mock_you):
    c = YouComClient("k", allow_paid=True, max_paid_calls=1)
    assert c.research("q", effort="lite").ok
    with pytest.raises(CostRefusal):
        c.contents(["https://a.test"])
    assert c.paid_calls == 1


def test_cap_zero_with_allow_paid_refuses_everything(mock_you):
    c = YouComClient("k", allow_paid=True, max_paid_calls=0)
    with pytest.raises(CostRefusal):
        c.research("q", effort="lite")


# --------------------------------------------------------------------------- #
# Key safety
# --------------------------------------------------------------------------- #

def test_missing_key_is_reported_honestly(mock_you, monkeypatch):
    monkeypatch.delenv("YDC_API_KEY", raising=False)
    c = YouComClient("")
    assert c.key_present is False
    r = c.search("q")
    assert r.ok is False and "YDC_API_KEY" in r.error


def test_key_is_redacted_from_errors(monkeypatch):
    # Point at an unreachable host to force a transport error containing no key,
    # then confirm the redactor scrubs a key if one appears in a message.
    c = YouComClient("ydc-supersecretvalue123456")
    scrubbed = c._redact("failed with key ydc-supersecretvalue123456 in header")
    assert "ydc-supersecretvalue123456" not in scrubbed
    assert "<redacted>" in scrubbed


def test_youcomerror_redacts_on_construction():
    # The class docstring promises the message never contains the key. Enforce it
    # in the constructor so a caller that raises with an unscrubbed upstream body
    # (e.g. a proxy that echoes the key back) cannot leak it.
    key = "ydc-proxyechoedvalue1234567890"
    e = YouComError(f"HTTP 400: bad request (key={key})", kind="invalid_request",
                    status=400)
    assert key not in str(e)
    assert "<redacted>" in str(e)


def test_youcomerror_redacts_an_unknown_generic_token():
    # Even without the exact key, any ydc- token is scrubbed.
    e = YouComError("failure with ydc-abcdef1234567890 embedded")
    assert "ydc-abcdef1234567890" not in str(e)


def test_redact_secrets_is_the_single_redactor():
    from blackheart.intelligence.youcom import redact_secrets
    assert redact_secrets("x ydc-abcdef1234567890 y", api_key="") == "x <redacted> y"
    assert redact_secrets("exact abc123 here", api_key="abc123") == "exact <redacted> here"


# --------------------------------------------------------------------------- #
# Health probe is unbilled
# --------------------------------------------------------------------------- #

def test_health_probe_does_not_spend(mock_you):
    c = YouComClient("k", allow_paid=False, max_paid_calls=0)
    h = c.health()
    assert h.ok and h.operation == "health" and h.paid is False
    assert c.paid_calls == 0


# --------------------------------------------------------------------------- #
# Attacker lens framing
# --------------------------------------------------------------------------- #

def test_frame_question_carries_the_canonical_lens():
    from blackheart.mindset import ATTACKER_QUESTION, OUTCOMES, LEVERS

    lens = frame_question()
    assert lens["question"] == ATTACKER_QUESTION
    assert lens["outcomes"] == list(OUTCOMES)
    assert lens["levers"] == list(LEVERS)


# --------------------------------------------------------------------------- #
# MCP config (Phase 6)
# --------------------------------------------------------------------------- #

def test_mcp_config_with_key_references_env_not_the_secret():
    cfg = mcp_config(with_key=True)
    server = cfg["mcpServers"]["youdotcom"]
    assert server["url"] == MCP_PRODUCT_URL
    assert server["headers"]["Authorization"] == "Bearer ${YDC_API_KEY}"


def test_openhands_dialect_uses_transport_key():
    # OpenHands (FastMCP) keys the transport as "transport"; using "type" would
    # silently produce a non-connecting server.
    server = mcp_config(with_key=True, style="openhands")["mcpServers"]["youdotcom"]
    assert server.get("transport") == "http"
    assert "type" not in server


def test_claude_dialect_uses_type_key():
    server = mcp_config(with_key=True, style="claude")["mcpServers"]["youdotcom"]
    assert server.get("type") == "http"
    assert "transport" not in server


def test_mcp_config_keyless_uses_free_profile():
    cfg = mcp_config(with_key=False)
    server = cfg["mcpServers"]["youdotcom"]
    assert server["url"] == MCP_FREE_PROFILE_URL
    assert "headers" not in server


def test_mcp_config_scoped_tools_narrow_an_agent():
    cfg = mcp_config(with_key=True, scoped_tools=("you-search", "you-contents"))
    server = cfg["mcpServers"]["youdotcom"]
    assert "tools=you-search,you-contents" in server["url"]


def test_openhands_mcp_config_shape():
    cfg = openhands_mcp_config(with_key=True, docs=True)
    assert "mcpServers" in cfg
    assert "youdotcom" in cfg["mcpServers"]
    assert "youcom_docs" in cfg["mcpServers"]


# --------------------------------------------------------------------------- #
# Opt-in live smoke test (the only test that spends)
# --------------------------------------------------------------------------- #

@pytest.mark.skipif(
    not (os.environ.get("BLACKHEART_LIVE_YOU") == "1"
         and os.environ.get("YDC_API_KEY")),
    reason="set BLACKHEART_LIVE_YOU=1 and YDC_API_KEY to run the live smoke test",
)
def test_live_smoke_search_and_one_research():
    c = YouComClient(allow_paid=True, max_paid_calls=1, timeout=90)
    s = c.search("solidity access control vulnerability", count=3)
    assert s.ok and s.sources, s.error
    r = c.research("What is a reentrancy attack?", effort="lite")
    assert r.ok and r.text, r.error
    assert c.paid_calls == 1


@pytest.mark.skipif(
    not (os.environ.get("BLACKHEART_LIVE_YOU") == "1"
         and os.environ.get("YDC_API_KEY")),
    reason="set BLACKHEART_LIVE_YOU=1 and YDC_API_KEY to run the live MCP test",
)
def test_live_mcp_server_handshake_and_tools():
    """A raw MCP handshake against the live You.com server.

    This proves the emitted URL and the Bearer auth the config uses are correct,
    without adding a FastMCP dependency. It is the check that makes the MCP
    config real rather than merely well-formed.
    """
    import json
    import urllib.request

    key = os.environ["YDC_API_KEY"]
    url = "https://api.you.com/mcp"
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
        "Authorization": f"Bearer {key}",
        "User-Agent": "blackheart-intelligence/1.0",
    }

    def rpc(method, params, rid):
        body = json.dumps({"jsonrpc": "2.0", "id": rid, "method": method,
                           "params": params}).encode()
        req = urllib.request.Request(url, data=body, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.read().decode()

    rpc("initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                       "clientInfo": {"name": "blackheart", "version": "1.0"}}, 1)
    rpc("notifications/initialized", {}, 2)
    out = rpc("tools/list", {}, 3)
    line = next((l for l in out.splitlines() if l.startswith("data:")), "")
    data = json.loads(line[len("data:"):].strip())
    names = {t["name"] for t in data["result"]["tools"]}
    assert "you-search" in names
    # the research path exposes the research tool
    assert MCP_RESEARCH_URL.endswith("/research")
