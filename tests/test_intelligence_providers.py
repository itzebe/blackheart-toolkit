"""Tests for the external-intelligence provider layer and its resilience.

These run against a local mock HTTP server that speaks the real shapes, so the
provider code (request building, error classification, retries, fallback,
provenance, disagreement) is exercised with no network and no spend. The
keyless providers are pointed at the same mock so their parsing is tested too.

One opt-in live test at the bottom is skipped unless ``BLACKHEART_LIVE_YOU=1``
and ``YDC_API_KEY`` are both set; it proves the live integration is real.
"""

from __future__ import annotations

import json
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import ClassVar

import pytest

import blackheart.intelligence.youcom as yc
from blackheart.intelligence.providers import (
    DuckDuckGoProvider,
    ProviderRegistry,
    SearchRouter,
    WikipediaProvider,
)
from blackheart.intelligence.youcom import ErrorKind, YouComClient

# --------------------------------------------------------------------------- #
# A configurable mock server
# --------------------------------------------------------------------------- #

class _Handler(BaseHTTPRequestHandler):
    seen: ClassVar[list[dict]] = []
    # path -> (status, body) or a callable(handler) for custom behaviour.
    routes: ClassVar[dict[str, object]] = {}
    counters: ClassVar[dict[str, int]] = {}
    sleep_s: float = 0.0

    def log_message(self, *a):  # silence
        pass

    def _respond(self, status: int, obj) -> None:
        body = obj if isinstance(obj, (bytes, str)) else json.dumps(obj)
        body = body.encode() if isinstance(body, str) else body
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self._dispatch()

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length) if length else b""
        try:
            body = json.loads(raw or b"{}")
        except json.JSONDecodeError:
            body = {}
        self._dispatch(body)

    def _dispatch(self, body=None):
        path = self.path.split("?", 1)[0]
        _Handler.seen.append({"path": path, "headers": dict(self.headers),
                              "body": body})
        _Handler.counters[path] = _Handler.counters.get(path, 0) + 1
        if _Handler.sleep_s:
            time.sleep(_Handler.sleep_s)
        route = _Handler.routes.get(path)
        if route is None:
            # match by suffix (the providers use query strings/prefixes)
            for key, val in _Handler.routes.items():
                if path.endswith(key):
                    route = val
                    break
        if route is None:
            return self._respond(404, {"detail": "not found"})
        if callable(route):
            return route(self)
        status, obj = route
        return self._respond(status, obj)


@pytest.fixture
def mock_server(monkeypatch):
    srv = HTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_address[1]}"
    _Handler.seen = []
    _Handler.counters = {}
    _Handler.routes = {}
    _Handler.sleep_s = 0.0
    # Point the You.com client endpoints and the keyless provider bases here.
    monkeypatch.setattr(yc, "SEARCH_URL", f"{base}/v1/search")
    monkeypatch.setattr(yc, "CONTENTS_URL", f"{base}/v1/contents")
    monkeypatch.setattr(yc, "RESEARCH_URL", f"{base}/v1/research")
    monkeypatch.setattr(DuckDuckGoProvider, "BASE", f"{base}/ddg")
    monkeypatch.setattr(WikipediaProvider, "BASE", f"{base}/wiki")
    try:
        yield base
    finally:
        srv.shutdown()


_SEARCH_OK = (200, {"results": {"web": [
    {"url": "https://a.test/1", "title": "First", "description": "d",
     "snippets": ["s1"], "page_age": "2025-01-01"},
]}})
_DDG_OK = (200, {"Heading": "Reentrancy", "AbstractURL": "https://ddg.test/r",
                 "AbstractText": "A reentrancy is...",
                 "RelatedTopics": [{"FirstURL": "https://ddg.test/1",
                                    "Text": "Topic one - detail"}]})
_WIKI_OK = (200, {"query": {"search": [
    {"title": "Reentrancy attack", "snippet": "an <span>attack</span> class"},
]}})


# --------------------------------------------------------------------------- #
# Error classification (mission requirement 8)
# --------------------------------------------------------------------------- #

def _client(**kw):
    return YouComClient("test-key", **kw)


@pytest.mark.parametrize("status,kind", [
    (401, ErrorKind.INVALID_KEY),
    (403, ErrorKind.INSUFFICIENT_SCOPE),
    (402, ErrorKind.PAYMENT_REQUIRED),
    (422, ErrorKind.INVALID_REQUEST),
])
def test_http_status_is_classified(mock_server, status, kind):
    _Handler.routes["/v1/search"] = (status, {"detail": "nope"})
    r = _client().search("x")
    assert r.ok is False and r.raw_status == 0  # result carries the reason, not a status
    assert r.error_kind == kind


def test_429_is_rate_limited_after_retries(mock_server):
    _Handler.routes["/v1/search"] = (429, {"detail": "slow down"})
    r = _client(max_retries=1).search("x")
    assert r.ok is False and r.error_kind == ErrorKind.RATE_LIMITED
    assert _Handler.counters["/v1/search"] == 2  # one retry


def test_500_is_server_error_after_retries(mock_server):
    _Handler.routes["/v1/search"] = (503, {"detail": "down"})
    r = _client(max_retries=1).search("x")
    assert r.ok is False and r.error_kind == ErrorKind.SERVER_ERROR
    assert _Handler.counters["/v1/search"] == 2


def test_transient_429_then_success_retries_and_succeeds(mock_server):
    calls = {"n": 0}

    def route(h):
        calls["n"] += 1
        if calls["n"] == 1:
            return h._respond(429, {"detail": "slow down"})
        return h._respond(200, _SEARCH_OK[1])

    _Handler.routes["/v1/search"] = route
    r = _client(max_retries=2).search("x")
    assert r.ok is True and calls["n"] == 2


def test_network_timeout_is_classified(mock_server):
    _Handler.routes["/v1/search"] = _SEARCH_OK
    _Handler.sleep_s = 1.5
    r = _client(timeout=1, max_retries=0).search("x")
    assert r.ok is False and r.error_kind == ErrorKind.NETWORK


def test_missing_key_is_reported_honestly(monkeypatch, mock_server):
    monkeypatch.delenv("YDC_API_KEY", raising=False)
    r = YouComClient("").search("x")
    assert r.ok is False and r.error_kind == ErrorKind.MISSING_KEY
    assert "YDC_API_KEY" in r.error  # clear setup instruction, not a fake success
    assert _Handler.seen == []       # nothing was sent


# --------------------------------------------------------------------------- #
# Secret redaction (mission requirement 12)
# --------------------------------------------------------------------------- #

def test_key_is_redacted_from_error_messages(mock_server):
    _Handler.routes["/v1/search"] = (401, {"detail": "bad key test-key here"})
    r = _client().search("x")
    assert "test-key" not in r.error
    assert "test-key" not in json.dumps(r.to_dict())


# --------------------------------------------------------------------------- #
# Provenance (mission requirement 11)
# --------------------------------------------------------------------------- #

def test_sources_carry_provider_provenance(mock_server):
    _Handler.routes["/v1/search"] = _SEARCH_OK
    r = _client().search("x")
    assert r.ok and r.provider == "you.com"
    assert all(s.provider == "you.com" for s in r.sources)
    assert r.to_dict()["provider"] == "you.com"


def test_wikipedia_provider_parses_and_tags(mock_server):
    _Handler.routes["/wiki"] = _WIKI_OK
    r = WikipediaProvider().search("reentrancy")
    assert r.ok and r.provider == "wikipedia"
    assert r.sources[0].provider == "wikipedia"
    assert r.sources[0].url.startswith("https://en.wikipedia.org/wiki/")
    assert "<span>" not in r.sources[0].snippets[0]  # markup stripped


def test_wikipedia_provider_sends_a_descriptive_user_agent(mock_server):
    # Wikimedia rate-limits generic User-Agents with HTTP 429; the provider must
    # send the descriptive UA its policy asks for. Regression for a live 429.
    _Handler.routes["/wiki"] = _WIKI_OK
    WikipediaProvider().search("reentrancy")
    seen = [s for s in _Handler.seen if s["path"] == "/wiki"]
    assert seen, "wikipedia request was not made"
    ua = seen[-1]["headers"].get("User-Agent", "")
    assert "BlackheartSecurityResearch" in ua
    assert "github.com/itzebe/blackheart" in ua


def test_duckduckgo_provider_parses_abstract_and_topics(mock_server):
    _Handler.routes["/ddg"] = _DDG_OK
    r = DuckDuckGoProvider().search("reentrancy")
    assert r.ok and r.provider == "duckduckgo"
    assert r.sources and all(s.provider == "duckduckgo" for s in r.sources)


def test_duckduckgo_empty_is_ok_not_a_failure(mock_server):
    # The Instant Answer API genuinely returns nothing for many queries; that is
    # an honest empty result, not a fabricated one and not an error.
    _Handler.routes["/ddg"] = (200, {"RelatedTopics": []})
    r = DuckDuckGoProvider().search("obscure technical query")
    assert r.ok is True and r.sources == [] and r.warnings


def test_duckduckgo_server_error_is_a_failure(mock_server):
    _Handler.routes["/ddg"] = (500, {"err": "boom"})
    r = DuckDuckGoProvider().search("x")
    assert r.ok is False and r.error_kind == ErrorKind.SERVER_ERROR


# --------------------------------------------------------------------------- #
# Registry + fallback (mission requirement: >=2 usable free providers)
# --------------------------------------------------------------------------- #

def test_registry_lists_three_providers(mock_server):
    reg = ProviderRegistry()
    assert set(reg.names()) == {"you.com", "duckduckgo", "wikipedia"}
    statuses = {s.name: s for s in reg.status()}
    assert statuses["you.com"].requires_key is True
    assert statuses["duckduckgo"].requires_key is False
    assert statuses["wikipedia"].requires_key is False
    # The two keyless providers are always available (no key needed).
    assert statuses["duckduckgo"].available and statuses["wikipedia"].available


def test_registry_youcom_unavailable_without_key(monkeypatch, mock_server):
    monkeypatch.delenv("YDC_API_KEY", raising=False)
    reg = ProviderRegistry()
    st = {s.name: s for s in reg.status()}["you.com"]
    assert st.available is False and st.key_present is False


def test_router_skips_unconfigured_and_uses_keyless(monkeypatch, mock_server):
    monkeypatch.delenv("YDC_API_KEY", raising=False)
    _Handler.routes["/ddg"] = _DDG_OK
    _Handler.routes["/wiki"] = _WIKI_OK
    out = SearchRouter(ProviderRegistry()).search("reentrancy")
    assert out.ok and out.provider == "duckduckgo"
    skipped = [a for a in out.attempts if a.get("skipped")]
    assert skipped and skipped[0]["provider"] == "you.com"


def test_router_enforces_primary_and_skips_generic_by_default(mock_server):
    # You.com is configured and up: it is the *only* provider used, so a technical
    # query is never silently answered by a thin keyless provider.
    _Handler.routes["/v1/search"] = _SEARCH_OK
    _Handler.routes["/ddg"] = _DDG_OK
    _Handler.routes["/wiki"] = _WIKI_OK
    reg = ProviderRegistry(youcom_client=YouComClient("test-key"))
    out = SearchRouter(reg).search("reentrancy")
    assert out.ok and out.provider == "you.com"
    assert [a["provider"] for a in out.attempts if not a.get("skipped")] == ["you.com"]
    assert "/ddg" not in _Handler.counters and "/wiki" not in _Handler.counters


def test_router_falls_back_on_provider_outage_when_opted_in(mock_server):
    # You.com is configured but the service is down (503 after retries). Falling
    # back is *opt-in*: the caller asks for it explicitly.
    _Handler.routes["/v1/search"] = (503, {"detail": "down"})
    _Handler.routes["/ddg"] = _DDG_OK
    reg = ProviderRegistry(youcom_client=YouComClient("test-key", max_retries=1))
    out = SearchRouter(reg).search("reentrancy", allow_fallback=True)
    assert out.ok and out.provider == "duckduckgo"
    first = out.attempts[0]
    assert first["provider"] == "you.com" and first["ok"] is False
    assert first["error_kind"] == ErrorKind.SERVER_ERROR


def test_router_primary_outage_is_honest_without_fallback(mock_server):
    # The enforced default does NOT silently substitute a generic provider: with
    # You.com down and no opt-in, the routed search reports the failure.
    _Handler.routes["/v1/search"] = (503, {"detail": "down"})
    _Handler.routes["/ddg"] = _DDG_OK
    reg = ProviderRegistry(youcom_client=YouComClient("test-key", max_retries=1))
    out = SearchRouter(reg).search("reentrancy")
    assert out.ok is False
    assert "/ddg" not in _Handler.counters


def test_router_prefers_provider_with_results_over_empty_when_opted_in(mock_server):
    # You.com returns a valid but empty result set; with fallback opted in, the
    # router keeps looking rather than returning the empty answer.
    _Handler.routes["/v1/search"] = (200, {"results": {"web": []}})
    _Handler.routes["/ddg"] = (200, {"RelatedTopics": []})
    _Handler.routes["/wiki"] = _WIKI_OK
    out = SearchRouter(ProviderRegistry()).search("reentrancy", allow_fallback=True)
    assert out.ok and out.provider == "wikipedia"


def test_router_reports_failure_honestly_when_all_fail(mock_server):
    _Handler.routes["/v1/search"] = (503, {"detail": "down"})
    _Handler.routes["/ddg"] = (500, {"e": "x"})
    _Handler.routes["/wiki"] = (500, {"e": "x"})
    out = SearchRouter(ProviderRegistry()).search("x")
    assert out.ok is False
    assert out.result is None or out.result.sources == []  # nothing fabricated
    assert all(a.get("ok") is False for a in out.attempts if not a.get("skipped"))


def test_router_never_substitutes_a_fabricated_result(mock_server):
    _Handler.routes["/v1/search"] = (503, {"detail": "down"})
    _Handler.routes["/ddg"] = (500, {})
    _Handler.routes["/wiki"] = (500, {})
    out = SearchRouter(ProviderRegistry()).search("x")
    # A failed routed search must not return ok with sources from thin air.
    assert out.ok is False


# --------------------------------------------------------------------------- #
# Cross-check / disagreement (mission requirement 10)
# --------------------------------------------------------------------------- #

def test_cross_check_records_disagreement_not_a_forced_winner(mock_server):
    _Handler.routes["/v1/search"] = _SEARCH_OK
    _Handler.routes["/ddg"] = (200, {"Heading": "h", "AbstractURL":
                                     "https://other.test/1",
                                     "AbstractText": "x", "RelatedTopics": []})
    _Handler.routes["/wiki"] = _WIKI_OK
    reg = ProviderRegistry(youcom_client=YouComClient("test-key"))
    out = SearchRouter(reg).search("reentrancy", cross_check=True)
    assert out.ok and out.provider == "you.com"
    by_provider = {d["provider"]: d for d in out.disagreements if d.get("ok")}
    assert "duckduckgo" in by_provider
    ddg = by_provider["duckduckgo"]
    assert ddg["only_in_primary"] == ["https://a.test/1"]
    assert ddg["only_in_other"] == ["https://other.test/1"]
    assert ddg["shared"] == []


# --------------------------------------------------------------------------- #
# Project bootstrap / inheritance (mission: future projects inherit it)
# --------------------------------------------------------------------------- #

def test_bootstrap_writes_mcp_without_secret(tmp_path, monkeypatch):
    from blackheart.intelligence.bootstrap import bootstrap_project

    monkeypatch.setenv("YDC_API_KEY", "ydc-secret-value")
    res = bootstrap_project(tmp_path)
    text = (tmp_path / ".openhands" / "mcp.json").read_text()
    assert "${YDC_API_KEY}" in text
    assert "ydc-secret-value" not in text
    assert "https://api.you.com/mcp" in text
    assert res.mcp_written is True


def test_bootstrap_is_idempotent_and_merges(tmp_path):
    from blackheart.intelligence.bootstrap import bootstrap_project

    mcp = tmp_path / ".openhands" / "mcp.json"
    mcp.parent.mkdir(parents=True)
    mcp.write_text(json.dumps({"mcpServers": {"existing": {"url": "x"}}}))
    bootstrap_project(tmp_path)
    data = json.loads(mcp.read_text())
    assert "existing" in data["mcpServers"]   # project's own server preserved
    assert "youdotcom" in data["mcpServers"]  # capability added
    second = bootstrap_project(tmp_path)
    assert second.mcp_written is False        # no change on the second run


def test_project_disable_requires_a_reason(tmp_path):
    from blackheart.intelligence.bootstrap import load_project_config

    cfg = tmp_path / ".openhands" / "intelligence.json"
    cfg.parent.mkdir(parents=True)
    cfg.write_text(json.dumps({"disable": {"you.com": "", "wikipedia": "no key policy"}}))
    loaded = load_project_config(tmp_path)
    assert "you.com" not in loaded["disable"]        # reasonless -> ignored
    assert loaded["disable"]["wikipedia"] == "no key policy"


def test_registry_respects_explicit_project_disable(tmp_path):
    from blackheart.intelligence.providers import ProviderRegistry

    cfg = tmp_path / ".openhands" / "intelligence.json"
    cfg.parent.mkdir(parents=True)
    cfg.write_text(json.dumps({"disable": {"you.com": "project policy: no external key"}}))
    reg = ProviderRegistry(project_root=str(tmp_path))
    assert "you.com" not in reg.names()
    assert reg.disabled["you.com"].startswith("project policy")


# --------------------------------------------------------------------------- #
# CLI integration (inherited capability + honest setup)
# --------------------------------------------------------------------------- #

def test_cli_providers_reports_unconfigured_honestly(monkeypatch, capsys):
    from blackheart.cli import main

    monkeypatch.delenv("YDC_API_KEY", raising=False)
    rc = main(["intel", "providers"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "UNAVAILABLE" in out          # not a fake success
    assert "duckduckgo" in out and "wikipedia" in out


def test_cli_bootstrap_then_registry_inherits(tmp_path, capsys):
    from blackheart.cli import main
    from blackheart.intelligence.bootstrap import load_project_config

    rc = main(["intel", "bootstrap", "--root", str(tmp_path)])
    assert rc == 0
    assert (tmp_path / ".openhands" / "mcp.json").is_file()
    assert load_project_config(tmp_path) == {}  # no disable written


# --------------------------------------------------------------------------- #
# Opt-in live smoke (spends nothing: a snippets search is unbilled)
# --------------------------------------------------------------------------- #

@pytest.mark.skipif(
    not (os.environ.get("BLACKHEART_LIVE_YOU") == "1" and os.environ.get("YDC_API_KEY")),
    reason="set BLACKHEART_LIVE_YOU=1 and YDC_API_KEY to run the live smoke test",
)
def test_live_you_search_returns_real_sources():
    client = YouComClient(timeout=30, max_retries=1)
    r = client.search("erc4626 share inflation", count=3)
    assert r.ok and r.raw_status == 200
    assert r.provider == "you.com"
    assert all(s.provider == "you.com" for s in r.sources)
    assert all(s.url.startswith("http") for s in r.sources)


# --------------------------------------------------------------------------- #
# Novelty-workflow integration: live search populates the public-disclosure set
# --------------------------------------------------------------------------- #

class _StubResult:
    def __init__(self, ok, provider, sources, error=""):
        self.ok, self.provider, self.sources, self.error = ok, provider, sources, error


class _StubSource:
    def __init__(self, url, provider, title=""):
        self.url, self.provider, self.title = url, provider, title


def test_collect_disclosures_records_provenance_and_coverage():
    from blackheart.models import NoveltyReview
    from blackheart.novelty import collect_disclosures

    review = NoveltyReview(finding_id="F-1", target="t",
                           queries=["erc4626 inflation", "share inflation attack"])

    def search_fn(query, count):
        return _StubResult(True, "you.com", [
            _StubSource(f"https://a.test/{query[:4]}", "you.com", "A"),
            _StubSource(f"https://b.test/{query[:4]}", "you.com", "B"),
        ])

    collect_disclosures(review, search_fn)
    assert len(review.disclosures) == 4            # deduped by URL
    assert all(d.source == "you.com" for d in review.disclosures)
    assert review.databases_searched == ["you.com"]  # real coverage, not hand-written


def test_collect_disclosures_failed_provider_is_recorded_not_faked():
    from blackheart.models import NoveltyReview
    from blackheart.novelty import collect_disclosures

    review = NoveltyReview(finding_id="F-1", queries=["q1"])

    def search_fn(query, count):
        return _StubResult(False, "", [], error="rate_limited")

    collect_disclosures(review, search_fn)
    assert review.disclosures == []
    assert any("rate_limited" in lim for lim in review.search_limitations)
    assert review.databases_searched == []
    assert any("under-powered" in lim for lim in review.search_limitations)


def test_collect_disclosures_dedupes_across_queries():
    from blackheart.models import NoveltyReview
    from blackheart.novelty import collect_disclosures

    review = NoveltyReview(finding_id="F-1", queries=["q1", "q2"])

    def search_fn(query, count):
        return _StubResult(True, "wikipedia",
                           [_StubSource("https://same.test/x", "wikipedia", "X")])

    collect_disclosures(review, search_fn)
    assert len(review.disclosures) == 1


def test_collect_disclosures_search_exception_is_recorded():
    from blackheart.models import NoveltyReview
    from blackheart.novelty import collect_disclosures

    review = NoveltyReview(finding_id="F-1", queries=["q1"])

    def boom(query, count):
        raise RuntimeError("backend down")

    collect_disclosures(review, boom)
    assert any("backend down" in lim for lim in review.search_limitations)


def test_cli_novelty_search_uses_router_and_keeps_gate_meaning(tmp_path, monkeypatch):
    # End-to-end through the CLI: --search populates disclosures from providers,
    # then the novelty gate adjudicates. With no matching disclosure and a
    # single provider that returns two sources, coverage is still under-powered,
    # so the honest verdict is INSUFFICIENT_EVIDENCE -- never LIKELY_NEW.
    from blackheart.cli import main

    class _Routed:
        # Mirrors the real SearchRouter shape: sources live under .result.
        def __init__(self, result):
            self.ok, self.provider, self.result = result.ok, result.provider, result

    class _Router:
        def search(self, query, count=10, **kw):
            return _Routed(_StubResult(True, "you.com", [
                _StubSource("https://a.test/1", "you.com", "A"),
                _StubSource("https://a.test/2", "you.com", "B"),
            ]))

    import blackheart.intelligence.providers as p
    monkeypatch.setattr(p, "SearchRouter", lambda *a, **k: _Router())

    review = {
        "finding_id": "F-9", "target": "t",
        "vulnerability_class": "reentrancy",
        "root_cause": "missing nonReentrant on withdraw",
        "affected_component": "Vault",
        "queries": ["vault reentrancy withdraw"],
    }
    f = tmp_path / "review.json"
    f.write_text(json.dumps(review), encoding="utf-8")
    rc = main(["novelty", "--file", str(f), "--search"])
    assert rc == 1  # blocked: search too thin to claim novelty


def test_collect_disclosures_empty_provider_does_not_inflate_coverage():
    # A provider that answers 200 with zero sources is not coverage: it must not
    # appear in databases_searched, and the review must be flagged under-powered.
    from blackheart.models import NoveltyReview
    from blackheart.novelty import collect_disclosures

    review = NoveltyReview(finding_id="F-1", queries=["q1"])

    def search_fn(query, count):
        return _StubResult(True, "duckduckgo", [])

    collect_disclosures(review, search_fn)
    assert review.disclosures == []
    assert review.databases_searched == []
    assert any("under-powered" in lim for lim in review.search_limitations)
