"""Tests for the Chrome VRP research harness (mission Part B).

The unit tests need no browser: they cover discovery, the DOM-result parser, and
the disposition logic, with a fake browser injected where the real one would be.

The integration tests drive a *real* Chromium build. They are skipped (not
passed) when no browser is present, and the skip is reported, so a green suite
never implies browser verification that did not happen.
"""

from __future__ import annotations

import json

import pytest

from blackheart.chrome import (
    HYPOTHESES,
    positive_control,
    run_engagement,
    smoke_test,
)
from blackheart.chrome import harness
from blackheart.chrome.harness import (
    ChromeError,
    ChromeNotFound,
    find_browser,
    serve_origins,
)


# --------------------------------------------------------------------------- #
# Browser discovery
# --------------------------------------------------------------------------- #

def test_find_browser_rejects_a_named_non_executable(tmp_path):
    missing = tmp_path / "not-a-browser"
    missing.write_text("#!/bin/sh\n")
    with pytest.raises(ChromeNotFound):
        find_browser(str(missing))


def test_find_browser_env_override_wins(monkeypatch, tmp_path):
    fake = tmp_path / "mybrowser"
    fake.write_text("#!/bin/sh\necho ok\n")
    fake.chmod(0o755)
    monkeypatch.setenv("BLACKHEART_CHROME", str(fake))
    assert find_browser() == str(fake)


def test_find_browser_env_override_must_be_executable(monkeypatch, tmp_path):
    fake = tmp_path / "mybrowser"
    fake.write_text("x")
    monkeypatch.setenv("BLACKHEART_CHROME", str(fake))
    with pytest.raises(ChromeNotFound):
        find_browser()


# --------------------------------------------------------------------------- #
# Result parsing
# --------------------------------------------------------------------------- #

def test_parse_result_reads_json_from_the_result_element():
    dom = '<html><pre id="result">{"a": 1, "b": "x"}</pre></html>'
    assert harness._parse_result(dom) == {"a": 1, "b": "x"}


def test_parse_result_unescapes_only_text_content_entities():
    # A DOM dump escapes &, <, > in text content but leaves quotes alone.
    dom = '<pre id="result">{"msg": "a &amp; b &lt;tag&gt;", "q": "x"}</pre>'
    parsed = harness._parse_result(dom)
    assert parsed["msg"] == "a & b <tag>"
    assert parsed["q"] == "x"


def test_parse_result_reports_a_missing_element():
    assert "_parse_error" in harness._parse_result("<html></html>")


def test_parse_result_reports_non_json():
    out = harness._parse_result('<pre id="result">not json</pre>')
    assert "_parse_error" in out


# --------------------------------------------------------------------------- #
# Origins
# --------------------------------------------------------------------------- #

def test_serve_origins_uses_two_distinct_origins(tmp_path):
    (tmp_path / "x.html").write_text("hi")
    with serve_origins(tmp_path) as pair:
        assert pair.url_a != pair.url_b
        assert pair.port_a != pair.port_b


# --------------------------------------------------------------------------- #
# Disposition logic -- the heart of "a negative result is a real result"
# --------------------------------------------------------------------------- #

def test_disposition_no_violation_is_false_positive():
    from blackheart.chrome import _disposition
    from blackheart.models import Classification

    assert _disposition([]) == Classification.FALSE_POSITIVE.value


def test_disposition_violation_is_a_candidate_not_a_finding():
    from blackheart.chrome import _disposition
    from blackheart.models import Classification

    # A violation must NOT be reported as CONFIRMED -- it needs verification.
    assert _disposition(["boom"]) == Classification.NEEDS_MORE_EVIDENCE.value
    assert _disposition(["boom"]) != Classification.CONFIRMED.value


# --------------------------------------------------------------------------- #
# Ledger integration with a fake browser (no real Chromium needed)
# --------------------------------------------------------------------------- #

class _FakeRun:
    def __init__(self, result):
        self.result = result
        self.url = "http://fake/"
        self.returncode = 0
        self.stderr = ""
        self.duration_ms = 1
        self.dom = "<pre id='result'>%s</pre>" % json.dumps(result)

    def to_dict(self):
        return {"url": self.url, "result": self.result}


class _FakeChromium:
    """A Chromium stand-in that returns canned probe results."""

    binary = "/fake/chromium"
    version = "Chromium 0.0.0.0-fake"

    def __init__(self, results):
        self._results = results

    def process_info(self):
        # A healthy multi-process model by default.
        return {"processInfo": [
            {"type": "browser", "id": 1},
            {"type": "renderer", "id": 2},
            {"type": "GPU", "id": 3},
        ]}

    def run_probe(self, url, virtual_time_ms=6000):
        key = ("isolated" if "isolated.html" in url else
               "plain" if "plain.html" in url else
               "postmessage" if "pm_top" in url else "sop")
        return _FakeRun(self._results.get(key, {"violations": [], "details": {}}))


def test_run_engagement_records_every_hypothesis_in_the_ledger(tmp_path):
    fake = _FakeChromium({})  # every probe reports no violations
    summary = run_engagement(tmp_path, chromium=fake)
    assert summary["hypotheses_run"] == len(HYPOTHESES)
    assert summary["candidates"] == []
    assert len(summary["disproven"]) == len(HYPOTHESES)
    assert summary["evidence_integrity"]["ok"] is True
    ledger = (tmp_path / "ledger" / "chrome-vrp.jsonl").read_text()
    assert "FALSE_POSITIVE" in ledger


def test_run_engagement_marks_a_violation_as_a_candidate(tmp_path):
    fake = _FakeChromium({"sop": {"violations": ["contentDocument readable"], "details": {}}})
    summary = run_engagement(tmp_path, chromium=fake)
    assert "H1" in summary["candidates"]
    assert "H1" not in summary["disproven"]


def test_run_engagement_only_runs_selected(tmp_path):
    fake = _FakeChromium({})
    summary = run_engagement(tmp_path, chromium=fake, only=["H1"])
    assert [r["id"] for r in summary["results"]] == ["H1"]


def test_run_engagement_survives_a_harness_error(tmp_path):
    class _Broken(_FakeChromium):
        def run_probe(self, url, virtual_time_ms=6000):
            raise ChromeError("browser crashed")

        def process_info(self):
            raise ChromeError("browser crashed")

    summary = run_engagement(tmp_path, chromium=_Broken({}))
    # A harness failure is NEEDS_MORE_EVIDENCE, never a fabricated finding.
    assert all(r["status"] == "NEEDS_MORE_EVIDENCE" for r in summary["results"])
    assert summary["candidates"]  # they remain open, not silently dropped


# --------------------------------------------------------------------------- #
# Real-browser integration (skipped when no browser is installed)
# --------------------------------------------------------------------------- #

def _browser_or_skip():
    try:
        return find_browser()
    except ChromeNotFound:
        pytest.skip("no Chromium/Chrome binary available; integration not run")


def test_real_browser_smoke():
    binary = _browser_or_skip()
    out = smoke_test(binary)
    assert "Chromium" in out["browser"] or "Chrome" in out["browser"]
    assert out["run"]["result"].get("probe") == "sop-read"
    # On a maintained release the SOP boundary holds.
    assert out["run"]["result"].get("violations") == []


def test_real_browser_positive_control_detects_a_breach():
    """Without this, a clean engagement run would prove nothing."""
    binary = _browser_or_skip()
    control = positive_control(binary)
    assert control["detected"] is True
    assert any("contentDocument readable" in v for v in control["violations"])


def test_real_browser_engagement_runs_all_hypotheses(tmp_path):
    binary = _browser_or_skip()
    summary = run_engagement(tmp_path, binary=binary)
    assert summary["hypotheses_run"] == len(HYPOTHESES)
    for r in summary["results"]:
        assert r["status"] in ("FALSE_POSITIVE", "NEEDS_MORE_EVIDENCE")
    assert summary["evidence_integrity"]["ok"] is True
