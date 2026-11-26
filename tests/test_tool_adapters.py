"""Acceptance tests for the live tool adapters (T1.3).

These tests do not require any scanner to be installed. They pin the properties
that make the adapters safe and honest:

  * authorization is fail-closed -- an unauthorized asset raises before any tool
    is located or run,
  * a missing binary is reported as ``available=False`` with a reason, never as a
    silent empty scan,
  * each adapter parses its tool's real output shape into structured findings,
  * unparseable output is captured raw and noted, never dropped or invented.

The parsers are exercised directly on fixtures that match each tool's documented
output, so the tests are hermetic and fast.
"""

from __future__ import annotations

import pytest

from blackheart.authz import AuthorizationError, new_record
from blackheart.models import AssetStatus
from blackheart.tools.adapters import ADAPTERS, adapter_for, available_adapters
from blackheart.tools.adapters.base import ToolRun
from blackheart.tools.adapters.web import (
    _parse_dalfox,
    _parse_ffuf,
    _parse_gitleaks,
    _parse_gobuster,
    _parse_nuclei,
    _parse_sqlmap,
    run_ffuf,
)


def _authorized():
    rec = new_record(
        program="example", platform="immunefi",
        target_url="https://example.test/program",
        scope_url="https://example.test/scope",
        program_active=True, safe_harbor=True, poc_required=True,
        nigerian_eligible=True, payout_feasible=True, zero_cost=True,
    )
    rec.assets = {"asset-a": AssetStatus.AUTHORIZED.value}
    rec.evidence = ["ev-1"]
    rec.verified = True
    return rec


def _run(tool: str, stdout: str) -> ToolRun:
    run = ToolRun(tool=tool, target="t", asset="a", command="c",
                  available=True, authorized=True)
    run.stdout = stdout
    return run


# -- authorization is fail-closed -------------------------------------------- #

def test_unauthorized_asset_refuses_before_running_any_tool():
    rec = new_record("p", "immunefi", "https://e.test", "https://e.test/s")
    with pytest.raises(AuthorizationError):
        run_ffuf("https://e.test/FUZZ", "/tmp/wl", record=rec, asset="asset-a")


def test_unknown_asset_under_a_verified_record_is_still_refused():
    rec = _authorized()
    with pytest.raises(AuthorizationError):
        run_ffuf("https://e.test/FUZZ", "/tmp/wl", record=rec, asset="some-other-asset")


def test_authorized_asset_with_missing_binary_is_honest_not_fabricated():
    rec = _authorized()
    run = run_ffuf("https://e.test/FUZZ", "/tmp/wl", record=rec, asset="asset-a")
    # ffuf is not installed in CI; the run must say so rather than return empty.
    assert run.authorized is True
    if not run.available:
        assert run.reason and "not installed" in run.reason
        assert run.findings == []


# -- parsers ------------------------------------------------------------------ #

def test_ffuf_json_parser_extracts_endpoints():
    run = _run("ffuf", '{"results": [{"url": "https://e.test/admin", '
                       '"status": 200, "length": 1234, "words": 50}]}')
    _parse_ffuf(run)
    assert len(run.findings) == 1
    f = run.findings[0]
    assert f.target == "https://e.test/admin"
    assert "200" in f.detail


def test_gobuster_line_parser_extracts_endpoints():
    run = _run("gobuster", "/admin                (Status: 200) [Size: 1234]\n"
                           "/login                (Status: 302) [Size: 0]")
    _parse_gobuster(run)
    assert {f.target for f in run.findings} == {"/admin", "/login"}
    assert all(f.kind == "endpoint" for f in run.findings)


def test_nuclei_jsonl_parser_extracts_templates_and_severity():
    run = _run("nuclei", '{"template-id": "cve-2021-1234", '
                         '"info": {"name": "Test RCE", "severity": "critical"}, '
                         '"matched-at": "https://e.test/x"}')
    _parse_nuclei(run)
    assert len(run.findings) == 1
    f = run.findings[0]
    assert f.kind == "cve-2021-1234"
    assert f.severity == "critical"
    assert f.target == "https://e.test/x"


def test_sqlmap_parser_flags_injectable_parameters():
    run = _run("sqlmap", "[INFO] GET parameter 'id' is 'AND boolean-based blind' injectable")
    _parse_sqlmap(run, "https://e.test/item?id=1")
    assert run.findings and run.findings[0].kind == "sql-injection"


def test_sqlmap_parser_reports_no_findings_cleanly():
    run = _run("sqlmap", "[INFO] all tested parameters do not appear to be injectable")
    _parse_sqlmap(run, "https://e.test/item?id=1")
    assert run.findings == []
    assert run.parse_notes


def test_dalfox_jsonl_parser_extracts_xss():
    run = _run("dalfox", '{"type": "V", "data": "https://e.test/?q=<script>", '
                         '"evidence": "reflected"}')
    _parse_dalfox(run, "https://e.test/?q=x")
    assert run.findings and run.findings[0].severity == "high"


def test_gitleaks_json_parser_extracts_secrets():
    run = _run("gitleaks", '[{"RuleID": "aws-access-key", "File": "a.py", '
                           '"StartLine": 10, "Description": "AWS key"}]')
    _parse_gitleaks(run)
    assert run.findings and run.findings[0].kind == "aws-access-key"


def test_unparseable_output_is_captured_raw_and_noted_not_dropped():
    run = _run("ffuf", "this is not json at all")
    _parse_ffuf(run)
    assert run.findings == []
    assert run.parse_notes                       # the miss is recorded
    assert run.stdout == "this is not json at all"   # the raw output is preserved


# -- registry ----------------------------------------------------------------- #

def test_registry_maps_names_to_callables_and_flags_wordlist_tools():
    assert set(ADAPTERS) >= {"ffuf", "gobuster", "nuclei", "sqlmap", "dalfox", "gitleaks"}
    assert adapter_for("ffuf").requires_wordlist
    assert not adapter_for("nuclei").requires_wordlist
    assert adapter_for("nope") is None
    assert isinstance(available_adapters(), list)
