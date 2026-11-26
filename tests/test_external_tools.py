"""External tools: fail-closed, parsed into leads, never faked into findings."""

from __future__ import annotations

import json
import subprocess
from types import SimpleNamespace

import pytest

from blackheart.cli import main
from blackheart.engines import external
from blackheart.engines.external import (
    EXTERNAL_TOOLS, doctor, parse_json, parse_sarif, parse_text, run_external,
)
from blackheart.toolchain.enforce import self_test_record

SARIF = {"runs": [{"results": [{
    "ruleId": "go.lang.security.audit.example",
    "level": "error",
    "message": {"text": "unsafe thing"},
    "locations": [{"physicalLocation": {
        "artifactLocation": {"uri": "a.go"}, "region": {"startLine": 10}}}],
}]}]}


def _installed(monkeypatch):
    monkeypatch.setattr(external, "resolve_tool",
                        lambda name: SimpleNamespace(binary=f"/x/{name}"))


def _not_installed(monkeypatch):
    monkeypatch.setattr(external, "resolve_tool", lambda name: None)


def _runner(stdout: str, returncode: int = 0):
    return lambda cmd, cwd, timeout: subprocess.CompletedProcess(cmd, returncode, stdout, "")


def test_registry_is_honest_runnable_entries_have_a_command_and_format():
    for tool in EXTERNAL_TOOLS.values():
        if tool.runnable:
            assert tool.command and tool.format in ("sarif", "json", "text"), tool.name
        else:
            assert tool.manual and tool.docs and tool.gap, tool.name


def test_parsers_extract_leads():
    leads = parse_sarif(SARIF)
    assert leads[0]["rule"].startswith("go.lang") and leads[0]["line"] == 10
    assert parse_json({"findings": [{"x": 1}]}) == [{"x": 1}]
    assert parse_json({"Issues": [{"rule_id": "G1"}]}) == [{"rule_id": "G1"}]
    assert len(parse_text("a\n\nb\nc")) == 3


def test_unknown_tool():
    out = run_external("nope", "t", compatibility=self_test_record())
    assert out.status == "UNKNOWN_TOOL"


def test_manual_tool_is_not_run():
    out = run_external("ityfuzz", "t", compatibility=self_test_record())
    assert out.status == "MANUAL"
    assert "ityfuzz" in out.detail


def test_missing_tool_is_not_installed(monkeypatch):
    _not_installed(monkeypatch)
    out = run_external("semgrep", "t", compatibility=self_test_record())
    assert out.status == "NOT_INSTALLED"
    assert "install" in out.detail.lower()


def test_no_compatibility_record_blocks_before_the_runner(monkeypatch):
    _installed(monkeypatch)

    def runner(*_a):
        raise AssertionError("the runner must not be called without a record")

    out = run_external("semgrep", "t", compatibility=None, runner=runner)
    assert out.status == "BLOCKED"
    assert "no compatibility record" in out.detail


def test_sarif_run_yields_leads_and_never_a_finding(monkeypatch):
    _installed(monkeypatch)
    out = run_external("semgrep", "t", compatibility=self_test_record(),
                       repository="blackheart", runner=_runner(json.dumps(SARIF)))
    assert out.status == "COMPLETED"
    assert out.leads and out.leads[0]["message"] == "unsafe thing"
    # A lead must not carry a finding's confirmation fields.
    assert "disposition" not in out.as_dict() and "confirmed" not in out.as_dict()
    assert "only BLACKHEART" in out.as_dict()["note"]


def test_json_run_yields_leads(monkeypatch):
    _installed(monkeypatch)
    out = run_external("gosec", "t", compatibility=self_test_record(),
                       repository="blackheart",
                       runner=_runner(json.dumps({"Issues": [{"rule_id": "G101"}]})))
    assert out.status == "COMPLETED"
    assert out.leads == [{"rule_id": "G101"}]


def test_clean_run_is_not_proof_of_safety(monkeypatch):
    _installed(monkeypatch)
    out = run_external("semgrep", "t", compatibility=self_test_record(),
                       repository="blackheart", runner=_runner(json.dumps({"runs": []})))
    assert out.status == "COMPLETED"
    assert out.leads == []
    assert "not a proof of safety" in out.detail


def test_nonzero_exit_with_unparseable_output_is_incomplete(monkeypatch):
    _installed(monkeypatch)
    out = run_external("semgrep", "t", compatibility=self_test_record(),
                       repository="blackheart",
                       runner=_runner("not json at all", returncode=2))
    assert out.status == "INCOMPLETE"


def test_doctor_reports_states(monkeypatch):
    _not_installed(monkeypatch)
    rows = {r["name"]: r["state"] for r in doctor()}
    assert rows["semgrep"] == "missing"
    assert rows["ityfuzz"] == "manual"


def test_cli_list_and_doctor_and_failclosed_run(tmp_path, capsys):
    assert main(["external", "--list"]) == 0
    assert "semgrep" in capsys.readouterr().out
    main(["external", "--doctor"])  # rc depends on host; must not raise
    capsys.readouterr()
    # run without a record is fail-closed
    assert main(["external", "--run", "semgrep", "--target", str(tmp_path)]) == 2
    assert "needs --compatibility" in capsys.readouterr().err
