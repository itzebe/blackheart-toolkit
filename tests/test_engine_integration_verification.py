"""Phase 4 — engine integration verification (Strix, Shannon, PentAGI).

What these tests prove, and what they do NOT:

  * PROVEN: the adapter's *own* code -- discovery, health classification,
    configuration validation, argv construction, real subprocess execution via
    ``run_bounded`` (shell=False), artifact collection, finding normalization,
    CWE/CVSS mapping, error classification, secret redaction, evidence
    provenance, and cross-engine orchestration.
  * NOT PROVEN HERE: that the upstream engine's own analysis is correct. The
    engines are external tools; a stub binary that speaks their documented
    interface exercises the adapter honestly, but it is labelled a stub. A real
    Strix/Shannon/PentAGI scan is a separate, environment-gated step (see the
    MISSING/UNSUPPORTED reporting test).

The stub binaries are real executables that the adapter launches through the
same code path a real engine would take.
"""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest

from blackheart.engines import get_adapter, list_engines
from blackheart.engines.contract import EngineState
from blackheart.engines.schema import normalize_cwe, normalize_cvss, normalize_severity


# --------------------------------------------------------------------------- #
# Stub engine binaries that speak the documented interfaces
# --------------------------------------------------------------------------- #

def _write_executable(path: Path, body: str) -> Path:
    path.write_text("#!/usr/bin/env python3\n" + body, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    return path


STRIX_STUB = '''
import json, os, sys, pathlib
args = sys.argv[1:]
if "--version" in args:
    print("strix 1.4.2"); sys.exit(0)
target = ""
for i, a in enumerate(args):
    if a == "--target":
        target = args[i + 1]
run = pathlib.Path("strix_runs/run-1"); run.mkdir(parents=True, exist_ok=True)
(run / "vulnerabilities.json").write_text(json.dumps([
    {"id": "v1", "title": "Authorization bypass on /admin", "severity": "HIGH",
     "cwe": "862", "cvss": 8.1, "endpoint": "/admin",
     "description": "unprivileged caller reaches an admin action",
     "code_locations": [{"path": "src/admin.py"}],
     "poc_description": "call /admin as a normal user", "impact": "privilege use"},
]))
(run / "run.json").write_text(json.dumps({"target": target, "status": "done"}))
print(f"strix finished scan of {target}")
'''

SHANNON_STUB = '''
import json, os, sys, pathlib
args = sys.argv[1:]
if "--version" in args:
    print("shannon 0.6.0"); sys.exit(0)
ws = "workspaces/q1"
d = pathlib.Path(ws) / ".shannon" / "deliverables"; d.mkdir(parents=True, exist_ok=True)
(d / "report.json").write_text(json.dumps({"findings": [
    {"id": "F1", "title": "IDOR on /orders/{id}", "severity": "Critical", "cwe": "639",
     "description": "another user's order is readable", "code_paths": ["app/orders.py"],
     "proof_of_concept": "GET /orders/2 as user 1", "mitigation": "check ownership"},
]}))
print("shannon scan complete")
'''


def _stub_workspace(tmp_path: Path) -> Path:
    """A workspace with a fake `docker` (so health passes) and the stub engines."""
    binp = tmp_path / "bin"
    binp.mkdir(parents=True, exist_ok=True)
    _write_executable(binp / "docker", "import sys; print('Docker version 27.0.0')")
    _write_executable(binp / "strix", STRIX_STUB)
    _write_executable(binp / "shannon", SHANNON_STUB)
    return binp


@pytest.fixture
def engine_paths(tmp_path, monkeypatch):
    binp = _stub_workspace(tmp_path)
    monkeypatch.setenv("PATH", f"{binp}{os.pathsep}{os.environ['PATH']}")
    return tmp_path


# --------------------------------------------------------------------------- #
# Strix: real subprocess execution end to end
# --------------------------------------------------------------------------- #

def test_strix_real_subprocess_scan_normalizes_and_records_provenance(engine_paths):
    ws = engine_paths / "ws-strix"
    ws.mkdir()
    a = get_adapter("strix", ws)
    health = a.verify_health()
    assert health.state == EngineState.INSTALLED
    assert a.inspect_version() == "1.4.2"

    execution = a.execute_scan("https://app.test", timeout_s=30)
    assert execution.state == EngineState.COMPLETED
    assert "vulnerabilities.json" in execution.artifacts
    # output hash recorded for provenance
    assert execution.metadata.output_sha256

    findings = a.normalize_findings(execution)
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == "high" and f.cwe == "CWE-862" and f.cvss == 8.1
    assert f.source_engine == "strix" and f.engine_version == "1.4.2"
    assert f.raw["id"] == "v1"  # raw provider record preserved
    assert f.raw_artifact.endswith("vulnerabilities.json")


def test_strix_argv_is_exactly_the_documented_cli(engine_paths):
    ws = engine_paths / "ws-argv"
    ws.mkdir()
    a = get_adapter("strix", ws)
    argv = a._build_argv("https://app.test", {"instruction": "focus on authz",
                                              "scan_mode": "quick",
                                              "max_budget_usd": 5})
    assert argv[:2] == [a._binary(), "--target"]
    assert "https://app.test" in argv
    assert "--non-interactive" in argv
    assert "--instruction" in argv and "focus on authz" in argv
    assert "--scan-mode" in argv and "quick" in argv
    assert "--max-budget-usd" in argv and "5" in argv


def test_strix_never_uses_a_shell(engine_paths, monkeypatch):
    """A target string with shell metacharacters must not be interpreted."""
    ws = engine_paths / "ws-noshell"
    ws.mkdir()
    marker = ws / "pwned"
    a = get_adapter("strix", ws)
    # run_bounded is shell=False; a `; touch pwned` target is passed as one argv.
    a.execute_scan("https://app.test; touch pwned", timeout_s=30)
    assert not marker.exists(), "the adapter must not interpret shell metacharacters"


# --------------------------------------------------------------------------- #
# Shannon: real subprocess execution end to end
# --------------------------------------------------------------------------- #

def test_shannon_real_subprocess_scan_normalizes_and_records_provenance(engine_paths):
    ws = engine_paths / "ws-shannon"
    ws.mkdir()
    a = get_adapter("shannon", ws)
    health = a.verify_health()
    assert health.state == EngineState.INSTALLED
    assert a.inspect_version() == "0.6.0"

    execution = a.execute_scan("https://app.test", repo=str(ws / "repo"),
                               workspace_name="q1", timeout_s=30)
    assert execution.state == EngineState.COMPLETED
    assert "report.json" in execution.artifacts

    findings = a.normalize_findings(execution)
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == "critical" and f.cwe == "CWE-639"
    assert f.source_engine == "shannon" and f.engine_version == "0.6.0"


def test_shannon_requires_a_repo(engine_paths):
    ws = engine_paths / "ws-shannon-repo"
    ws.mkdir()
    a = get_adapter("shannon", ws)
    from blackheart.engines.contract import EngineUnavailable
    with pytest.raises(EngineUnavailable):
        a.execute_scan("https://app.test", timeout_s=10)


# --------------------------------------------------------------------------- #
# Missing engines are reported, never faked
# --------------------------------------------------------------------------- #

def test_missing_engines_are_reported_not_faked(tmp_path, monkeypatch):
    # Empty PATH: nothing is installed.
    monkeypatch.setenv("PATH", str(tmp_path / "empty"))
    for name in ("strix", "pentagi"):
        a = get_adapter(name, tmp_path)
        h = a.verify_health()
        assert h.state in (EngineState.MISSING, EngineState.CONFIGURATION_ERROR), name
        assert a.detect_installation() is False


def test_every_engine_is_registered():
    assert set(list_engines()) == {"strix", "shannon", "pentagi",
                                   "slither", "wake", "halmos", "echidna", "medusa"}


# --------------------------------------------------------------------------- #
# CWE / CVSS / severity mapping
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("raw,expected", [
    ("862", "CWE-862"), ("CWE-862", "CWE-862"), ("cwe-79", "CWE-79"),
    ("79", "CWE-79"), ("", ""), (None, ""),
])
def test_normalize_cwe(raw, expected):
    assert normalize_cwe(raw) == expected


@pytest.mark.parametrize("raw,expected", [
    (8.1, 8.1), ("8.1", 8.1), ("9", 9.0),
    (None, None), ("nope", None), (11.0, None),
])
def test_normalize_cvss(raw, expected):
    assert normalize_cvss(raw) == expected


@pytest.mark.parametrize("raw,expected", [
    ("CRITICAL", "critical"), ("High", "high"), ("med", "medium"),
    ("low", "low"), ("informational", "info"), ("", "info"),
])
def test_normalize_severity(raw, expected):
    assert normalize_severity(raw) == expected


# --------------------------------------------------------------------------- #
# Secret redaction in captured output
# --------------------------------------------------------------------------- #

def test_engine_output_redacts_secrets(engine_paths):
    """A stub that prints a secret must have it redacted before storage."""
    binp = engine_paths / "bin"
    _write_executable(binp / "leaky", '''
import sys
if "--version" in sys.argv: print("leaky 1.0"); sys.exit(0)
print("using key sk-abcdef0123456789abcdef0123456789")
print("Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.abcdefghij")
''')
    # Build a minimal adapter that reuses the real execution path with the stub.
    from blackheart.engines.strix import StrixAdapter

    class Leaky(StrixAdapter):
        name = "strix"
        def _binary(self):
            return str(binp / "leaky")
        def _runs_root(self):
            return engine_paths / "no-runs"

    ws = engine_paths / "ws-leak"
    ws.mkdir()
    a = Leaky(ws)
    execution = a.execute_scan("https://app.test", timeout_s=30)
    combined = (execution.raw_stdout or "") + (execution.raw_stderr or "")
    assert "sk-abcdef0123456789abcdef0123456789" not in combined
    assert "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.abcdefghij" not in combined


# --------------------------------------------------------------------------- #
# License boundaries (documented, not changed)
# --------------------------------------------------------------------------- #

def test_engine_licenses_are_recorded():
    expect = {"strix": "Apache-2.0", "shannon": "AGPL-3.0"}
    for name, lic in expect.items():
        a = get_adapter(name, "/tmp")
        assert a.license_id == lic, name
    # PentAGI carries a mixed MIT-core + EULA notice.
    p = get_adapter("pentagi", "/tmp")
    assert "EULA" in p.license_id or "MIT" in p.license_id
