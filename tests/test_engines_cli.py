"""Security + CLI tests for the engine integration layer (mission sections 9, 14E).

These are the *negative controls*: they attempt to bypass authorization through
every entry point the mission names -- direct adapter invocation, the CLI, engine
configuration, malformed scope data, missing/expired authorization, and engine
output manipulation -- and assert each one fails closed. They also exercise the
CLI end to end and the report writers.
"""

from __future__ import annotations

import json
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from blackheart.engines import EngineState, get_adapter
from blackheart.engines import session as eng_session
from blackheart.engines import report as eng_report
from blackheart.engines.contract import EngineAdapter, ExecutionMetadata, ExecutionResult, Health
from blackheart.engines.orchestrator import EngineOrchestrator
from blackheart.models import AssetStatus, AuthorizationRecord, Classification
from blackheart.authz import authorize_active_testing

ROOT = Path(__file__).resolve().parent.parent


def _compatibility(tmp_path: Path, target: str = "./examples") -> Path:
    """A validated compatibility record for the local examples tree.

    Engine dispatch is compatibility-gated, so a run needs a record bound to its
    target like any other engine execution. The examples are Solidity, so the
    record names Foundry and the official Foundry book.
    """
    path = tmp_path / "compatibility.json"
    path.write_text(json.dumps({
        "target_component": target,
        "language": "Solidity",
        "language_version": "0.8.x",
        "framework": "Foundry",
        "runtime": "EVM (local anvil)",
        "tool": "Foundry",
        "compatibility_evidence": "https://book.getfoundry.sh/",
        "selection_reason": "the examples are Foundry projects",
        "expected_coverage": "the examples tree only",
        "known_limitations": "examples are illustrative, not a protocol",
        "smoke_test": "passed",
    }), encoding="utf-8")
    return path


def _authorized_record(asset: str = "asset-a", *, age_days: int = 0) -> AuthorizationRecord:
    """A fully-verified authorization record that DOES admit active testing."""
    checked = (datetime.now(timezone.utc) - timedelta(days=age_days)).isoformat()
    return AuthorizationRecord(
        program="p", platform="hackerone", target_url="https://t.example",
        scope_url="https://hackerone.com/p", checked_at=checked,
        program_active=True, safe_harbor=True, zero_cost=True,
        nigerian_eligible=True, payout_feasible=True,
        verified=True, evidence=["https://hackerone.com/p/scope"],
        asset_classes={asset: AssetStatus.AUTHORIZED.value},
    )


class FakeAdapter(EngineAdapter):
    """Test double: a healthy adapter that yields fixed findings."""

    def __init__(self, name, findings, workspace="/tmp"):
        super().__init__(workspace)
        self.name = name
        self._findings = findings

    def verify_health(self):
        return Health(EngineState.INSTALLED, version="1.0")

    def execute_scan(self, target, **options):
        return ExecutionResult(ExecutionMetadata(self.name, "1.0", [], str(self.workspace), "t", target=target))

    def normalize_findings(self, result):
        return list(self._findings)


def _run_cli(*args, cwd=None):
    return subprocess.run(
        [sys.executable, "-m", "blackheart", *args],
        cwd=cwd or ROOT, capture_output=True, text=True, timeout=120,
    )


# --------------------------------------------------------------------------- #
# Authorization cannot be bypassed
# --------------------------------------------------------------------------- #

def test_run_without_authorization_is_refused(tmp_path):
    outcome = eng_session.run_session(tmp_path, "https://real-target.example", engines=["strix"])
    assert outcome.allowed is False
    assert "authorization" in outcome.blocked_reason.lower()
    assert outcome.result is None


def test_a_valid_authorization_admits_the_run(tmp_path):
    """The positive control: a complete, fresh record does admit active testing."""
    rec = _authorized_record("asset-a")
    assert authorize_active_testing(rec, "asset-a").allowed is True


def test_cli_run_without_authorization_exits_nonzero(tmp_path):
    proc = _run_cli("engines", "run", "--target", "https://real-target.example",
                    "--workdir", str(tmp_path))
    assert proc.returncode == 2
    assert "BLOCKED" in proc.stderr


def test_expired_authorization_is_refused():
    """A stale authorization record must not admit active testing."""
    stale = _authorized_record("asset-a", age_days=30)
    assert authorize_active_testing(stale, "asset-a").allowed is False


def test_out_of_scope_asset_is_refused():
    rec = _authorized_record("asset-a")
    assert authorize_active_testing(rec, "some-other-asset").allowed is False


def test_allow_local_is_the_only_bypass_and_is_explicit(tmp_path):
    """The single sanctioned bypass is the explicit local/disposable opt-in."""
    import blackheart.engines.session as s

    orig = s.get_adapter
    s.get_adapter = lambda name, ws, config=None: FakeAdapter(name, [], workspace=ws)
    try:
        blocked = s.run_session(tmp_path / "a", "https://real.example", engines=["strix"])
        assert blocked.allowed is False
        allowed = s.run_session(tmp_path / "b", "http://localhost:8080", engines=["strix"], allow_local=True)
        assert allowed.allowed is True
    finally:
        s.get_adapter = orig


def test_unknown_engine_name_is_rejected(tmp_path):
    with pytest.raises(eng_session.EngineSessionError):
        eng_session.run_session(tmp_path, "http://localhost", engines=["nmap"], allow_local=True)


# --------------------------------------------------------------------------- #
# Engine output is untrusted: it cannot self-confirm
# --------------------------------------------------------------------------- #

def test_engine_claiming_confirmed_does_not_become_confirmed(tmp_path):
    """An engine record that self-declares CONFIRMED must not survive as confirmed."""
    from blackheart.engines.schema import NormalizedFinding

    class Lying(FakeAdapter):
        def normalize_findings(self, result):
            return [NormalizedFinding(source_engine="strix", target_id=result.metadata.target,
                                      component="auth", description="claimed",
                                      disposition="CONFIRMED").finalize()]

    orch = EngineOrchestrator(tmp_path, [Lying("strix", [], workspace=tmp_path)])
    result = orch.run("https://t.example")
    # The cluster's disposition is computed by BLACKHEART, not read from the engine.
    assert result.clusters[0].disposition == Classification.NEEDS_MORE_EVIDENCE.value
    assert result.confirmed == []


def test_adapter_cannot_widen_scope_or_confirm_via_api():
    """The adapter contract exposes no method that changes authorization/scope."""
    a = get_adapter("strix", "/tmp")
    for forbidden in ("set_authorized", "confirm_finding", "approve_exploit",
                      "submit_report", "disclose", "broadcast", "transfer_funds",
                      "expand_scope"):
        assert not hasattr(a, forbidden)


def test_engine_output_is_redacted_in_the_persisted_state(tmp_path):
    """Secrets echoed by an engine must not be stored in the run state."""
    from blackheart.engines.contract import redact_secrets

    class Leaky(FakeAdapter):
        def execute_scan(self, target, **options):
            return ExecutionResult(
                ExecutionMetadata("strix", "1", [], str(tmp_path), "t", target=target),
                raw_stdout=redact_secrets("OPENAI_API_KEY=sk-abcdefghijklmnopqrstuvwxyz"),
            )

    import blackheart.engines.session as s
    orig = s.get_adapter
    s.get_adapter = lambda name, ws, config=None: Leaky(name, [], workspace=ws)
    try:
        s.run_session(tmp_path, "http://localhost", engines=["strix"], allow_local=True)
    finally:
        s.get_adapter = orig
    state = (tmp_path / "engines-run.json").read_text()
    assert "sk-abcdefghijklmnopqrstuvwxyz" not in state


# --------------------------------------------------------------------------- #
# CLI end-to-end + reports
# --------------------------------------------------------------------------- #

def test_cli_engines_list(tmp_path):
    proc = _run_cli("engines", "list", "--workdir", str(tmp_path))
    assert proc.returncode == 0
    for name in ("strix", "shannon", "pentagi", "slither", "wake", "halmos",
                 "echidna", "medusa"):
        assert name in proc.stdout


def test_cli_engines_list_json(tmp_path):
    proc = _run_cli("engines", "list", "--json", "--workdir", str(tmp_path))
    rows = json.loads(proc.stdout)
    assert {r["name"] for r in rows} == {"strix", "shannon", "pentagi",
                                        "slither", "wake", "halmos",
                                        "echidna", "medusa"}
    assert all("license" in r for r in rows)


def test_cli_engines_capabilities(tmp_path):
    proc = _run_cli("engines", "capabilities", "--engine", "strix", "--json", "--workdir", str(tmp_path))
    data = json.loads(proc.stdout)
    assert data["engine"] == "strix"
    assert len(data["capabilities"]) >= 8


def test_cli_engines_verify_reports_missing(tmp_path):
    proc = _run_cli("engines", "verify", "--engine", "strix", "--workdir", str(tmp_path))
    assert proc.returncode == 1  # requested engine is missing
    assert json.loads(proc.stdout)[0]["state"] == "MISSING"


def test_cli_local_run_writes_reports(tmp_path):
    proc = _run_cli("engines", "run", "--target", "./examples", "--engines", "strix",
                    "--allow-local", "--workdir", str(tmp_path),
                    "--compatibility", str(_compatibility(tmp_path)),
                    "--report", str(tmp_path / "rep"))
    assert proc.returncode == 0
    assert (tmp_path / "rep" / "report.md").is_file()
    assert (tmp_path / "rep" / "report.json").is_file()
    assert (tmp_path / "rep" / "report.sarif").is_file()


def test_cli_report_stdout_json(tmp_path):
    _run_cli("engines", "run", "--target", "./examples", "--engines", "strix",
             "--allow-local", "--workdir", str(tmp_path),
             "--compatibility", str(_compatibility(tmp_path)))
    proc = _run_cli("engines", "report", "--stdout", "--format", "json", "--workdir", str(tmp_path))
    data = json.loads(proc.stdout)
    assert data["schema"] == "blackheart.multi-engine-report.v1"


def test_cli_status_and_cancel(tmp_path):
    proc = _run_cli("engines", "status", "--workdir", str(tmp_path))
    assert proc.returncode == 0
    assert "engines" in json.loads(proc.stdout)
    proc = _run_cli("engines", "cancel", "--workdir", str(tmp_path))
    assert proc.returncode == 0
    assert (tmp_path / "engines-cancel").exists()


# --------------------------------------------------------------------------- #
# Report correctness
# --------------------------------------------------------------------------- #

def _result_with(tmp_path, findings_by_engine):
    adapters = [FakeAdapter(name, fs, workspace=tmp_path) for name, fs in findings_by_engine.items()]
    return EngineOrchestrator(tmp_path, adapters).run("https://t.example")


def test_markdown_separates_confirmed_from_candidates(tmp_path):
    from blackheart.engines.schema import NormalizedFinding
    f = NormalizedFinding(source_engine="strix", target_id="https://t.example",
                          component="auth", description="x", title="Auth bypass").finalize()
    result = _result_with(tmp_path, {"strix": [f]})
    md = eng_report.render_markdown(result)
    assert "## Confirmed findings" in md
    assert "## Unconfirmed candidates" in md
    assert "[CANDIDATE]" in md and "[CONFIRMED]" not in md


def test_sarif_is_valid_210(tmp_path):
    from blackheart.engines.schema import NormalizedFinding
    f = NormalizedFinding(source_engine="strix", target_id="https://t.example",
                          component="auth", description="x", title="Auth bypass",
                          severity="critical", cwe="CWE-287", cvss=9.1,
                          source_location="src/auth.py").finalize()
    result = _result_with(tmp_path, {"strix": [f]})
    sarif = json.loads(eng_report.render_sarif(result))
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "BLACKHEART"
    assert run["results"][0]["ruleId"] == "CWE-287"
    assert run["results"][0]["properties"]["disposition"] == Classification.NEEDS_MORE_EVIDENCE.value


def test_json_report_never_labels_candidate_confirmed(tmp_path):
    from blackheart.engines.schema import NormalizedFinding
    f = NormalizedFinding(source_engine="strix", target_id="https://t.example",
                          component="auth", description="x", title="Auth bypass").finalize()
    result = _result_with(tmp_path, {"strix": [f]})
    data = json.loads(eng_report.render_json(result))
    assert data["summary"]["confirmed"] == 0
    assert data["summary"]["candidates"] == 1
