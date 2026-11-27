"""Tests for the engine integration layer (mission sections 4-7, 14).

These tests exercise the adapter *contract* and the cross-engine *coordination*
with real code paths. Engine binaries are not installed in CI, so live execution
is asserted only where the environment provides it; everything else is tested
against the real adapter logic (argv construction, state machine, artifact
parsing, normalization, orchestration) using synthetic engine output that matches
the documented on-disk format.

Every mock here is clearly a *fixture* standing in for an engine's file output,
never a fake claim that an engine ran.
"""

from __future__ import annotations

import json

import pytest

from blackheart.engines import (
    EngineState,
    NormalizedFinding,
    get_adapter,
    list_engines,
    normalize_cwe,
    normalize_cvss,
    normalize_severity,
)
from blackheart.engines.contract import (
    EngineAdapter,
    ExecutionMetadata,
    ExecutionResult,
    Health,
    redact_secrets,
    run_bounded,
)
from blackheart.engines.orchestrator import EngineOrchestrator, _canonical_category
from blackheart.models import Classification


# --------------------------------------------------------------------------- #
# Contract + state vocabulary
# --------------------------------------------------------------------------- #

#: The three subordinate agentic engines plus the five Solidity analysers form
#: one registry. Keeping the expected set explicit means a new engine cannot be
#: registered silently, and a removed one cannot vanish unnoticed.
EXPECTED_ENGINES = {"strix", "shannon", "pentagi",
                    "slither", "wake", "halmos", "echidna", "medusa"}


def test_every_engine_is_registered():
    assert set(list_engines()) == EXPECTED_ENGINES


def test_unknown_engine_raises():
    with pytest.raises(KeyError):
        get_adapter("nmap", "/tmp")


def test_adapter_base_is_honest_when_not_implemented(tmp_path):
    """The base adapter must not claim to be installed."""
    class Dummy(EngineAdapter):
        name = "dummy"

    d = Dummy(tmp_path)
    with pytest.raises(NotImplementedError):
        d.detect_installation()
    assert d.normalize_findings(ExecutionResult(ExecutionMetadata("dummy", "", [], str(tmp_path), "t"))) == []


def test_engine_states_are_the_required_vocabulary():
    required = {
        "INSTALLED", "MISSING", "UNSUPPORTED", "CONFIGURATION_ERROR", "READY",
        "RUNNING", "COMPLETED", "PARTIAL", "FAILED", "CANCELLED",
        "VERIFICATION_PENDING",
    }
    assert required <= {s.value for s in EngineState}


def test_run_bounded_captures_output_and_exit(tmp_path):
    out = run_bounded(["python3", "-c", "print('hello-engine')"], cwd=tmp_path, timeout_s=30)
    assert out.returncode == 0
    assert "hello-engine" in out.stdout
    assert out.output_sha256 and not out.timed_out


def test_run_bounded_enforces_timeout(tmp_path):
    out = run_bounded(["python3", "-c", "import time; time.sleep(30)"], cwd=tmp_path, timeout_s=0.5)
    assert out.timed_out is True
    assert out.returncode is not None  # it was actually terminated


def test_run_bounded_does_not_use_a_shell(tmp_path):
    """A shell metacharacter in an arg must not be interpreted."""
    out = run_bounded(["python3", "-c", "import sys; print(sys.argv[1])", "a; touch pwned"], cwd=tmp_path)
    assert "a; touch pwned" in out.stdout
    assert not (tmp_path / "pwned").exists()


def test_run_bounded_caps_output(tmp_path):
    out = run_bounded(["python3", "-c", "print('x'*100000)"], cwd=tmp_path, max_output_bytes=1000)
    assert "truncated" in out.stdout


def test_redact_secrets_hides_credentials():
    text = "OPENAI_API_KEY=sk-abcdefghijklmnopqrstuvwxyz\nAuthorization: Bearer eyJhbGciOi"
    red = redact_secrets(text)
    assert "sk-abcdefghijklmnopqrstuvwxyz" not in red


# --------------------------------------------------------------------------- #
# Unified schema
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("raw,expected", [
    ("CRITICAL", "critical"), ("High", "high"), ("moderate", "medium"),
    ("sev3", "low"), ("informational", "info"), (None, "info"), ("", "info"),
])
def test_normalize_severity(raw, expected):
    assert normalize_severity(raw) == expected


@pytest.mark.parametrize("raw,expected", [
    ("CWE-79", "CWE-79"), ("cwe: 89", "CWE-89"), ("306", "CWE-306"),
    (22, "CWE-22"), (None, ""), ("nonsense", ""),
])
def test_normalize_cwe(raw, expected):
    assert normalize_cwe(raw) == expected


@pytest.mark.parametrize("raw,expected", [(9.8, 9.8), ("CVSS: 7.5", 7.5), (11, None), (None, None)])
def test_normalize_cvss(raw, expected):
    assert normalize_cvss(raw) == expected


def test_fingerprint_is_engine_independent_and_deterministic():
    """The same defect described differently by two engines must collide."""
    a = NormalizedFinding(source_engine="strix", target_id="t1", component="auth",
                          description="Auth bypass via JWT confusion",
                          severity="high", cwe="CWE-287").finalize()
    b = NormalizedFinding(source_engine="shannon", target_id="t1", component="AUTH",
                          description="auth  bypass   via jwt confusion",
                          severity="critical", cwe="cwe:287").finalize()
    assert a.fingerprint == b.fingerprint
    assert a.finding_id == b.finding_id


def test_different_defects_have_different_fingerprints():
    a = NormalizedFinding(target_id="t", component="auth", description="x").finalize()
    b = NormalizedFinding(target_id="t", component="billing", description="x").finalize()
    assert a.fingerprint != b.fingerprint


def test_location_line_numbers_do_not_change_identity():
    a = NormalizedFinding(target_id="t", description="d", source_location="src/v.sol:10").finalize()
    b = NormalizedFinding(target_id="t", description="d", source_location="src/v.sol:99-120").finalize()
    assert a.fingerprint == b.fingerprint


def test_candidate_default_disposition_is_not_confirmed():
    f = NormalizedFinding(title="x").finalize()
    assert f.disposition == Classification.NEEDS_MORE_EVIDENCE.value
    assert not f.may_be_read_as_vulnerability()


# --------------------------------------------------------------------------- #
# Adapter health honesty
# --------------------------------------------------------------------------- #

def test_strix_missing_when_binary_absent(tmp_path, monkeypatch):
    monkeypatch.setattr("shutil.which", lambda name: None)
    a = get_adapter("strix", tmp_path)
    h = a.verify_health()
    assert h.state == EngineState.MISSING
    assert not any(c.available for c in a.inspect_capabilities())


def test_shannon_unsupported_without_docker(tmp_path, monkeypatch):
    def fake_which(name):
        return "/usr/bin/npx" if name == "npx" else None
    monkeypatch.setattr("shutil.which", fake_which)
    a = get_adapter("shannon", tmp_path)
    h = a.verify_health()
    assert h.state == EngineState.UNSUPPORTED
    assert "docker" in h.detail


def test_pentagi_missing_without_instance(tmp_path, monkeypatch):
    monkeypatch.delenv("PENTAGI_BASE_URL", raising=False)
    a = get_adapter("pentagi", tmp_path)
    assert a.verify_health().state == EngineState.MISSING


def test_pentagi_configuration_error_without_token(tmp_path):
    a = get_adapter("pentagi", tmp_path, config={"base_url": "https://pentagi.example"})
    h = a.verify_health()
    assert h.state == EngineState.CONFIGURATION_ERROR


def test_execute_scan_raises_when_engine_unavailable(tmp_path, monkeypatch):
    monkeypatch.setattr("shutil.which", lambda name: None)
    a = get_adapter("strix", tmp_path)
    from blackheart.engines import EngineUnavailable
    with pytest.raises(EngineUnavailable):
        a.execute_scan("https://example.com")


# --------------------------------------------------------------------------- #
# Adapter argv construction (no engine run)
# --------------------------------------------------------------------------- #

def test_strix_argv_is_the_documented_cli(tmp_path, monkeypatch):
    monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/strix" if name == "strix" else None)
    a = get_adapter("strix", tmp_path)
    meta = a.prepare_execution("https://app.test", instruction="focus auth", max_budget_usd=5)
    assert meta.argv[0].endswith("strix")
    assert meta.argv[1:3] == ["--target", "https://app.test"]
    assert "--non-interactive" in meta.argv
    assert "--instruction" in meta.argv and "focus auth" in meta.argv
    assert "--max-budget-usd" in meta.argv


def test_shannon_argv_is_the_documented_cli(tmp_path, monkeypatch):
    monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/npx" if name == "npx" else None)
    a = get_adapter("shannon", tmp_path)
    monkeypatch.setattr(a, "inspect_version", lambda: "3.5.1")  # isolate argv from npx probing
    meta = a.prepare_execution("https://app.test", repo="/src")
    assert "start" in meta.argv
    assert "-u" in meta.argv and "https://app.test" in meta.argv
    assert "-r" in meta.argv and "/src" in meta.argv
    assert "--yes" in meta.argv


def test_shannon_requires_a_repo(tmp_path, monkeypatch):
    monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/npx" if name == "npx" else None)
    a = get_adapter("shannon", tmp_path)
    monkeypatch.setattr(a, "inspect_version", lambda: "3.5.1")
    from blackheart.engines import EngineUnavailable
    # docker missing => health UNSUPPORTED, still a controlled EngineUnavailable
    with pytest.raises(EngineUnavailable):
        a.execute_scan("https://app.test")


# --------------------------------------------------------------------------- #
# Normalization from real on-disk formats (fixtures = documented file shapes)
# --------------------------------------------------------------------------- #

def test_strix_normalizes_vulnerabilities_json(tmp_path):
    run_dir = tmp_path / "strix_runs" / "run1"
    run_dir.mkdir(parents=True)
    (run_dir / "vulnerabilities.json").write_text(json.dumps([
        {"id": "v1", "title": "JWT algorithm confusion", "severity": "CRITICAL",
         "description": "accepts unsigned tokens", "cwe": "CWE-287", "cvss": 9.1,
         "endpoint": "/api/auth", "code_locations": [{"path": "src/auth.py"}],
         "poc_description": "forge a token", "impact": "account takeover",
         "remediation_steps": "verify signature"},
    ]), encoding="utf-8")
    a = get_adapter("strix", tmp_path)
    recs = a._load_vulnerabilities(run_dir)
    result = ExecutionResult(
        ExecutionMetadata("strix", "1.2.3", [], str(tmp_path), "t", target="https://app.test"),
        artifacts={"vulnerabilities.json": str(run_dir / "vulnerabilities.json")},
        raw_records=recs,
    )
    findings = a.normalize_findings(result)
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == "critical" and f.cwe == "CWE-287" and f.cvss == 9.1
    assert f.source_engine == "strix" and f.engine_version == "1.2.3"
    assert f.raw["id"] == "v1"  # provenance preserved


def test_shannon_normalizes_report_json(tmp_path):
    deliv = tmp_path / "workspaces" / "q1" / ".shannon" / "deliverables"
    deliv.mkdir(parents=True)
    (deliv / "report.json").write_text(json.dumps({
        "findings": [
            {"id": "F1", "title": "SQL injection", "severity": "High", "cwe": "89",
             "description": "union-based", "code_paths": ["app/db.py"],
             "proof_of_concept": "curl ...", "mitigation": "parameterise"},
        ]
    }), encoding="utf-8")
    a = get_adapter("shannon", tmp_path)
    ws = a._find_workspace("q1")
    recs = a._load_report_json(ws)
    result = ExecutionResult(
        ExecutionMetadata("shannon", "3.5.1", [], str(tmp_path), "t", target="https://app.test"),
        artifacts=a.collect_artifacts(ws), raw_records=recs,
    )
    findings = a.normalize_findings(result)
    assert len(findings) == 1
    assert findings[0].severity == "high" and findings[0].cwe == "CWE-89"


def test_normalization_skips_records_without_a_title(tmp_path):
    a = get_adapter("strix", tmp_path)
    result = ExecutionResult(
        ExecutionMetadata("strix", "1", [], str(tmp_path), "t"),
        raw_records=[{"severity": "high"}, {"title": "real"}],
    )
    assert len(a.normalize_findings(result)) == 1


def test_malformed_json_is_handled_not_raised(tmp_path):
    run_dir = tmp_path / "strix_runs" / "r"
    run_dir.mkdir(parents=True)
    (run_dir / "vulnerabilities.json").write_text("{not json", encoding="utf-8")
    a = get_adapter("strix", tmp_path)
    assert a._load_vulnerabilities(run_dir) == []


# --------------------------------------------------------------------------- #
# PentAGI adapter over a real (local) HTTP server -- proves the path is live
# --------------------------------------------------------------------------- #

def _pentagi_server():
    """A minimal threaded HTTP server that speaks the PentAGI API shape."""
    import json as _json
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer

    state = {"flows": {}, "created": 0}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *a):  # silence
            pass

        def _send(self, obj, code=200):
            body = _json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            if self.path.endswith("/api/v1/info"):
                return self._send({"version": "1.2.3", "status": "ok"})
            if "/api/v1/flows/" in self.path:
                fid = self.path.rsplit("/", 1)[-1]
                return self._send(state["flows"].get(fid, {}))
            return self._send({}, 404)

        def do_POST(self):
            length = int(self.headers.get("Content-Length", 0))
            payload = self.rfile.read(length)
            try:
                req = _json.loads(payload or b"{}")
            except Exception:
                req = {}
            query = str(req.get("query", ""))
            if "createFlow" in query:
                state["created"] += 1
                fid = f"flow-{state['created']}"
                state["flows"][fid] = {
                    "id": fid, "title": "t", "status": "finished",
                    "vulnerabilities": [{
                        "title": "Auth bypass in API", "severity": "high",
                        "cwe": "287", "description": "unprivileged bypass", "host": "api",
                    }],
                }
                return self._send({"data": {"createFlow": {"id": fid, "title": "t",
                                                           "status": "created", "createdAt": "now"}}})
            # flow status query
            fid = str((req.get("variables") or {}).get("id", ""))
            status = state["flows"].get(fid, {}).get("status", "failed")
            return self._send({"data": {"flow": {"id": fid, "title": "t", "status": status}}})

    srv = HTTPServer(("127.0.0.1", 0), Handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv, state


def test_pentagi_adapter_runs_against_a_live_instance(tmp_path):
    srv, state = _pentagi_server()
    base = f"http://127.0.0.1:{srv.server_address[1]}"
    try:
        a = get_adapter("pentagi", tmp_path,
                        config={"base_url": base, "api_token": "t", "poll_interval_s": 0.05})
        assert a.verify_health().state == EngineState.INSTALLED
        assert a.inspect_version() == "1.2.3"
        execution = a.execute_scan("http://app.test", timeout_s=5)
        assert execution.state == EngineState.COMPLETED
        findings = a.normalize_findings(execution)
        assert len(findings) == 1
        assert findings[0].severity == "high" and findings[0].cwe == "CWE-287"
        assert state["created"] == 1
    finally:
        srv.shutdown()


# --------------------------------------------------------------------------- #
# Orchestration: dedup, corroboration, contradiction, chains, prior art
# --------------------------------------------------------------------------- #

def _finding(**kw):
    base = dict(target_id="https://app.test", component="auth", description="auth bypass")
    base.update(kw)
    return NormalizedFinding(**base).finalize()


def _orchestrator_with(tmp_path, findings_by_engine):
    """A test double orchestrator whose adapters yield fixed findings."""
    class FakeAdapter(EngineAdapter):
        def __init__(self, name, findings):
            super().__init__(tmp_path)
            self.name = name
            self._findings = findings

        def verify_health(self):
            return Health(EngineState.INSTALLED, version="9.9")

        def execute_scan(self, target, **options):
            return ExecutionResult(ExecutionMetadata(self.name, "9.9", [], str(tmp_path), "t", target=target))

        def normalize_findings(self, result):
            return list(self._findings)

    adapters = [FakeAdapter(name, fs) for name, fs in findings_by_engine.items()]
    return EngineOrchestrator(tmp_path, adapters)


def test_cross_engine_dedup_collapses_same_root_cause(tmp_path):
    a = _finding(source_engine="strix", severity="high")
    b = _finding(source_engine="shannon", severity="critical")  # same fingerprint
    orch = _orchestrator_with(tmp_path, {"strix": [a], "shannon": [b]})
    result = orch.run("https://app.test")
    assert len(result.candidates) == 2
    assert len(result.clusters) == 1
    cluster = result.clusters[0]
    assert cluster.corroborated is True
    assert set(cluster.sources) == {"strix", "shannon"}


def test_two_engines_agreeing_does_not_confirm(tmp_path):
    """Corroboration raises confidence but must never set CONFIRMED."""
    a = _finding(source_engine="strix")
    b = _finding(source_engine="shannon")
    orch = _orchestrator_with(tmp_path, {"strix": [a], "shannon": [b]})
    result = orch.run("https://app.test")
    assert result.clusters[0].disposition == Classification.NEEDS_MORE_EVIDENCE.value
    assert result.confirmed == []


def test_contradiction_is_preserved_not_resolved(tmp_path):
    claim = _finding(source_engine="strix", severity="critical")
    deny = _finding(source_engine="shannon", reproduction_status="failed_to_reproduce",
                    disposition="FALSE_POSITIVE")
    orch = _orchestrator_with(tmp_path, {"strix": [claim], "shannon": [deny]})
    result = orch.run("https://app.test")
    cluster = result.clusters[0]
    assert cluster.contradiction is True
    assert "shannon" in cluster.contradiction_detail
    assert cluster.disposition == Classification.NEEDS_MORE_EVIDENCE.value


def test_prior_art_is_marked_duplicate(tmp_path):
    f = _finding(source_engine="strix")
    orch = _orchestrator_with(tmp_path, {"strix": [f]})
    orch.ledger_fingerprints = {f.fingerprint}
    result = orch.run("https://app.test")
    assert result.clusters[0].known_prior_art is True
    assert result.clusters[0].disposition == Classification.DUPLICATE_OR_KNOWN.value


def test_attack_chain_requires_a_real_enabling_edge(tmp_path):
    authn = _finding(source_engine="strix", category="authentication", description="jwt bypass", component="api")
    authz = _finding(source_engine="strix", category="authorization", description="idor on orders", component="api")
    orch = _orchestrator_with(tmp_path, {"strix": [authn, authz]})
    result = orch.run("https://app.test")
    assert len(result.chains) == 1
    assert result.chains[0].edges == [("authentication", "authorization")]


def test_no_chain_from_unrelated_findings(tmp_path):
    x = _finding(source_engine="strix", category="xss", description="reflected xss", component="web")
    y = _finding(source_engine="strix", category="csrf", description="csrf on form", component="web")
    orch = _orchestrator_with(tmp_path, {"strix": [x, y]})
    result = orch.run("https://app.test")
    assert result.chains == []


def test_no_chain_across_different_components(tmp_path):
    authn = _finding(source_engine="strix", category="authentication", description="a", component="api")
    authz = _finding(source_engine="strix", category="authorization", description="b", component="admin")
    orch = _orchestrator_with(tmp_path, {"strix": [authn, authz]})
    assert orch.run("https://app.test").chains == []


def test_missing_engine_is_reported_and_does_not_abort(tmp_path):
    class Missing(EngineAdapter):
        name = "pentagi"
        def verify_health(self):
            return Health(EngineState.MISSING, detail="not configured")

    good = _orchestrator_with(tmp_path, {"strix": [_finding(source_engine="strix")]})
    orch = EngineOrchestrator(tmp_path, [*good.adapters, Missing(tmp_path)])
    result = orch.run("https://app.test")
    assert "pentagi" in result.missing_engines
    assert len(result.candidates) == 1  # the available engine still ran


def test_engine_crash_is_contained(tmp_path):
    class Boom(EngineAdapter):
        name = "strix"
        def verify_health(self):
            return Health(EngineState.INSTALLED)
        def execute_scan(self, target, **options):
            raise RuntimeError("engine exploded")

    orch = EngineOrchestrator(tmp_path, [Boom(tmp_path)])
    result = orch.run("https://app.test")
    assert result.engines[0].state == EngineState.FAILED.value
    assert result.candidates == []


def test_canonical_category_mapping():
    assert _canonical_category("SQLi") == "injection"
    assert _canonical_category("PrivEsc") == "privilege_escalation"
    assert _canonical_category("access control") == "authorization"


def test_orchestration_result_serializes(tmp_path):
    orch = _orchestrator_with(tmp_path, {"strix": [_finding(source_engine="strix")]})
    d = orch.run("https://app.test").to_dict()
    assert d["target"] == "https://app.test"
    assert d["clusters"] and "representative" in d["clusters"][0]


# --------------------------------------------------------------------------- #
# The attacker lens is applied to engine findings (mission mindset wiring)
# --------------------------------------------------------------------------- #

def test_cluster_carries_the_attacker_lens(tmp_path):
    from blackheart.mindset import OUTCOMES, LEVERS

    f = _finding(source_engine="strix", category="authorization",
                 description="idor lets an attacker read another user's orders")
    orch = _orchestrator_with(tmp_path, {"strix": [f]})
    lens = orch.run("https://app.test").clusters[0].attacker_lens()
    assert lens["outcome"] in OUTCOMES
    assert lens["outcome"] == "bypass a restriction"
    assert set(lens["levers"]) <= set(LEVERS)


def test_report_carries_the_canonical_attacker_question(tmp_path):
    from blackheart.engines import report as eng_report
    from blackheart.mindset import ATTACKER_QUESTION

    orch = _orchestrator_with(tmp_path, {"strix": [_finding(source_engine="strix")]})
    result = orch.run("https://app.test")
    md = eng_report.render_markdown(result)
    assert ATTACKER_QUESTION in md
    assert "Attacker outcome:" in md and "Attacker levers:" in md
    import json as _json

    assert _json.loads(eng_report.render_json(result))["attacker_question"] == ATTACKER_QUESTION
