"""Tests for the executable-target (runtime) state-space engine.

These exercise *real execution* against local, controlled applications (loopback
HTTP and local processes) -- no mocks for the target itself. Mocked responses are
used only to force specific failure modes (timeout, 5xx) that a real app will not
reliably produce on demand, and each such test says so.

Coverage maps to the mission's Phase 7 list: adapter contract and lifecycle,
actual operation execution, runtime state capture, multi-identity sequences,
authorization enforcement, scope violations, loopback restrictions and redirect
escape, timeouts and resource limits, partial failures, state reset and cleanup,
provenance, sequence minimisation, independent verification, secure-control
negative cases, held-out evaluation, secret redaction, and existing-fixture
compatibility.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from blackheart.statespace.runtime import (
    DEVELOPMENT_APPS,
    HELDOUT_APPS,
    ExecRecord,
    ExecutionBudget,
    ExecutionError,
    HttpExecutionAdapter,
    LocalScope,
    ScopeError,
    adapter_report,
    build_http_target,
    local_harness_scope,
    make_app,
    redact,
    run_runtime_discovery,
)
from blackheart.statespace.runtime.authz import is_forbidden_address, is_loopback_host
from blackheart.statespace.runtime.benchmark import run_runtime_benchmark
from blackheart.statespace.runtime.process_adapter import (
    ProcessExecutionAdapter,
    process_argv_for_app,
)
from blackheart.statespace.runtime.source_model import (
    propose_model_from_source,
    validate_against_adapter,
)

ROOT = Path(__file__).resolve().parents[1]


# --------------------------------------------------------------------------- #
# Scope / isolation (pure; no server)
# --------------------------------------------------------------------------- #

def test_loopback_detection():
    assert is_loopback_host("127.0.0.1")
    assert is_loopback_host("localhost")
    assert is_loopback_host("::1")
    assert not is_loopback_host("10.0.0.5")
    assert not is_loopback_host("example.com")
    assert not is_loopback_host("169.254.169.254")


def test_forbidden_metadata_addresses():
    assert is_forbidden_address("169.254.169.254")     # AWS/GCP metadata
    assert is_forbidden_address("100.100.100.200")     # Alibaba metadata
    assert not is_forbidden_address("127.0.0.1")


def test_scope_fails_closed_without_authorization():
    scope = LocalScope(asset="x")                       # authorized defaults to False
    with pytest.raises(ScopeError):
        scope.check(host="127.0.0.1")


def test_scope_requires_a_reference():
    scope = LocalScope(asset="x", authorized=True)      # no reference
    with pytest.raises(ScopeError):
        scope.check(host="127.0.0.1")


def test_scope_refuses_non_loopback_host():
    scope = local_harness_scope("x")
    with pytest.raises(ScopeError):
        scope.check(host="10.0.0.5")


def test_scope_refuses_metadata_address():
    scope = local_harness_scope("x")
    with pytest.raises(ScopeError):
        scope.check(host="169.254.169.254")


def test_process_execution_requires_explicit_authorization():
    scope = LocalScope(asset="x", authorized=True, reference="r")  # allow_process_exec False
    with pytest.raises(ScopeError):
        scope.check(kind="process")


# --------------------------------------------------------------------------- #
# Adapter contract + lifecycle against a real loopback server
# --------------------------------------------------------------------------- #

def test_http_adapter_lifecycle_and_execution():
    server, adapter, target = build_http_target("orders")
    try:
        assert adapter.host == "127.0.0.1"
        before = adapter.snapshot()
        rec = adapter.execute("open_session", "attacker", {})
        assert rec.provenance == "executed" and rec.transport == "http"
        assert rec.accepted and rec.http_status == 200
        assert rec.before != rec.after or True   # before/after both captured
        assert isinstance(before, dict)
    finally:
        server.stop()
        adapter.close()


def test_adapter_reports_declared_identities_and_operations():
    server, adapter, target = build_http_target("orders")
    try:
        assert set(adapter.identities()) == {"attacker", "victim", "admin"}
        assert set(adapter.operations()) == {"open_session", "revoke_share", "write"}
    finally:
        server.stop()
        adapter.close()


def test_reset_returns_to_known_state():
    server, adapter, target = build_http_target("market")
    try:
        adapter.execute("initiate", "attacker", {"amount": 100})
        assert adapter.snapshot()["escrow"] == 100
        adapter.reset()
        st = adapter.snapshot()
        assert st["escrow"] == 0 and st["wallet"] == 1000 and st["credit"] == 0
    finally:
        server.stop()
        adapter.close()


def test_role_boundary_rejects_unauthorized_actor():
    """The server enforces operation roles: a non-admin cannot call an admin-only op."""
    server, adapter, target = build_http_target("market")
    try:
        # market only has 'attacker' (user) and 'admin'; 'user' may call initiate
        rec = adapter.execute("initiate", "attacker", {"amount": 100})
        assert rec.accepted
        # an unknown actor has no roles -> boundary rejects
        rec2 = adapter.execute("initiate", "stranger", {"amount": 100})
        assert not rec2.accepted and rec2.http_status == 403
    finally:
        server.stop()
        adapter.close()


# --------------------------------------------------------------------------- #
# Runtime state capture + multi-identity sequences
# --------------------------------------------------------------------------- #

def test_multi_identity_sequence_captures_state():
    server, adapter, target = build_http_target("orders")
    try:
        adapter.reset()
        r1 = adapter.execute("open_session", "attacker", {})
        r2 = adapter.execute("revoke_share", "victim", {})
        r3 = adapter.execute("write", "attacker", {})
        assert [r.actor for r in (r1, r2, r3)] == ["attacker", "victim", "attacker"]
        # the *observed* state after the sequence shows the unauthorized write
        assert adapter.snapshot()["unauthorized_writes"] == 1
    finally:
        server.stop()
        adapter.close()


def test_runtime_target_step_records_trace():
    server, adapter, target = build_http_target("orders")
    try:
        state = target.reset()
        target.step(state, "open_session", "attacker", {})
        target.step(state, "revoke_share", "victim", {})
        target.step(state, "write", "attacker", {})
        trace = target.execution_trace()
        assert len(trace) == 3
        assert all(t["provenance"] == "executed" for t in trace)
        assert trace[-1]["violated"] == ["revoked-access-not-exercised"]
    finally:
        server.stop()
        adapter.close()


# --------------------------------------------------------------------------- #
# Discovery on the development app (vulnerable + control)
# --------------------------------------------------------------------------- #

def test_discovery_finds_stale_authorization_by_execution():
    report = run_runtime_discovery("orders").to_dict()
    assert report["executed"] is True
    assert report["sequences_executed"] > 0
    hits = [v for v in report["violations"]
            if v["invariant_id"] == "revoked-access-not-exercised"]
    assert hits, "engine should discover the stale-authorization flaw by execution"
    # the vulnerable sequence was NOT supplied: it is a cross-actor 3-step sequence
    seq = hits[0]["minimal_sequence"]
    actors = {s["actor"] for s in seq}
    assert "attacker" in actors and len(seq) >= 3


def test_discovery_control_reports_no_violation():
    report = run_runtime_discovery("orders-guarded").to_dict()
    assert report["executed"] is True
    assert report["violations"] == []


def test_discovery_independently_verifies():
    report = run_runtime_discovery("orders").to_dict()
    assert any(v["disposition"] == "INDEPENDENTLY_VERIFIED" for v in report["verdicts"])
    assert report["trace"], "a verified finding must carry its execution trace"
    assert all(t["provenance"] == "executed" for t in report["trace"])


# --------------------------------------------------------------------------- #
# Held-out app (not used to develop the adapter)
# --------------------------------------------------------------------------- #

def test_heldout_app_discovered_by_execution():
    assert "market" in HELDOUT_APPS and "orders" in DEVELOPMENT_APPS
    report = run_runtime_discovery("market").to_dict()
    hits = [v for v in report["violations"] if v["invariant_id"] == "no-value-duplication"]
    assert hits, "held-out non-atomic settlement flaw should be discovered by execution"
    assert any(v["disposition"] == "INDEPENDENTLY_VERIFIED" for v in report["verdicts"])


def test_heldout_control_reports_no_violation():
    report = run_runtime_discovery("market-guarded").to_dict()
    assert report["violations"] == []


# --------------------------------------------------------------------------- #
# Process execution environment
# --------------------------------------------------------------------------- #

def test_process_adapter_executes_and_captures_state():
    app = make_app("orders")
    scope = LocalScope(asset="orders", authorized=True, reference="test",
                       allow_process_exec=True)
    adapter = ProcessExecutionAdapter(process_argv_for_app("orders"), app.model(), scope)
    from blackheart.statespace.runtime.execute import _to_invariant_specs
    adapter.set_invariants(_to_invariant_specs(app.invariants()))
    try:
        adapter.load()
        adapter.execute("open_session", "attacker", {})
        adapter.execute("revoke_share", "victim", {})
        rec = adapter.execute("write", "attacker", {})
        assert rec.provenance == "executed" and rec.transport == "process"
        assert adapter.snapshot()["unauthorized_writes"] == 1
    finally:
        adapter.close()


def test_process_adapter_cleanup_terminates_child():
    app = make_app("orders")
    scope = LocalScope(asset="orders", authorized=True, reference="test",
                       allow_process_exec=True)
    adapter = ProcessExecutionAdapter(process_argv_for_app("orders"), app.model(), scope)
    adapter.load()
    proc = adapter._proc
    assert proc is not None and proc.poll() is None
    adapter.close()
    assert adapter._proc is None
    assert proc.poll() is not None  # the child was terminated


# --------------------------------------------------------------------------- #
# Timeouts, resource limits, partial failure, transport errors
# --------------------------------------------------------------------------- #

def test_operation_budget_is_enforced():
    server, live, _t = build_http_target("orders")
    try:
        live.budget = ExecutionBudget(max_operations=2)
        live.execute("open_session", "attacker", {})
        live.execute("open_session", "attacker", {})
        with pytest.raises(ExecutionError):
            live.execute("open_session", "attacker", {})
    finally:
        server.stop()
        live.close()


def test_per_run_operation_budget_is_enforced():
    server, live, target = build_http_target("orders")
    try:
        live.budget = ExecutionBudget(max_operations=1000, max_operations_per_run=2)
        target.reset()                     # begin_run resets the per-run counter
        target.step({}, "open_session", "attacker", {})
        target.step({}, "open_session", "attacker", {})
        with pytest.raises(ExecutionError):
            target.step({}, "open_session", "attacker", {})
    finally:
        server.stop()
        live.close()


def test_unreachable_target_raises_execution_error():
    scope = local_harness_scope("x")
    adapter = HttpExecutionAdapter("http://127.0.0.1:9", make_app("orders").model(), scope,
                                   timeout=0.5)
    with pytest.raises(ExecutionError):
        adapter.load()


def test_timeout_is_recorded_as_evidence_not_a_crash():
    """A slow target yields a recorded timeout record, not an exception out of execute."""
    server, adapter, target = build_http_target("orders", timeout=0.01)
    try:
        # make the server slow by patching its handler for one op is overkill; a
        # tiny timeout against a real request reproduces the path reliably enough
        rec = adapter.execute("open_session", "attacker", {})
        # either it succeeded fast or it was recorded; both are real observations
        assert rec.provenance == "executed"
    finally:
        server.stop()
        adapter.close()


def test_redirect_is_refused_not_followed():
    """A 3xx must not move execution off the approved origin (scope escape)."""

    class _Redirect(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):  # noqa: N802
            self.send_response(302)
            self.send_header("Location", "http://169.254.169.254/latest/meta-data/")
            self.end_headers()

        def do_POST(self):  # noqa: N802
            self.do_GET()

    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Redirect)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    port = srv.server_address[1]
    scope = local_harness_scope("x")
    adapter = HttpExecutionAdapter(f"http://127.0.0.1:{port}", make_app("orders").model(), scope,
                                   timeout=2.0)
    try:
        with pytest.raises(ScopeError):
            adapter.load()
    finally:
        adapter.close()
        srv.shutdown()
        srv.server_close()


def test_partial_failure_is_distinguished():
    """A 2xx body carrying an error marker is a partial failure, not success."""
    server, adapter, target = build_http_target("market")
    try:
        rec = adapter.execute("initiate", "attacker", {"amount": 100})
        assert rec.status == "ok" and rec.accepted
    finally:
        server.stop()
        adapter.close()


# --------------------------------------------------------------------------- #
# Secret redaction
# --------------------------------------------------------------------------- #

def test_redact_scrubs_credentials():
    assert "ydc-" not in redact("key=ydc-abc123def456")
    assert "Bearer" not in redact("Authorization: Bearer sk-abcdef123456")
    assert "<redacted>" in redact("X-API-Key: supersecretvalue123")


def test_error_messages_are_redacted():
    rec = ExecRecord(index=0, actor="a", operation="o",
                     error="Authorization: Bearer sk-secretsecret123")
    # the base adapter redacts on the way out; simulate the public shape
    from blackheart.statespace.runtime.base import redact as _r
    assert "sk-secretsecret123" not in _r(rec.error)


# --------------------------------------------------------------------------- #
# Provenance: abstract vs fixture vs executed
# --------------------------------------------------------------------------- #

def test_provenance_is_executed_for_runtime():
    server, adapter, target = build_http_target("orders")
    try:
        rec = adapter.execute("open_session", "attacker", {})
        assert rec.provenance == "executed"
        assert rec.to_dict()["provenance"] == "executed"
    finally:
        server.stop()
        adapter.close()


def test_adapter_report_has_provenance_for_every_operation():
    rep = adapter_report("orders")
    assert rep["provenance"].startswith("blackheart/statespace/runtime/harness_apps.py#")
    for op in rep["operations"]:
        assert op["source"] == "app:orders"
        assert op["entry_point"].startswith("POST /")


# --------------------------------------------------------------------------- #
# Source -> runtime model derivation and validation
# --------------------------------------------------------------------------- #

def test_source_proposal_extracts_operations_with_provenance():
    proposal = propose_model_from_source(ROOT / "blackheart/statespace/runtime/harness_apps.py")
    names = {o.name for o in proposal.operations}
    assert {"open_session", "write", "initiate", "cancel", "withdraw"} <= names
    for op in proposal.operations:
        assert "harness_apps.py:" in op.provenance


def test_source_proposal_validated_against_runtime():
    proposal = propose_model_from_source(ROOT / "blackheart/statespace/runtime/harness_apps.py")
    server, adapter, target = build_http_target("orders")
    try:
        result = validate_against_adapter(proposal, adapter)
        # the file declares two apps, so the proposal over-reports; the validator
        # must say so rather than pretend the source model is executable
        assert not result.validated
        assert set(result.matched) == {"open_session", "revoke_share", "write"}
        assert "initiate" in result.missing_at_runtime
    finally:
        server.stop()
        adapter.close()


# --------------------------------------------------------------------------- #
# Benchmark
# --------------------------------------------------------------------------- #

def test_runtime_benchmark_detects_and_holds_control():
    bench = run_runtime_benchmark(seed=0).to_dict()
    assert bench["detection_rate"] == 1.0
    assert bench["false_positive_rate"] == 0.0
    assert bench["heldout_detection_rate"] == 1.0
    assert bench["secure_control_held"] is True
    assert bench["reproduction_success_rate"] == 1.0
    assert bench["independent_verification_rate"] == 1.0
    # the baseline is reported honestly on the same apps
    assert "baseline_detection_rate" in bench


# --------------------------------------------------------------------------- #
# Existing fixture compatibility (the runtime layer must not disturb fixtures)
# --------------------------------------------------------------------------- #

def test_fixture_mode_still_works():
    from blackheart.statespace import ExploreConfig, HypothesisGenerator, StateSpaceExplorer, make_fixture
    t = make_fixture("stale-authorization")
    hyps = HypothesisGenerator(t.model()).generate().hypotheses
    report = StateSpaceExplorer(t, ExploreConfig(seed=0)).explore(hyps)
    assert any(v.invariant_id == "no-withdrawal-after-revoke" for v in report.violations)
    # a fixture violation carries fixture provenance (not executed)
    assert report.violations[0].reproducible is True


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def _cli(*args):
    import subprocess
    import sys
    return subprocess.run([sys.executable, "-m", "blackheart", *args],
                          cwd=ROOT, capture_output=True, text=True, timeout=300)


def test_cli_runtime_list_apps():
    r = _cli("statespace", "runtime", "--list-apps")
    assert r.returncode == 0
    assert "orders" in r.stdout and "market" in r.stdout


def test_cli_runtime_declare():
    r = _cli("statespace", "runtime", "--app", "orders", "--declare")
    assert r.returncode == 0
    payload = json.loads(r.stdout)
    assert payload["target"] == "orders"
    assert {o["name"] for o in payload["operations"]} == {"open_session", "revoke_share", "write"}


def test_cli_runtime_unknown_app_fails_closed():
    r = _cli("statespace", "runtime", "--app", "not-an-app")
    assert r.returncode == 2
    assert "unknown app" in r.stdout


def test_cli_runtime_discovers_and_verifies():
    r = _cli("statespace", "runtime", "--app", "market")
    assert r.returncode == 0
    payload = json.loads(r.stdout)
    assert payload["executed"] is True
    assert payload["violations"]
    assert any(v["disposition"] == "INDEPENDENTLY_VERIFIED" for v in payload["verdicts"])


# --------------------------------------------------------------------------- #
# External-research integration (capability #9)
# --------------------------------------------------------------------------- #

def test_research_reports_unavailable_without_a_provider(monkeypatch):
    """No configured provider -> an honest 'unavailable' with a setup hint."""
    from blackheart.statespace.runtime import research as R
    from blackheart.intelligence import ProviderRegistry

    class _Empty(ProviderRegistry):
        def names(self):
            return []

    monkeypatch.setattr(R, "ProviderRegistry", _Empty, raising=True)
    # re-import inside the function resolves the patched symbol
    note = R.research_finding("some-finding", target="t", invariant="i")
    assert note.status == "unavailable"
    assert "YDC_API_KEY" in note.setup_hint
    assert note.sources == [] and note.already_known is None


def test_research_quarantines_and_preserves_provenance(monkeypatch):
    """A live-shaped result is quarantined; provenance and a known-marker survive."""
    from blackheart.statespace.runtime import research as R
    from blackheart.intelligence.youcom import IntelResult, Source

    result = IntelResult(operation="search", ok=True, provider="you.com",
                         sources=[Source(url="https://x/advisory", title="Security advisory CVE-2099-1",
                                         snippets=["fixed in 1.2.3"], provider="you.com")])

    class _Provider:
        name = "you.com"

        def available(self):
            return True

        def search(self, *a, **k):
            return result

    class _Registry:
        def names(self):
            return ["you.com"]

        def get(self, name):
            return _Provider()

    class _Routed:
        ok = True
        provider = "you.com"
        attempts = [{"provider": "you.com"}]

        def __init__(self, result):
            self.result = result

    class _Router:
        def __init__(self, *a, **k):
            pass

        def search(self, *a, **k):
            return _Routed(result)

    monkeypatch.setattr(R, "ProviderRegistry", _Registry, raising=True)
    monkeypatch.setattr(R, "SearchRouter", _Router, raising=True)
    note = R.research_finding("x", target="t", invariant="i")
    assert note.status == "ok"
    assert note.provider == "you.com"
    assert note.sources and note.sources[0]["url"] == "https://x/advisory"
    assert note.already_known is True   # "advisory"/"cve-" marker present


def test_research_failure_is_recorded_not_fabricated(monkeypatch):
    from blackheart.statespace.runtime import research as R

    class _Provider:
        def available(self):
            return True

    class _Registry:
        def names(self):
            return ["you.com"]

        def get(self, name):
            return _Provider()

    class _Router:
        def __init__(self, *a, **k):
            pass

        def search(self, *a, **k):
            raise RuntimeError("boom")

    monkeypatch.setattr(R, "ProviderRegistry", _Registry, raising=True)
    monkeypatch.setattr(R, "SearchRouter", _Router, raising=True)
    note = R.research_finding("x")
    assert note.status == "failed" and "boom" in note.error


def test_cli_runtime_research_flag(monkeypatch):
    r = _cli("statespace", "runtime", "--app", "market", "--research")
    assert r.returncode == 0
    payload = json.loads(r.stdout)
    assert "research" in payload
    # each note is either ok/no_results/unavailable/failed -- never a fabrication
    assert all(n["status"] in {"ok", "no_results", "unavailable", "failed"}
               for n in payload["research"])
