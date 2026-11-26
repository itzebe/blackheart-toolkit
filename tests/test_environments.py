"""The core research workflow must run on *more than one* execution backend.

This is the acceptance bar for environment independence. It proves, with real
backends and a real central authorization gate, that:

  * the same probe workflow (build an authorized request, route it to a backend,
    execute, capture an observation) works on **two materially different**
    backends -- a real local source repository and a real HTTP endpoint -- and on a
    simulation backend that drives the existing invariant-engine state machine;
  * removing or disabling one backend does not break a workflow another backend can
    serve;
  * a capability neither backend declares is an explicit ``Unroutable`` limitation,
    never a fabricated result;
  * the **central authorization gate** refuses an unauthorized asset on *every*
    backend, and no backend can be constructed that overrides the gated entry
    point;
  * a simulation is never reported as real execution.

Every test here would fail if the property it checks were removed.
"""

from __future__ import annotations

import http.server
import os
import threading

import pytest

from blackheart.authz import new_record
from blackheart.environments import (
    AdapterError,
    AdapterState,
    AuthorizationDenied,
    Capabilities,
    CapabilityError,
    EnvironmentRegistry,
    ExecutionAdapter,
    HttpServiceAdapter,
    LocalSourceAdapter,
    Observation,
    ProbeRequest,
    ProbeResult,
    SequenceModelAdapter,
    Unroutable,
    validate_declaration,
)
from blackheart.coverage_engine.fixtures import MultiTenantDocs
from blackheart.environments.destination import DestinationPolicy


# --------------------------------------------------------------------------- #
# Helpers: a real authorized asset, and a real local HTTP server
# --------------------------------------------------------------------------- #

def _loopback_adapter(**kw) -> HttpServiceAdapter:
    """An HTTP backend allowed to reach a loopback fixture.

    Loopback is refused by the default policy; a test that runs a real server on
    127.0.0.1 has to say so, which is exactly the operator opt-in the adapter
    records in its audit trail.
    """
    kw.setdefault("policy", DestinationPolicy(allow_private=True))
    return HttpServiceAdapter(**kw)


def _authorized_record(asset: str):
    """A record that genuinely passes the central gate: asset AUTHORIZED + every
    program check True + dated evidence. Mirrors what the operator path records."""
    from blackheart.models import utcnow

    rec = new_record(program="P", platform="direct", target_url="https://x",
                     scope_url="https://x/scope")
    rec.assets[asset] = "AUTHORIZED"
    rec.program_active = True
    rec.safe_harbor = True
    rec.zero_cost = True
    rec.nigerian_eligible = True
    rec.payout_feasible = True
    rec.verified = True
    rec.checked_at = utcnow()
    rec.retrieved_scope = {"source_url": "https://x/scope", "text": "asset is in scope"}
    rec.evidence = ["evidence://scope-capture"]
    return rec


@pytest.fixture
def http_server():
    """A real local HTTP server, so the HTTP backend is genuinely exercised."""
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            body = b'{"ok": true, "route": "/health"}'
            if self.path.startswith("/redirect"):
                self.send_response(302)
                self.send_header("Location", "https://evil.example.net/")
                self.end_headers()
                return
            if self.path.startswith("/big"):
                body = b"x" * 600_000
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):  # noqa: N802  (should never be called by the adapter)
            self.send_response(405)
            self.end_headers()

        def log_message(self, *a):  # silence the test output
            pass

    server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()
    server.server_close()


# --------------------------------------------------------------------------- #
# 1. Two materially different real backends serve the SAME core workflow
# --------------------------------------------------------------------------- #

def test_two_real_backends_run_the_same_probe_workflow(tmp_path, http_server):
    """The identical workflow runs on a local-source backend AND an HTTP backend."""
    (tmp_path / "svc.py").write_text("def handler(): return 1\n", encoding="utf-8")
    (tmp_path / "README.md").write_text("# svc\n", encoding="utf-8")

    local = LocalSourceAdapter(str(tmp_path))
    http_adapter = _loopback_adapter()
    registry = EnvironmentRegistry()
    registry.register(local)
    registry.register(http_adapter)

    for adapter in (local, http_adapter):
        assert adapter.probe().ready, f"{adapter.name} not ready"

    # Backend A: local source, an `inspect` probe.
    rec_a = _authorized_record(str(tmp_path))
    obs_a = local.execute(ProbeRequest(
        target=str(tmp_path),
        target_type="source-repository", operation="inspect", authorization=rec_a,
    ))
    assert obs_a.ok and obs_a.can_support_finding()
    assert obs_a.facts["files_hashed"] >= 2
    assert ".py" in obs_a.facts["source_files_by_ext"]

    # Backend B: HTTP, an `inspect` probe. Same request shape, different backend.
    rec_b = _authorized_record(http_server)
    obs_b = http_adapter.execute(ProbeRequest(
        target=http_server,
        target_type="http-service", operation="inspect", authorization=rec_b,
    ))
    assert obs_b.ok and obs_b.can_support_finding()
    assert obs_b.facts["status"] == 200

    # Both produced a real-execution observation with the same contract fields.
    for obs in (obs_a, obs_b):
        assert obs.evidence_tier == "real-execution"
        assert obs.started_at and obs.duration_s >= 0


# --------------------------------------------------------------------------- #
# 2. Removing one backend does not break an unrelated workflow
# --------------------------------------------------------------------------- #

def test_disabling_one_backend_leaves_the_other_working(tmp_path, http_server):
    local = LocalSourceAdapter(str(tmp_path))
    http_adapter = _loopback_adapter()
    registry = EnvironmentRegistry()
    registry.register(local)
    registry.register(http_adapter)
    registry.probe_all()

    # With both present, an HTTP probe routes to the http backend.
    decision = registry.route("http-service", "inspect")
    assert decision.chosen == "http-service"

    # Disable the http backend: the local workflow must still route.
    registry.disable("http-service")
    assert registry.route("http-service", "inspect").routed is False
    local_decision = registry.route("source-repository", "inspect")
    assert local_decision.chosen == "local-source"
    obs = registry.resolve("source-repository", "inspect").execute(ProbeRequest(
        target=str(tmp_path), target_type="source-repository",
        operation="inspect", authorization=_authorized_record(str(tmp_path)),
    ))
    assert obs.ok


# --------------------------------------------------------------------------- #
# 3. A capability no backend declares is an explicit limitation
# --------------------------------------------------------------------------- #

def test_missing_capability_is_explicit_unroutable_not_fabricated():
    # Only a local-source backend; it declares no `transact` capability.
    reg = EnvironmentRegistry()
    reg.register(LocalSourceAdapter("/workspace/project/blackheart"))
    reg.probe_all()
    with pytest.raises(Unroutable) as exc:
        reg.resolve("evm-chain", "transact")
    assert "no ready backend declares" in str(exc.value)


def test_empty_registry_is_unroutable_not_a_silent_success():
    reg = EnvironmentRegistry()
    with pytest.raises(Unroutable):
        reg.resolve("http-service", "inspect")


# --------------------------------------------------------------------------- #
# 4. The central authorization gate is universal across every backend
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("make", [
    lambda tmp: LocalSourceAdapter(str(tmp)),
    lambda tmp: HttpServiceAdapter(),
    lambda tmp: SequenceModelAdapter(MultiTenantDocs()),
])
def test_unauthorized_asset_is_refused_on_every_backend(make, tmp_path, http_server):
    """No backend executes an asset the central gate has not authorized."""
    adapter = make(tmp_path)
    adapter.probe()
    # No authorization record at all -> refused before any execution.
    with pytest.raises(AuthorizationDenied):
        adapter.execute(ProbeRequest(target="thing", target_type="source-repository",
                                     operation="inspect", authorization=None))
    # A record that does NOT authorize the asset -> refused.
    rec = new_record(program="P", platform="direct", target_url="https://x",
                     scope_url="https://x/s")
    with pytest.raises(AuthorizationDenied):
        adapter.execute(ProbeRequest(target="thing", target_type="source-repository",
                                     operation="inspect", authorization=rec))


def test_out_of_scope_asset_is_refused_even_when_record_otherwise_valid(tmp_path):
    adapter = LocalSourceAdapter(str(tmp_path))
    adapter.probe()
    rec = _authorized_record("some-other-asset")
    rec.assets["thing"] = "OUT_OF_SCOPE"
    with pytest.raises(AuthorizationDenied):
        adapter.execute(ProbeRequest(target="thing", target_type="source-repository",
                                     operation="inspect", authorization=rec))


def test_a_backend_cannot_override_the_gated_entry_point():
    """A subclass that overrides ``execute`` is rejected at construction."""
    class Sneaky(LocalSourceAdapter):
        name = "sneaky"

        def execute(self, request):  # bypasses the gate
            return Observation(adapter="sneaky", target=request.target,
                               operation="x", ok=True, evidence_tier="real-execution")

    with pytest.raises(AdapterError) as exc:
        Sneaky("/tmp")
    assert "override" in str(exc.value).lower()


# --------------------------------------------------------------------------- #
# 5. A simulation is never reported as real execution
# --------------------------------------------------------------------------- #

def test_simulation_cannot_support_a_finding():
    adapter = SequenceModelAdapter(MultiTenantDocs())
    assert adapter.probe().ready
    obs = adapter.execute(ProbeRequest(
        target="docs", target_type="protocol-implementation", operation="inspect",
        authorization=_authorized_record("docs"),
    ))
    assert obs.ok
    assert obs.evidence_tier == "simulation"
    assert obs.can_support_finding() is False


def test_real_backend_can_support_a_finding_but_only_with_evidence_tier_real(tmp_path):
    (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
    adapter = LocalSourceAdapter(str(tmp_path))
    adapter.probe()
    obs = adapter.execute(ProbeRequest(
        target=str(tmp_path), target_type="source-repository", operation="inspect",
        authorization=_authorized_record(str(tmp_path)),
    ))
    assert obs.can_support_finding() is True


# --------------------------------------------------------------------------- #
# 6. Capability declarations are validated, not trusted
# --------------------------------------------------------------------------- #

def test_invalid_capability_declaration_is_rejected():
    class BadReal(ExecutionAdapter):
        name = "bad-real"
        declared = Capabilities(target_types=("source-repository",),
                                operations=("inspect",),  # no 'execute'
                                evidence_tier="real-execution")

        def _probe(self):
            return ProbeResult(state=AdapterState.READY)

        def _execute(self, request, caps):
            return Observation(adapter="bad-real", target=request.target,
                               operation="inspect", ok=True, evidence_tier="real-execution")

    with pytest.raises(AdapterError) as exc:
        BadReal()
    assert "real-execution" in str(exc.value)


def test_validate_declaration_catches_unknown_vocabulary():
    caps = Capabilities(target_types=("quantum-computer",), operations=("teleport",),
                        evidence_tier="real-execution")
    problems = validate_declaration(caps)
    assert any("unknown target type" in p for p in problems)
    assert any("unknown operation" in p for p in problems)


# --------------------------------------------------------------------------- #
# 7. Capability errors are classified, and an unsupported op never runs
# --------------------------------------------------------------------------- #

def test_unsupported_operation_is_a_capability_error(tmp_path):
    adapter = LocalSourceAdapter(str(tmp_path))
    adapter.probe()
    with pytest.raises(CapabilityError):
        adapter.execute(ProbeRequest(
            target=str(tmp_path), target_type="source-repository",
            operation="transact",  # not declared by a local source backend
            authorization=_authorized_record(str(tmp_path)),
        ))


# --------------------------------------------------------------------------- #
# 8. HTTP backend self-imposed safety (beyond the central gate)
# --------------------------------------------------------------------------- #

def test_http_backend_refuses_write_methods(http_server):
    adapter = _loopback_adapter()
    adapter.probe()
    obs = adapter.execute(ProbeRequest(
        target=http_server, target_type="http-service", operation="inspect",
        authorization=_authorized_record(http_server),
        params={"url": http_server, "method": "POST"},
    ))
    assert obs.ok is False
    assert "read-only" in obs.error.lower()


def test_http_backend_refuses_non_http_scheme():
    adapter = HttpServiceAdapter()
    adapter.probe()
    obs = adapter.execute(ProbeRequest(
        target="file:///etc/passwd", target_type="http-service", operation="inspect",
        authorization=_authorized_record("file:///etc/passwd"),
    ))
    assert obs.ok is False
    assert "scheme" in obs.error.lower() and "not http/https" in obs.error.lower()


def test_http_backend_refuses_redirect_to_an_unauthorized_host(http_server):
    """A redirect to another host is re-authorized and refused; it is never a hop."""
    adapter = _loopback_adapter()
    adapter.probe()
    obs = adapter.execute(ProbeRequest(
        target=http_server, target_type="http-service", operation="inspect",
        authorization=_authorized_record(http_server),
        params={"url": http_server + "/redirect"},
    ))
    # The redirect is refused as an authorization decision: no request reaches
    # evil.example, and the outcome is BLOCKED rather than a successful probe.
    assert obs.ok is False
    assert obs.facts["blocked"] is True
    assert "evil.example.net" in obs.error
    assert obs.facts["egress"]["hops"][0]["status"] == 302


def test_http_backend_host_allowlist_narrows_scope():
    adapter = HttpServiceAdapter(allow_hosts=("allowed.example",))
    adapter.probe()
    obs = adapter.execute(ProbeRequest(
        target="http://notallowed.example", target_type="http-service",
        operation="inspect", authorization=_authorized_record("http://notallowed.example"),
    ))
    assert obs.ok is False
    assert "allowlist" in obs.error.lower()


# --------------------------------------------------------------------------- #
# 9. Local-source command allowlist: no arbitrary command execution
# --------------------------------------------------------------------------- #

def test_local_backend_refuses_command_outside_allowlist(tmp_path):
    adapter = LocalSourceAdapter(str(tmp_path))
    adapter.probe()
    obs = adapter.execute(ProbeRequest(
        target=str(tmp_path), target_type="source-repository", operation="execute",
        authorization=_authorized_record(str(tmp_path)),
        params={"argv": ["rm", "-rf", "/"]},
    ))
    assert obs.ok is False
    assert "allowlist" in obs.error.lower()


def test_local_backend_requires_argv_list_not_shell_string(tmp_path):
    adapter = LocalSourceAdapter(str(tmp_path))
    adapter.probe()
    obs = adapter.execute(ProbeRequest(
        target=str(tmp_path), target_type="source-repository", operation="execute",
        authorization=_authorized_record(str(tmp_path)),
        params={"argv": "python3 -c 'print(1)'"},
    ))
    assert obs.ok is False
    assert "list of strings" in obs.error.lower()


def test_local_backend_runs_an_allowed_command(tmp_path):
    (tmp_path / "test_ok.py").write_text("def test_ok():\n    assert True\n", encoding="utf-8")
    adapter = LocalSourceAdapter(str(tmp_path))
    adapter.probe()
    obs = adapter.execute(ProbeRequest(
        target=str(tmp_path), target_type="source-repository", operation="execute",
        authorization=_authorized_record(str(tmp_path)),
        params={"argv": ["python3", "-m", "pytest", "-q"]}, timeout_s=120,
    ))
    assert "exit_code" in obs.facts
    assert obs.facts["argv"][0] == "python3"


# --------------------------------------------------------------------------- #
# 10. Sequence-model backend reaches a planted defect (real execution of a model)
# --------------------------------------------------------------------------- #

def test_sequence_backend_reaches_planted_idor():
    adapter = SequenceModelAdapter(MultiTenantDocs())
    assert adapter.probe().ready
    obs = adapter.execute(ProbeRequest(
        target="docs", target_type="protocol-implementation", operation="sequence",
        authorization=_authorized_record("docs"),
        sequence=(("read", {"actor": "alice", "params": {"doc": "bob:secret"}}),),
    ))
    assert obs.ok
    assert "ownership" in obs.facts["violated_invariants"]


def test_sequence_backend_reports_no_violation_on_guarded_twin():
    from blackheart.coverage_engine.fixtures import GuardedMultiTenantDocs

    adapter = SequenceModelAdapter(GuardedMultiTenantDocs())
    assert adapter.probe().ready
    # A legitimate sequence: alice reads her own document. No violation, no raise.
    obs = adapter.execute(ProbeRequest(
        target="docs", target_type="protocol-implementation", operation="sequence",
        authorization=_authorized_record("docs"),
        sequence=(("read", {"actor": "alice", "params": {"doc": "alice:secret"}}),),
    ))
    assert obs.ok
    assert obs.facts["violated_invariants"] == []


def test_sequence_backend_reports_a_refused_step_as_not_ok():
    """The guarded twin refuses a cross-tenant read; that is an honest non-ok step,
    not a silent success and not a fabricated violation."""
    from blackheart.coverage_engine.fixtures import GuardedMultiTenantDocs

    adapter = SequenceModelAdapter(GuardedMultiTenantDocs())
    adapter.probe()
    obs = adapter.execute(ProbeRequest(
        target="docs", target_type="protocol-implementation", operation="sequence",
        authorization=_authorized_record("docs"),
        sequence=(("read", {"actor": "alice", "params": {"doc": "bob:secret"}}),),
    ))
    assert obs.ok is False
    assert "permissionerror" in obs.error.lower()


# --------------------------------------------------------------------------- #
# 11. Missing tool / unavailable environment reported honestly
# --------------------------------------------------------------------------- #

def test_missing_repository_is_missing_state(tmp_path):
    adapter = LocalSourceAdapter(str(tmp_path / "does-not-exist"))
    result = adapter.probe()
    assert result.state is AdapterState.MISSING
    assert adapter.state is AdapterState.MISSING


def test_unreachable_http_endpoint_is_a_limitation_not_a_crash():
    adapter = _loopback_adapter(timeout_s=2)
    adapter.probe()
    obs = adapter.execute(ProbeRequest(
        # A reserved-for-documentation address that cannot be connected to.
        target="http://127.0.0.1:1", target_type="http-service",
        operation="inspect", authorization=_authorized_record("http://127.0.0.1:1"),
    ))
    assert obs.ok is False
    assert "request failed" in obs.error.lower()


# --------------------------------------------------------------------------- #
# 12. The capability matrix is honest
# --------------------------------------------------------------------------- #

def test_capability_matrix_reports_states_and_tiers(tmp_path, http_server):
    reg = EnvironmentRegistry()
    reg.register(LocalSourceAdapter(str(tmp_path)))
    reg.register(HttpServiceAdapter())
    reg.register(SequenceModelAdapter(MultiTenantDocs()))
    reg.probe_all()
    matrix = reg.capability_matrix()
    assert set(matrix) == {"local-source", "http-service", "sequence-model"}
    assert matrix["local-source"]["capabilities"]["evidence_tier"] == "real-execution"
    assert matrix["sequence-model"]["capabilities"]["evidence_tier"] == "simulation"
    # A real-execution backend exists, so the registry can prove real execution.
    assert reg.can_prove_real_execution() is True


def test_registry_cannot_prove_real_execution_with_only_a_simulation():
    reg = EnvironmentRegistry()
    reg.register(SequenceModelAdapter(MultiTenantDocs()))
    reg.probe_all()
    assert reg.can_prove_real_execution() is False


# --------------------------------------------------------------------------- #
# Security regressions: an authorized asset must not be a stepping stone
# --------------------------------------------------------------------------- #

def test_http_backend_refuses_to_fetch_a_host_other_than_the_authorized_asset():
    """SSRF / scope bypass: the gate authorizes `asset_id`, but the request is
    issued to `params['url']`. A probe for an authorized host must not reach a
    different one, or the authorized asset becomes a stepping stone."""
    adapter = HttpServiceAdapter()
    adapter.probe()
    obs = adapter.execute(ProbeRequest(
        target="https://app.example.com", target_type="http-service",
        operation="inspect",
        authorization=_authorized_record("https://app.example.com"),
        params={"url": "http://127.0.0.1:9/internal"},
    ))
    assert obs.ok is False
    assert "may not widen scope" in obs.error


def test_http_backend_allows_a_url_on_the_authorized_host(http_server):
    adapter = _loopback_adapter()
    adapter.probe()
    obs = adapter.execute(ProbeRequest(
        target=http_server, target_type="http-service", operation="inspect",
        authorization=_authorized_record(http_server), params={"url": http_server},
    ))
    assert obs.ok is True
    assert obs.facts["status"] == 200


def test_local_backend_refuses_an_interpreter_code_injection_flag(tmp_path):
    """A bare `python3` allowlist prefix must not mean `python3 -c <anything>`."""
    (tmp_path / "x.py").write_text("print(1)", encoding="utf-8")
    adapter = LocalSourceAdapter(str(tmp_path))
    adapter.probe()
    obs = adapter.execute(ProbeRequest(
        target=str(tmp_path), target_type="source-repository", operation="execute",
        authorization=_authorized_record(str(tmp_path)),
        params={"argv": ["python3", "-c", "print('RCE')"]},
    ))
    assert obs.ok is False
    assert "not permitted" in obs.error


def test_local_backend_withholds_inherited_secrets_from_the_subprocess(tmp_path):
    """The target runs its own code; it must not be able to read the operator's
    API keys out of the inherited environment."""
    (tmp_path / "x.py").write_text("print(1)", encoding="utf-8")
    adapter = LocalSourceAdapter(str(tmp_path))
    adapter.probe()
    os.environ["BLACKHEART_FAKE_SECRET"] = "super-secret-value"
    try:
        obs = adapter.execute(ProbeRequest(
            target=str(tmp_path), target_type="source-repository", operation="execute",
            authorization=_authorized_record(str(tmp_path)),
            params={"argv": ["python3", "-m", "pytest", "-q", "--collect-only"]},
        ))
    finally:
        os.environ.pop("BLACKHEART_FAKE_SECRET", None)
    assert "super-secret-value" not in obs.raw
    assert "super-secret-value" not in str(obs.facts)


def test_local_backend_still_runs_a_permitted_test_command(tmp_path):
    (tmp_path / "test_ok.py").write_text("def test_it():\n    assert True\n", encoding="utf-8")
    adapter = LocalSourceAdapter(str(tmp_path))
    adapter.probe()
    obs = adapter.execute(ProbeRequest(
        target=str(tmp_path), target_type="source-repository", operation="execute",
        authorization=_authorized_record(str(tmp_path)),
        params={"argv": ["python3", "-m", "pytest", "-q"]},
    ))
    assert obs.ok is True, obs.error
    assert "1 passed" in obs.raw or "passed" in obs.raw
