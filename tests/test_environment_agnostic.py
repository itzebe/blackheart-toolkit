"""End-to-end: the SAME research workflow runs on inputs it was never built against.

This is the "environment-agnostic research" acceptance test. It exercises one
pipeline -- a target profile -> applicability -> hypotheses -> routing -> execution
adapter -> observation -> coverage ledger -- against three genuinely different
targets:

  * a local source repository (a real filesystem target),
  * an HTTP service (a real network target),
  * an invariant-engine state machine (a simulation target).

The point is that none of these required a change to the coverage engine or the
controller: the engine is target-agnostic and the execution environment is a
pluggable backend behind the central authorization gate.
"""

from __future__ import annotations

import http.server
import threading

import pytest

from blackheart.coverage_engine import (
    ControllerConfig,
    ResearchController,
    StopReason,
    Taxonomy,
)
from blackheart.coverage_engine.fixtures import MultiTenantDocs
from blackheart.environments.destination import DestinationPolicy
from blackheart.environments import (
    EnvironmentRegistry,
    HttpServiceAdapter,
    LocalSourceAdapter,
    ProbeRequest,
    SequenceModelAdapter,
)
from blackheart.objectives import TargetProfile

from tests.test_environments import _authorized_record


@pytest.fixture
def http_server():
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            body = b'{"status":"ok"}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()
    server.server_close()


def _controller() -> ResearchController:
    return ResearchController(Taxonomy(), ControllerConfig(max_probes=40))


# --------------------------------------------------------------------------- #
# The same controller, unchanged, on a local source repository
# --------------------------------------------------------------------------- #

def test_workflow_on_local_source_target(tmp_path):
    (tmp_path / "vault.sol").write_text("contract Vault {}", encoding="utf-8")
    (tmp_path / "Vault.sol").write_text("// logic\n", encoding="utf-8")
    profile = TargetProfile(name="vault-repo", kind="source-repository",
                            assets=["vault.sol"], entry_points=["deposit", "withdraw"],
                            roles=["owner", "user"], notes="solidity vault, share accounting")

    adapter = LocalSourceAdapter(str(tmp_path))
    registry = EnvironmentRegistry()
    registry.register(adapter)
    assert adapter.probe().ready

    seen: list[str] = []

    def probe(class_key, hyp_id, strategy):
        # Route a real inspect probe to the local backend through the registry.
        a = registry.resolve("source-repository", "inspect")
        obs = a.execute(ProbeRequest(
            target=str(tmp_path), target_type="source-repository", operation="inspect",
            authorization=_authorized_record(str(tmp_path)),
        ))
        seen.append(obs.evidence_tier)
        from blackheart.coverage_engine import ProbeOutcome
        return ProbeOutcome(ok=False, failure_kind="strategy-invalid",
                            failure_reason="static inspection only",
                            evidence_tier=obs.evidence_tier)

    result = _controller().run(profile, probe=probe)
    assert seen and seen[0] == "real-execution"
    assert result.probes > 0
    assert result.stop_reason in (StopReason.STRATEGY_SPACE_EXHAUSTED,
                                  StopReason.BUDGET_EXHAUSTED)


# --------------------------------------------------------------------------- #
# The same controller, unchanged, on an HTTP service
# --------------------------------------------------------------------------- #

def test_workflow_on_http_target(http_server):
    profile = TargetProfile(name="api", kind="http-service",
                            assets=[http_server], entry_points=["GET /health"],
                            notes="REST API, token authentication, JSON input")

    # A loopback fixture is a private destination; the operator opt-in is explicit.
    adapter = HttpServiceAdapter(policy=DestinationPolicy(allow_private=True))
    registry = EnvironmentRegistry()
    registry.register(adapter)
    assert adapter.probe().ready

    tiers: list[str] = []

    def probe(class_key, hyp_id, strategy):
        a = registry.resolve("http-service", "inspect")
        obs = a.execute(ProbeRequest(
            target=http_server, target_type="http-service", operation="inspect",
            authorization=_authorized_record(http_server),
            params={"url": http_server},
        ))
        assert obs.facts["status"] == 200
        tiers.append(obs.evidence_tier)
        from blackheart.coverage_engine import ProbeOutcome
        return ProbeOutcome(ok=False, failure_kind="strategy-invalid",
                            evidence_tier=obs.evidence_tier)

    result = _controller().run(profile, probe=probe)
    assert set(tiers) == {"real-execution"}
    assert result.probes > 0


# --------------------------------------------------------------------------- #
# The same controller, unchanged, on a simulation state machine
# --------------------------------------------------------------------------- #

def test_workflow_on_simulation_target():
    profile = TargetProfile(name="docs", kind="protocol-implementation",
                            entry_points=["read", "become"], roles=["admin", "user"],
                            notes="document store with ownership and roles")

    adapter = SequenceModelAdapter(MultiTenantDocs())
    registry = EnvironmentRegistry()
    registry.register(adapter)
    assert adapter.probe().ready

    def probe(class_key, hyp_id, strategy):
        from blackheart.coverage_engine import ProbeOutcome
        if class_key != "access-control":
            return ProbeOutcome(ok=False, failure_kind="strategy-invalid")
        a = registry.resolve("protocol-implementation", "sequence")
        obs = a.execute(ProbeRequest(
            target="docs", target_type="protocol-implementation", operation="sequence",
            authorization=_authorized_record("docs"),
            sequence=(("read", {"actor": "alice", "params": {"doc": "bob:secret"}}),),
        ))
        if obs.facts.get("violated_invariants"):
            return ProbeOutcome(ok=True, evidence_tier=obs.evidence_tier,
                                reproduced=True,
                                evidence=[f"{hyp_id}:sim"])
        return ProbeOutcome(ok=False, failure_kind="hypothesis-disproven")

    result = _controller().run(profile, probe=probe)
    assert result.reproductions >= 1
    # The reproduction is simulation-tier, never promoted to real execution.
    assert result.record.classes["access-control"].best_evidence_tier == "simulation"


# --------------------------------------------------------------------------- #
# One registry, three backends: routing picks the right one per target
# --------------------------------------------------------------------------- #

def test_one_registry_routes_three_target_kinds(tmp_path, http_server):
    (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
    registry = EnvironmentRegistry()
    registry.register(LocalSourceAdapter(str(tmp_path)))
    registry.register(HttpServiceAdapter())
    registry.register(SequenceModelAdapter(MultiTenantDocs()))
    registry.probe_all()

    assert registry.resolve("source-repository", "inspect").name == "local-source"
    assert registry.resolve("http-service", "inspect").name == "http-service"
    assert registry.resolve("protocol-implementation", "sequence").name == "sequence-model"
    # No backend declares an EVM transaction capability -> explicit limitation.
    from blackheart.environments import Unroutable
    with pytest.raises(Unroutable):
        registry.resolve("evm-chain", "transact")


# --------------------------------------------------------------------------- #
# The pipeline is target-agnostic: same code path, different targets
# --------------------------------------------------------------------------- #

def test_coverage_ledger_shape_is_identical_across_target_kinds(tmp_path, http_server):
    (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
    kinds = [
        TargetProfile(name="repo", kind="source-repository", assets=["a.py"],
                      entry_points=["run"], notes="python repo with auth"),
        TargetProfile(name="api", kind="http-service", assets=[http_server],
                      entry_points=["GET /"], notes="http api with roles"),
    ]
    shapes = []
    for profile in kinds:
        result = _controller().run(profile, probe=None)
        s = result.summary()
        shapes.append((set(s["counts"]), s["verdict"]))
    # The ledger has the same structure regardless of the target kind.
    assert shapes[0][0] == shapes[1][0]
