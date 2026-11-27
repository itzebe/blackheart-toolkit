"""The local devnet backend is bounded to one compose file and a fixed verb set."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from blackheart.authz import new_record
from blackheart.environments import (
    AdapterState,
    AuthorizationDenied,
    DevnetAdapter,
    ProbeRequest,
    default_registry,
)
from blackheart.environments.devnet import compose_services

COMPOSE = """\
services:
  chain:
    image: ghcr.io/example/chain:v1
    ports:
      - "26657:26657"
  faucet:
    image: ghcr.io/example/faucet:v1
    ports:
      - "8000:8000"
"""


def _authorized_record(asset: str):
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
def compose_file(tmp_path: Path) -> Path:
    path = tmp_path / "docker-compose.yml"
    path.write_text(COMPOSE, encoding="utf-8")
    return path


@pytest.fixture
def fake_docker(tmp_path: Path, monkeypatch):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    docker = bindir / "docker"
    docker.write_text(
        "#!/bin/sh\n"
        "if [ \"$1\" = compose ] && [ \"$2\" = version ]; then\n"
        "  echo 'Docker Compose version v2.29.0'\n"
        "  exit 0\n"
        "fi\n"
        "echo \"fake docker: $*\"\n"
        "exit 0\n",
        encoding="utf-8",
    )
    docker.chmod(0o755)
    monkeypatch.setenv("PATH", str(bindir) + os.pathsep + os.environ.get("PATH", ""))
    return docker


def test_compose_services_reads_names_images_and_ports(compose_file: Path):
    services = compose_services(compose_file.read_text(encoding="utf-8"))
    assert set(services) == {"chain", "faucet"}
    assert services["chain"]["image"] == "ghcr.io/example/chain:v1"
    assert services["chain"]["ports"] == [26657]


def test_probe_is_missing_without_docker(compose_file: Path, monkeypatch):
    monkeypatch.setenv("PATH", str(compose_file.parent))
    adapter = DevnetAdapter(compose_file)
    result = adapter.probe()
    assert result.state is AdapterState.MISSING
    assert "docker" in result.detail


def test_probe_confirms_a_real_compose_file(compose_file: Path, fake_docker):
    adapter = DevnetAdapter(compose_file)
    result = adapter.probe()
    assert result.state is AdapterState.READY
    assert result.confirmed is not None
    assert result.confirmed.tools["docker"] is True
    assert result.confirmed.evidence_tier == "real-execution"
    assert any("exec disabled" in item for item in result.confirmed.limitations)


def test_inspect_is_gated_and_reports_services(compose_file: Path, fake_docker):
    adapter = DevnetAdapter(compose_file)
    adapter.probe()
    request = ProbeRequest(
        target="local:devnet", target_type="non-evm-chain", operation="inspect",
        authorization=_authorized_record("local:devnet"),
    )
    observation = adapter.execute(request)
    assert observation.ok
    assert observation.facts["services"]["chain"]["image"].endswith("chain:v1")
    assert observation.can_support_finding() is True


def test_inspect_without_authorization_is_refused(compose_file: Path, fake_docker):
    adapter = DevnetAdapter(compose_file)
    adapter.probe()
    with pytest.raises(AuthorizationDenied):
        adapter.execute(ProbeRequest(
            target="local:devnet", target_type="non-evm-chain", operation="inspect",
        ))


def test_exec_is_opt_in_and_never_a_shell(compose_file: Path, fake_docker):
    adapter = DevnetAdapter(compose_file)
    adapter.probe()
    request = ProbeRequest(
        target="local:devnet", target_type="non-evm-chain", operation="execute",
        authorization=_authorized_record("local:devnet"),
        params={"action": "exec", "service": "chain", "argv": ["true"]},
    )
    observation = adapter.execute(request)
    assert not observation.ok
    assert "disabled" in observation.error

    enabled = DevnetAdapter(compose_file, allow_exec=True)
    enabled.probe()
    observation = enabled.execute(request)
    assert observation.ok
    assert observation.facts["service"] == "chain"


def test_registry_routes_a_non_evm_probe_to_the_devnet(compose_file: Path, fake_docker):
    reg = default_registry(devnet_compose=str(compose_file))
    reg.probe_all()
    decision = reg.route("non-evm-chain", "execute")
    assert decision.routed
    assert decision.chosen == "local-devnet"
