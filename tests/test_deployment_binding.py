"""One command joins deployment truth, verified source, component and record."""

from __future__ import annotations

import json
import shutil

import pytest

from blackheart.ingest.deployment import bind_deployment, write_binding
from blackheart.watch.source import SourceBundle

SOURCE = """pragma solidity ^0.8.20;

contract Vault {
    address public owner;

    constructor() { owner = msg.sender; }

    function setOwner(address next) external { owner = next; }
}
"""


class _Chain:
    def call(self, method: str, params: list) -> str:
        return {
            "eth_chainId": "0x1",
            "eth_blockNumber": "0x10",
            "eth_getCode": "0x6000",
            "eth_getStorageAt": "0x0",
        }[method]


class _Source:
    def __init__(self, files: dict[str, str] | None = None, status: str = "verified"):
        self.files = files if files is not None else {"src/Vault.sol": SOURCE}
        self.status = status

    def fetch(self, chain_id: int, address: str) -> SourceBundle:
        return SourceBundle(
            chain_id=chain_id, address=address, status=self.status,
            ok=self.status == "verified", files=self.files,
            compiler="0.8.20", compiler_version="0.8.20",
        )


def _bind(**overrides):
    kwargs = dict(
        repository="example/protocol", commit="a" * 40, rpc_url="http://fake",
        client=_Chain(), source_client=_Source(),
        recompile=lambda files, compiler: bytes.fromhex("6000"),
        smoke_test="passed",
    )
    kwargs.update(overrides)
    return bind_deployment(
        "0x0000000000000000000000000000000000000001", 1, **kwargs)


def test_a_verified_deployment_emits_a_complete_record():
    binding = _bind()
    assert binding.bound, binding.reason
    assert binding.component == "Vault"
    assert binding.record["repository"] == "example/protocol"
    assert binding.record["commit"] == "a" * 40
    assert binding.record["smoke_test"] == "passed"
    assert binding.decision["admitted"] is True


def test_a_missing_commit_blocks_before_any_chain_call():
    binding = _bind(commit="")
    assert binding.status == "BLOCKED"
    assert "commit" in binding.missing


def test_a_source_that_is_not_runtime_bound_blocks():
    class Unbound(_Source):
        def fetch(self, chain_id: int, address: str) -> SourceBundle:
            bundle = super().fetch(chain_id, address)
            bundle.status = "unverified"
            bundle.ok = False
            return bundle

    binding = _bind(source_client=Unbound())
    assert binding.status == "BLOCKED"
    assert "source_bound" in binding.missing


def test_a_failed_smoke_test_blocks_the_record():
    binding = _bind(smoke_test="failed")
    assert binding.status == "BLOCKED"
    assert "smoke_test" in binding.missing
    assert "smoke test is failed" in binding.reason


def test_an_unknown_component_blocks():
    binding = _bind(component="Missing")
    assert binding.status == "BLOCKED"
    assert "component" in binding.missing


def test_write_binding_writes_a_loadable_record(tmp_path):
    binding = _bind()
    path = tmp_path / "binding.json"
    write_binding(binding, str(path))
    payload = json.loads(path.read_text())
    assert payload["bound"] is True
    record = json.loads(path.with_suffix(".record.json").read_text())
    assert record["target_component"] == "Vault"


@pytest.mark.skipif(shutil.which("forge") is None, reason="forge is not installed")
def test_automatic_smoke_test_compiles_the_verified_source():
    binding = _bind(smoke_test="auto")
    assert binding.bound, binding.reason
    assert binding.smoke_test == "passed"
