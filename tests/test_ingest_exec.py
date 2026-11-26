"""Execution-grade evidence for an ingest --synthesize witness: gated, honest, never faked."""

from __future__ import annotations

import json
import subprocess

from blackheart.cli import main
from blackheart.ingest.execute import (
    contract_path_for, execute_witness, read_solidity_sources,
)
from blackheart.toolchain.enforce import self_test_record

SOURCE = """pragma solidity ^0.8.0;
contract C {
    address public owner;
    function setOwner(address a) external { owner = a; }
}
"""


class _Cert:
    """A minimal stand-in for a CertifyResult carrying one renderable witness."""

    def __init__(self, invariant_id: str = "authorization:owner") -> None:
        self.violations = [{
            "invariant_id": invariant_id,
            "minimal_sequence": [{
                "index": 0, "actor": "attacker", "action": "setOwner",
                "params": {"newOwner": "attacker"},
            }],
        }]


def _passing_runner(cmd, cwd, timeout):
    payload = {"test/Poc.t.sol:T": {"passed": [{"name": "test_certificate_witness()"}]}}
    return subprocess.CompletedProcess(cmd, 0, json.dumps(payload), "")


def _failing_runner(cmd, cwd, timeout):
    payload = {"test/Poc.t.sol:T": {"passed": [], "failed": [
        {"name": "test_certificate_witness()"}]}}
    return subprocess.CompletedProcess(cmd, 1, json.dumps(payload), "")


def _files() -> dict[str, str]:
    return {"C.sol": SOURCE}


def test_witness_runs_and_reports_pass_without_touching_the_verdict():
    outcome = execute_witness(
        _Cert(), contract="C", contract_path="C.sol", files=_files(),
        compatibility=self_test_record(), repository="blackheart",
        runner=_passing_runner,
    )
    assert outcome["status"] == "PASS"
    # The model verdict is not changed here; execution evidence is separate.
    assert "verdict" not in outcome


def test_a_failing_forge_run_is_reported_as_fail_not_pass():
    outcome = execute_witness(
        _Cert(), contract="C", contract_path="C.sol", files=_files(),
        compatibility=self_test_record(), repository="blackheart",
        runner=_failing_runner,
    )
    assert outcome["status"] == "FAIL"


def test_no_compatibility_record_blocks_before_the_runner_is_called():
    def runner(*_args):
        raise AssertionError("the runner must not be called without a record")

    outcome = execute_witness(
        _Cert(), contract="C", contract_path="C.sol", files=_files(),
        compatibility=None, repository="blackheart", runner=runner,
    )
    assert outcome["status"] == "BLOCKED"
    assert "no compatibility record" in outcome["detail"]


def test_a_non_renderable_invariant_is_unsupported_and_does_not_run():
    def runner(*_args):
        raise AssertionError("an unsupported invariant must not reach the runner")

    outcome = execute_witness(
        _Cert("custom:whatever"), contract="C", contract_path="C.sol", files=_files(),
        compatibility=self_test_record(), repository="blackheart", runner=runner,
    )
    assert outcome["status"] == "UNSUPPORTED"


def test_no_witness_is_skipped():
    class _Empty:
        violations = []

    outcome = execute_witness(
        _Empty(), contract="C", contract_path="C.sol", files=_files(),
        compatibility=self_test_record(), repository="blackheart",
    )
    assert outcome["status"] == "SKIPPED"


def test_read_solidity_sources_and_contract_path(tmp_path):
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "C.sol").write_text(SOURCE)
    files = read_solidity_sources(tmp_path)
    assert "sub/C.sol" in files
    assert contract_path_for(str(tmp_path / "sub" / "C.sol"), tmp_path) == "sub/C.sol"


def test_cli_exec_without_compatibility_exits_2(tmp_path, capsys):
    (tmp_path / "C.sol").write_text(SOURCE)
    rc = main(["ingest", str(tmp_path), "--synthesize", "--exec"])
    assert rc == 2
    assert "needs --compatibility" in capsys.readouterr().err
