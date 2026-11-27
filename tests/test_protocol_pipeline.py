"""The source loop composes contracts, traces the owner, and renders a PoC."""

from __future__ import annotations

import hashlib
import json
import subprocess
from dataclasses import replace

import pytest

from blackheart.engines.solidity.base import resolve_tool
from blackheart.models import AttackStep
from blackheart.pipeline import PipelineConfig, run_source_pipeline
from blackheart.pocgen import execute_source_poc, render_protocol_poc
from blackheart.toolchain.enforce import self_test_record

PUBLIC_VULNERABLE = """
contract Token {
    mapping(address => uint) public balance;
    uint public totalSupply;
    function mint(uint amount) external { balance[msg.sender] += amount; }
}
contract Vault {
    mapping(address => uint) public shares;
    uint public totalShares;
    function deposit(uint amount) external {
        shares[msg.sender] += amount;
        totalShares += amount;
    }
}
"""

PUBLIC_CONTROL = """
contract Token {
    mapping(address => uint) public balance;
    uint public totalSupply;
    function mint(uint amount) external {
        balance[msg.sender] += amount;
        totalSupply += amount;
    }
}
contract Vault {
    mapping(address => uint) public shares;
    uint public totalShares;
    function deposit(uint amount) external {
        shares[msg.sender] += amount;
        totalShares += amount;
    }
}
"""

VULNERABLE = """
contract Token {
    mapping(address => uint) balance;
    uint totalSupply;
    function mint(uint amount) external { balance[msg.sender] += amount; }
}
contract Vault {
    mapping(address => uint) shares;
    uint totalShares;
    function deposit(uint amount) external {
        shares[msg.sender] += amount;
        totalShares += amount;
    }
}
"""

CONTROL = """
contract Token {
    mapping(address => uint) balance;
    uint totalSupply;
    function mint(uint amount) external {
        balance[msg.sender] += amount;
        totalSupply += amount;
    }
}
contract Vault {
    mapping(address => uint) shares;
    uint totalShares;
    function deposit(uint amount) external {
        shares[msg.sender] += amount;
        totalShares += amount;
    }
}
"""


def _write(tmp_path, name: str, source: str):
    path = tmp_path / name
    path.write_text(source, encoding="utf-8")
    return path


def test_protocol_pipeline_composes_and_traces_the_owning_contract(tmp_path):
    source = _write(tmp_path, "Protocol.sol", VULNERABLE)
    result = run_source_pipeline(PipelineConfig(
        source_path=str(source), protocol=True, max_depth=2,
        write_finding=False, evidence_root=str(tmp_path / "evidence"),
    ))
    assert result.status == "REPRODUCED", result.to_dict()
    assert result.invariant_id.startswith("Token:conservation:")
    assert result.model["protocol"]["contracts"]
    assert result.model_coverage["complete"] is True
    assert result.source_trace
    assert all(frame["mapped"] for frame in result.source_trace)
    assert {frame["contract"] for frame in result.source_trace} == {"Token"}


def test_a_guarded_protocol_control_can_confirm_the_witness(tmp_path):
    source = _write(tmp_path, "Protocol.sol", VULNERABLE)
    control = _write(tmp_path, "Control.sol", CONTROL)
    result = run_source_pipeline(PipelineConfig(
        source_path=str(source), protocol=True,
        control_source=str(control), max_depth=2,
        in_scope=True, authorization_gate_passed=True,
        write_finding=True,
        findings_root=str(tmp_path / "findings"),
        evidence_root=str(tmp_path / "evidence"),
        reports_root=str(tmp_path / "reports"),
    ))
    assert result.status == "VERIFIED", result.to_dict()
    assert result.finding_status == "CONFIRMED"
    assert result.confirmed
    assert result.verification["checks"]["control_integrity"]["passed"] is True


def test_protocol_poc_deploys_each_called_contract_and_routes_the_step():
    from blackheart.ingest.solidity import scan_source

    surfaces = {c.name: c for c in scan_source(VULNERABLE, "Protocol.sol")}
    steps = [AttackStep(index=0, actor="attacker", action="Vault.deposit",
                        params={"amount": 1})]
    candidate = render_protocol_poc(
        {"Protocol.sol": VULNERABLE}, surfaces, steps,
        "Token:conservation:balance-totalSupply")
    assert candidate.rendered
    assert candidate.test_name == "test_protocol_witness"
    assert "Token token = new Token();" in candidate.solidity
    assert "Vault vault = new Vault();" in candidate.solidity
    assert "vault.deposit(1);" in candidate.solidity
    assert "token.balance(attacker)" in candidate.solidity


def test_the_protocol_pipeline_is_reachable_from_the_cli(tmp_path):
    from blackheart.cli import main

    source = _write(tmp_path, "Protocol.sol", VULNERABLE)
    code = main([
        "pipeline", "--source", str(source), "--protocol",
        "--max-depth", "2", "--no-finding",
        "--evidence", str(tmp_path / "evidence"), "--json",
    ])
    assert code == 0


def test_a_protocol_poc_runs_under_the_gate():
    from blackheart.ingest.solidity import scan_source

    surfaces = {c.name: c for c in scan_source(VULNERABLE, "Protocol.sol")}
    steps = [AttackStep(index=0, actor="attacker", action="Vault.deposit",
                        params={"amount": 1})]
    candidate = render_protocol_poc(
        {"Protocol.sol": VULNERABLE}, surfaces, steps,
        "Token:conservation:balance-totalSupply")

    def runner(cmd, cwd, timeout):
        payload = {"test/Poc.t.sol:BlackheartProtocolTest": {
            "passed": ["test_protocol_witness()"],
        }}
        return subprocess.CompletedProcess(cmd, 0, json.dumps(payload), "")

    outcome = execute_source_poc(
        candidate, compatibility=self_test_record(),
        target_component="ingest:protocol", repository="blackheart",
        runner=runner,
    )
    assert outcome.status == "PASS"
    assert outcome.test_name == "test_protocol_witness"


@pytest.mark.skipif(resolve_tool("forge") is None, reason="forge is not installed")
def test_a_protocol_poc_can_be_the_distinct_engine_that_confirms(tmp_path):
    source = _write(tmp_path, "Protocol.sol", PUBLIC_VULNERABLE)
    control = _write(tmp_path, "Control.sol", PUBLIC_CONTROL)
    files = {source.name: source.read_text(encoding="utf-8")}
    digest = hashlib.sha256(
        json.dumps(files, sort_keys=True).encode("utf-8")).hexdigest()[:16]
    record = replace(
        self_test_record(), target_component="ingest:protocol",
        repository=f"local:{source.resolve()}", commit=digest)
    result = run_source_pipeline(PipelineConfig(
        source_path=str(source), protocol=True,
        control_source=str(control), max_depth=2,
        in_scope=True, authorization_gate_passed=True,
        compatibility=record, run_poc=True,
        require_independent_engine=True,
        write_finding=False, evidence_root=str(tmp_path / "evidence"),
    ))
    assert result.status == "VERIFIED", result.to_dict()
    assert result.poc["status"] == "PASS"
    assert result.verification["independence"] == "INDEPENDENT_ENGINE"
    assert result.verification["checks"]["independent_engine"]["passed"] is True
