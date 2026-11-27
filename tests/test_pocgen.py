"""A certificate witness becomes a source-level Foundry test, or says why not."""

from __future__ import annotations

import json
import subprocess

from blackheart.models import AttackStep
from blackheart.pocgen import execute_source_poc, render_source_poc
from blackheart.toolchain.enforce import self_test_record

SOURCE = """
contract Vault {
    mapping(address => uint) public balance;
    uint public totalSupply;
    function mint(uint amount) external { balance[msg.sender] += amount; }
}
"""

STEPS = [AttackStep(index=0, actor="attacker", action="mint",
                    params={"amount": 1}, target_contract="Vault")]


def test_a_conservation_witness_renders_a_real_contract_call():
    candidate = render_source_poc({"Vault.sol": SOURCE}, "Vault", "Vault.sol",
                                  STEPS, "conservation:balance-totalSupply")
    assert candidate.rendered
    assert 'import {Vault} from "../src/Vault.sol";' in candidate.solidity
    assert "vm.prank(attacker);" in candidate.solidity
    assert "target.mint(1);" in candidate.solidity
    assert "target.balance(attacker)" in candidate.solidity
    assert "target.totalSupply()" in candidate.solidity
    assert "require(observed != target.totalSupply()" in candidate.solidity


def test_an_invariant_without_a_renderable_assertion_is_unsupported():
    candidate = render_source_poc({"Vault.sol": SOURCE}, "Vault", "Vault.sol",
                                  STEPS, "invariant:opaque")
    assert candidate.status == "UNSUPPORTED"
    assert not candidate.rendered
    assert "conservation" in candidate.reason


def test_authorization_solvency_and_bounded_assertions_render():
    auth = render_source_poc({"Vault.sol": SOURCE}, "Vault", "Vault.sol",
                             STEPS, "authorization:owner")
    assert auth.rendered and "address initialOwner = target.owner();" in auth.solidity
    assert "target.owner() != initialOwner" in auth.solidity
    solvency = render_source_poc({"Vault.sol": SOURCE}, "Vault", "Vault.sol",
                                 STEPS, "solvency:balance-totalSupply")
    assert solvency.rendered and "target.balance() < target.totalSupply()" in solvency.solidity
    bounded = render_source_poc({"Vault.sol": SOURCE}, "Vault", "Vault.sol",
                                STEPS, "bounded:totalSupply-100")
    assert bounded.rendered and "target.totalSupply() > 100" in bounded.solidity


def test_a_rendered_candidate_runs_under_the_gate():
    candidate = render_source_poc({"Vault.sol": SOURCE}, "Vault", "Vault.sol",
                                  STEPS, "conservation:balance-totalSupply")

    def runner(cmd, cwd, timeout):
        payload = {"test/Poc.t.sol:BlackheartCertificateTest": {
            "passed": ["test_certificate_witness()"],
        }}
        return subprocess.CompletedProcess(cmd, 0, json.dumps(payload), "")

    outcome = execute_source_poc(
        candidate, compatibility=self_test_record(), target_component="ingest:Vault",
        repository="blackheart", runner=runner,
    )
    assert outcome.status == "PASS"
    assert outcome.test_name == "test_certificate_witness"


def test_without_a_record_the_poc_is_blocked_and_nothing_runs():
    candidate = render_source_poc({"Vault.sol": SOURCE}, "Vault", "Vault.sol",
                                  STEPS, "conservation:balance-totalSupply")
    calls = []

    def runner(cmd, cwd, timeout):
        calls.append(cmd)
        raise AssertionError("blocked PoC must not invoke forge")

    outcome = execute_source_poc(
        candidate, compatibility=None, target_component="ingest:Vault",
        repository="blackheart", runner=runner,
    )
    assert outcome.status == "BLOCKED"
    assert calls == []


def test_arguments_keep_declaration_order_not_alphabetical_order():
    step = AttackStep(index=0, actor="attacker", action="transfer",
                      params={"to": "victim", "amount": 7}, target_contract="Vault")
    candidate = render_source_poc({"Vault.sol": SOURCE}, "Vault", "src/Vault.sol",
                                  [step], "conservation:balance-totalSupply")
    assert candidate.rendered
    assert "target.transfer(victim, 7);" in candidate.solidity
    assert 'from "../src/Vault.sol"' in candidate.solidity


def test_an_unknown_actor_is_unsupported_not_silently_the_victim():
    step = AttackStep(index=0, actor="admin", action="mint", params={"amount": 1})
    candidate = render_source_poc({"Vault.sol": SOURCE}, "Vault", "Vault.sol",
                                  [step], "conservation:balance-totalSupply")
    assert candidate.status == "UNSUPPORTED"
    assert "actor" in candidate.reason


def test_constructor_arguments_are_rendered_not_inferred():
    candidate = render_source_poc(
        {"Vault.sol": SOURCE}, "Vault", "Vault.sol", STEPS,
        "conservation:balance-totalSupply", constructor_args=[7, "0x1111111111111111111111111111111111111111"])
    assert candidate.rendered
    assert "new Vault(7, address(uint160(" in candidate.solidity
    assert candidate.constructor_args == (7, "0x1111111111111111111111111111111111111111")


def test_a_deployed_address_targets_the_forked_contract_instead_of_deploying():
    candidate = render_source_poc(
        {"Vault.sol": SOURCE}, "Vault", "Vault.sol", STEPS,
        "conservation:balance-totalSupply",
        deployed_address="0x2222222222222222222222222222222222222222")
    assert candidate.rendered
    assert "Vault target = Vault(address(uint160(" in candidate.solidity
    assert "new Vault()" not in candidate.solidity


def test_proxy_mode_deploys_an_implementation_behind_a_delegatecall_proxy():
    candidate = render_source_poc(
        {"Vault.sol": SOURCE}, "Vault", "Vault.sol", STEPS,
        "conservation:balance-totalSupply", proxy=True)
    assert candidate.rendered
    assert "contract BHProxy" in candidate.solidity
    assert "delegatecall" in candidate.solidity
    assert "Vault target = Vault(address(proxy))" in candidate.solidity


def test_fork_flags_reach_the_forge_command():
    candidate = render_source_poc(
        {"Vault.sol": SOURCE}, "Vault", "Vault.sol", STEPS,
        "conservation:balance-totalSupply")
    seen = {}

    def runner(cmd, cwd, timeout):
        seen["cmd"] = cmd
        payload = {"test/Poc.t.sol:BlackheartCertificateTest": {
            "passed": ["test_certificate_witness()"]}}
        return subprocess.CompletedProcess(cmd, 0, json.dumps(payload), "")

    outcome = execute_source_poc(
        candidate, compatibility=self_test_record(), target_component="ingest:Vault",
        repository="blackheart", runner=runner, fork_url="https://rpc.invalid",
        fork_block=42)
    assert outcome.status == "PASS"
    assert "--fork-url" in seen["cmd"]
    assert "--fork-block-number" in seen["cmd"]


def test_proxy_and_helper_deployments_are_rendered_explicitly():
    from blackheart.pocgen import render_source_poc
    steps = [AttackStep(index=0, actor="attacker", action="deposit",
                        params={"amount": 1}, target_contract="Vault")]
    candidate = render_source_poc(
        {"Vault.sol": "contract Vault { function deposit(uint256) external {} }"},
        "Vault", "Vault.sol", steps, "conservation:balance-totalSupply",
        constructor_args=[7], proxy=True,
        helper_deployments=(("Token", [1000]),))
    assert candidate.rendered
    assert "import {Vault, Token}" in candidate.solidity
    assert "contract BHProxy" in candidate.solidity
    assert "Token token = new Token(1000);" in candidate.solidity
    assert "new Vault(7)" in candidate.solidity
    assert candidate.proxy is True
    assert [name for name, _ in candidate.helpers] == ["Token"]


def test_deployed_address_targets_an_existing_contract():
    from blackheart.pocgen import render_source_poc
    steps = [AttackStep(index=0, actor="attacker", action="deposit",
                        params={"amount": 1}, target_contract="Vault")]
    candidate = render_source_poc(
        {"Vault.sol": "contract Vault { function deposit(uint256) external {} }"},
        "Vault", "Vault.sol", steps, "conservation:balance-totalSupply",
        deployed_address="0x" + "11" * 20)
    assert candidate.rendered
    assert "Vault(address(uint160(" in candidate.solidity
    assert "new Vault" not in candidate.solidity
