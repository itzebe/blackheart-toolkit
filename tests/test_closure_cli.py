"""The closure surface is reachable from the CLI, not only the Python API."""

from __future__ import annotations

import json
import subprocess
import sys


def run(*args):
    return subprocess.run([sys.executable, "-m", "blackheart", *args],
                          capture_output=True, text=True, timeout=120)


def test_market_is_priced_from_the_cli():
    proc = run("closure", "market", "--pool-in", "1000000000000000000",
               "--pool-out", "1000000000000000000", "--victim", "100000000000000000",
               "--attacker", "10000000000000000")
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert "gross_profit" in payload
    assert "victim_loss" in payload


def test_bytecode_witness_is_replayed_from_the_cli(tmp_path):
    runtime = tmp_path / "runtime.hex"
    runtime.write_text("0x60006000fd", encoding="utf-8")
    witness = tmp_path / "witness.json"
    witness.write_text('{"_halt":"revert"}', encoding="utf-8")
    proc = run("closure", "bytecode", "--runtime", str(runtime),
               "--witness", str(witness))
    assert proc.returncode == 0, proc.stderr
    assert json.loads(proc.stdout)["status"] == "VERIFIED"


def test_corpus_add_and_verify_from_the_cli(tmp_path):
    path = tmp_path / "corpus.jsonl"
    proc = run("closure", "corpus", "--path", str(path),
               "--add", '{"target":"A"}', "--verdict", "PASS")
    assert proc.returncode == 0, proc.stderr
    assert json.loads(proc.stdout)["new"] is True
    proc = run("closure", "corpus", "--path", str(path), "--verify")
    assert proc.returncode == 0, proc.stderr
    assert json.loads(proc.stdout)["ok"] is True


def test_corpus_invalidation_pending_and_shards_are_cli_visible(tmp_path):
    path = tmp_path / "corpus.jsonl"
    shard = tmp_path / "shard.json"
    assert run("closure", "corpus", "--path", str(path),
               "--add", '{"target":"A"}', "--verdict", "PASS").returncode == 0
    proc = run("closure", "corpus", "--path", str(path),
               "--invalidate", '{"target":"A"}', "--reason", "stale")
    assert proc.returncode == 0, proc.stderr
    assert json.loads(proc.stdout)["verdict"] == "INVALIDATED"
    proc = run("closure", "corpus", "--path", str(path),
               "--pending", '[{"target":"A"},{"target":"B"}]')
    assert json.loads(proc.stdout)["pending"] == [{"target": "A"}, {"target": "B"}]
    assert run("closure", "corpus", "--path", str(path),
               "--export-shard", str(shard)).returncode == 0
    other = tmp_path / "other.jsonl"
    proc = run("closure", "corpus", "--path", str(other),
               "--merge-shard", str(shard))
    assert proc.returncode == 0, proc.stderr
    assert json.loads(proc.stdout)["merged"] == 1


def test_market_models_are_reachable_from_the_cli():
    proc = run("closure", "market", "--model", "lending",
               "--total-supply", "1000", "--total-borrow", "800",
               "--base-rate-bps", "100", "--slope-bps", "9000")
    assert proc.returncode == 0, proc.stderr
    assert json.loads(proc.stdout)["utilization_bps"] == 8000
    proc = run("closure", "market", "--model", "bundle", "--gross", "1000",
               "--gas", "100", "--priority-fee", "50", "--bribe", "200",
               "--inclusion-bps", "5000")
    assert proc.returncode == 0, proc.stderr
    assert json.loads(proc.stdout)["expected_wei"] == 325


def test_foundry_backend_is_gated_from_the_cli(tmp_path):
    source = tmp_path / "src"
    source.mkdir()
    (source / "Vault.sol").write_text(
        "contract Vault { function f() external {} }", encoding="utf-8")
    test = tmp_path / "Exploit.t.sol"
    test.write_text("contract T { function test_witness() public {} }",
                    encoding="utf-8")
    proc = run("closure", "foundry", "--source", str(source), "--test", str(test))
    assert proc.returncode == 0, proc.stderr
    assert json.loads(proc.stdout)["status"] == "BLOCKED"


def test_class_specific_mutation_is_selectable_from_the_cli(tmp_path):
    source = tmp_path / "Vault.sol"
    source.write_text(
        "contract Vault { uint public owner; function f() external { owner = 1; } }",
        encoding="utf-8")
    proc = run("closure", "mutate", "--source", str(source), "--contract", "Vault",
               "--class", "access-control", "--max-depth", "1")
    assert proc.returncode == 0, proc.stderr
    findings = json.loads(proc.stdout)["findings"]
    assert {f["mutation"] for f in findings} == {"owner-to-attacker", "zero-owner"}


def test_protocol_infer_and_deploy_plan_are_cli_visible(tmp_path):
    source = tmp_path / "Protocol.sol"
    source.write_text("""
contract Token { function mint(address to, uint amount) external {} }
contract Vault {
    constructor(uint seed) {}
    function deposit(uint amount) external { token.mint(msg.sender, amount); }
}
""", encoding="utf-8")
    proc = run("closure", "protocol", "--source", str(source), "--infer")
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert payload["report"]["callgraph"]["edges"]
    proc = run("closure", "deploy-plan", "--source", str(source), "--contract", "Vault")
    assert proc.returncode == 0, proc.stderr
    plan = json.loads(proc.stdout)
    assert plan["status"] == "BLOCKED"
    assert "seed" in plan["steps"][0]["reason"]


def test_live_market_and_queue_are_cli_visible(tmp_path):
    proc = run("closure", "market", "--model", "live")
    assert proc.returncode == 0, proc.stderr
    assert json.loads(proc.stdout)["status"] == "UNAVAILABLE"
    queue = tmp_path / "queue.jsonl"
    proc = run("closure", "corpus", "--path", str(tmp_path / "c.jsonl"),
               "--queue", str(queue), "--queue-claim", "--worker", "w1",
               "--keys", '["a","b"]', "--limit", "1")
    assert proc.returncode == 0, proc.stderr
    assert [l["key"] for l in json.loads(proc.stdout)["leases"]] == ["a"]


def test_foundry_auto_is_gated_from_the_cli(tmp_path):
    source = tmp_path / "Vault.sol"
    source.write_text(
        "contract Vault { mapping(address=>uint) public balance; uint public totalSupply;"
        " function mint(uint amount) external { balance[msg.sender] += amount; } }",
        encoding="utf-8")
    proc = run("closure", "foundry", "--source", str(source), "--auto",
               "--contract", "Vault", "--steps",
               '[{"actor":"attacker","action":"mint","params":{"amount":1}}]',
               "--invariant", "conservation:balance-totalSupply")
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert payload["run"]["status"] == "BLOCKED"
