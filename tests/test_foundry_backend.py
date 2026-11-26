"""The Foundry backend compiles arbitrary source and runs a caller-supplied test."""

from __future__ import annotations

import json
import subprocess

from blackheart.ingest.foundry import run_foundry_test
from blackheart.toolchain.enforce import self_test_record

FILES = {"Token.sol": "contract Token { function f() external {} }"}
TEST = "contract T { function test_witness() public {} }"


def test_a_caller_test_runs_against_the_supplied_source():
    seen = {}

    def runner(cmd, cwd, timeout):
        seen["cmd"] = cmd
        payload = {"test/Poc.t.sol:T": {"passed": ["test_witness()"]}}
        return subprocess.CompletedProcess(cmd, 0, json.dumps(payload), "")

    result = run_foundry_test(
        FILES, TEST, compatibility=self_test_record(),
        target_component="ingest:Token", repository="blackheart", runner=runner,
        fork_url="https://example.invalid/rpc", fork_block=123,
    )
    assert result.status == "PASS"
    assert "--fork-url" in seen["cmd"]
    assert "https://example.invalid/rpc" in seen["cmd"]
    assert "--fork-block-number" in seen["cmd"]
    assert "123" in seen["cmd"]


def test_without_a_record_nothing_runs():
    calls = []

    def runner(cmd, cwd, timeout):
        calls.append(cmd)
        raise AssertionError("blocked backend must not invoke forge")

    result = run_foundry_test(FILES, TEST, compatibility=None,
                              target_component="ingest:Token", repository="blackheart",
                              runner=runner)
    assert result.status == "BLOCKED"
    assert calls == []


def test_missing_source_is_incomplete_not_a_clean_run():
    result = run_foundry_test({}, TEST, compatibility=self_test_record(),
                              target_component="ingest:Token", repository="blackheart")
    assert result.status == "INCOMPLETE"
