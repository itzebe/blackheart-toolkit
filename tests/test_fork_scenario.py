"""A fork scenario is explicit, gated and never claims a run it did not make."""

from __future__ import annotations

import json
import subprocess

import pytest

from blackheart.fork_scenario import (
    BalanceDelta, ForkCall, ForkScenario, render_fork_scenario_test,
    run_fork_scenario, scenario_from_dict,
)
from blackheart.symbolic.poc_runner import PocRunOutcome
from blackheart.toolchain.enforce import self_test_record

TARGET = "0x0000000000000000000000000000000000000001"
CALLER = "0x0000000000000000000000000000000000000002"


def _scenario() -> ForkScenario:
    return ForkScenario(
        name="sandwich",
        calls=(
            ForkCall(TARGET, "0x12345678", CALLER, value=10),
            ForkCall(TARGET, "0xabcdef01", CALLER, expect_revert=True),
        ),
        fund={CALLER: 1000},
        balance_deltas=(BalanceDelta(CALLER, -10),),
    )


def test_scenario_renders_decimal_addresses_and_multi_call_assertions():
    source = render_fork_scenario_test(_scenario())
    assert f"address(uint160({int(TARGET, 16)}))" in source
    assert f"address(uint160({int(CALLER, 16)}))" in source
    assert "vm.deal" in source
    assert "vm.prank" in source
    assert 'call{value: 10}' in source
    assert "was expected to revert" in source
    assert "balance delta 0 did not hold" in source
    assert "int256(-10)" in source


def test_scenario_parses_json_and_validates_addresses_and_calldata():
    scenario = scenario_from_dict({
        "name": "two-calls",
        "calls": [
            {"target": TARGET, "data": "0x1234", "caller": CALLER},
            {"target": TARGET, "data": "0x", "expect_revert": True},
        ],
        "fund": {CALLER: "500"},
        "balance_deltas": [{"address": CALLER, "delta": "-5"}],
    })
    assert scenario.name == "two-calls"
    assert scenario.fund[CALLER] == 500
    assert scenario.balance_deltas[0].delta == -5
    with pytest.raises(ValueError, match="20-byte"):
        scenario_from_dict({"calls": [{"target": "0x1", "data": "0x"}]})
    with pytest.raises(ValueError, match="even number"):
        scenario_from_dict({"calls": [{"target": TARGET, "data": "0x1"}]})


def test_scenario_requires_at_least_one_call():
    with pytest.raises(ValueError, match="at least one call"):
        ForkScenario(name="empty", calls=())


def test_no_rpc_blocks_before_the_runner_is_called():
    outcome = run_fork_scenario(
        _scenario(), compatibility=self_test_record(),
        target_component="blackheart", repository="blackheart")
    assert outcome.status == "BLOCKED"
    assert "--rpc" in outcome.detail


def test_no_compatibility_record_blocks_before_the_runner_is_called():
    def runner(*_args):
        raise AssertionError("the runner must not be called")

    outcome = run_fork_scenario(
        _scenario(), compatibility=None, target_component="blackheart",
        repository="blackheart", rpc_url="http://fake", runner=runner)
    assert outcome.status == "BLOCKED"
    assert "no compatibility record" in outcome.detail


def test_an_admitted_scenario_passes_the_fork_flags_and_parses_pass():
    seen = []

    def runner(command, cwd, timeout):
        seen.append((command, cwd, timeout))
        return subprocess.CompletedProcess(
            command, 0,
            json.dumps({"test/ForkScenario.t.sol:T": {
                "passed": ["test_fork_scenario()"]}}), "")

    outcome = run_fork_scenario(
        _scenario(), compatibility=self_test_record(),
        target_component="blackheart", repository="blackheart",
        rpc_url="https://rpc.example", block=123, runner=runner)
    assert outcome.status == "PASS"
    assert "--fork-url" in seen[0][0]
    assert "https://rpc.example" in seen[0][0]
    assert "--fork-block-number" in seen[0][0]
    assert "123" in seen[0][0]


def test_cli_scenario_runs_and_prints_the_outcome(monkeypatch, capsys, tmp_path):
    from blackheart import cli

    path = tmp_path / "scenario.json"
    path.write_text(json.dumps({
        "name": "cli-scenario",
        "calls": [{"target": TARGET, "data": "0x"}],
    }), encoding="utf-8")
    monkeypatch.setattr(
        "blackheart.fork_scenario.run_fork_scenario",
        lambda *a, **k: PocRunOutcome("PASS", "assertions held", "test_fork_scenario"))
    rc = cli.main(["closure", "scenario", "--scenario", str(path),
                   "--rpc", "http://fake", "--repository", "blackheart"])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["run"]["status"] == "PASS"
    assert payload["scenario"]["name"] == "cli-scenario"
