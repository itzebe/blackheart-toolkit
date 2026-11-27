"""A PoC run is gated, parsed honestly and never faked."""

from __future__ import annotations

import json
import subprocess

from blackheart.symbolic.poc_runner import (interpret_forge_json, run_poc_text,
                                            write_poc_project)
from blackheart.toolchain.enforce import self_test_record


def _completed(payload: dict) -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(["forge"], 0, json.dumps(payload), "")


def test_write_poc_project_creates_a_standalone_foundry_project(tmp_path):
    path = write_poc_project("contract C {}", tmp_path)
    assert path == tmp_path / "test" / "Poc.t.sol"
    assert path.read_text() == "contract C {}"
    assert (tmp_path / "foundry.toml").exists()
    assert (tmp_path / "src").is_dir()


def test_old_forge_shape_is_read_as_pass():
    payload = {"test/Poc.t.sol:BlackheartWitnessTest": {
        "passed": [{"name": "test_witness()"}], "failed": [], "skipped": []}}
    status, detail = interpret_forge_json(json.dumps(payload), "test_witness")
    assert status == "PASS"
    assert "assertion held" in detail


def test_new_forge_shape_is_read_as_pass_or_fail():
    passed = {"test/Poc.t.sol:T": {"test_results": {
        "test_witness()": {"status": "Success"}}}}
    failed = {"test/Poc.t.sol:T": {"test_results": {
        "test_witness()": {"status": "Failure"}}}}
    skipped = {"test/Poc.t.sol:T": {"test_results": {
        "test_witness()": {"status": "Skipped"}}}}
    assert interpret_forge_json(json.dumps(passed), "test_witness")[0] == "PASS"
    assert interpret_forge_json(json.dumps(failed), "test_witness")[0] == "FAIL"
    assert interpret_forge_json(json.dumps(skipped), "test_witness")[0] is None


def test_leading_noise_before_the_json_is_tolerated():
    payload = {"test/Poc.t.sol:T": {"passed": ["test_witness()"]}}
    status, _ = interpret_forge_json("warning: something\n" + json.dumps(payload),
                                     "test_witness")
    assert status == "PASS"


def test_a_missing_test_is_not_a_pass():
    status, detail = interpret_forge_json("{}", "test_witness")
    assert status is None
    assert "not found" in detail


def test_no_compatibility_record_blocks_before_the_runner_is_called():
    def runner(*_args):
        raise AssertionError("the runner must not be called")

    outcome = run_poc_text("contract C {}", compatibility=None,
                           target_component="t", repository="r", runner=runner)
    assert outcome.status == "BLOCKED"
    assert "no compatibility record" in outcome.detail


def test_a_record_for_another_target_blocks():
    outcome = run_poc_text("contract C {}", compatibility=self_test_record(),
                           target_component="other", repository="other",
                           runner=lambda *_: (_ for _ in ()).throw(AssertionError()))
    assert outcome.status == "BLOCKED"
    assert "gate refused" in outcome.detail


def test_an_admitted_run_parses_pass_and_fail():
    payload = {"test/Poc.t.sol:T": {"passed": ["test_witness()"]}}
    seen = []

    def runner(command, cwd, timeout):
        seen.append((command, cwd, timeout))
        return _completed(payload)

    outcome = run_poc_text("contract C {}", compatibility=self_test_record(),
                           target_component="blackheart", repository="blackheart",
                           runner=runner)
    assert outcome.status == "PASS"
    assert seen and seen[0][0][:2] == ["forge", "test"]
    assert "--match-test" in seen[0][0]

    failed = {"test/Poc.t.sol:T": {"failed": ["test_witness()"]}}
    outcome = run_poc_text("contract C {}", compatibility=self_test_record(),
                           target_component="blackheart", repository="blackheart",
                           runner=lambda *_: _completed(failed))
    assert outcome.status == "FAIL"


def test_a_timeout_is_incomplete_not_a_pass():
    def runner(*_args):
        raise subprocess.TimeoutExpired(["forge"], 1)

    outcome = run_poc_text("contract C {}", compatibility=self_test_record(),
                           target_component="blackheart", repository="blackheart",
                           runner=runner)
    assert outcome.status == "INCOMPLETE"
    assert "could not complete" in outcome.detail


def test_keep_dir_leaves_the_project_for_inspection(tmp_path):
    payload = {"test/Poc.t.sol:T": {"passed": ["test_witness()"]}}
    outcome = run_poc_text("contract C {}", compatibility=self_test_record(),
                           target_component="blackheart", repository="blackheart",
                           keep_dir=str(tmp_path), runner=lambda *_: _completed(payload))
    assert outcome.status == "PASS"
    assert outcome.project_dir == str(tmp_path)
    assert (tmp_path / "test" / "Poc.t.sol").exists()
