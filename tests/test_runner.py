"""Acceptance bar for gated tool execution.

The property that matters is the one the engine-enforcement tests already hold
for every other engine: **a blocked run must not invoke the tool at all.** A fake
``forge`` on PATH records whether it was called, so a gate that printed BLOCKED
and then ran anyway would fail here.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from blackheart.ingest.runner import (
    detect,
    run_foundry,
    solidity_record,
    write_harness,
)

REPO = "itzebe/blackheart"
COMPONENT = "Bank"
COMMIT = "abc123"


def _fake_forge(tmp_path: Path, stdout: str, exit_code: int = 0) -> tuple[Path, Path]:
    """Install a fake forge that marks invocation and prints ``stdout``."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    marker = tmp_path / "invoked.marker"
    payload = tmp_path / "forge.out"
    payload.write_text(stdout)
    script = bin_dir / "forge"
    script.write_text(
        "#!/bin/sh\n"
        f"echo invoked > {marker}\n"
        f"cat {payload}\n"
        f"exit {exit_code}\n"
    )
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    return bin_dir, marker


def _use(monkeypatch, bin_dir: Path) -> None:
    # The resolver checks BLACKHEART_FORGE before PATH, so pin the fake there
    # as well: a real forge in ~/.foundry/bin must not shadow the test's tool.
    monkeypatch.setenv("BLACKHEART_FORGE", str(bin_dir / "forge"))
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}")


def test_detect_returns_an_availability_record():
    availability = detect()
    assert isinstance(availability.forge, bool)
    assert isinstance(availability.any_solidity, bool)


def test_no_record_blocks_and_never_invokes_the_tool(tmp_path, monkeypatch):
    bin_dir, marker = _fake_forge(tmp_path, '{"passed": 1, "failed": 0}')
    _use(monkeypatch, bin_dir)
    outcome = run_foundry(tmp_path, compatibility=None,
                          target_component=COMPONENT, repository=REPO, commit=COMMIT)
    assert outcome.status == "BLOCKED"
    assert not marker.exists(), "a blocked run invoked forge"


def test_record_for_another_component_blocks_and_never_invokes(tmp_path, monkeypatch):
    bin_dir, marker = _fake_forge(tmp_path, '{"passed": 1, "failed": 0}')
    _use(monkeypatch, bin_dir)
    record = solidity_record(target_component="SomeOtherContract", repository=REPO, commit=COMMIT)
    outcome = run_foundry(tmp_path, compatibility=record,
                          target_component=COMPONENT, repository=REPO, commit=COMMIT)
    assert outcome.status == "BLOCKED"
    assert "does not authorise" in outcome.detail or "not 'Bank'" in outcome.detail
    assert not marker.exists(), "a blocked run invoked forge"


def test_record_for_another_commit_blocks(tmp_path, monkeypatch):
    bin_dir, marker = _fake_forge(tmp_path, '{"passed": 1, "failed": 0}')
    _use(monkeypatch, bin_dir)
    record = solidity_record(target_component=COMPONENT, repository=REPO, commit="different")
    outcome = run_foundry(tmp_path, compatibility=record,
                          target_component=COMPONENT, repository=REPO, commit=COMMIT)
    assert outcome.status == "BLOCKED"
    assert not marker.exists()


def test_admitted_clean_run_is_no_findings(tmp_path, monkeypatch):
    bin_dir, marker = _fake_forge(tmp_path, '{"passed": 7, "failed": 0}')
    _use(monkeypatch, bin_dir)
    record = solidity_record(target_component=COMPONENT, repository=REPO, commit=COMMIT)
    outcome = run_foundry(tmp_path, compatibility=record,
                          target_component=COMPONENT, repository=REPO, commit=COMMIT)
    assert outcome.status == "NO_FINDINGS", outcome.detail
    assert marker.exists()


def test_admitted_failing_run_is_pass(tmp_path, monkeypatch):
    bin_dir, _ = _fake_forge(tmp_path, '{"passed": 3, "failed": 2}')
    _use(monkeypatch, bin_dir)
    record = solidity_record(target_component=COMPONENT, repository=REPO, commit=COMMIT)
    outcome = run_foundry(tmp_path, compatibility=record,
                          target_component=COMPONENT, repository=REPO, commit=COMMIT)
    assert outcome.status == "PASS", outcome.detail
    assert "2 failing" in outcome.detail


def test_unparseable_output_is_incomplete(tmp_path, monkeypatch):
    bin_dir, _ = _fake_forge(tmp_path, "compiler error: not json", exit_code=1)
    _use(monkeypatch, bin_dir)
    record = solidity_record(target_component=COMPONENT, repository=REPO, commit=COMMIT)
    outcome = run_foundry(tmp_path, compatibility=record,
                          target_component=COMPONENT, repository=REPO, commit=COMMIT)
    assert outcome.status == "INCOMPLETE", outcome.detail


def test_absent_tool_blocks_without_running(tmp_path, monkeypatch):
    import blackheart.ingest.runner as runner_module
    monkeypatch.setattr(runner_module, "resolve_tool", lambda _name: None)
    record = solidity_record(target_component=COMPONENT, repository=REPO, commit=COMMIT)
    outcome = run_foundry(tmp_path, compatibility=record,
                          target_component=COMPONENT, repository=REPO, commit=COMMIT)
    assert outcome.status == "BLOCKED"
    assert "not installed" in outcome.detail


def test_harness_is_a_skeleton_with_the_invariant_named(tmp_path):
    path = write_harness("Bank", ("conservation:balances-totalSupply",),
                         "src/Bank.sol", tmp_path / "test")
    text = path.read_text()
    assert path.name == "BankInvariant.t.sol"
    assert "invariant_conservation_balances_totalSupply" in text
    assert "SKELETON" in text
    assert "TODO" in text
