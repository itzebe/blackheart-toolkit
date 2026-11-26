"""Guarded-control automation: fetch a pinned twin and compare the witness."""

from __future__ import annotations

import subprocess
from pathlib import Path

from blackheart.control import (
    build_control,
    compare_sequence,
    fetch_patched_source,
    load_source_tree,
)
from blackheart.ingest.solidity import scan_source
from blackheart.ingest.synthesize import synthesize
from blackheart.models import AttackStep
from blackheart.toolchain.enforce import self_test_record

VULNERABLE = """
contract Token {
    mapping(address => uint) balance;
    uint totalSupply;
    function mint(uint amount) external { balance[msg.sender] += amount; }
}
"""

GUARDED = """
contract Token {
    mapping(address => uint) balance;
    uint totalSupply;
    function mint(uint amount) external { balance[msg.sender] += amount; totalSupply += amount; }
}
"""

STEPS = [AttackStep(index=0, actor="attacker", action="mint", params={"amount": 1})]


def _target(source: str):
    return synthesize(scan_source(source, "Token.sol")[0])[0]


def test_a_fixed_twin_is_clean_on_the_same_witness():
    control = build_control({"Token.sol": GUARDED})
    result = compare_sequence(_target(VULNERABLE), control, STEPS,
                              compatibility=self_test_record(), repository="blackheart")
    assert result.status == "CONTROL_CLEAN"
    assert result.specific
    assert result.vulnerable_violations
    assert not result.control_violations


def test_a_twin_with_the_same_bug_is_not_specific():
    control = build_control({"Token.sol": VULNERABLE})
    result = compare_sequence(_target(VULNERABLE), control, STEPS,
                              compatibility=self_test_record(), repository="blackheart")
    assert result.status == "CONTROL_ALSO_VULNERABLE"
    assert not result.specific


def test_without_a_record_the_differential_is_blocked():
    control = build_control({"Token.sol": GUARDED})
    result = compare_sequence(_target(VULNERABLE), control, STEPS, compatibility=None)
    assert result.status == "BLOCKED"


def test_a_pinned_commit_is_fetched_and_scanned(tmp_path):
    dest = tmp_path / "control"

    def runner(cmd, **kwargs):
        if "checkout" in cmd:
            (dest / "src").mkdir(parents=True, exist_ok=True)
            (dest / "src" / "Token.sol").write_text(GUARDED, encoding="utf-8")
        return subprocess.CompletedProcess(cmd, 0, "", "")

    source = fetch_patched_source("https://example.invalid/repo.git", "abc123", dest,
                                  runner=runner)
    assert source.status == "FETCHED"
    assert source.commit == "abc123"
    assert "src/Token.sol" in source.files


def test_a_failed_fetch_is_named_not_treated_as_a_control(tmp_path):
    def runner(cmd, **kwargs):
        return subprocess.CompletedProcess(cmd, 1, "", "not found")

    source = fetch_patched_source("https://example.invalid/repo.git", "abc123",
                                  tmp_path / "control", runner=runner)
    assert source.status == "FETCH_FAILED"
    assert source.files == {}


def test_load_source_tree_reads_solidity_only(tmp_path):
    (tmp_path / "A.sol").write_text("contract A {}", encoding="utf-8")
    (tmp_path / "README.md").write_text("no", encoding="utf-8")
    assert list(load_source_tree(tmp_path)) == ["A.sol"]


def test_control_discovery_picks_the_first_descendant_touching_the_path(tmp_path):
    from blackheart.control import discover_control_commit
    seen = []

    def runner(cmd, **kwargs):
        import subprocess
        seen.append(cmd)
        if cmd[1] == "clone":
            return subprocess.CompletedProcess(cmd, 0, "", "")
        if "cat-file" in cmd:
            return subprocess.CompletedProcess(cmd, 0, "", "")
        if "log" in cmd:
            return subprocess.CompletedProcess(cmd, 0, "old\nvuln\nfix\n", "")
        if "merge-base" in cmd:
            candidate = cmd[-1]
            return subprocess.CompletedProcess(cmd, 0 if candidate == "fix" else 1, "", "")
        if "checkout" in cmd:
            dest.mkdir(parents=True, exist_ok=True)
            (dest / "Vault.sol").write_text(
                "contract Vault { function f() external {} }", encoding="utf-8")
            return subprocess.CompletedProcess(cmd, 0, "", "")
        return subprocess.CompletedProcess(cmd, 0, "", "")

    dest = tmp_path / "control"
    source = discover_control_commit(
        "https://example.invalid/repo.git", "vuln", dest,
        paths=("src/Vault.sol",), runner=runner)
    assert source.status == "FETCHED"
    assert source.commit == "fix"
    assert "Vault.sol" in source.files
    assert any("--" in cmd for cmd in seen)


def test_control_discovery_never_returns_the_vulnerable_commit(tmp_path):
    from blackheart.control import discover_control_commit

    def runner(cmd, **kwargs):
        import subprocess
        if "log" in cmd:
            return subprocess.CompletedProcess(cmd, 0, "vuln\n", "")
        return subprocess.CompletedProcess(cmd, 0, "", "")

    source = discover_control_commit("https://example.invalid/repo.git", "vuln",
                                     tmp_path / "control2", runner=runner)
    assert source.status == "FETCH_FAILED"
    assert source.commit == "vuln"
