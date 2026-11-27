"""Acceptance bar for repository ingestion.

The point of ``blackheart.ingest`` is to remove hand-transcription from the
start of a mission. These tests assert the properties that make it trustworthy
rather than merely present:

* noise stripping preserves offsets, so every flag's ``file:line`` is real;
* the scanner recovers contracts, functions, visibility, modifiers and state;
* each rule fires on the vulnerable shape *and stays silent on its guarded twin*
  -- precision is the only reason a triage sheet gets read;
* every rule maps to a category that exists in the objective catalog;
* test/snapshot trees are excluded by default;
* the CLI runs end to end.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from blackheart import capability
from blackheart.ingest import (
    RULES,
    as_dict,
    evaluate,
    ingest,
    render_markdown,
    scan_source,
    strip_noise,
)
from blackheart.objectives import _OBJECTIVE_CATALOG

FIXTURE = """
// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

contract Vaultish {
    address public owner;
    mapping(address => uint256) public balances;

    modifier onlyOwner() { require(msg.sender == owner); _; }

    function setOwner(address who) external { owner = who; }              // unguarded
    function setOwnerGuarded(address who) external onlyOwner { owner = who; }

    function drain(address to) external {                                  // unguarded
        (bool ok, ) = to.call{value: 1 ether}("");
        require(ok);
    }

    function drainUnchecked(address to) external onlyOwner {
        to.call{value: 1 ether}("");                                       // unchecked
    }

    function proxy(address impl) external onlyOwner {
        impl.delegatecall(abi.encodeWithSignature("run()"));               // delegatecall
    }

    function auth() external view returns (bool) {
        return tx.origin == owner;                                         // tx-origin
    }

    function initialize(address who) external { owner = who; }             // unguarded init
    function initializeGuarded(address who) external initializer { owner = who; }

    function kill() external onlyOwner { selfdestruct(payable(owner)); }    // selfdestruct

    function loop(address[] calldata users) external onlyOwner {
        for (uint256 i = 0; i < users.length; ++i) { balances[users[i]] = 1; }
    }

    function recover(bytes32 h, uint8 v, bytes32 r, bytes32 s) external pure returns (address) {
        return ecrecover(h, v, r, s);                                      // unchecked ecrecover
    }

    function price() external view returns (uint256) {
        (, int256 answer, , , ) = ORACLE.latestRoundData();                // no updatedAt
        return uint256(answer);
    }

    function sharePrice() external view returns (uint256) {
        return totalAssets() * 1e18 / TOKEN.balanceOf(address(this));      // self balance
    }

    function mintShares(address to, uint256 amount) external onlyOwner {
        _mint(to, amount);                                                 // no transferFrom
    }

    function expire() external view returns (bool) {
        return block.timestamp > deadline;                                 // timestamp
    }

    function totalAssets() internal view returns (uint256) { return 1; }
    uint256 internal deadline;
    address internal constant ORACLE = address(0x1);
    address internal constant TOKEN = address(0x2);
    function _mint(address, uint256) internal {}
}
"""


def _scan() -> tuple:
    contracts = scan_source(FIXTURE, "Fixture.sol")
    assert len(contracts) == 1
    report = ingest_from(contracts)
    return contracts[0], report


def ingest_from(contracts):
    from blackheart.ingest.solidity import SurfaceReport

    return SurfaceReport(root="<fixture>", files=("Fixture.sol",), contracts=tuple(contracts))


# --------------------------------------------------------------------------- #
# Noise stripping and offsets
# --------------------------------------------------------------------------- #

def test_strip_noise_preserves_length_and_newlines():
    src = 'contract A { string s = "/*not a comment*/"; } // trailing\n/* block\ncomment */'
    out = strip_noise(src)
    assert len(out) == len(src)
    assert out.count("\n") == src.count("\n")
    assert "not a comment" not in out
    assert "trailing" not in out
    assert "block" not in out


def test_strip_noise_keeps_offsets_so_line_numbers_are_real():
    src = "// one\n// two\ncontract A { function f() external {} }\n"
    out = strip_noise(src)
    assert out.index("contract") == src.index("contract")


# --------------------------------------------------------------------------- #
# Surface extraction
# --------------------------------------------------------------------------- #

def test_scan_extracts_functions_visibility_modifiers_and_lines():
    contract, _ = _scan()
    assert contract.name == "Vaultish"
    assert contract.has_access_control
    by_name = {f.name: f for f in contract.functions}

    assert by_name["setOwner"].visibility == "external"
    assert by_name["setOwner"].modifiers == ()
    assert by_name["setOwnerGuarded"].modifiers == ("onlyOwner",)
    assert by_name["auth"].mutability == "view"
    assert by_name["auth"].line > 0
    assert "loop(address[])" in by_name["loop"].signature


def test_state_vars_are_recovered():
    contract, _ = _scan()
    assert "owner" in contract.state_vars
    assert "balances" in contract.state_vars


# --------------------------------------------------------------------------- #
# Precision: each rule fires on the vulnerable twin and not the guarded one
# --------------------------------------------------------------------------- #

def test_unguarded_state_changer_fires_only_on_the_unguarded_twin():
    _, report = _scan()
    flags = evaluate(report)
    funcs = {f.function for f in flags if f.rule == "unguarded-state-changer"}
    assert "setOwner" in funcs
    assert "setOwnerGuarded" not in funcs
    assert "auth" not in funcs  # view cannot change state


def test_unchecked_low_level_call_distinguishes_checked_from_unchecked():
    _, report = _scan()
    flags = evaluate(report)
    funcs = {f.function for f in flags if f.rule == "unchecked-low-level-call"}
    assert "drainUnchecked" in funcs
    assert "drain" not in funcs  # (bool ok, ) = ... then require(ok)


def test_unguarded_initializer_skips_the_initializer_modifier():
    _, report = _scan()
    flags = evaluate(report)
    funcs = {f.function for f in flags if f.rule == "unguarded-initializer"}
    assert "initialize" in funcs
    assert "initializeGuarded" not in funcs


@pytest.mark.parametrize(
    "rule, function",
    [
        ("delegatecall-present", "proxy"),
        ("tx-origin-used", "auth"),
        ("selfdestruct-present", "kill"),
        ("unbounded-loop-over-param", "loop"),
        ("ecrecover-unchecked", "recover"),
        ("oracle-staleness-unchecked", "price"),
        ("self-balance-pricing", "sharePrice"),
        ("mint-without-transfer", "mintShares"),
        ("timestamp-comparison", "expire"),
    ],
)
def test_each_rule_fires_on_its_shape(rule, function):
    _, report = _scan()
    hits = {(f.rule, f.function) for f in evaluate(report)}
    assert (rule, function) in hits


# --------------------------------------------------------------------------- #
# Linkage and output shape
# --------------------------------------------------------------------------- #

def test_every_rule_category_exists_in_the_objective_catalog():
    for rule in RULES:
        assert rule.category in _OBJECTIVE_CATALOG, rule.name


def test_flags_are_sorted_most_severe_first_and_carry_evidence():
    _, report = _scan()
    flags = evaluate(report)
    order = {"medium": 0, "low": 1, "info": 2}
    keys = [order[f.severity_hint] for f in flags]
    assert keys == sorted(keys)
    for f in flags:
        assert f.evidence
        assert f.path == "Fixture.sol"
        assert f.line > 0


def test_report_states_that_leads_are_not_findings():
    _, report = _scan()
    md = render_markdown(report, evaluate(report))
    assert "leads, not findings" in md
    payload = as_dict(report, evaluate(report))
    assert payload["disclaimer"].startswith("These are leads, not findings")
    assert payload["flags"] == len(payload["candidates"])


# --------------------------------------------------------------------------- #
# Directory ingestion excludes test trees by default
# --------------------------------------------------------------------------- #

def test_test_trees_are_excluded_by_default(tmp_path):
    prod = tmp_path / "src" / "A.sol"
    test = tmp_path / "test" / "A.t.sol"
    prod.parent.mkdir(parents=True)
    test.parent.mkdir(parents=True)
    prod.write_text("contract A { function f() external {} }")
    test.write_text("contract AT { function setUp() external {} }")

    default = ingest(tmp_path)
    assert len(default.files) == 1 and default.files[0].endswith("A.sol")

    with_tests = ingest(tmp_path, include_tests=True)
    assert len(with_tests.files) == 2


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def _run(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "blackheart", *args],
        capture_output=True, text=True, timeout=120,
    )


def test_cli_ingest_runs_and_emits_json(tmp_path):
    target = tmp_path / "Fixture.sol"
    target.write_text(FIXTURE)
    proc = _run("ingest", str(target), "--json")
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert payload["flags"] > 0
    assert payload["disclaimer"].startswith("These are leads")


def test_cli_ingest_writes_report(tmp_path):
    target = tmp_path / "Fixture.sol"
    target.write_text(FIXTURE)
    out = tmp_path / "out"
    proc = _run("ingest", str(target), "--out", str(out))
    assert proc.returncode == 0, proc.stderr
    assert (out / "surface.md").is_file()


def test_cli_capability_is_honest():
    proc = _run("capability", "--json")
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert payload["can_find_payable_bug_unaided"] is False
    assert "Partially capable" in payload["verdict"]


def test_initializer_modifier_is_recognised_as_a_guard():
    # Regression for a real miss found while re-checking past work: an OZ
    # `initializer` modifier is access control, and must not read as unguarded.
    src = """
    contract Proxy {
        address public owner;
        uint256 public x;
        modifier onlyOwner() { require(msg.sender == owner); _; }
        function initialize(uint256 v) external initializer { x = v; }
        function setX(uint256 v) external { x = v; }
    }
    """
    from blackheart.ingest.solidity import SurfaceReport
    contracts = scan_source(src, "Proxy.sol")
    report = SurfaceReport(root="<mem>", files=("Proxy.sol",), contracts=contracts)
    flagged = {f.function for f in evaluate(report) if f.rule == "unguarded-state-changer"}
    assert "initialize" not in flagged
    assert "setX" in flagged
