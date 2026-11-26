"""Acceptance tests for the ranked capability upgrades."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from blackheart import improve
from blackheart.bounty import PolicySnapshot, ProgramPolicy
from blackheart.improve.bounty_package import package_from_policy
from blackheart.improve.closed import analyze_closed
from blackheart.improve.competition import Searcher, simulate_race
from blackheart.improve.continuous import run_continuous
from blackheart.improve.crosschain import (
    BridgeMessage, BridgeReplayModel, OracleReading, bridge_replay_sequence,
    oracle_status,
)
from blackheart.improve.execution import compile_and_model
from blackheart.improve.invariants import discover_invariants
from blackheart.improve.model_coverage import audit_source
from blackheart.improve.review_gate import gate_review
from blackheart.improve.scale import batch_ingest, rank_targets
from blackheart.models import Classification, Finding, ReviewIndependence
from blackheart.providers.router import ReviewerModel
from blackheart.toolchain.enforce import self_test_record
from blackheart.watch import CycleConfig, CycleReport, Lead, Target, make_event


SOURCE = """
pragma solidity ^0.8.0;
contract Vault {
    mapping(address => uint256) public balances;
    uint256 public totalSupply;
    address public owner;
    modifier onlyOwner() { require(msg.sender == owner); _; }
    function deposit(uint256 amount) external { balances[msg.sender] += amount; totalSupply += amount; }
    function withdraw(uint256 amount) external { require(block.timestamp > 0); balances[msg.sender] -= amount; totalSupply -= amount; }
    function mint(address to, uint256 amount) external onlyOwner { balances[to] += amount; totalSupply += amount; }
}
"""


def test_status_lists_every_ranked_upgrade() -> None:
    payload = improve.status()
    assert len(payload["improvements"]) == 10
    assert payload["counts"]["partial"] == 1
    assert "compiler-execution" in {i["key"] for i in payload["improvements"]}


def test_compile_is_blocked_without_a_record() -> None:
    result = compile_and_model(
        ".", compatibility=None, target_component="x", repository="y")
    assert result.status == "BLOCKED"
    assert not result.ok


@pytest.mark.skipif(shutil.which("forge") is None, reason="forge not installed")
def test_compile_and_model_reads_an_abi(tmp_path: Path) -> None:
    (tmp_path / "foundry.toml").write_text("[profile.default]\nsrc='src'\nout='out'\n")
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "A.sol").write_text(
        "pragma solidity ^0.8.0; contract A { function ping(uint x) external { require(x > 0); } }"
    )
    result = compile_and_model(
        str(tmp_path), compatibility=self_test_record(),
        target_component="improve-test", repository="blackheart",
        contract="A",
    )
    assert result.status == "OK", result.reason
    assert "ping" in result.model_operations


def test_model_coverage_names_unmodelled_statements() -> None:
    coverage = audit_source("<memory>", text=SOURCE)
    assert coverage
    assert coverage[0].contract == "Vault"
    assert coverage[0].total_ops >= 3
    assert 0 <= coverage[0].coverage_bps <= 10_000


def test_closed_surface_and_witness_are_separate() -> None:
    surface = analyze_closed(
        "0x00",
        decompiled_text="function ping(uint256 x) external returns (uint256)",
    )
    assert surface.status == "SURFACE_ONLY"
    assert surface.functions[0]["name"] == "ping"

    witness = analyze_closed("0x00", witness={})
    assert witness.status == "WITNESS_VERIFIED"


def test_invariant_discovery_has_provenance() -> None:
    with pytest.MonkeyPatch.context() as mp:
        path = Path("Vault.sol")
        mp.setattr(Path, "read_text", lambda self, encoding=None: SOURCE)
        report = discover_invariants([str(path)])
    kinds = {c.kind for c in report.candidates}
    assert "conservation" in kinds
    assert "authorization" in kinds
    assert all(c.provenance for c in report.candidates)


def test_market_race_winner_and_exclusion() -> None:
    result = simulate_race(
        [Searcher("us", 100, 100), Searcher("fast", 200, 100),
         Searcher("late", 999, 99_999)],
        victim_value_wei=1_000, block_time_ms=12_000,
    )
    assert result.winner == "fast"
    assert result.our_rank == 2
    assert result.excluded_searchers == ["late"]
    assert result.our_expected_profit_wei == 0


def test_bridge_replay_and_oracle_status() -> None:
    model = BridgeReplayModel(10, frozenset({1}), frozenset({"0xsender"}))
    message = BridgeMessage(1, 10, "0xsender", "n1", "0xabc")
    results = bridge_replay_sequence(model, [message, message])
    assert [r.status for r in results] == ["ACCEPTED", "REPLAYED"]
    wrong = model.process(BridgeMessage(1, 11, "0xsender", "n2", "0xabc"))
    assert wrong.status == "REJECTED_CHAIN"

    stale = oracle_status(OracleReading(100, 0), now=10_000, heartbeat=3_600)
    assert stale.status == "STALE"
    deviated = oracle_status(
        OracleReading(200, 9_000), now=10_000, heartbeat=3_600,
        reference_price=100, max_deviation_bps=500)
    assert deviated.status == "DEVIATED"


def test_bounty_package_fails_closed_on_an_unverified_policy() -> None:
    finding = Finding(finding_id="F1", title="t", target="asset",
                      classification=Classification.CONFIRMED)
    policy = ProgramPolicy(
        program="p",
        snapshot=PolicySnapshot("p", "", "", ""),
    )
    package = package_from_policy(finding, policy)
    assert package.outcome == "POLICY_UNVERIFIED"
    assert package.submission_allowed is False
    assert package.blockers


def test_review_gate_refuses_configured_unverified_and_same_model() -> None:
    configured = ReviewerModel(
        False, provider="other", configured=True, verified=False,
        independence=ReviewIndependence.SAME_MODEL,
    )
    assert gate_review(configured).status == "CONFIGURED_UNVERIFIED"
    independent = ReviewerModel(
        True, provider="other", verified=True,
        independence=ReviewIndependence.INDEPENDENT_MODEL,
    )
    assert gate_review(independent).status == "PASS"


def test_scale_batch_and_stable_rank(tmp_path: Path) -> None:
    (tmp_path / "A.sol").write_text(SOURCE)
    (tmp_path / "B.sol").write_text(SOURCE.replace("Vault", "VaultB"))
    results = batch_ingest([str(tmp_path / "A.sol"), str(tmp_path / "B.sol")])
    assert all(r.status == "OK" for r in results)
    assert all(r.contracts == 1 for r in results)
    ranked = rank_targets(["a", "b", "c"], lambda x: {"a": 1, "b": 2, "c": 1}[x])
    assert [r.item for r in ranked] == ["b", "a", "c"]


def test_continuous_enqueues_only_recommended_leads() -> None:
    target = Target("slug", "name", "group", "ACTIVE")
    event = make_event(target="slug", kind="policy", component="x", summary="s")
    good = Lead(event=event, target=target, status="INVESTIGATE", score=100,
                components={}, rationale=[], recommend=True)
    blocked = Lead(event=event, target=target, status="POLICY_BLOCKED", score=100,
                   components={}, rationale=[], recommend=True, policy_blocked=True)
    report = CycleReport("c1", "now")
    report.targets = []
    # CycleReport.leads is derived from targets, so attach a real TargetReport.
    from blackheart.watch.cycle import TargetReport
    tr = TargetReport(target)
    tr.leads = [good, blocked]
    report.targets = [tr]
    seen: list[dict] = []
    result = run_continuous(
        CycleConfig(dry_run=True), enqueue=seen.append, dry_run=True,
        cycle_runner=lambda config, **kw: report,
    )
    assert len(seen) == 0
    assert result.offered[0]["target"] == "slug"
    assert result.enqueued == []
    assert len(result.skipped) == 1
    assert result.skipped[0]["skip"] == "policy blocked"


def test_improve_status_cli(capsys) -> None:
    from blackheart.cli import main
    assert main(["improve", "status", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert len(payload["improvements"]) == 10
