"""Acceptance bar for the capability statement.

The capability matrix is only worth having if it cannot quietly inflate itself.
These tests pin the honest answer (no, it cannot find a payable bug unaided),
require every capability to carry evidence and a limitation, require the
diagnosis to keep both a fixed and an open gap, and require the three hard gaps
that cost the last three missions to stay named.
"""

from __future__ import annotations

import json
import subprocess
import sys

from blackheart import capability


def test_the_headline_answer_is_no():
    payload = capability.as_dict()
    assert payload["can_find_payable_bug_unaided"] is False
    assert "Partially capable" in payload["verdict"]


def test_every_capability_has_a_status_evidence_and_a_limitation():
    for cap in capability.CAPABILITIES:
        assert cap.status in capability.STATUSES, cap.name
        assert cap.what_it_does
        assert cap.evidence
        assert cap.limitation


def test_ingestion_and_flags_are_claimed_as_yes():
    by_name = {c.name: c for c in capability.CAPABILITIES}
    assert by_name["source-ingestion"].status == "yes"
    assert by_name["candidate-weakness-flags"].status == "yes"


def test_the_hard_gaps_stay_named_and_no_gap_is_dressed_up():
    by_name = {c.name: c for c in capability.CAPABILITIES}
    # The two gaps the ingest work narrowed are honestly "partial", not "yes".
    assert by_name["solidity-execution"].status == "partial"
    assert by_name["model-synthesis-from-source"].status == "partial"
    # `blackheart deployed` reads real deployment facts, so "no" was itself a
    # stale claim. It is "partial", and the limitation must still name what it
    # cannot do: a status upgrade may not quietly drop the remaining gap.
    assert by_name["deployment-truth"].status == "partial"
    assert "verified source" in by_name["deployment-truth"].limitation
    # The decompiler recovers a closed surface and the AMM prices one venue, so
    # both are "partial" -- and each limitation must still name what is missing.
    assert by_name["closed-source-components"].status == "partial"
    assert "semantics" in by_name["closed-source-components"].limitation
    assert by_name["economic-simulation-of-external-venues"].status == "partial"
    assert "order-book" in by_name["economic-simulation-of-external-venues"].limitation.lower()


def test_new_environments_are_claimed_with_their_limits():
    """A new capability may be "yes" only with a limitation that names its blind spot."""
    by_name = {c.name: c for c in capability.CAPABILITIES}
    for name in ("rust-substrate-ingestion", "assumption-interrogation"):
        cap = by_name[name]
        assert cap.status == "yes", name
        assert cap.evidence, name
        assert cap.limitation, name
    assert "does not expand macros" in by_name["rust-substrate-ingestion"].limitation
    assert "never a proof" in by_name["assumption-interrogation"].limitation


def test_diagnosis_keeps_both_fixed_and_open_items():
    statuses = {d.status for d in capability.DIAGNOSIS}
    assert "fixed" in statuses
    assert "open" in statuses
    for d in capability.DIAGNOSIS:
        assert d.gap and d.impact and d.fix


def test_markdown_carries_the_same_answer():
    md = capability.render_markdown()
    assert "Can it find a payable bug unaided? **No.**" in md


def test_cli_capability_matches_the_module():
    proc = subprocess.run(
        [sys.executable, "-m", "blackheart", "capability", "--json"],
        capture_output=True, text=True, timeout=120,
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert payload["can_find_payable_bug_unaided"] is False
    assert len(payload["capabilities"]) == len(capability.CAPABILITIES)
    assert len(payload["diagnosis"]) == len(capability.DIAGNOSIS)


def test_the_new_depth_is_claimed_with_its_remaining_blind_spot():
    by_name = {c.name: c for c in capability.CAPABILITIES}
    assert by_name["witness-to-poc"].status == "partial"
    assert "does not compile" in by_name["witness-to-poc"].limitation
    assert by_name["storage-layout-diff"].status == "yes"
    assert "does not fetch" in by_name["storage-layout-diff"].limitation
    assert by_name["symbolic-256-bit-arithmetic"].status == "partial"
    assert "MUL" in by_name["symbolic-256-bit-arithmetic"].limitation


def test_source_symbolic_reachability_is_claimed_with_its_limit():
    by_name = {c.name: c for c in capability.CAPABILITIES}
    cap = by_name["source-symbolic-reachability"]
    assert cap.status == "partial"
    assert "symbolic mapping key" in cap.limitation
    assert "budget" in cap.limitation


def test_sarif_interchange_is_claimed_with_its_limit():
    by_name = {c.name: c for c in capability.CAPABILITIES}
    cap = by_name["sarif-interchange"]
    assert cap.status == "yes"
    assert "presentation hint" in cap.limitation
    assert "properties" in cap.limitation


def test_incremental_baseline_is_claimed_with_its_limit():
    by_name = {c.name: c for c in capability.CAPABILITIES}
    cap = by_name["incremental-baseline"]
    assert cap.status == "yes"
    assert "moved root-cause line" in cap.limitation
    assert "ingest flags" in cap.limitation


def test_the_new_execution_and_minimization_depth_is_claimed_honestly():
    by_name = {c.name: c for c in capability.CAPABILITIES}
    assert by_name["witness-poc-execution"].status == "partial"
    assert "forge" in by_name["witness-poc-execution"].limitation
    assert by_name["calldata-minimization"].status == "yes"
    assert "not a proven minimal" in by_name["calldata-minimization"].limitation


def test_close_the_loop_is_claimed_with_its_limit():
    by_name = {c.name: c for c in capability.CAPABILITIES}
    cap = by_name["verified-source-to-finding"]
    assert cap.status == "partial"
    assert "model-level" in cap.limitation
    assert "guarded control" in cap.limitation
    assert "severity is unrated" in cap.limitation


def test_the_closure_depth_is_claimed_with_its_remaining_blind_spot():
    by_name = {c.name: c for c in capability.CAPABILITIES}
    for name in ("cross-contract-callgraph-inference", "deployment-planning",
                 "semantic-equivalence-checks", "live-market-data",
                 "multi-invariant-source-poc", "deployment-truth-join",
                 "deployment-binding"):
        assert by_name[name].status == "partial", name
        assert by_name[name].limitation, name
    assert "semantic equivalence" in by_name["deployment-binding"].limitation
    assert "three shapes" in by_name["generated-invariant-tests"].limitation
    assert "refused rather than fabricated" in by_name[
        "multi-contract-composition"].what_it_does
    assert "UNMODELLED" in by_name["multi-contract-composition"].limitation
    assert "bounded call stack" in by_name["multi-contract-composition"].limitation
    assert "default is source-regex" in by_name[
        "cross-contract-callgraph-inference"].limitation
    assert "V3" in by_name["live-market-data"].limitation
    for name in ("distributed-lease-queue", "local-reviewer-model"):
        assert by_name[name].status == "yes", name
        assert by_name[name].limitation, name


def test_capability_claims_do_not_go_stale_after_a_feature_lands():
    by_name = {c.name: c for c in capability.CAPABILITIES}
    assert "Only `conservation" not in by_name["source-level-foundry-poc"].limitation
    assert "not inferred from external calls" not in by_name[
        "multi-contract-composition"].limitation
    assert "no live reserves" not in by_name["market-ordering-economics"].limitation
    assert "no distributed scheduler or worker leases" not in by_name[
        "bounded-parallel-corpus"].limitation
    assert "there is no order book" not in by_name["amm-venue-simulation"].limitation
    assert "Conditional effects are split" in by_name[
        "source-symbolic-reachability"].what_it_does


def test_model_coverage_is_claimed_with_its_remaining_blind_spot():
    by_name = {c.name: c for c in capability.CAPABILITIES}
    cap = by_name["model-coverage-contract"]
    assert cap.status == "partial"
    assert "function-level" in cap.limitation
    assert "hand-written" in cap.limitation
    assert "EXTERNAL" in cap.limitation


def test_the_new_analysis_and_execution_depth_is_claimed_honestly():
    by_name = {c.name: c for c in capability.CAPABILITIES}
    assert by_name["whole-program-taint"].status == "partial"
    assert "lead" in by_name["whole-program-taint"].limitation
    assert by_name["real-evm-execution"].status == "partial"
    assert "local fallback" in by_name["real-evm-execution"].limitation
    assert by_name["smt-path-conditions"].status == "partial"
    assert "optional" in by_name["smt-path-conditions"].limitation
    assert by_name["witness-source-trace"].status == "yes"
    assert "ambiguous" in by_name["witness-source-trace"].limitation
    assert by_name["pipeline-ci-artifacts"].status == "yes"
    assert "findings" in by_name["pipeline-ci-artifacts"].limitation


def test_distinct_engine_verification_is_claimed_with_its_opt_in_limit():
    by_name = {c.name: c for c in capability.CAPABILITIES}
    cap = by_name["distinct-engine-verification"]
    assert cap.status == "partial"
    assert "opt-in" in cap.limitation
    assert "REPRODUCED" in cap.limitation
