"""Tests for the real-target fork harness integration (mission sections 2C, 5, 12).

These tests are deliberately split:

  * pure-logic tests (target registry, authorization gating, campaign reporting)
    run always, with no network and no `forge`; and
  * fork tests that need `forge` + a mainnet RPC are skipped when unavailable,
    and say so explicitly (a skip is not a pass).
"""

from __future__ import annotations

import json
import blackheart.fork as fork_module
from pathlib import Path

import pytest

from blackheart.authz import new_record
from blackheart.fork import (
    FORK_HYPOTHESES,
    authorize_fork_target,
    build_trust_boundary_finding,
    record_fork_hypotheses,
    run_fork_campaign,
)
from blackheart.models import AssetStatus
from blackheart.targets import (
    FORK_TARGETS,
    available_fork_targets,
    get_fork_target,
    is_fetched,
)
from blackheart.verify import IndependentVerifier, VerificationContext


def test_registry_is_non_empty_and_well_formed():
    assert FORK_TARGETS, "at least one real-target harness must be registered"
    for t in FORK_TARGETS:
        assert t.upstream.startswith("https://github.com/")
        assert len(t.pinned_commit) == 40, "targets must pin an exact commit"
        assert t.scope_url.startswith("https://")
        assert t.test_contracts, "a harness without test contracts is useless"


def test_known_target_lookup():
    assert "twyne-aave-wrapper" in available_fork_targets()
    t = get_fork_target("twyne-aave-wrapper")
    assert t.pinned_commit == "797be33e22cce033f6d9c66650d9604ee48fc60d"


def test_unknown_target_raises():
    with pytest.raises(KeyError):
        get_fork_target("does-not-exist")


# --------------------------------------------------------------------------- #
# Authorization gating of active/live-fork testing (mission section 5, 12)
# --------------------------------------------------------------------------- #

def _record(status: str, **checks):
    rec = new_record(
        program="Twyne (Immunefi)",
        platform="immunefi",
        target_url="https://immunefi.com/bug-bounty/twyne/information/",
        scope_url="https://immunefi.com/bug-bounty/twyne/information/",
        **checks,
    )
    rec.assets = {"AaveV3 aToken Wrapper (0xTwyne/aave-v3-aToken-wrapper)": status}
    rec.evidence = ["ev-test"]
    rec.verified = True
    return rec


def test_active_fork_is_blocked_without_full_authorization():
    target = get_fork_target("twyne-aave-wrapper")
    # No program checks set -> everything defaults to None -> fail closed.
    rec = _record(AssetStatus.AUTHORIZED.value)
    decision = authorize_fork_target(target, rec)
    assert not decision.allowed
    assert decision.blockers


def test_active_fork_is_blocked_when_asset_unknown():
    target = get_fork_target("twyne-aave-wrapper")
    rec = _record(
        AssetStatus.UNKNOWN.value,
        program_active=True,
        safe_harbor=True,
        poc_required=True,
        nigerian_eligible=True,
        payout_feasible=True,
        zero_cost=True,
    )
    decision = authorize_fork_target(target, rec)
    assert not decision.allowed
    assert any("UNKNOWN" in b for b in decision.blockers)


def test_active_fork_allowed_only_when_everything_verified():
    target = get_fork_target("twyne-aave-wrapper")
    rec = _record(
        AssetStatus.AUTHORIZED.value,
        program_active=True,
        safe_harbor=True,
        poc_required=True,
        nigerian_eligible=True,
        payout_feasible=True,
        zero_cost=True,
    )
    decision = authorize_fork_target(target, rec)
    assert decision.allowed, decision.blockers


# --------------------------------------------------------------------------- #
# Campaign reporting honesty
# --------------------------------------------------------------------------- #

def test_campaign_blocks_honestly_without_forge(tmp_path, monkeypatch):
    """Without `forge` the campaign must report BLOCKED, never fake a result."""
    monkeypatch.setattr(fork_module, "resolve_tool", lambda _name: None)
    target = get_fork_target("twyne-aave-wrapper")
    summary = run_fork_campaign(target, tmp_path)
    assert summary["status"] == "BLOCKED"
    assert "forge" in summary["blocked_reason"]
    written = json.loads((tmp_path / "fork-campaign-summary.json").read_text())
    assert written["status"] == "BLOCKED"


# --------------------------------------------------------------------------- #
# The trust-boundary finding must NOT be self-confirmed
# --------------------------------------------------------------------------- #

def test_trust_boundary_finding_is_not_auto_confirmed():
    target = get_fork_target("twyne-aave-wrapper")
    finding = build_trust_boundary_finding(target)
    # Honest context: mechanism reproducible, but attacker reachability unproven.
    ctx = VerificationContext(
        in_scope=True,
        scope_reference=target.scope_asset,
        protection_exists=False,
        behavior_intentional=False,
        duplicate_known=False,
        attacker_controls_input=None,
        reachable=None,
        measurable_impact=None,
        reproduce=lambda: True,  # even if the mechanism reproduces...
    )
    IndependentVerifier().verify(finding, ctx)
    # ...the finding still must not be CONFIRMED, because gates 1/2/5 are unknown.
    assert finding.classification.value != "CONFIRMED"
    assert finding.classification.value == "NEEDS_MORE_EVIDENCE"


def test_ledger_records_only_honest_statuses(tmp_path):
    target = get_fork_target("twyne-aave-wrapper")
    view = record_fork_hypotheses(target, tmp_path)
    assert view, "hypotheses must be recorded"
    statuses = {rec["status"] for rec in view.values()}
    # No hypothesis is CONFIRMED: nothing was proven reachable+impactful.
    assert "CONFIRMED" not in statuses
    # At least one is honestly left open (the trust-boundary observation).
    assert "NEEDS_MORE_EVIDENCE" in statuses
    # The disproofs are recorded as FALSE_POSITIVE, not as findings.
    assert statuses <= {"FALSE_POSITIVE", "NEEDS_MORE_EVIDENCE", "INFORMATIONAL"}


def test_every_registered_target_has_hypotheses():
    for name in available_fork_targets():
        assert FORK_HYPOTHESES.get(name), f"{name} has no recorded hypotheses"


def test_fork_ledger_cli_default_matches_campaign_output_dir(tmp_path, monkeypatch):
    """`fork ledger` must read the same directory `fork run` writes to.

    Regression: the ledger CLI defaulted to `research/private/fork` while the
    campaign writes to `<workdir>/ledger`, so `fork ledger` reported an empty
    ledger even after a successful run.
    """
    from blackheart import cli

    parser = cli.build_parser()
    args = parser.parse_args(["fork", "ledger", "--target", "twyne-aave-wrapper"])
    run_args = parser.parse_args(["fork", "run", "--target", "twyne-aave-wrapper"])
    # run writes to Path(run_args.workdir) / "ledger"; ledger must read the same.
    assert Path(args.ledger_dir) == Path(run_args.workdir) / "ledger"


# --------------------------------------------------------------------------- #
# Fork tests (need forge + RPC; skipped honestly when unavailable)
# --------------------------------------------------------------------------- #

forge_missing = fork_module.resolve_tool("forge") is None
fetched = is_fetched(get_fork_target("twyne-aave-wrapper"))


@pytest.mark.skipif(forge_missing, reason="forge not on PATH")
@pytest.mark.skipif(not fetched, reason="real source not fetched (run: blackheart fork fetch)")
def test_real_wrapper_adversarial_suite_passes(tmp_path):
    """The real harness must compile and its adversarial tests must run green."""
    target = get_fork_target("twyne-aave-wrapper")
    summary = run_fork_campaign(target, tmp_path, runs=8, depth=8, timeout=900)
    assert summary["status"] == "COMPLETED", summary.get("blocked_reason")
    adv = summary["stages"]["adversarial"]
    assert adv["failed"] == 0
    assert adv["passed"] >= 5, "expected the full adversarial suite to run"
    smoke = summary["stages"]["smoke"]
    assert smoke["failed"] == 0 and smoke["passed"] >= 2
