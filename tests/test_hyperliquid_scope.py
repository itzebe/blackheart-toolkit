"""Authorization-gate tests for the Hyperliquid engagement (mission sections 5, 12).

These are regression tests for the gate itself: they assert that the recorded
Hyperliquid scope decisions fail closed until the operator privately confirms
their own KYC/KYB and payout eligibility, and that only the assets the program
actually authorizes can ever become testable.
"""

from __future__ import annotations

from datetime import datetime, timezone

from blackheart.authz import authorize_active_testing
from blackheart.models import AssetStatus, AuthorizationRecord
from blackheart.scope import check_asset

SCOPE_TEXT = (
    "In scope: On mainnet, any bug that would cause an outage or logical error on "
    "nodes or API servers is in scope. Experimental features on testnet are not in "
    "scope, unless otherwise announced in Discord or Telegram announcements. "
    "Prohibited activity: Testing on mainnet code; all testing should be done on "
    "testnet or local forks."
)

AUTHORIZED = [
    "hypercore-l1 (nodes, consensus, API servers)",
    "hypercore-portfolio-margin",
    "hip-4-binary-outcomes (testnet)",
]
OUT_OF_SCOPE = [
    "hip-4-multi-outcome",
    "hyperevm-third-party-contracts",
    "web-frontend",
]


def _record(**checks) -> AuthorizationRecord:
    # A *fresh* timestamp: these tests exercise the scope/eligibility gate, not the
    # staleness gate. A hardcoded date would make them pass only inside the 7-day
    # evidence window and fail afterwards (a time-bomb test). The staleness gate has
    # its own dedicated test below.
    checked_at = datetime.now(timezone.utc).isoformat()
    return AuthorizationRecord(
        program="Hyperliquid Bug Bounty Program",
        platform="vendor",
        target_url="https://hyperliquid.gitbook.io/hyperliquid-docs/bug-bounty-program",
        scope_url="https://hyperliquid.gitbook.io/hyperliquid-docs/bug-bounty-program",
        checked_at=checked_at,
        retrieved_scope={"text": SCOPE_TEXT, "source_url": "https://hyperliquid.gitbook.io/"},
        asset_classes={a: "AUTHORIZED" for a in AUTHORIZED}
        | {a: "OUT_OF_SCOPE" for a in OUT_OF_SCOPE},
        evidence=["ev-test"],
        verified=True,
        **checks,
    )


def test_operator_eligibility_unconfirmed_blocks_all_active_testing():
    """With no KYC/payout assertion, every authorized asset is still blocked."""
    rec = _record(program_active=True, safe_harbor=True, poc_required=True, zero_cost=True)
    for asset in AUTHORIZED:
        decision = authorize_active_testing(rec, asset)
        assert not decision.allowed, f"{asset} must be blocked without KYC confirmation"
        assert any("nigerian_eligible" in b or "payout_feasible" in b
                   for b in decision.blockers)


def test_operator_eligibility_confirmed_unblocks_only_authorized_assets():
    rec = _record(
        program_active=True, safe_harbor=True, poc_required=True, zero_cost=True,
        nigerian_eligible=True, payout_feasible=True,
    )
    for asset in AUTHORIZED:
        assert authorize_active_testing(rec, asset).allowed, asset
    for asset in OUT_OF_SCOPE:
        assert not authorize_active_testing(rec, asset).allowed, asset


def test_unknown_asset_is_never_authorized():
    rec = _record(program_active=True, safe_harbor=True, poc_required=True, zero_cost=True,
                  nigerian_eligible=True, payout_feasible=True)
    decision = authorize_active_testing(rec, "some-unlisted-component")
    assert not decision.allowed
    assert decision.status is AssetStatus.UNKNOWN


def test_check_asset_matches_authorize_active_testing():
    rec = _record(program_active=True, safe_harbor=True, poc_required=True, zero_cost=True,
                  nigerian_eligible=True, payout_feasible=True)
    for asset in AUTHORIZED + OUT_OF_SCOPE:
        assert check_asset(rec, asset).allowed == authorize_active_testing(rec, asset).allowed


def test_stale_evidence_blocks_active_testing():
    """The 7-day evidence window is enforced: an old record must fail closed.

    This is the gate the rest of the file deliberately avoids tripping, so it is
    covered explicitly here with a record that is provably older than the limit.
    """
    from datetime import timedelta

    from blackheart.authz import MAX_EVIDENCE_AGE, evidence_age

    rec = _record(program_active=True, safe_harbor=True, poc_required=True, zero_cost=True,
                  nigerian_eligible=True, payout_feasible=True)
    # Back-date the record beyond the limit.
    stale = datetime.now(timezone.utc) - (MAX_EVIDENCE_AGE + timedelta(days=1))
    rec.checked_at = stale.isoformat()
    assert evidence_age(rec) > MAX_EVIDENCE_AGE
    for asset in AUTHORIZED:
        decision = authorize_active_testing(rec, asset)
        assert not decision.allowed, asset
        assert any("stale" in b for b in decision.blockers)
