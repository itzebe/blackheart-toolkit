"""Regression tests for the authorization gate (mission section 12).

The gate is the single most safety-critical component: it is the thing that stops
active testing against an unauthorized target. These tests are deliberately
adversarial about it.
"""

from __future__ import annotations

import pytest

from blackheart.authz import (
    AuthorizationError,
    assert_authorized,
    authorize_active_testing,
    classify_asset,
    new_record,
    program_checks_pass,
    reject_inferred_authorization,
)
from blackheart.models import AssetStatus


def _fully_authorized(**overrides):
    rec = new_record(
        program="example",
        platform="immunefi",
        target_url="https://example.test/program",
        scope_url="https://example.test/scope",
        program_active=True,
        safe_harbor=True,
        poc_required=True,
        nigerian_eligible=True,
        payout_feasible=True,
        zero_cost=True,
    )
    rec.assets = {"asset-a": AssetStatus.AUTHORIZED.value}
    rec.evidence = ["ev-deadbeef"]
    rec.verified = True
    for k, v in overrides.items():
        setattr(rec, k, v)
    return rec


def test_fully_authorized_asset_is_allowed():
    rec = _fully_authorized()
    decision = authorize_active_testing(rec, "asset-a")
    assert decision.allowed
    assert decision.status == AssetStatus.AUTHORIZED


def test_unknown_asset_is_blocked():
    rec = _fully_authorized()
    decision = authorize_active_testing(rec, "asset-not-listed")
    assert not decision.allowed
    assert decision.status == AssetStatus.UNKNOWN
    assert any("UNKNOWN" in b for b in decision.blockers)


@pytest.mark.parametrize("status", ["PASSIVE_ONLY", "UNKNOWN", "OUT_OF_SCOPE"])
def test_non_authorized_statuses_are_blocked(status):
    rec = _fully_authorized()
    rec.assets = {"asset-a": status}
    decision = authorize_active_testing(rec, "asset-a")
    assert not decision.allowed


@pytest.mark.parametrize(
    "check",
    ["program_active", "safe_harbor", "zero_cost", "nigerian_eligible",
     "payout_feasible", "verified"],
)
def test_each_required_check_blocks_when_missing(check):
    rec = _fully_authorized(**{check: False})
    decision = authorize_active_testing(rec, "asset-a")
    assert not decision.allowed, f"missing {check} must block active testing"
    assert decision.blockers


def test_missing_evidence_blocks():
    rec = _fully_authorized()
    rec.evidence = []
    assert not authorize_active_testing(rec, "asset-a").allowed


def test_missing_scope_url_blocks():
    rec = _fully_authorized()
    rec.scope_url = ""
    assert not authorize_active_testing(rec, "asset-a").allowed


def test_unverified_record_blocks_even_if_all_checks_true():
    rec = _fully_authorized()
    rec.verified = False
    ok, blockers = program_checks_pass(rec)
    assert not ok
    assert any("verified" in b for b in blockers)


def test_assert_authorized_raises_for_unknown_asset():
    rec = _fully_authorized()
    with pytest.raises(AuthorizationError):
        assert_authorized(rec, "asset-not-listed")


def test_classify_defaults_to_unknown():
    rec = _fully_authorized()
    assert classify_asset(rec, "never-heard-of-it") == AssetStatus.UNKNOWN


def test_classify_garbage_value_is_unknown():
    rec = _fully_authorized()
    rec.assets = {"asset-a": "totally-made-up"}
    assert classify_asset(rec, "asset-a") == AssetStatus.UNKNOWN


@pytest.mark.parametrize(
    "source",
    ["public-repository", "deployed-application", "third-party-tracker",
     "company-ownership", "assumption"],
)
def test_inferred_authorization_is_rejected(source):
    with pytest.raises(AuthorizationError):
        reject_inferred_authorization(source, "some-asset")


def test_ownership_is_not_permission():
    """A company owning an in-scope asset does not authorize its other assets."""
    rec = _fully_authorized()
    decision = authorize_active_testing(rec, "another-company-asset")
    assert not decision.allowed


# --- evidence freshness (mission: "cannot silently reuse expired evidence") ---

def test_stale_evidence_blocks():
    from datetime import datetime, timedelta, timezone

    rec = _fully_authorized()
    old = datetime.now(timezone.utc) - timedelta(days=30)
    rec.checked_at = old.isoformat()
    decision = authorize_active_testing(rec, "asset-a")
    assert not decision.allowed
    assert any("stale" in b for b in decision.blockers)


def test_unparsable_checked_at_blocks():
    rec = _fully_authorized()
    rec.checked_at = "not-a-timestamp"
    decision = authorize_active_testing(rec, "asset-a")
    assert not decision.allowed
    assert any("checked_at" in b for b in decision.blockers)


def test_fresh_evidence_is_allowed():
    from datetime import datetime, timedelta, timezone

    rec = _fully_authorized()
    rec.checked_at = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
    assert authorize_active_testing(rec, "asset-a").allowed


def test_evidence_just_within_window_is_allowed():
    from datetime import datetime, timedelta, timezone

    from blackheart.authz import MAX_EVIDENCE_AGE

    rec = _fully_authorized()
    rec.checked_at = (datetime.now(timezone.utc) - MAX_EVIDENCE_AGE + timedelta(hours=1)).isoformat()
    assert authorize_active_testing(rec, "asset-a").allowed
