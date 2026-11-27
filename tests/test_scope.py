"""Tests for the engagement-authorization scope registry (mission section 5)."""

from __future__ import annotations

import json

import pytest

from blackheart.authz import classify_asset
from blackheart.models import AssetStatus
from blackheart.scope import ScopeError, check_asset, load_record, record_authorization


def _record(**overrides):
    from blackheart.authz import new_record

    rec = new_record(
        program="Example",
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
    rec.asset_classes = {
        "vault": AssetStatus.AUTHORIZED.value,
        "oracle": AssetStatus.PASSIVE_ONLY.value,
        "bridge": AssetStatus.OUT_OF_SCOPE.value,
    }
    rec.retrieved_scope = {
        "source_url": "https://example.test/scope",
        "text": "In scope: the vault. Out of scope: the bridge.",
    }
    rec.verified = True
    for k, v in overrides.items():
        setattr(rec, k, v)
    return rec


def test_record_captures_scope_as_evidence(tmp_path):
    rec = _record()
    summary = record_authorization(
        rec, registry_path=tmp_path / "reg.jsonl", evidence_root=tmp_path / "ev"
    )
    assert summary["authorized_assets"] == ["vault"]
    assert rec.evidence, "scope text must be captured as evidence"
    # The registry is append-only JSONL.
    lines = (tmp_path / "reg.jsonl").read_text().strip().splitlines()
    assert len(lines) == 1
    assert json.loads(lines[0])["program"] == "Example"


def test_verified_record_without_scope_text_is_refused(tmp_path):
    rec = _record(retrieved_scope={"source_url": "https://example.test/scope", "text": ""})
    with pytest.raises(ScopeError):
        record_authorization(
            rec, registry_path=tmp_path / "r.jsonl", evidence_root=tmp_path / "ev"
        )


def test_verified_record_without_scope_source_is_refused(tmp_path):
    rec = _record(retrieved_scope={"text": "some scope"})
    with pytest.raises(ScopeError):
        record_authorization(
            rec, registry_path=tmp_path / "r.jsonl", evidence_root=tmp_path / "ev"
        )


def test_invalid_asset_classification_is_refused(tmp_path):
    rec = _record()
    rec.asset_classes = {"vault": "TOTALLY_MAKE_BELIEVE"}
    with pytest.raises(ScopeError):
        record_authorization(
            rec, registry_path=tmp_path / "r.jsonl", evidence_root=tmp_path / "ev"
        )


def test_structured_asset_classes_take_precedence():
    rec = _record()
    rec.assets = {"vault": AssetStatus.UNKNOWN.value}  # legacy map disagrees
    assert classify_asset(rec, "vault") == AssetStatus.AUTHORIZED


def test_check_only_authorized_is_allowed(tmp_path):
    rec = _record()
    record_authorization(
        rec, registry_path=tmp_path / "r.jsonl", evidence_root=tmp_path / "ev"
    )
    assert check_asset(rec, "vault").allowed
    assert not check_asset(rec, "oracle").allowed
    assert not check_asset(rec, "bridge").allowed
    assert not check_asset(rec, "unknown-asset").allowed


def test_load_record_roundtrip(tmp_path):
    rec = _record()
    record_authorization(
        rec, registry_path=tmp_path / "r.jsonl", evidence_root=tmp_path / "ev"
    )
    path = tmp_path / "rec.json"
    path.write_text(json.dumps(rec.to_dict()), encoding="utf-8")
    loaded = load_record(path)
    assert loaded.program == "Example"
    assert classify_asset(loaded, "vault") == AssetStatus.AUTHORIZED
