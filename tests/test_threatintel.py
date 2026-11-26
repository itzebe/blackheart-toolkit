"""Acceptance bar for the public threat-intel ingester.

Every normalized pattern is a LEAD that traces to a public source; nothing is
scored, and no live network is touched unless a fetcher is supplied. Rejected
records are reported, never silently dropped.
"""

from __future__ import annotations

import json

import pytest

from blackheart.threatintel import (
    NetworkDisabled,
    ThreatIntelError,
    fetch_text,
    ingest,
    ingest_from_url,
    normalize_record,
    to_regression_fixture,
    write_fixtures,
)

SOLODIT = {"id": "S-1", "title": "Reentrancy in withdraw", "severity": "High",
           "category": "Reentrancy", "description": "external call before state write",
           "url": "https://solodit.xyz/x", "date": "2024-01-01"}
IMMUNEFI = {"id": "I-1", "title": "Oracle manipulation", "severity": "Critical",
            "attack_class": "Price oracle", "url": "https://immunefi.com/y",
            "project": "SomeProtocol"}
DEFILLAMA = {"name": "Euler", "id": "D-1", "classification": "Flashloan",
             "date": "2023-03-13", "link": "https://defillama.com/hacks"}


def test_normalize_solodit():
    p = normalize_record(SOLODIT, "solodit")
    assert p.source == "solodit" and p.source_id == "S-1"
    assert p.attack_class == "Reentrancy"
    assert p.severity == "High"
    assert p.url == "https://solodit.xyz/x"
    assert p.verdict == "LEAD"


def test_normalize_immunefi_and_defillama():
    p = normalize_record(IMMUNEFI, "immunefi")
    assert p.project == "SomeProtocol" and p.attack_class == "Price oracle"
    d = normalize_record(DEFILLAMA, "defillama")
    assert d.title == "Euler" and d.source_id == "D-1"
    assert d.attack_class == "Flashloan"


def test_unknown_source_is_an_error():
    with pytest.raises(ThreatIntelError):
        normalize_record(SOLODIT, "darkweb")


def test_record_without_title_or_id_is_rejected_and_reported():
    result = ingest([SOLODIT, {"severity": "Low"}], "solodit")
    assert len(result.patterns) == 1
    assert result.skipped and result.skipped[0]["index"] == 1
    assert "title/id" in result.skipped[0]["reason"]


def test_fetch_is_disabled_by_default():
    with pytest.raises(NetworkDisabled):
        fetch_text("https://example.invalid/feed.json")


def test_ingest_from_url_with_injected_fetcher():
    feed = json.dumps([SOLODIT, IMMUNEFI])
    result = ingest_from_url("https://example.invalid/feed.json", "solodit",
                             fetcher=lambda _url: feed)
    assert len(result.patterns) == 2
    assert all(p.verdict == "LEAD" for p in result.patterns)


def test_regression_fixture_shape_and_no_score():
    p = normalize_record(IMMUNEFI, "immunefi")
    fx = to_regression_fixture(p)
    assert fx["verdict"] == "LEAD"
    assert fx["class"] == "Price oracle"
    assert fx["expected"] == "violated"
    assert fx["provenance"]["url"] == "https://immunefi.com/y"
    # No invented numeric score / severity threshold anywhere in the fixture.
    assert "score" not in fx and "research_score" not in fx


def test_write_fixtures(tmp_path):
    result = ingest([SOLODIT], "solodit")
    paths = write_fixtures(result.patterns, tmp_path)
    assert len(paths) == 1
    data = json.loads(paths[0].read_text())
    assert data["id"] == "S-1" and data["verdict"] == "LEAD"
