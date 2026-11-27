"""Acceptance bar for the free prior-art source.

Two properties matter more than coverage here:

  * a query the API cannot honour is **refused**, not sent -- because
    ``GET /advisories`` silently ignores free text and returns its global feed,
    which would compare a candidate against unrelated advisories; and
  * quota exhaustion is an **error**, never an empty result -- an exhausted quota
    must not read as "nothing published, therefore novel".

The network tests are marked ``network`` and skipped by default; the offline ones
pin the behaviour that the network tests would otherwise be the only evidence for.
"""

from __future__ import annotations

import json

import pytest

from blackheart import prior_art as P


# -- package-shape gate (offline) ------------------------------------------- #

@pytest.mark.parametrize("name", ["lodash", "openzeppelin", "@openzeppelin/contracts",
                                  "requests", "CVE-2021-44228", "cve-2021-44228"])
def test_package_shaped_queries_are_accepted(name):
    assert P.looks_like_package(name) or name.upper().startswith("CVE-")


@pytest.mark.parametrize("sentence", [
    "reentrancy lets an attacker drain the vault",
    "the vault trusts an external oracle",
    "", "   ",
])
def test_sentences_are_not_packages(sentence):
    assert not P.looks_like_package(sentence)


def test_sentence_query_is_refused_without_network():
    """The API ignores free text; sending it would return unrelated advisories."""
    search = P.GitHubAdvisorySearch(token="x")
    result = search("reentrancy lets an attacker drain the vault")
    assert result.ok is False
    assert "not a package name" in result.error
    assert result.sources == []


def test_empty_query_is_refused():
    assert P.GitHubAdvisorySearch(token="x")("").ok is False


def test_package_query_targets_affects_not_q():
    search = P.GitHubAdvisorySearch(token="x")
    url, is_cve = search._url("lodash", 5)
    assert "affects=lodash" in url
    assert "q=" not in url, "the q parameter is ignored by the API and must not be used"
    assert is_cve is False


def test_cve_query_targets_cve_id():
    search = P.GitHubAdvisorySearch(token="x")
    url, is_cve = search._url("CVE-2021-44228", 5)
    assert "cve_id=CVE-2021-44228" in url
    assert is_cve is True


def test_count_is_clamped_to_the_api_maximum():
    search = P.GitHubAdvisorySearch(token="x")
    url, _ = search._url("lodash", 5000)
    assert "per_page=100" in url


# -- row mapping (offline) -------------------------------------------------- #

def test_row_to_source_maps_the_fields_the_gate_compares_on():
    row = {
        "ghsa_id": "GHSA-aaaa-bbbb-cccc",
        "summary": "lodash prototype pollution",
        "description": "x" * 5000,
        "severity": "high",
        "html_url": "https://github.com/advisories/GHSA-aaaa-bbbb-cccc",
        "published_at": "2021-01-01T00:00:00Z",
        "identifiers": [{"type": "GHSA", "value": "GHSA-aaaa-bbbb-cccc"},
                        {"type": "CVE", "value": "CVE-2021-0001"}],
    }
    src = P._row_to_source(row)
    assert src.identifier == "GHSA-aaaa-bbbb-cccc"
    assert src.cve == "CVE-2021-0001"
    assert src.severity == "high"
    assert src.provider == "github-advisories"
    # The description is capped so one advisory cannot flood the review.
    assert len(src.description) == 2000


def test_row_without_a_url_is_dropped():
    assert P._row_to_source({"ghsa_id": "", "html_url": ""}) is None


# -- quota is not emptiness (offline) -------------------------------------- #

def test_quota_exhaustion_is_an_error_not_an_empty_result(monkeypatch):
    import urllib.error

    def boom(*a, **k):
        raise urllib.error.HTTPError("u", 429, "Too Many Requests", {}, None)

    monkeypatch.setattr(P.urllib.request, "urlopen", boom)
    result = P.GitHubAdvisorySearch(token="x")("lodash")
    assert result.ok is False, "a 429 must not look like 'no advisories exist'"
    assert "rate limited" in result.error
    assert result.sources == []


def test_network_failure_is_reported(monkeypatch):
    import urllib.error

    def boom(*a, **k):
        raise urllib.error.URLError("no route")

    monkeypatch.setattr(P.urllib.request, "urlopen", boom)
    result = P.GitHubAdvisorySearch(token="x")("lodash")
    assert result.ok is False and result.error


# -- live behaviour (opt-in) ----------------------------------------------- #

@pytest.mark.network
def test_live_package_lookup_returns_real_advisories():
    result = P.GitHubAdvisorySearch()("lodash", count=3)
    if not result.ok and "rate limited" in result.error:
        pytest.skip("GitHub advisory quota exhausted")
    assert result.ok
    assert result.sources, "lodash has published advisories"
    assert all(s.url.startswith("https://github.com/advisories/") for s in result.sources)


@pytest.mark.network
def test_live_cve_lookup():
    result = P.GitHubAdvisorySearch()("CVE-2021-44228", count=1)
    if not result.ok and "rate limited" in result.error:
        pytest.skip("GitHub advisory quota exhausted")
    assert result.ok and result.sources
    assert "log4j" in (result.sources[0].title + result.sources[0].description).lower()
