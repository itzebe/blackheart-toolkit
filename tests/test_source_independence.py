"""Source-independence accounting and defensible novelty assessment.

Four search results are not four sources when they share a publisher. These tests
pin the behaviour that stops a novelty verdict from resting on the number of
results or the number of providers rather than on genuinely independent origins.
"""

from __future__ import annotations

import pytest

from blackheart.intelligence.sources import (
    analyse,
    canonical_url,
    classify_evidence_tier,
    registrable_domain,
)
from blackheart.models import NoveltyClass, NoveltyReview
from blackheart.novelty import (
    MIN_QUERIES_FOR_NOVELTY,
    MIN_SOURCES_FOR_NOVELTY,
    collect_disclosures,
    evaluate_novelty,
)


# --------------------------------------------------------------------------- #
# canonical_url / registrable_domain
# --------------------------------------------------------------------------- #

def test_canonical_url_collapses_www_scheme_port_fragment_and_tracking():
    a = canonical_url("https://www.Example.com/a/?utm_source=x&b=2&a=1#frag")
    b = canonical_url("http://example.com:80/a?a=1&b=2")
    assert a == b


def test_canonical_url_keeps_a_meaningful_query_parameter():
    assert canonical_url("https://example.com/x?page=2") != canonical_url(
        "https://example.com/x?page=3")


def test_canonical_url_is_stable_and_lowercased():
    assert canonical_url("HTTPS://EXAMPLE.COM/Path") == "https://example.com/Path"
    assert canonical_url("http://example.com/x") == canonical_url("https://example.com/x")


@pytest.mark.parametrize("url,expected", [
    ("https://a.b.example.co.uk/x", "example.co.uk"),
    ("https://sub.github.com/x", "github.com"),
    ("https://x.y.z.com/", "z.com"),
    ("https://1.2.3.4/x", "1.2.3.4"),
    ("https://münchen.de/x", "xn--mnchen-3ya.de"),
])
def test_registrable_domain_handles_compound_suffixes_ip_and_idn(url, expected):
    assert registrable_domain(url) == expected


# --------------------------------------------------------------------------- #
# evidence tiering
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("url,tier", [
    ("https://nvd.nist.gov/vuln/detail/CVE-2024-1", "primary"),
    ("https://github.com/o/r/issues/1", "primary"),
    ("https://github.com/o/r/pull/2", "primary"),
    ("https://github.com/o/r/commit/abc", "primary"),
    ("https://vendor.example/security/advisories/GHSA-x", "primary"),
    ("https://medium.com/@x/a-blog-post", "secondary"),
    ("https://en.wikipedia.org/wiki/Reentrancy", "secondary"),
])
def test_classify_evidence_tier(url, tier):
    assert classify_evidence_tier(url) == tier


# --------------------------------------------------------------------------- #
# analyse(): the core independence rules
# --------------------------------------------------------------------------- #

def test_four_results_from_one_domain_are_one_independent_source():
    urls = [f"https://blog.example.com/post-{i}" for i in range(4)]
    rep = analyse(urls)
    assert rep.total_urls == 4
    assert rep.independent_source_count == 1
    assert rep.origins == ["example.com"]


def test_four_genuinely_independent_origins_are_four():
    urls = ["https://a.com/x", "https://b.org/y", "https://c.net/z", "https://d.io/w"]
    rep = analyse(urls)
    assert rep.independent_source_count == 4
    assert len(rep.origins) == 4


def test_duplicate_urls_collapse():
    urls = ["https://example.com/x", "https://example.com/x",
            "https://www.example.com/x?utm_source=n", "http://example.com/x#f"]
    rep = analyse(urls)
    assert rep.total_urls == 4
    assert rep.unique_urls == 1
    assert rep.duplicates == 3
    assert rep.independent_source_count == 1


def test_multiple_articles_repeating_one_disclosure_are_one_origin():
    # Three "news" articles all on one publisher about the same original finding.
    urls = [
        "https://news.example.com/story-1",
        "https://news.example.com/story-2",
        "https://news.example.com/story-3",
    ]
    rep = analyse(urls)
    assert rep.independent_source_count == 1


def test_primary_and_secondary_are_distinguished():
    urls = [
        "https://github.com/o/r/issues/1",          # primary
        "https://nvd.nist.gov/vuln/detail/CVE-1",   # primary
        "https://someblog.com/writeup",             # secondary
    ]
    rep = analyse(urls)
    assert rep.primary_count == 2
    assert rep.secondary_count == 1


# --------------------------------------------------------------------------- #
# novelty coverage now rests on independent origins
# --------------------------------------------------------------------------- #

def _review(queries=("q1", "q2", "q3")):
    return NoveltyReview(
        finding_id="F-1", target="t",
        root_cause="a bespoke mechanism zzz",
        affected_component="a component yyy",
        queries=list(queries),
    )


def test_single_publisher_cannot_satisfy_the_source_threshold():
    review = _review()
    review.independent_sources = ["example.com"]      # four results, one origin
    review.disclosures = []
    evaluate_novelty(review)
    assert review.classification == NoveltyClass.INSUFFICIENT_EVIDENCE.value
    assert not review.is_submittable()


def test_four_independent_origins_plus_queries_can_reach_likely_new():
    review = _review()
    review.independent_sources = ["a.com", "b.org", "c.net", "d.io"]
    review.disclosures = []
    evaluate_novelty(review)
    assert review.classification == NoveltyClass.LIKELY_NEW.value
    assert review.is_submittable()


def test_zero_results_is_insufficient_evidence_not_novel():
    review = _review()
    review.independent_sources = []
    review.databases_searched = []
    review.disclosures = []
    evaluate_novelty(review)
    assert review.classification == NoveltyClass.INSUFFICIENT_EVIDENCE.value


def test_provider_outage_never_becomes_likely_new():
    review = _review()

    def outage(query, count):
        class R:
            ok = False
            provider = ""
            sources: list = []
            error = "provider outage"
        return R()

    collect_disclosures(review, outage)
    evaluate_novelty(review)
    assert review.classification == NoveltyClass.INSUFFICIENT_EVIDENCE.value
    assert not review.is_submittable()


def test_hand_recorded_review_without_origins_keeps_prior_meaning():
    # Backwards compatibility: a review that only names providers still works.
    review = _review()
    review.databases_searched = ["GHSA", "NVD", "OSV", "advisories"]
    review.disclosures = []
    evaluate_novelty(review)
    assert review.classification == NoveltyClass.LIKELY_NEW.value


def test_collect_disclosures_records_independent_origins():
    review = _review(queries=("q1",))

    class S:
        def __init__(self, url):
            self.url, self.provider, self.title = url, "you.com", "T"

    class R:
        ok = True
        provider = "you.com"
        error = ""
        sources = [
            S("https://a.example.com/1"),
            S("https://www.example.com/1?utm_source=x"),   # same origin
            S("https://b.org/2"),
        ]

    collect_disclosures(review, lambda q, count: R())
    assert review.independent_sources == ["b.org", "example.com"]
    # Provider coverage is still recorded separately.
    assert review.databases_searched == ["you.com"]


def test_partial_provider_failure_is_recorded_and_does_not_fake_coverage():
    review = _review(queries=("q1", "q2"))
    calls = {"n": 0}

    class S:
        def __init__(self, url):
            self.url, self.provider, self.title = url, "you.com", "T"

    class Ok:
        ok, provider, error = True, "you.com", ""
        sources = [S("https://a.org/1")]

    class Fail:
        ok, provider, sources, error = False, "", [], "rate_limited"

    def search_fn(query, count):
        calls["n"] += 1
        return Ok() if calls["n"] == 1 else Fail()

    collect_disclosures(review, search_fn)
    assert len(review.disclosures) == 1
    assert any("rate_limited" in lim for lim in review.search_limitations)


def test_known_vulnerability_discovered_forces_duplicate():
    from blackheart.models import PublicDisclosure
    review = _review()
    review.root_cause = "workflow_run artifact checkout without repo binding"
    review.affected_component = "GitHub Actions workflow_run jobs"
    review.independent_sources = ["a.com", "b.org", "c.net", "d.io"]
    review.disclosures = [PublicDisclosure(
        source="GHSA", identifier="GHSA-xxxx", url="https://github.com/o/r/advisories/1",
        root_cause="workflow_run artifact checkout without repo binding",
        affected_component="GitHub Actions workflow_run jobs",
    )]
    evaluate_novelty(review)
    assert review.classification in (
        NoveltyClass.LIKELY_DUPLICATE.value, NoveltyClass.ALREADY_FIXED.value
    )
    assert not review.is_submittable()
