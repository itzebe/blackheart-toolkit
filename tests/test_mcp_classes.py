"""Tests for the MCP-server attack class.

An MCP server is an OAuth 2.1 protected resource before it is a tool surface, and
the classes a bounty program accepts for it are authorization classes. Two are
executable here and are held to the same non-vacuity discipline as every other
pair: the vulnerable model must yield an attacker-reachable violation, the
guarded twin must yield none, and the two must differ only in the one control.

The remaining three accepted classes need a live tenant and a real token, so they
are recorded as PROSE_ONLY. These tests assert they are reported as gaps rather
than quietly counted as coverage -- the ledger must never overstate what the
engine can break.
"""

from __future__ import annotations

import pytest

from blackheart.invariants import FuzzConfig, StatefulFuzzer
from blackheart.invariants.coverage import (
    CATEGORY_KIND,
    PROSE_ONLY,
    Coverage,
    coverage_report,
    coverage_summary,
)
from blackheart.invariants.mcp_targets import (
    AudienceConfusedVerifier,
    CorsResource,
    GuardedAudienceVerifier,
    GuardedCorsResource,
)
from blackheart.invariants.registry import make_target
from blackheart.objectives import available_categories


def _run(cls, runs=500, steps=10):
    return StatefulFuzzer(cls(), FuzzConfig(runs=runs, steps_per_run=steps, seed=0)).run()


# --------------------------------------------------------------------------- #
# Per-class contrast: the vulnerable model breaks, the guarded one holds
# --------------------------------------------------------------------------- #

def test_cors_credential_leak_is_exploitable_and_guarded_is_not():
    vuln = _run(CorsResource)
    guard = _run(GuardedCorsResource)
    assert vuln.failures, "a reflected Origin with allow-credentials must be findable"
    assert all(f.reachable_by_attacker for f in vuln.failures)
    assert any(f.inv_id == "no-cross-origin-credential-read" for f in vuln.failures)
    assert guard.failures == [], "an allowlist must refuse an unlisted origin"


def test_null_origin_is_never_granted_a_credentialed_read_when_guarded():
    guard = _run(GuardedCorsResource)
    assert not any(f.inv_id == "no-null-origin-trust" for f in guard.failures)


def test_token_audience_confusion_is_exploitable_and_guarded_is_not():
    vuln = _run(AudienceConfusedVerifier)
    guard = _run(GuardedAudienceVerifier)
    assert vuln.failures, "accepting a token for another resource/tenant must be findable"
    assert any(f.inv_id == "no-cross-tenant-disclosure" for f in vuln.failures)
    assert any(f.inv_id == "token-bound-to-resource" for f in vuln.failures)
    assert guard.failures == [], "audience+tenant binding must refuse a foreign token"


def test_the_guarded_and_vulnerable_models_differ_only_in_the_control():
    """The differential must isolate one control, not a whole redesign."""
    assert CorsResource()._allowed("https://evil.example") is True
    assert GuardedCorsResource()._allowed("https://evil.example") is False
    assert GuardedCorsResource()._allowed("null") is False
    assert GuardedCorsResource()._allowed("https://app.atlassian.com") is True

    v, g = AudienceConfusedVerifier(), GuardedAudienceVerifier()
    assert v._token_valid("https://mcp.example/v2/mcp", "site-b") is True
    assert g._token_valid("https://mcp.example/v2/mcp", "site-b") is False
    assert g._token_valid("https://mcp.example/v1/mcp", "site-a") is True


@pytest.mark.parametrize(
    "vuln,guard",
    [("mcp-cors", "mcp-cors-guarded"), ("mcp-audience", "mcp-audience-guarded")],
)
def test_mcp_pairs_are_registered_and_contrast_through_the_registry(vuln, guard):
    cfg = FuzzConfig(runs=400, steps_per_run=10, seed=0)
    vr = StatefulFuzzer(make_target(vuln), cfg).run()
    gr = StatefulFuzzer(make_target(guard), cfg).run()
    assert [f for f in vr.failures if f.reachable_by_attacker], \
        f"{vuln} produced no attacker-reachable violation"
    assert not gr.failures, f"{guard} must not violate any invariant"


# --------------------------------------------------------------------------- #
# The ledger must be honest about what it can and cannot execute
# --------------------------------------------------------------------------- #

def test_every_mcp_category_is_accounted_for():
    mcp_categories = {
        "cors-credential-leak",
        "token-audience-confusion",
        "mcp-cross-tenant-disclosure",
        "mcp-scope-overreach",
        "mcp-consent-bypass",
    }
    assert mcp_categories <= set(available_categories())

    report = {c.category: c for c in coverage_report()}
    # The two executable classes are MODELLED with a real registered pair.
    for cat in ("cors-credential-leak", "token-audience-confusion"):
        assert report[cat].coverage is Coverage.MODELLED, cat
        assert report[cat].targets, f"{cat} claims modelled with no registered target"
    # The three live-system classes are PROSE_ONLY, with a stated reason, and are
    # NOT counted as modelled.
    for cat in ("mcp-cross-tenant-disclosure", "mcp-scope-overreach",
                "mcp-consent-bypass"):
        assert report[cat].coverage is Coverage.PROSE_ONLY, cat
        assert report[cat].reason, f"{cat} is prose-only without a reason"
        assert cat in PROSE_ONLY


def test_prose_only_classes_are_never_counted_as_coverage():
    summary = coverage_summary()
    assert summary["prose_only"] == len(PROSE_ONLY) >= 3
    assert summary["modelled"] + summary["prose_only"] + summary["unmodelled"] == \
        summary["categories"]
    # The honest claim: a modelled category has a representative, not exhaustive
    # coverage -- and prose-only ones are reported, never claimed.
    assert "not exhaustive" in summary["note"]


def test_coverage_cli_reports_prose_only_rather_than_claiming_full_coverage(capsys):
    from blackheart.cli import main

    rc = main(["coverage"])
    out = capsys.readouterr().out
    assert "prose-only" in out
    assert "Every objective category has a representative model" not in out
    # No unmodelled category means the gate still passes.
    assert rc == 0
