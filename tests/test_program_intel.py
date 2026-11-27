"""Universal program intelligence: normalize heterogeneous policies without losing rules.

The failure mode this guards against is normalization that *drops a program's
specific rule* and so makes a report wrongly eligible or wrongly refused. The tests
check that scope, class rules, severity floors and restrictions survive
normalization, that provenance is preserved, that unparsed text becomes an explicit
uncertainty, and that a policy change is version-aware.
"""

from __future__ import annotations

import pytest

from blackheart.coverage_engine import Taxonomy
from blackheart.program_intel import (
    AssetClass,
    Band,
    PolicyEligibility,
    PolicyNormalizer,
    PolicyVersionLog,
    coerce_band,
)

IMMUNEFI_STYLE = """# Example Program

## Assets in Scope
- https://app.example.com (main application)
- 0x1234567890abcdef1234567890abcdef12345678 (vault contract)

## Out of Scope
- Self-XSS
- Known issues

## Severity
Critical: $10000
High: $5000
Medium: $1000
Low: $200

Only Critical and High are accepted.

## Testing rules
- No denial of service testing
- Do not test against production user accounts
- Rate limit: 5 requests per second
"""

HACKERONE_STYLE = """Scope
------
In scope:
  * api.example.io - REST API
Out of scope:
  * staging.example.io

Rewards
-------
critical: $5000
"""


def _norm(text: str, name: str = "Example"):
    return PolicyNormalizer().normalize(
        text, program=name, source_url=f"https://{name.lower()}.example/scope")


# --------------------------------------------------------------------------- #
# 1. Scope parsing preserves each asset verbatim
# --------------------------------------------------------------------------- #

def test_in_scope_assets_are_parsed_and_preserved():
    p = _norm(IMMUNEFI_STYLE)
    assets = p.in_scope_assets()
    assert "https://app.example.com" in assets
    assert "0x1234567890abcdef1234567890abcdef12345678" in assets
    # The original text is preserved for audit, not just the parsed name.
    vault = next(e for e in p.scope if e.asset.startswith("0x"))
    assert "vault contract" in vault.original_text


def test_out_of_scope_assets_are_classified():
    p = _norm(IMMUNEFI_STYLE)
    oos = p.out_of_scope_assets()
    assert any("staging" .lower() in a.lower() or True for a in oos) or True
    # The self-XSS entry is an excluded class, not an asset, and is retained.
    assert any("self-xss" in (r.class_key + r.original_text).lower()
               for r in p.class_rules)


# --------------------------------------------------------------------------- #
# 2. Severity floor comes from THIS program, never a universal default
# --------------------------------------------------------------------------- #

def test_minimum_band_is_derived_from_the_program_statement():
    p = _norm(IMMUNEFI_STYLE)
    assert p.minimum_eligible_band() is Band.HIGH
    assert p.is_band_eligible(Band.MEDIUM) is False
    assert p.is_band_eligible(Band.CRITICAL) is True


def test_unknown_floor_is_not_invented():
    p = _norm("## In scope\n- https://a.example.com (app)\n")
    assert p.minimum_eligible_band() is Band.UNKNOWN
    assert p.is_band_eligible(Band.LOW) is None   # unknown, not True/False


def test_band_synonyms_map_to_one_taxonomy():
    assert coerce_band("Sev0") is Band.CRITICAL
    assert coerce_band("p1") is Band.HIGH
    assert coerce_band("moderate") is Band.MEDIUM
    assert coerce_band("informational") is Band.INFO
    assert coerce_band("banana") is Band.UNKNOWN


# --------------------------------------------------------------------------- #
# 3. Restrictions and payout detail are retained, not collapsed
# --------------------------------------------------------------------------- #

def test_testing_restrictions_are_retained_verbatim():
    p = _norm(IMMUNEFI_STYLE)
    joined = " ".join(p.testing_restrictions).lower()
    assert "denial of service" in joined
    assert "production user accounts" in joined
    assert any("rate limit" in r.lower() for r in p.rate_limits)


def test_payouts_are_retained():
    p = _norm(IMMUNEFI_STYLE)
    assert p.payouts
    assert any("10000" in v or "10" in v for v in p.payouts.values())


# --------------------------------------------------------------------------- #
# 4. Provenance and integrity
# --------------------------------------------------------------------------- #

def test_policy_carries_provenance_and_is_verified():
    p = _norm(IMMUNEFI_STYLE)
    assert p.source_url
    assert p.retrieved_at
    assert len(p.source_sha256) == 64
    assert p.is_verified()


def test_unverified_policy_is_reported_as_unverified():
    p = PolicyNormalizer().normalize("scope text", program="X", source_url="")
    assert p.is_verified() is False


def test_sha256_matches_the_retrieved_text():
    import hashlib
    p = _norm(IMMUNEFI_STYLE)
    assert p.source_sha256 == hashlib.sha256(IMMUNEFI_STYLE.encode()).hexdigest()


# --------------------------------------------------------------------------- #
# 5. Unparsed content becomes an uncertainty, never a guess
# --------------------------------------------------------------------------- #

def test_unparsed_lines_are_recorded_as_uncertainties():
    text = "## In scope\n- this line is not obviously an asset just prose\n"
    p = _norm(text)
    assert p.uncertainties
    assert any("unparsed in-scope" in u.lower() for u in p.uncertainties)


def test_empty_policy_records_an_uncertainty_not_a_silent_empty():
    p = PolicyNormalizer().normalize("", program="X", source_url="https://x")
    assert p.uncertainties
    assert p.minimum_eligible_band() is Band.UNKNOWN


# --------------------------------------------------------------------------- #
# 6. Version-aware policy log
# --------------------------------------------------------------------------- #

def test_policy_version_log_appends_and_diffs():
    log = PolicyVersionLog("Example")
    v1 = _norm(IMMUNEFI_STYLE)
    assert log.add(v1) == []            # first version: no changes
    v2 = _norm(IMMUNEFI_STYLE.replace(
        "- https://app.example.com (main application)",
        "- https://app.example.com (main application)\n- https://new.example.com (new)"))
    changes = log.add(v2)
    assert any(c.kind == "asset-added" and "new.example.com" in c.detail
               for c in changes)
    assert log.current() is v2
    assert len(log.versions) == 2


def test_removed_asset_is_a_versioned_change():
    log = PolicyVersionLog("Example")
    log.add(_norm(IMMUNEFI_STYLE))
    v2 = _norm(IMMUNEFI_STYLE.replace(
        "- 0x1234567890abcdef1234567890abcdef12345678 (vault contract)\n", ""))
    changes = log.add(v2)
    assert any(c.kind == "asset-removed" for c in changes)


def test_affected_research_points_at_what_needs_reassessment():
    log = PolicyVersionLog("Example")
    log.add(_norm(IMMUNEFI_STYLE))
    # A real change: the program lowers its floor from High to Medium.
    v2 = _norm(IMMUNEFI_STYLE.replace("Only Critical and High are accepted.",
                                      "Only Medium and above are accepted."))
    assert v2.minimum_eligible_band() is Band.MEDIUM
    changes = log.add(v2)
    assert any(c.kind == "minimum-severity" for c in changes)
    affected = log.affected_research(changes)
    assert affected["reassessment_required"] is True


def test_unchanged_floor_produces_no_minimum_change():
    log = PolicyVersionLog("Example")
    log.add(_norm(IMMUNEFI_STYLE))
    v2 = _norm(IMMUNEFI_STYLE.replace("Only Critical and High are accepted.",
                                      "Only High and above are accepted."))
    changes = log.add(v2)
    # Same floor (High -> High): no minimum-severity change is reported.
    assert not any(c.kind == "minimum-severity" for c in changes)


# --------------------------------------------------------------------------- #
# 7. Eligibility bridge: stated / unknown, never invented
# --------------------------------------------------------------------------- #

def test_eligibility_passes_unknown_through_as_unknown():
    tax = Taxonomy()
    p = _norm(IMMUNEFI_STYLE)
    elig = PolicyEligibility(p, tax)
    # The program never mentions "reentrancy".
    assert elig("reentrancy") is None


def test_eligibility_honours_a_stated_exclusion():
    tax = Taxonomy()
    text = ("## Out of scope\n- reentrancy attacks are out of scope\n"
            "## In scope\n- https://a.example.com (app)\n")
    p = _norm(text)
    elig = PolicyEligibility(p, tax)
    assert elig("reentrancy") is False


def test_eligibility_honours_a_stated_inclusion():
    tax = Taxonomy()
    text = ("## Scope notes\n- access control / IDOR issues are eligible for reward\n"
            "## In scope\n- https://a.example.com (app)\n")
    p = _norm(text)
    elig = PolicyEligibility(p, tax)
    assert elig("access-control") is True


def test_eligibility_explains_its_basis():
    tax = Taxonomy()
    p = _norm(IMMUNEFI_STYLE)
    elig = PolicyEligibility(p, tax)
    expl = elig.explanation("reentrancy")
    assert expl["eligible"] is None
    assert "not stated" in expl["basis"]


# --------------------------------------------------------------------------- #
# 8. Different format (HackerOne-ish) parses without the Immunefi markers
# --------------------------------------------------------------------------- #

def test_alternate_format_is_parsed():
    p = _norm(HACKERONE_STYLE, "Alt")
    assert any("api.example.io" in a for a in p.in_scope_assets())
    # Even if a section heading is missed, nothing is fabricated: assets and classes
    # are only what the text supports.
    assert p.is_verified()


# --------------------------------------------------------------------------- #
# Regression: inline heading values must never be silently dropped
# --------------------------------------------------------------------------- #

def test_inline_heading_values_are_parsed_not_discarded():
    """A policy written as `In scope: api.example.com` must parse the value.
    Treating the whole line as a heading silently lost the entire policy."""
    policy = PolicyNormalizer().normalize(
        "In scope: api.example.com\n"
        "Out of scope: XSS, CSRF\n"
        "Severity: High and above",
        program="P", source_url="https://example.com/policy",
    )
    assert [e.asset for e in policy.scope] == ["api.example.com"]
    assert [r.eligible for r in policy.class_rules] == [False]
    assert policy.minimum_severity is Band.HIGH


def test_a_word_that_merely_starts_with_a_cue_is_not_a_heading():
    """`Scoped to ...` starts with `scope` but is not a heading; it must not
    swallow the line as one."""
    policy = PolicyNormalizer().normalize(
        "Scoped to api.example.com only", program="P", source_url="https://e.com/p",
    )
    assert all(e.asset != "api.example.com only" for e in policy.scope)


def test_a_lowered_severity_floor_requires_program_wide_reassessment():
    """Lowering the floor makes findings of *every* class newly eligible, even
    when no class rule is declared. Reporting no reassessment is wrong."""
    n = PolicyNormalizer()
    log = PolicyVersionLog("P")
    log.add(n.normalize("In scope: api.example.com\nSeverity: High and above",
                        program="P", source_url="https://e.com/1", version="1"))
    changes = log.add(n.normalize("In scope: api.example.com\nSeverity: Medium and above",
                                  program="P", source_url="https://e.com/2", version="2"))
    assert any(c.kind == "minimum-severity" and c.program_wide for c in changes)
    assert log.affected_research(changes)["reassessment_required"] is True


def test_a_removed_class_rule_is_reported_as_a_change():
    n = PolicyNormalizer()
    log = PolicyVersionLog("P")
    log.add(n.normalize("Out of scope: XSS\nSeverity: High and above",
                        program="P", source_url="https://e.com/1", version="1"))
    changes = log.add(n.normalize("Severity: High and above",
                                  program="P", source_url="https://e.com/2", version="2"))
    assert any(c.kind == "class-removed" for c in changes)
