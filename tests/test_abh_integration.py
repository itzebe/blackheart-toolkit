"""Tests for the Agentic-Bug-Hunter-derived capabilities integrated into BLACKHEART.

Two capabilities are covered:

  1. The deterministic scope matcher (``blackheart.authz.scope_matcher``), an
     adapted port of ABH's ``scope_checker.py``. Positive cases (a URL that
     should be authorized), negative cases (subdomain confusion, encoding
     tricks, public-suffix wildcards), and fail-closed behaviour.
  2. The deterministic weak-finding gate (``blackheart.verify.triage``), an
     adapted port of ABH's triage tables. Positive cases (a strong finding
     passes), negative cases (a weak/never-submit class is rejected), the
     chain-required downgrade, and integration with the report submission gate.

Plus integration tests proving the scope matcher feeds BLACKHEART's existing
authorization gate and the triage gate feeds the report gate, and that the
existing (pre-integration) behaviour is unchanged.
"""

from __future__ import annotations

import pytest

from blackheart.authz import (
    authorize_active_testing,
    classify_asset_by_pattern,
    new_record,
)
from blackheart.authz.scope_matcher import (
    ScopeMatcher,
    ScopePatternError,
)
from blackheart.models import AssetStatus, Classification, Finding
from blackheart.report import is_submission_ready
from blackheart.verify.triage import (
    CHAIN_REQUIRED,
    Evidence,
    TriageGate,
)

# --------------------------------------------------------------------------- #
# Scope matcher — positive cases
# --------------------------------------------------------------------------- #

def test_exact_host_is_in_scope():
    m = ScopeMatcher(allow=["target.com"])
    assert m.is_in_scope("target.com")
    assert m.is_in_scope("https://target.com/path")


def test_wildcard_matches_subdomain():
    m = ScopeMatcher(allow=["*.target.com"])
    assert m.is_in_scope("api.target.com")
    assert m.is_in_scope("a.b.target.com")


def test_cidr_matches_ip_in_range():
    m = ScopeMatcher(allow=["10.0.0.0/24"])
    assert m.is_in_scope("10.0.0.7")
    assert not m.is_in_scope("10.0.1.7")


def test_port_constrained_pattern():
    m = ScopeMatcher(allow=["api.target.com:8443"])
    assert m.is_in_scope("https://api.target.com:8443/x")
    assert not m.is_in_scope("https://api.target.com/x")  # default 443


def test_path_prefix_pattern():
    m = ScopeMatcher(allow=["target.com/api/"])
    assert m.is_in_scope("https://target.com/api/v1")
    assert not m.is_in_scope("https://target.com/other")


def test_ipv6_cidr():
    m = ScopeMatcher(allow=["2001:db8::/32"])
    assert m.is_in_scope("2001:db8::1")


# --------------------------------------------------------------------------- #
# Scope matcher — negative cases (the reason the port exists)
# --------------------------------------------------------------------------- #

def test_wildcard_does_not_match_apex():
    m = ScopeMatcher(allow=["*.target.com"])
    assert not m.is_in_scope("target.com")


def test_wildcard_does_not_match_subdomain_confusion():
    m = ScopeMatcher(allow=["*.target.com"])
    assert not m.is_in_scope("evil-target.com")
    assert not m.is_in_scope("target.com.evil.com")


def test_exclusion_covers_subdomains():
    m = ScopeMatcher(allow=["*.target.com"], exclude=["blog.target.com"])
    assert not m.is_in_scope("blog.target.com")
    assert not m.is_in_scope("cdn.blog.target.com")


def test_backslash_encoding_trick_is_out_of_scope():
    m = ScopeMatcher(allow=["*.target.com"])
    assert not m.is_in_scope("https://target.com\\@evil.com/")


def test_userinfo_confusion_is_out_of_scope():
    m = ScopeMatcher(allow=["*.target.com"])
    assert not m.is_in_scope("https://evil.com@target.com.evil.com/")


def test_non_http_scheme_is_out_of_scope():
    m = ScopeMatcher(allow=["*.target.com"])
    assert not m.is_in_scope("ftp://api.target.com")
    assert not m.is_in_scope("javascript:alert(1)")


def test_empty_and_garbage_fail_closed():
    m = ScopeMatcher(allow=["*.target.com"])
    for bad in ["", "   ", "::::", "http://", "http:///path"]:
        assert not m.is_in_scope(bad)


def test_public_suffix_wildcard_is_refused_at_construction():
    with pytest.raises(ScopePatternError):
        ScopeMatcher(allow=["*.com"])
    with pytest.raises(ScopePatternError):
        ScopeMatcher(allow=["*.co.uk"])


def test_single_label_wildcard_is_refused():
    with pytest.raises(ScopePatternError):
        ScopeMatcher(allow=["*.local"])


def test_unusable_allow_pattern_never_widens_scope():
    # A malformed allow pattern is dropped, so it cannot accidentally match.
    m = ScopeMatcher(allow=["not a host!!"])
    assert not m.is_in_scope("anything.com")


def test_decision_records_which_rule_matched():
    m = ScopeMatcher(allow=["*.target.com"])
    d = m.explain("api.target.com")
    assert d.in_scope and d.matched_rule == "*.target.com"
    assert d.status == AssetStatus.AUTHORIZED


def test_excluded_class_helper():
    m = ScopeMatcher(allow=["*.target.com"], excluded_classes=["self-xss"])
    assert not m.is_class_allowed("self-xss")
    assert m.is_class_allowed("idor")


# --------------------------------------------------------------------------- #
# Scope matcher — integration with BLACKHEART's authorization gate
# --------------------------------------------------------------------------- #

def _rec(**kw):
    rec = new_record(
        program="P", platform="immunefi",
        target_url="https://target.com/program", scope_url="https://target.com/scope",
        program_active=True, safe_harbor=True, poc_required=True,
        nigerian_eligible=True, payout_feasible=True, zero_cost=True,
    )
    rec.verified = True
    rec.asset_classes = {}
    rec.scope_patterns = ["*.target.com"]
    rec.evidence = ["https://target.com/scope (retrieved 2026-11-15)"]
    rec.checked_at = _now_iso()
    for k, v in kw.items():
        setattr(rec, k, v)
    return rec


def _now_iso() -> str:
    from datetime import UTC, datetime
    return datetime.now(UTC).isoformat()


def test_authorize_active_testing_uses_patterns_for_unlisted_asset():
    rec = _rec()
    # Not in the exact map, but matches the recorded pattern -> authorized.
    decision = authorize_active_testing(rec, "api.target.com")
    assert decision.allowed is True
    assert decision.status == AssetStatus.AUTHORIZED
    assert any("scope pattern" in r for r in decision.reasons)


def test_authorize_active_testing_rejects_confusion_via_patterns():
    rec = _rec()
    decision = authorize_active_testing(rec, "evil-target.com")
    assert decision.allowed is False
    assert decision.status == AssetStatus.OUT_OF_SCOPE


def test_explicit_map_still_takes_precedence_over_patterns():
    rec = _rec()
    # An explicit OUT_OF_SCOPE entry overrides a matching allow pattern.
    rec.asset_classes = {"api.target.com": AssetStatus.OUT_OF_SCOPE.value}
    decision = authorize_active_testing(rec, "api.target.com")
    assert decision.allowed is False


def test_classify_by_pattern_returns_none_without_patterns():
    rec = _rec(scope_patterns=[])
    assert classify_asset_by_pattern(rec, "api.target.com") is None


def test_pattern_path_still_requires_program_checks():
    rec = _rec(payout_feasible=False)  # a program check fails
    decision = authorize_active_testing(rec, "api.target.com")
    assert decision.allowed is False
    assert decision.status == AssetStatus.AUTHORIZED  # in scope, but gate closed


# --------------------------------------------------------------------------- #
# Triage gate — positive cases
# --------------------------------------------------------------------------- #

_STRONG = [Evidence.REPRODUCED, Evidence.IN_SCOPE, Evidence.IMPACT_BEYOND_INFO]


def test_strong_idor_passes():
    v = TriageGate().evaluate("idor", _STRONG + [Evidence.CROSS_IDENTITY])
    assert v.disposition == "PASS" and not v.weak


def test_strong_xss_with_execution_passes():
    v = TriageGate().evaluate("reflected-xss", _STRONG + [Evidence.EXECUTION])
    assert v.disposition == "PASS"


def test_sqli_with_data_exfil_passes():
    v = TriageGate().evaluate("sql-injection", _STRONG + [Evidence.DATA_EXFIL])
    assert v.disposition == "PASS"


def test_open_redirect_with_chain_passes():
    v = TriageGate().evaluate("open-redirect", _STRONG + [Evidence.AUTH_CODE_THEFT])
    assert v.disposition == "PASS"


# --------------------------------------------------------------------------- #
# Triage gate — negative cases (must reject weak/false-positive findings)
# --------------------------------------------------------------------------- #

def test_xss_without_execution_is_rejected():
    v = TriageGate().evaluate("reflected-xss", _STRONG)
    assert v.reject and any(s["id"] == "xss-no-execution" for s in v.kill_signals)


def test_idor_on_own_data_is_rejected():
    v = TriageGate().evaluate("idor", _STRONG)
    assert v.reject and any(s["id"] == "idor-own-data" for s in v.kill_signals)


def test_ssrf_dns_only_is_downgraded():
    # SSRF with only a DNS callback is chain-conditional (needs internal data),
    # so it is downgraded rather than hard-rejected.
    v = TriageGate().evaluate("ssrf", _STRONG)
    assert v.downgrade and not v.reject
    assert any(s["id"] == "ssrf-dns-only" for s in v.kill_signals)


def test_sqli_error_only_is_rejected():
    v = TriageGate().evaluate("sqli", _STRONG)
    assert v.reject


def test_never_submit_class_is_rejected():
    v = TriageGate().evaluate("missing-csp", _STRONG)
    assert v.reject and any(s["id"].startswith("never-submit") for s in v.kill_signals)


def test_missing_universal_evidence_is_rejected():
    v = TriageGate().evaluate("idor", [Evidence.CROSS_IDENTITY])  # not reproduced
    assert v.reject and any(s["id"] == "universal-reproduced" for s in v.kill_signals)


def test_unreproduced_finding_is_rejected_even_for_a_strong_class():
    v = TriageGate().evaluate("idor", [Evidence.IN_SCOPE, Evidence.CROSS_IDENTITY,
                                       Evidence.IMPACT_BEYOND_INFO])
    assert v.reject


# --------------------------------------------------------------------------- #
# Triage gate — chain-required downgrade
# --------------------------------------------------------------------------- #

def test_open_redirect_alone_is_downgraded_not_passed():
    v = TriageGate().evaluate("open-redirect", _STRONG)
    assert v.downgrade and not v.reject
    assert v.chain_required == CHAIN_REQUIRED["open-redirect"]


def test_chain_demonstrated_clears_the_downgrade():
    v = TriageGate().evaluate("open-redirect", _STRONG, chain_demonstrated=True)
    assert v.disposition == "PASS"


def test_cors_wildcard_downgraded_without_credentialed_exfil():
    v = TriageGate().evaluate("cors-wildcard", _STRONG)
    assert v.downgrade


# --------------------------------------------------------------------------- #
# Triage gate — integration with the report submission gate
# --------------------------------------------------------------------------- #

def _confirmed_finding(category: str, evidence_tags: list[str]) -> Finding:
    from blackheart.models import GateResult, GateStatus

    f = Finding(finding_id="F-1", title="t", target="api.target.com",
                component="c", scope_reference="https://target.com/scope",
                classification=Classification.CONFIRMED, category=category,
                evidence_tags=evidence_tags)
    f.gates = [GateResult(i, n, GateStatus.PASS, "ok")
               for i, n in enumerate(
                   ["reachability", "control", "defense-bypass", "reproduction",
                    "impact", "independent-verification", "scope"], start=1)]
    return f


def test_confirmed_finding_of_a_weak_class_is_not_submission_ready():
    # Technically confirmed and in scope, but a kill-signal class -> blocked.
    f = _confirmed_finding("reflected-xss", _STRONG)
    assert is_submission_ready(f) is False


def test_confirmed_strong_finding_is_submission_ready():
    f = _confirmed_finding("idor", _STRONG + [Evidence.CROSS_IDENTITY])
    assert is_submission_ready(f) is True


def test_finding_without_evidence_tags_is_unchanged():
    # No tags -> the triage gate is not consulted; legacy behaviour preserved.
    f = _confirmed_finding("reflected-xss", [])
    assert is_submission_ready(f) is True


def test_submission_blockers_names_the_triage_rejection():
    from blackheart.report import submission_blockers

    f = _confirmed_finding("reflected-xss", _STRONG)
    blockers = submission_blockers(f)
    assert any("triage gate rejected" in b for b in blockers)


# --------------------------------------------------------------------------- #
# Adversarial: a chain-required weak class cannot bypass triage via the gate
# --------------------------------------------------------------------------- #

def test_chain_required_finding_is_not_submission_ready_without_the_chain():
    # open-redirect is only payable with an auth-code-theft chain. Without it the
    # gate must block submission -- not silently pass a downgraded finding.
    f = _confirmed_finding("open-redirect", _STRONG)
    assert is_submission_ready(f) is False
    from blackheart.report import submission_blockers
    assert any("downgraded" in b for b in submission_blockers(f))


def test_chain_required_finding_with_the_chain_is_submission_ready():
    f = _confirmed_finding("open-redirect", _STRONG + [Evidence.AUTH_CODE_THEFT])
    assert is_submission_ready(f) is True


# --------------------------------------------------------------------------- #
# A same-model review can never be submission-ready, even with all gates PASS
# --------------------------------------------------------------------------- #

def test_same_model_review_is_never_submission_ready():
    from blackheart.models import ReviewIndependence
    from blackheart.report import submission_blockers

    f = _confirmed_finding("idor", _STRONG + [Evidence.CROSS_IDENTITY])
    assert is_submission_ready(f) is True  # baseline: this one is submittable

    f.review_independence = ReviewIndependence.SAME_MODEL
    assert is_submission_ready(f) is False
    assert any("not independent verification" in b
               for b in submission_blockers(f))


def test_an_unrecognised_provenance_is_never_submission_ready():
    """A bogus provenance string must fail closed, not slip past the SAME_MODEL check."""
    from blackheart.models import ReviewIndependence
    from blackheart.report import submission_blockers

    f = _confirmed_finding("idor", _STRONG + [Evidence.CROSS_IDENTITY])
    f.review_independence = "bogus"  # a raw string, bypassing from_dict coercion
    assert is_submission_ready(f) is False
    assert any("not independent verification" in b
               for b in submission_blockers(f))


def test_cors_wildcard_without_credentialed_exfil_is_not_submission_ready():
    f = _confirmed_finding("cors-wildcard", _STRONG)
    assert is_submission_ready(f) is False


def test_never_submit_class_cannot_bypass_via_the_report_gate():
    f = _confirmed_finding("missing-csp", _STRONG)
    assert is_submission_ready(f) is False


# --------------------------------------------------------------------------- #
# Adversarial: scope matcher host/URL ambiguity cases
# --------------------------------------------------------------------------- #

def test_trailing_root_dot_is_the_same_host():
    m = ScopeMatcher(allow=["target.com"])
    assert m.is_in_scope("target.com.") is True


def test_case_is_normalized():
    m = ScopeMatcher(allow=["target.com"])
    assert m.is_in_scope("TARGET.COM") is True


def test_ipv4_alternate_encodings_fail_closed():
    # Decimal/octal/hex integer forms of an in-scope IP must not be accepted as
    # if they were the dotted-quad, and must not be silently coerced into scope.
    m = ScopeMatcher(allow=["10.0.0.0/8"])
    for enc in ["0x0a000001", "167772161", "012.0.0.1", "10.0.0.1.5"]:
        d = m.explain(enc)
        assert d.in_scope is False, enc


def test_malformed_hostname_fails_closed():
    m = ScopeMatcher(allow=["*.target.com"])
    for bad in ["", "   ", "..", ".target.com", "target..com", "a b.target.com"]:
        assert m.is_in_scope(bad) is False, bad


def test_userinfo_cannot_smuggle_an_authorized_host():
    # https://target.com@evil.com connects to evil.com; it must not be in scope.
    m = ScopeMatcher(allow=["*.target.com"])
    assert m.is_in_scope("https://target.com@evil.com/") is False
    assert m.is_in_scope("https://evil.com#@target.com") is False


def test_exclusion_of_a_bare_host_covers_its_subdomains():
    m = ScopeMatcher(allow=["*.target.com"], exclude=["blog.target.com"])
    assert m.is_in_scope("blog.target.com") is False
    assert m.is_in_scope("cdn.blog.target.com") is False
    assert m.is_in_scope("www.target.com") is True


def test_empty_and_malformed_scope_entries_never_widen_scope():
    # Unusable allow patterns are skipped, so scope never widens by accident.
    m = ScopeMatcher(allow=["", "   ", "://", "target.com:notaport"])
    assert m.is_in_scope("target.com") is False


# --------------------------------------------------------------------------- #
# Regression: the upstream MIT notice is preserved
# --------------------------------------------------------------------------- #
def test_mit_notice_preserved_in_ported_modules():
    import blackheart.authz.scope_matcher as sm
    import blackheart.verify.triage as tg

    assert "Claude Bug Bounty Hunter Contributors" in sm.__doc__
    assert "MIT License" in sm.__doc__
    assert "Claude Bug Bounty Hunter Contributors" in tg.__doc__
    assert "MIT License" in tg.__doc__


# --------------------------------------------------------------------------- #
# Duplicate-finding handling (ABH triage: dedup before writing a report)
# --------------------------------------------------------------------------- #

def test_duplicate_finding_is_linked_not_reported_as_new():
    import tempfile

    from blackheart.findings import FindingRecord, FindingRepository

    repo = FindingRepository(tempfile.mkdtemp())
    r1 = repo.add(FindingRecord(
        finding_id="F-1", title="IDOR on orders", target="api.target.com",
        component="orders", design_mistake="missing object-level authorization"))
    r2 = FindingRecord(
        finding_id="F-2", title="IDOR read on orders endpoint", target="api.target.com",
        component="orders", design_mistake="missing object-level authorization")
    dups = repo.find_duplicates(r2)
    assert [d.finding_id for d in dups] == [r1.finding_id]


def test_shared_symptom_is_not_auto_merged_as_a_duplicate():
    # ABH's rule, preserved: a shared *symptom* is not a shared root cause.
    import tempfile

    from blackheart.findings import FindingRecord, FindingRepository

    repo = FindingRepository(tempfile.mkdtemp())
    repo.add(FindingRecord(
        finding_id="F-1", title="IDOR on orders", target="api.target.com",
        component="orders", design_mistake="missing object-level authorization"))
    other = FindingRecord(
        finding_id="F-2", title="IDOR on invoices", target="api.target.com",
        component="invoices", design_mistake="missing object-level authorization")
    assert repo.find_duplicates(other) == []
