"""Tests for the mandatory pre-submission novelty gate (mission Phase 2 & 3).

The gate exists because OSS-001 was a real, reproducible vulnerability that was
rejected as a duplicate. These tests pin the behaviour that would have caught it.
"""

from __future__ import annotations

from pathlib import Path

from blackheart.models import (
    Classification,
    Finding,
    GateResult,
    GateStatus,
    NoveltyClass,
    NoveltyReview,
    PublicDisclosure,
)
from blackheart.novelty import (
    MIN_QUERIES_FOR_NOVELTY,
    MIN_SOURCES_FOR_NOVELTY,
    NoveltyGate,
    evaluate_novelty,
    match_disclosure,
)
from blackheart.report import is_submission_ready_with_novelty


def _oss001_candidate() -> NoveltyReview:
    return NoveltyReview(
        finding_id="OSS-001",
        target="some/oss-project",
        vulnerability_class="github-actions-workflow-run-artifact-checkout",
        root_cause=(
            "workflow_run continuation checks out a repository/ref from a downloaded "
            "artifact without binding it to github.repository"
        ),
        affected_component="GitHub Actions workflow_run continuation jobs",
        trust_boundary="untrusted fork artifact -> privileged base-repo workflow_run context",
        exploit_path="fork PR artifact checked out and executed in the privileged continuation",
        impact="code execution in a privileged workflow with write token and secrets",
    )


def _oss001_disclosure() -> PublicDisclosure:
    return PublicDisclosure(
        source="github-advisory",
        identifier="known-workflow_run-artifact-checkout",
        url="https://example.invalid/advisory",
        summary="the same workflow_run artifact-checkout class already reported",
        root_cause=(
            "workflow_run continuation checks out artifact repository ref without "
            "binding to github.repository"
        ),
        affected_component="GitHub Actions workflow_run continuation jobs",
        trust_boundary="untrusted fork artifact to privileged workflow_run context",
        exploit_path="fork PR artifact checked out and executed in privileged continuation",
        impact="code execution in privileged workflow with secrets",
    )


# --------------------------------------------------------------------------- #
# The decisive rule: same root cause + same component == duplicate
# --------------------------------------------------------------------------- #

def test_same_root_cause_and_component_is_a_duplicate_despite_new_technique():
    review = _oss001_candidate()
    review.disclosures = [_oss001_disclosure()]
    review.databases_searched = ["GHSA", "issues", "PRs", "advisories"]
    review.queries = ["workflow_run artifact checkout", "pwn request", "untrusted continuation"]
    evaluate_novelty(review)
    assert review.classification == NoveltyClass.LIKELY_DUPLICATE.value
    assert not review.is_submittable()


def test_duplicate_with_remediation_is_already_fixed():
    review = _oss001_candidate()
    disc = _oss001_disclosure()
    disc.remediation = "checkout is now pinned to github.repository in the continuation"
    review.disclosures = [disc]
    review.databases_searched = ["a", "b", "c", "d"]
    review.queries = ["x", "y", "z"]
    evaluate_novelty(review)
    assert review.classification == NoveltyClass.ALREADY_FIXED.value
    assert not review.is_submittable()


def test_exact_match_is_a_duplicate():
    review = _oss001_candidate()
    disc = _oss001_disclosure()
    disc.root_cause = review.root_cause
    disc.affected_component = review.affected_component
    disc.trust_boundary = review.trust_boundary
    disc.exploit_path = review.exploit_path
    disc.impact = review.impact
    review.disclosures = [disc]
    evaluate_novelty(review)
    assert review.classification == NoveltyClass.LIKELY_DUPLICATE.value


# --------------------------------------------------------------------------- #
# Absence of a public result is NOT proof of novelty
# --------------------------------------------------------------------------- #

def test_thin_search_is_insufficient_evidence_not_novel():
    review = _oss001_candidate()
    review.databases_searched = ["google"]          # 1 < MIN_SOURCES
    review.queries = ["one query"]                  # 1 < MIN_QUERIES
    review.disclosures = []
    evaluate_novelty(review)
    assert review.classification == NoveltyClass.INSUFFICIENT_EVIDENCE.value
    assert not review.is_submittable()


def test_adequate_search_with_no_match_is_likely_new():
    review = _oss001_candidate()
    review.root_cause = "a unique bespoke root cause xyzzy plugh"
    review.affected_component = "a component never reported before zorkmid"
    review.disclosures = [_oss001_disclosure()]  # unrelated enough
    review.databases_searched = ["GHSA", "NVD", "issues", "advisories"]
    review.queries = ["q1", "q2", "q3"]
    evaluate_novelty(review)
    assert review.classification in (
        NoveltyClass.LIKELY_NEW.value, NoveltyClass.POSSIBLE_VARIANT.value
    )
    assert review.is_submittable()


def test_partial_match_is_a_possible_variant():
    review = _oss001_candidate()
    disc = _oss001_disclosure()
    disc.root_cause = "a completely different mechanism with no overlap at all"
    disc.affected_component = "GitHub Actions workflow_run continuation jobs"  # same component
    disc.trust_boundary = "untrusted fork artifact to privileged workflow_run context"  # same
    disc.exploit_path = "unrelated"
    disc.impact = "code execution in privileged workflow with secrets"  # same
    review.disclosures = [disc]
    review.databases_searched = ["GHSA", "NVD", "issues", "advisories"]
    review.queries = ["q1", "q2", "q3"]
    evaluate_novelty(review)
    assert review.classification == NoveltyClass.POSSIBLE_VARIANT.value


# --------------------------------------------------------------------------- #
# The gate composes with the technical gate and fails closed
# --------------------------------------------------------------------------- #

def _confirmed_finding() -> Finding:
    f = Finding(finding_id="F1", title="t", target="tgt")
    f.classification = Classification.CONFIRMED
    f.scope_reference = "https://scope#1"
    f.gates = [GateResult(i, n, GateStatus.PASS, "") for i, (n, _) in enumerate(
        [("reachability", ""), ("control", ""), ("defense", ""), ("reproduction", ""),
         ("impact", ""), ("independent", ""), ("scope", "")], start=1)]
    return f


def test_gate_refuses_submission_without_a_review():
    gate = NoveltyGate()
    allowed, reason = gate.allows_submission("F1")
    assert not allowed
    assert "no novelty review" in reason


def test_gate_refuses_duplicate_even_when_technically_confirmed():
    gate = NoveltyGate()
    review = _oss001_candidate()
    review.finding_id = "F1"
    review.disclosures = [_oss001_disclosure()]
    review.databases_searched = ["a", "b", "c", "d"]
    review.queries = ["x", "y", "z"]
    gate.record(review)
    allowed, reason = is_submission_ready_with_novelty(_confirmed_finding(), gate)
    assert not allowed
    assert "duplicate" in reason.lower() or "LIKELY_DUPLICATE" in reason


def test_gate_allows_likely_new_when_technically_confirmed():
    gate = NoveltyGate()
    review = _oss001_candidate()
    review.finding_id = "F1"
    review.root_cause = "unique mechanism zzz"
    review.affected_component = "unique component zzz"
    review.disclosures = []
    review.databases_searched = ["GHSA", "NVD", "issues", "advisories"]
    review.queries = ["q1", "q2", "q3"]
    gate.record(review)
    allowed, _ = is_submission_ready_with_novelty(_confirmed_finding(), gate)
    assert allowed


def test_gate_refuses_when_technical_gate_fails():
    gate = NoveltyGate()
    review = _oss001_candidate()
    review.finding_id = "F1"
    review.databases_searched = ["a", "b", "c", "d"]
    review.queries = ["x", "y", "z"]
    gate.record(review)
    f = _confirmed_finding()
    f.classification = Classification.NEEDS_MORE_EVIDENCE
    allowed, reason = is_submission_ready_with_novelty(f, gate)
    assert not allowed
    assert "technically not submission-ready" in reason


def test_minimums_are_above_one():
    # The thresholds exist precisely so "I searched once and found nothing"
    # cannot be read as novelty.
    assert MIN_SOURCES_FOR_NOVELTY > 1
    assert MIN_QUERIES_FOR_NOVELTY > 1


def test_match_disclosure_reports_shared_fields():
    m = match_disclosure(_oss001_candidate(), _oss001_disclosure())
    assert "affected_component" in m.shared
    assert m.field_sims["affected_component"] >= 0.5


def test_reviews_persist_across_a_restart(tmp_path):
    gate = NoveltyGate()
    review = _oss001_candidate()
    review.finding_id = "F1"
    review.disclosures = [_oss001_disclosure()]
    review.databases_searched = ["a", "b", "c", "d"]
    review.queries = ["x", "y", "z"]
    gate.record(review)
    gate.save(tmp_path)

    reloaded = NoveltyGate.load(tmp_path)
    allowed, reason = reloaded.allows_submission("F1")
    assert not allowed
    assert "duplicate" in reason.lower() or "LIKELY_DUPLICATE" in reason


def test_missing_persistence_directory_is_not_an_error(tmp_path):
    gate = NoveltyGate.load(tmp_path / "does-not-exist")
    assert gate.all_reviews() == []
