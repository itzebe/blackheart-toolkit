"""Bounty intelligence must make evidence-grounded, program-specific decisions.

Each test attacks one failure mode the mission names: a fabricated policy, an
incorrect source URL, an expired snapshot, a missing severity definition,
conflicting payouts, in- vs out-of-scope assets, explicit exclusions, duplicates,
known issues, valid-but-non-payable findings, **payable Low and Medium findings**,
unverified eligibility, incomplete proof, misrepresented reproduction, manipulated
provenance, a generic confidence threshold that would suppress an eligible
finding, and a policy update that improperly rewrites history.

The most important guarantee: a valid finding is never called invalid merely
because it is not payable, and a payable Low/Medium is never suppressed.
"""

from __future__ import annotations

import pytest

from blackheart.bounty import (
    BountyLedger,
    Evaluation,
    Outcome,
    PolicySnapshot,
    ProgramPolicy,
    Severity,
    evaluate,
    prepare_submission,
    reevaluate,
    sha256_text,
    severity_for,
)
from blackheart.models import (
    Classification,
    Finding,
    GateResult,
    GateStatus,
    ReviewIndependence,
)


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

POLICY_TEXT = """Official program scope: vault and router contracts in scope.
Severity: critical/reentrancy -> critical. Excluded: self-xss.
Payouts: low $500, medium $2000, high $10000, critical $50000."""


def _snapshot(**kw):
    base = dict(
        program="Acme", source_url="https://acme.example/scope",
        retrieved_at="2026-01-01T00:00:00+00:00",
        sha256=sha256_text(POLICY_TEXT), captured_text=POLICY_TEXT,
        revision="rev-1",
    )
    base.update(kw)
    return PolicySnapshot(**base)


def _policy(**kw):
    base = dict(
        program="Acme", snapshot=_snapshot(),
        assets={"vault": "in_scope", "router": "in_scope", "old": "out_of_scope"},
        excluded_classes=["self-xss"],
        severity_definitions={"reentrancy": "critical"},
        payouts={"low": "$500", "medium": "$2000", "high": "$10000", "critical": "$50000"},
        minimum_severity="",
        known_issues=[],
        poc_required=True,
    )
    base.update(kw)
    return ProgramPolicy(**base)


def _gates():
    from blackheart.models import gate6_detail
    gates = [GateResult(gate=i, name=f"gate-{i}", status=GateStatus.PASS)
             for i in range(1, 6)]
    # Gate 6 must carry the canonical provenance detail, or the report layer
    # (correctly) refuses to read the finding as independently reviewed.
    status, detail = gate6_detail(ReviewIndependence.INDEPENDENT_MODEL)
    gates.append(GateResult(gate=6, name="gate-6", status=status, detail=detail))
    gates.append(GateResult(gate=7, name="gate-7", status=GateStatus.PASS))
    return gates


def _finding(**kw):
    base = dict(
        finding_id="F-1", title="Reentrancy drains vault", target="vault",
        classification=Classification.CONFIRMED, severity="critical",
        category="reentrancy", impact="fund theft",
        evidence_ids=["ev-1"], reproduction_steps=["step 1", "step 2"],
        poc_path="poc.sol",
        # Submission-readiness needs a real review and all seven gates; these make
        # the fixture a genuinely ready finding so the submission boundary is the
        # only thing under test.
        scope_reference="https://acme.example/scope",
        review_independence=ReviewIndependence.INDEPENDENT_MODEL,
        gates=_gates(),
    )
    base.update(kw)
    return Finding(**base)


# --------------------------------------------------------------------------- #
# Policy provenance
# --------------------------------------------------------------------------- #

def test_verified_snapshot_requires_matching_hash():
    assert _snapshot().is_verified() is True
    # A fabricated hash that does not match the captured text is unverified.
    assert _snapshot(sha256="0" * 64).is_verified() is False
    # No source URL / date / text -> unverified.
    assert _snapshot(source_url="").is_verified() is False
    assert _snapshot(retrieved_at="").is_verified() is False
    assert _snapshot(captured_text="", sha256="").is_verified() is False


def test_unverified_policy_short_circuits_everything():
    pol = _policy(snapshot=_snapshot(sha256="0" * 64))
    ev = evaluate(_finding(), pol)
    assert ev.outcome == Outcome.POLICY_UNVERIFIED
    assert ev.payable is None            # unknown, not False
    assert ev.technically_valid is False  # we assert nothing downstream


def test_missing_source_url_is_unverified():
    ev = evaluate(_finding(), _policy(snapshot=_snapshot(source_url="")))
    assert ev.outcome == Outcome.POLICY_UNVERIFIED


# --------------------------------------------------------------------------- #
# Technical validity vs payout eligibility (kept separate)
# --------------------------------------------------------------------------- #

def test_false_positive_is_invalid():
    ev = evaluate(_finding(classification=Classification.FALSE_POSITIVE), _policy())
    assert ev.outcome == Outcome.INVALID
    assert ev.is_valid() is False


def test_unconfirmed_without_evidence_is_insufficient():
    ev = evaluate(_finding(classification=Classification.NEEDS_MORE_EVIDENCE,
                           evidence_ids=[]), _policy())
    assert ev.outcome == Outcome.INSUFFICIENT_EVIDENCE


def test_unconfirmed_with_evidence_needs_reproduction():
    ev = evaluate(_finding(classification=Classification.NEEDS_MORE_EVIDENCE), _policy())
    assert ev.outcome == Outcome.REPRODUCTION_REQUIRED


def test_valid_but_not_payable_is_not_invalid():
    """A real bug the program does not pay for is non-payable, never invalid."""
    # severity high, but this program publishes no payout for 'high' in this variant
    pol = _policy(payouts={"low": "$500", "medium": "$2000"})
    f = _finding(severity="high", category="logic", impact="griefing")
    ev = evaluate(f, pol)
    assert ev.outcome in (Outcome.VALID_BUT_NOT_PAYABLE,
                          Outcome.VALID_WITH_UNVERIFIED_ELIGIBILITY)
    assert ev.outcome != Outcome.INVALID
    assert ev.technically_valid is True


# --------------------------------------------------------------------------- #
# Payable Low and Medium (the suppression risk)
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("severity,amount", [("low", "$500"), ("medium", "$2000")])
def test_payable_low_and_medium_are_not_suppressed(severity, amount):
    f = _finding(severity=severity, category="logic", impact="minor griefing")
    ev = evaluate(f, _policy())
    assert ev.outcome == Outcome.VALID_AND_PAYABLE
    assert ev.severity == severity
    assert ev.payable is True


def test_below_minimum_severity_is_valid_but_not_payable():
    pol = _policy(minimum_severity="high")
    f = _finding(severity="low", category="logic", impact="minor")
    ev = evaluate(f, pol)
    assert ev.outcome == Outcome.VALID_BUT_NOT_PAYABLE
    assert ev.technically_valid is True      # still a real bug
    assert ev.payable is False


def test_no_numeric_confidence_input_can_suppress():
    """evaluate() takes no confidence score -- the only inputs are finding+policy."""
    import inspect
    params = list(inspect.signature(evaluate).parameters)
    assert params == ["finding", "policy"]
    for forbidden in ("confidence", "score", "threshold", "cvss"):
        assert forbidden not in params


# --------------------------------------------------------------------------- #
# Scope
# --------------------------------------------------------------------------- #

def test_out_of_scope_asset():
    ev = evaluate(_finding(target="old"), _policy())
    assert ev.outcome == Outcome.OUT_OF_SCOPE
    assert ev.in_scope is False


def test_unlisted_asset_is_unverified_not_out_of_scope():
    ev = evaluate(_finding(target="unknown-contract"), _policy())
    assert ev.outcome == Outcome.VALID_WITH_UNVERIFIED_ELIGIBILITY
    assert ev.in_scope is None


def test_excluded_class():
    f = _finding(title="Self-XSS in profile", category="self-xss", impact="none")
    ev = evaluate(f, _policy())
    assert ev.outcome == Outcome.EXCLUDED_BY_POLICY
    assert "self-xss" in ev.exclusions


def test_known_issue():
    pol = _policy(known_issues=["reentrancy drains vault"])
    ev = evaluate(_finding(), pol)
    assert ev.outcome == Outcome.DUPLICATE_OR_KNOWN


# --------------------------------------------------------------------------- #
# Severity resolution
# --------------------------------------------------------------------------- #

def test_program_severity_definition_wins():
    sev, reason = severity_for(_policy(), _finding(severity="low"))
    assert sev == "critical"                 # program says reentrancy -> critical
    assert "program severity definition" in reason


def test_missing_severity_definition_is_unverified():
    pol = _policy(severity_definitions={}, payouts={})
    ev = evaluate(_finding(severity="weird"), pol)
    assert ev.outcome == Outcome.VALID_WITH_UNVERIFIED_ELIGIBILITY
    assert ev.severity == ""


def test_severity_rank_order():
    assert Severity.rank("low") < Severity.rank("medium") < Severity.rank("high") < Severity.rank("critical")
    assert Severity.rank("info") == -1


# --------------------------------------------------------------------------- #
# Payout
# --------------------------------------------------------------------------- #

def test_zero_payout_is_not_payable():
    pol = _policy(payouts={"critical": "$0"})
    ev = evaluate(_finding(), pol)
    assert ev.outcome == Outcome.VALID_BUT_NOT_PAYABLE
    assert ev.payable is False


def test_full_payable_path():
    ev = evaluate(_finding(), _policy())
    assert ev.outcome == Outcome.VALID_AND_PAYABLE
    assert ev.payable is True and ev.in_scope is True and ev.technically_valid is True
    assert ev.policy_sha256 == sha256_text(POLICY_TEXT)


# --------------------------------------------------------------------------- #
# Policy change: history is preserved, not rewritten
# --------------------------------------------------------------------------- #

def test_policy_update_appends_and_preserves_history(tmp_path):
    ledger = BountyLedger(tmp_path / "bounty")
    f = _finding()
    old_pol = _policy()
    ev1 = reevaluate(f, old_pol, ledger)

    # A new official policy: reentrancy now medium, payout medium only.
    new_text = "New policy: reentrancy -> medium. Payouts: medium $2000."
    new_pol = _policy(
        snapshot=_snapshot(retrieved_at="2026-02-01T00:00:00+00:00",
                          sha256=sha256_text(new_text), captured_text=new_text,
                          revision="rev-2"),
        severity_definitions={"reentrancy": "medium"},
        payouts={"medium": "$2000"},
    )
    ev2 = reevaluate(f, new_pol, ledger)

    # Both evaluations survive; the old one is unchanged.
    history = ledger.for_finding(f.finding_id)
    assert len(history) == 2
    assert ev1.policy_sha256 == sha256_text(POLICY_TEXT)
    assert ev2.policy_sha256 == sha256_text(new_text)
    assert ev2.supersedes.startswith(ev1.policy_sha256[:12])
    # The first decision still reads as it was made.
    assert ev1.severity == "critical"
    assert ev2.severity == "medium"


def test_reevaluation_does_not_mutate_prior_record(tmp_path):
    ledger = BountyLedger(tmp_path / "bounty")
    f = _finding()
    reevaluate(f, _policy(), ledger)
    before = ledger.all()[0].to_dict()

    new_text = "changed"
    reevaluate(f, _policy(snapshot=_snapshot(
        sha256=sha256_text(new_text), captured_text=new_text)), ledger)
    after = ledger.for_finding(f.finding_id)[0].to_dict()
    assert before == after


def test_ledger_is_hash_chained(tmp_path):
    ledger = BountyLedger(tmp_path / "bounty")
    for i in range(4):
        reevaluate(_finding(finding_id=f"F-{i}"), _policy(), ledger)
    assert ledger.verify_integrity()["status"] == "VERIFIED"


# --------------------------------------------------------------------------- #
# Submission boundary
# --------------------------------------------------------------------------- #

def test_submission_is_prepared_but_not_submitted():
    f = _finding()
    ev = evaluate(f, _policy())
    pkg = prepare_submission(f, ev)
    assert pkg["submission_allowed"] is True
    assert "never submits" in pkg["note"]
    assert pkg["policy_sha256"] == sha256_text(POLICY_TEXT)


def test_non_payable_blocks_submission():
    f = _finding(target="old")               # out of scope
    ev = evaluate(f, _policy())
    pkg = prepare_submission(f, ev)
    assert pkg["submission_allowed"] is False
    assert pkg["blockers"]


def test_misrepresented_evidence_is_not_submission_ready():
    """A CONFIRMED finding with no evidence ids is not submission-ready."""
    f = _finding(evidence_ids=[])
    # Force a payable evaluation to reach the submission gate itself.
    ev = evaluate(f, _policy())
    pkg = prepare_submission(f, ev)
    assert pkg["submission_allowed"] is False


# --------------------------------------------------------------------------- #
# Class matching must be token-aware, not substring
# --------------------------------------------------------------------------- #

def test_exclusion_does_not_match_inside_an_unrelated_word():
    """'rce' must not exclude 'resource-exhaustion'.

    Substring matching would silently drop a genuine finding as excluded -- the
    exact false-negative this module exists to prevent.
    """
    f = _finding(title="Memory exhaustion in queue", category="resource-exhaustion",
                 severity="high")
    ev = evaluate(f, _policy(excluded_classes=["rce"]))
    assert ev.outcome != Outcome.EXCLUDED_BY_POLICY
    assert ev.outcome == Outcome.VALID_AND_PAYABLE


def test_exclusion_matches_a_real_class_phrase():
    f = _finding(title="Remote code execution in vault", category="rce",
                 severity="critical")
    ev = evaluate(f, _policy(excluded_classes=["rce"]))
    assert ev.outcome == Outcome.EXCLUDED_BY_POLICY
    assert ev.exclusions == ["rce"]


def test_multiword_exclusion_matches_across_separators():
    """'self xss' must match the hyphenated class 'self-xss'."""
    f = _finding(title="Self-XSS in profile", category="self-xss", severity="low")
    ev = evaluate(f, _policy(excluded_classes=["self xss"]))
    assert ev.outcome == Outcome.EXCLUDED_BY_POLICY


def test_known_issue_does_not_match_inside_an_unrelated_word():
    f = _finding(title="Fee rounding", category="rounding", severity="low")
    ev = evaluate(f, _policy(known_issues=["fee on transfer"]))
    assert ev.outcome != Outcome.DUPLICATE_OR_KNOWN


def test_known_issue_matches_its_phrase():
    f = _finding(title="Fee on transfer breaks accounting", category="fee",
                 severity="high")
    ev = evaluate(f, _policy(known_issues=["fee on transfer"]))
    assert ev.outcome == Outcome.DUPLICATE_OR_KNOWN
