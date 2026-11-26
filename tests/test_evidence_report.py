"""Tests for evidence store, ledger, and report honesty."""

from __future__ import annotations

from blackheart.evidence import EvidenceStore
from blackheart.ledger import EngagementLedger
from blackheart.models import (
    Classification, Finding, GateResult, GateStatus, ReviewIndependence, Severity,
)
from blackheart.report import (
    is_submission_ready, render_report, submission_blockers, write_report,
)


def test_evidence_is_content_addressed_and_immutable(tmp_path):
    store = EvidenceStore(tmp_path / "evidence")
    a = store.put_text("hello world", kind="log", description="first")
    b = store.put_text("hello world", kind="log", description="second")
    assert a.evidence_id == b.evidence_id, "same content must map to the same id"
    assert store.verify_integrity()["ok"]


def test_evidence_tamper_is_detected(tmp_path):
    store = EvidenceStore(tmp_path / "evidence")
    ev = store.put_text("original", kind="log", description="x")
    (store.root / ev.path).write_bytes(b"tampered")
    assert not store.verify_integrity()["ok"]


def test_evidence_never_overwrites(tmp_path):
    store = EvidenceStore(tmp_path / "evidence")
    store.put_text("one", kind="log", description="x")
    store.put_text("two", kind="log", description="y")
    assert len(store.all()) == 2


def test_ledger_does_not_rerun_disproven(tmp_path):
    ledger = EngagementLedger(tmp_path / "ledger", "eng")
    ledger.add_hypothesis("h1", "first", "detail")
    ledger.add_hypothesis("h2", "second", "detail")
    ledger.set_status("h1", Classification.FALSE_POSITIVE, note="disproven")
    assert ledger.disproven_hypotheses() == {"h1"}
    assert [h["id"] for h in ledger.open_hypotheses()] == ["h2"]


def _confirmed_finding() -> Finding:
    gates = [
        GateResult(i, n, GateStatus.PASS, "ok")
        for i, n in enumerate(
            ["reachability", "control", "defense-bypass", "reproduction",
             "impact", "independent-verification", "scope"], start=1
        )
    ]
    return Finding(
        finding_id="t:1",
        title="Example finding",
        target="example",
        scope_reference="local reference target",
        classification=Classification.CONFIRMED,
        severity=Severity.HIGH.value,
        gates=gates,
        evidence_ids=["ev-1"],
    )


def test_a_forged_independence_claim_contradicting_gate_six_is_not_submittable():
    """Provenance is a claim; gate 6 is the record. A finding edited to claim an
    independent review while its own gate-6 detail says same-model must fail."""
    from blackheart.models import ReviewIndependence, gate6_detail

    finding = _confirmed_finding()
    finding.review_independence = ReviewIndependence.INDEPENDENT_MODEL
    finding.gates[5] = GateResult(
        6, "independent-verification", GateStatus.PASS,
        gate6_detail(ReviewIndependence.SAME_MODEL)[1],
    )
    assert finding.gates_pass()  # the gates alone would be fooled
    assert is_submission_ready(finding) is False
    assert any("contradicts" in b for b in submission_blockers(finding))


def test_a_gate_six_detail_claiming_independence_must_match_the_provenance():
    """The reverse direction: gate 6 says an independent model reviewed it while
    the finding records no provenance. One of the two is false, so fail closed."""
    from blackheart.models import ReviewIndependence, gate6_detail

    finding = _confirmed_finding()
    finding.review_independence = ReviewIndependence.UNRECORDED
    finding.gates[5] = GateResult(
        6, "independent-verification", GateStatus.PASS,
        gate6_detail(ReviewIndependence.INDEPENDENT_MODEL)[1],
    )
    assert is_submission_ready(finding) is False
    assert any("contradicts" in b for b in submission_blockers(finding))


def test_a_legacy_gate_six_detail_is_still_submittable():
    """Older findings carry a free-text gate-6 detail. It claims no provenance,
    so the consistency check must not block them."""
    finding = _confirmed_finding()
    assert finding.gates[5].detail == "ok"
    assert is_submission_ready(finding)


def test_an_independence_claim_on_legacy_free_text_is_refused():
    """The legacy escape hatch must not launder a *new* independence claim.

    A detail that names no provenance cannot prove one, so claiming
    ``INDEPENDENT_MODEL`` on top of it is refused rather than trusted. No producer
    writes that pairing: a real independent model always writes the canonical
    detail with the claim.
    """
    from blackheart.models import ReviewIndependence

    finding = _confirmed_finding()
    assert finding.gates[5].detail == "ok"
    finding.review_independence = ReviewIndependence.INDEPENDENT_MODEL
    assert finding.gates_pass()  # the gates alone would be fooled
    assert is_submission_ready(finding) is False
    assert any("no provenance to prove" in b for b in submission_blockers(finding))


def test_the_canonical_independence_pairing_is_submittable():
    """The positive control: claim and canonical gate-6 detail agree, so the
    provenance checks must not block it."""
    from blackheart.models import ReviewIndependence, gate6_detail

    finding = _confirmed_finding()
    finding.review_independence = ReviewIndependence.INDEPENDENT_MODEL
    finding.gates[5] = GateResult(
        6, "independent-verification", GateStatus.PASS,
        gate6_detail(ReviewIndependence.INDEPENDENT_MODEL)[1],
    )
    assert is_submission_ready(finding)
    assert submission_blockers(finding) == []


def test_an_unrecorded_provenance_is_never_described_as_an_independent_model():
    """``UNRECORDED`` may confirm -- the deterministic verifier is a real,
    model-independent review -- but no surface may call it an independent model."""
    finding = _confirmed_finding()
    assert finding.review_independence is ReviewIndependence.UNRECORDED
    assert is_submission_ready(finding)
    text = render_report(finding)
    assert "not an independent-model review" in text
    assert "independently authenticated reviewer model" not in text


def test_report_marks_confirmed_and_is_submission_ready(tmp_path):
    finding = _confirmed_finding()
    assert is_submission_ready(finding)
    text = render_report(finding, remediation="use virtual shares")
    assert "CONFIRMED" in text
    path = write_report(finding, tmp_path / "reports")
    assert path.exists()


def test_report_never_presents_a_hypothesis_as_confirmed(tmp_path):
    finding = Finding(
        finding_id="t:2",
        title="Unproven hypothesis",
        target="example",
        classification=Classification.NEEDS_MORE_EVIDENCE,
    )
    assert not is_submission_ready(finding)
    text = render_report(finding)
    assert "**Classification:** NEEDS_MORE_EVIDENCE" in text
    assert "**Classification:** CONFIRMED" not in text


def test_report_renders_the_economic_account_when_priced(tmp_path):
    """A priced finding must show its value account; an unpriced one says so."""
    finding = _confirmed_finding()
    finding.economic = {
        "attacker": "attacker",
        "attacker_profit": 42,
        "victim_loss": 40,
        "protocol_loss": 2,
        "value_created": 0,
        "conservation_residual": 0,
        "repeatable": True,
        "max_extraction": 42,
        "financial_impact_established": True,
        "tracked": True,
        "notes": ["value tracked from the target's own snapshot"],
    }
    text = render_report(finding)
    assert "## Economic account" in text
    assert "Attacker profit" in text and "42" in text
    assert "value tracked from the target's own snapshot" in text

    unpriced = render_report(_confirmed_finding())
    assert "Not priced" in unpriced



def test_report_states_the_reviewer_provenance_honestly():
    from blackheart.models import ReviewIndependence

    finding = _confirmed_finding()
    assert "deterministic verifier" in render_report(finding)

    finding.review_independence = ReviewIndependence.SAME_MODEL
    text = render_report(finding)
    assert "NOT an independent second model" in text
    assert "independently authenticated reviewer model" not in text

    finding.review_independence = ReviewIndependence.INDEPENDENT_MODEL
    assert "an independently authenticated reviewer model" in render_report(finding)


def test_a_same_model_claim_contradicting_an_independent_gate6_detail_is_refused():
    """The reverse contradiction also fails closed.

    A finding that claims ``SAME_MODEL`` while its own gate-6 detail records an
    independent-model review is inconsistent. It is already blocked (a same-model
    review is never submission-ready), and the blocker must describe the real
    problem rather than misreport it as an independence claim.
    """
    from blackheart.models import (
        Classification, Finding, GateResult, GateStatus, ReviewIndependence,
        gate6_detail,
    )
    from blackheart.report import is_submission_ready, submission_blockers

    gates = [GateResult(n, name, GateStatus.PASS, "ok")
             for n, name in enumerate(
                 ["reachability", "control", "defense-bypass", "reproduction",
                  "impact", "independent-verification", "scope"], start=1)]
    gates[5] = GateResult(
        6, "independent-verification", GateStatus.PASS,
        gate6_detail(ReviewIndependence.INDEPENDENT_MODEL)[1],
    )
    finding = Finding(
        finding_id="BH-REV", title="t", target="Vault",
        classification=Classification.CONFIRMED, gates=gates,
        evidence_ids=["ev-1"], scope_reference="https://example.test/scope",
        review_independence=ReviewIndependence.SAME_MODEL,
    )
    assert not is_submission_ready(finding)
    blockers = submission_blockers(finding)
    assert any("inconsistent" in b for b in blockers)
    assert not any(b.startswith("claimed an independent-model review") for b in blockers)
