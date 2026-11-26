"""The official bounty policy must be the only authority on eligibility.

Each test attacks one way a submission decision could go wrong: an internal score
standing in for the program's rules, a high score buying eligibility the policy
denies, a low score suppressing a valid Low/Medium, an invented decision when the
policy is missing, deployment evidence assumed rather than shown, a submission
package without traceable policy provenance, a policy change rewriting history,
and existing candidate records being lost.

The load-bearing guarantee: ``gate`` never reads ``research_score``. Eligibility
is decided by the published policy, and a candidate with no verified policy
snapshot is BLOCKED rather than guessed.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

import pytest

from blackheart import doctrine
from blackheart.bounty import (
    BountyLedger,
    CandidateRecord,
    Disposition,
    Evaluation,
    Outcome,
    POLICY_UNVERIFIED_BLOCKER,
    PolicySnapshot,
    ProgramPolicy,
    assert_submission_ready,
    disposition_for,
    evaluate,
    gate_candidate,
    prepare_submission,
    reevaluate,
    sha256_text,
)
from blackheart.bounty.gate import SUBMISSION_READY_REQUIRES
from blackheart.cli import main as cli_main
from blackheart.models import Classification, Finding

ARCHIVE = Path(__file__).resolve().parent.parent / "findings" / "informational-recovery"

POLICY_TEXT = (
    "Official program scope: vault and router in scope, old is out of scope.\n"
    "Excluded: self-xss.\n"
    "Severity: reentrancy -> critical.\n"
    "Payouts: low $500, medium $2000, high $10000, critical $50000.\n"
)


def _record(**kw) -> CandidateRecord:
    """A candidate that satisfies every gate. Tests change one field at a time."""
    base = dict(
        candidate_id="C-1",
        target="vault",
        component="Vault.sol",
        program="Acme",
        policy_url="https://acme.example/scope",
        policy_verified_at="2026-01-01T00:00:00Z",
        policy_revision="rev-1",
        policy_sha256=sha256_text(POLICY_TEXT),
        policy_text=POLICY_TEXT,
        in_scope_assets=["vault", "router"],
        out_of_scope_assets=["old"],
        exclusions=["self-xss"],
        severity_criteria={"reentrancy": "critical"},
        required_impact="fund theft from an in-scope contract",
        reward_conditions="low $500 / medium $2000 / high $10000 / critical $50000",
        demonstrated_impact="drains the vault",
        attacker_prerequisites=["unprivileged user"],
        reproduction_status="CONFIRMED",
        evidence_refs=["ev/run.txt"],
        root_cause="missing access check",
        affected_deployment="0xvault on mainnet",
        deployment_verified=True,
        deployment_truth={
            "status": "SOURCE_VERIFIED",
            "address": "0x" + "1" * 40,
            "chain_id": 1,
            "source_status": "verified",
            "source_bound": True,
            "runtime_binding": {"status": "EXACT", "bound": True},
        },
        asset_scope="in_scope",
        vulnerability_class="reentrancy",
        program_severity="medium",
        impact_meets_policy=True,
        known_or_fixed=False,
        duplicate_check="no public report",
        remediation_check="unfixed",
        reward_available=True,
        expected_payout="$2000",
        policy_sections=["Scope > In scope", "Rewards > Medium"],
        research_score=65,
    )
    base.update(kw)
    return CandidateRecord(**base)


# --------------------------------------------------------------------------- #
# 1-6: the score never decides eligibility
# --------------------------------------------------------------------------- #

def test_a_candidate_scoring_65_can_be_submission_ready():
    out = gate_candidate(_record(research_score=65))
    assert out.disposition == Disposition.SUBMISSION_READY
    assert out.submission_ready is True
    assert out.blockers == []


def test_a_candidate_scoring_95_is_rejected_when_the_policy_excludes_the_class():
    out = gate_candidate(_record(research_score=95, vulnerability_class="self-xss"))
    assert out.disposition == Disposition.VALID_NOT_PAYABLE
    assert out.submission_ready is False
    assert "excluded by policy" in out.blockers[0]


def test_missing_policy_produces_blocked_not_a_guess():
    out = gate_candidate(_record(policy_sha256="", policy_text=""))
    assert out.disposition == Disposition.NOT_ASSESSED
    assert out.policy_verified is False
    assert out.blockers[0] == POLICY_UNVERIFIED_BLOCKER
    assert out.policy_evidence["sha256"] == ""


def test_a_fabricated_policy_hash_is_blocked():
    # A hash that does not match the captured text proves nothing.
    out = gate_candidate(_record(policy_sha256="0" * 64))
    assert out.disposition == Disposition.NOT_ASSESSED
    assert out.blockers[0] == POLICY_UNVERIFIED_BLOCKER


def test_out_of_scope_asset_cannot_become_submission_ready_through_a_high_score():
    out = gate_candidate(_record(asset_scope="out_of_scope", research_score=100))
    assert out.disposition == Disposition.VALID_NOT_PAYABLE
    assert out.submission_ready is False
    assert "out of scope" in out.blockers[0]


def test_a_valid_medium_finding_is_not_rejected_by_a_numeric_threshold():
    out = gate_candidate(_record(program_severity="medium", research_score=10))
    assert out.disposition == Disposition.SUBMISSION_READY
    assert "medium" in " ".join(out.reasons)


def test_severity_is_evaluated_independently_of_the_score():
    low = gate_candidate(_record(research_score=0))
    high = gate_candidate(_record(research_score=100))
    assert low.disposition == high.disposition
    assert low.blockers == high.blockers
    assert low.reasons == high.reasons


@pytest.mark.parametrize("score", [None, -1000.0, 0.0, 42.5, 65.0, 100.0,
                                   1e9, float("nan"), float("inf")])
def test_gate_is_blind_to_the_research_score(score):
    out = gate_candidate(_record(research_score=score))
    assert out.disposition == Disposition.SUBMISSION_READY
    assert out.blockers == []


# --------------------------------------------------------------------------- #
# 7: deployment evidence is shown, never assumed
# --------------------------------------------------------------------------- #

def test_missing_deployment_evidence_is_never_reported_as_live():
    out = gate_candidate(_record(deployment_verified=None))
    assert out.disposition == Disposition.POTENTIALLY_PAYABLE
    assert out.submission_ready is False
    assert "deployment not verified" in out.blockers[0]
    with pytest.raises(ValueError):
        assert_submission_ready(_record(deployment_verified=None))


def test_a_source_only_defect_is_not_a_live_vulnerability():
    out = gate_candidate(_record(deployment_verified=False))
    assert out.disposition == Disposition.VALID_NOT_PAYABLE
    assert "no affected deployment verified" in out.blockers[0]


def test_a_verified_deployment_claim_needs_a_runtime_bound_truth_record():
    out = gate_candidate(_record(deployment_truth={}))
    assert out.disposition == Disposition.POTENTIALLY_PAYABLE
    assert "deployment truth" in out.blockers[0]
    assert "no deployment truth record" in out.blockers[0]


def test_a_source_only_truth_record_does_not_prove_the_deployment():
    truth = {
        "status": "SOURCE_VERIFIED", "address": "0x" + "1" * 40, "chain_id": 1,
        "source_bound": False, "runtime_binding": {"status": "NO_RECOMPILE"},
    }
    out = gate_candidate(_record(deployment_truth=truth))
    assert out.disposition == Disposition.POTENTIALLY_PAYABLE
    assert "not bound to the deployed runtime" in out.blockers[0]


def test_a_runtime_mismatch_does_not_prove_the_deployment():
    truth = {
        "status": "SOURCE_VERIFIED", "address": "0x" + "1" * 40, "chain_id": 1,
        "source_bound": True, "runtime_binding": {"status": "MISMATCH"},
    }
    out = gate_candidate(_record(deployment_truth=truth))
    assert out.disposition == Disposition.POTENTIALLY_PAYABLE
    assert "runtime binding is MISMATCH" in out.blockers[0]


# --------------------------------------------------------------------------- #
# 8: a submission-ready candidate has traceable policy evidence
# --------------------------------------------------------------------------- #

def test_every_submission_ready_candidate_has_traceable_policy_evidence():
    rec = _record()
    out = gate_candidate(rec)
    assert out.disposition == Disposition.SUBMISSION_READY
    assert out.policy_verified is True
    assert out.policy_evidence["url"] == rec.policy_url
    assert out.policy_evidence["retrieved_at"] == rec.policy_verified_at
    assert out.policy_evidence["sha256"] == sha256_text(POLICY_TEXT)
    assert rec.policy_sections, "a submission-ready record must cite policy sections"


def test_a_candidate_without_a_cited_policy_section_is_not_submission_ready():
    out = gate_candidate(_record(policy_sections=[]))
    assert out.disposition == Disposition.POTENTIALLY_PAYABLE
    assert "no policy section cited" in out.blockers[0]


def test_the_submission_ready_bar_is_stated_once():
    joined = " ".join(SUBMISSION_READY_REQUIRES)
    for needle in ("verified official policy", "in scope", "reproduced",
                   "published severity definition", "reward actually available",
                   "policy sections cited"):
        assert needle in joined, needle


# --------------------------------------------------------------------------- #
# 9: a policy change re-assesses without rewriting history
# --------------------------------------------------------------------------- #

def _snapshot(**kw) -> PolicySnapshot:
    base = dict(program="Acme", source_url="https://acme.example/scope",
                retrieved_at="2026-01-01T00:00:00+00:00",
                sha256=sha256_text(POLICY_TEXT), captured_text=POLICY_TEXT,
                revision="rev-1")
    base.update(kw)
    return PolicySnapshot(**base)


def _policy(**kw) -> ProgramPolicy:
    base = dict(program="Acme", snapshot=_snapshot(),
                assets={"vault": "in_scope"},
                excluded_classes=[], severity_definitions={},
                payouts={"low": "$500"},
                minimum_severity="", known_issues=[], poc_required=True)
    base.update(kw)
    return ProgramPolicy(**base)


def test_policy_change_triggers_reassessment_and_preserves_history(tmp_path):
    finding = Finding(finding_id="F-1", title="Reentrancy drains vault",
                      target="vault", classification=Classification.CONFIRMED,
                      severity="medium", category="reentrancy",
                      impact="fund theft", evidence_ids=["ev-1"])
    ledger = BountyLedger(tmp_path / "bounty")

    first = ledger.record(evaluate(finding, _policy()))
    assert first.outcome == Outcome.VALID_WITH_UNVERIFIED_ELIGIBILITY

    text2 = POLICY_TEXT + "\nPayouts: medium $2000.\n"
    policy2 = _policy(snapshot=_snapshot(sha256=sha256_text(text2),
                                         captured_text=text2, revision="rev-2"),
                      payouts={"low": "$500", "medium": "$2000"})
    second = reevaluate(finding, policy2, ledger)

    assert second.outcome == Outcome.VALID_AND_PAYABLE
    assert second.policy_revision == "rev-2"
    assert second.supersedes, "the new evaluation must link to the prior one"

    history = ledger.for_finding("F-1")
    assert len(history) == 2, "the prior decision must survive the policy change"
    assert {e.policy_revision for e in history} == {"rev-1", "rev-2"}


# --------------------------------------------------------------------------- #
# 10: existing candidate records and evidence are preserved
# --------------------------------------------------------------------------- #

def test_gating_does_not_mutate_the_candidate_record():
    rec = _record()
    before = rec.to_dict()
    gate_candidate(rec)
    assert rec.to_dict() == before


def test_the_archive_checksums_still_verify():
    sums = ARCHIVE / "SHA256SUMS.txt"
    if not sums.exists():
        pytest.skip("archive not present in this checkout")
    checked = 0
    for line in sums.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        digest, _, rel = line.partition("  ")
        target = (ARCHIVE / rel).resolve()
        assert target.is_file(), f"listed file is missing: {rel}"
        actual = hashlib.sha256(target.read_bytes()).hexdigest()
        assert actual == digest, f"checksum mismatch for {rel}"
        checked += 1
    assert checked >= 8, "the archive should list its own files"


def test_the_archive_records_gate_to_their_stated_disposition():
    """Every candidate.json in the archive must gate to its recorded disposition."""
    records = sorted(ARCHIVE.glob("candidates/*/candidate.json"))
    if not records:
        pytest.skip("archive not present in this checkout")
    for path in records:
        rec = CandidateRecord.from_dict(json.loads(path.read_text(encoding="utf-8")))
        out = gate_candidate(rec)
        assert out.disposition == rec.disposition, path
        assert out.submission_ready == (rec.disposition == Disposition.SUBMISSION_READY), path


# --------------------------------------------------------------------------- #
# Dispositions: distinct, complete, and enforced
# --------------------------------------------------------------------------- #

def test_informational_observation_is_e_not_d():
    out = gate_candidate(_record(reproduction_status="INFORMATIONAL"))
    assert out.disposition == Disposition.INFORMATIONAL


def test_disproven_claim_is_d():
    out = gate_candidate(_record(reproduction_status="FALSE_POSITIVE"))
    assert out.disposition == Disposition.INVALID


def test_an_impact_below_the_published_bar_is_c_not_a_guess():
    out = gate_candidate(_record(impact_meets_policy=False))
    assert out.disposition == Disposition.VALID_NOT_PAYABLE
    assert "does not meet the published requirement" in out.blockers[0]


def test_a_confirmed_claim_without_evidence_is_not_assessed():
    out = gate_candidate(_record(evidence_refs=[]))
    assert out.disposition == Disposition.NOT_ASSESSED
    assert "no evidence references" in out.blockers[0]


@pytest.mark.parametrize("record_kw", [
    {"reproduction_status": "FALSE_POSITIVE"},
    {"reproduction_status": "INFORMATIONAL"},
    {"impact_meets_policy": False},
    {"evidence_refs": []},
    {"asset_scope": "out_of_scope"},
    {"vulnerability_class": "self-xss"},
    {"known_or_fixed": True},
    {"deployment_verified": None},
    {"deployment_verified": False},
    {"program_severity": ""},
    {"reward_available": False},
    {"reward_available": None},
    {"policy_sections": []},
    {"policy_sha256": ""},
])
def test_assert_submission_ready_raises_for_every_non_ready_state(record_kw):
    with pytest.raises(ValueError):
        assert_submission_ready(_record(**record_kw))


def test_assert_submission_ready_returns_the_outcome_when_ready():
    out = assert_submission_ready(_record())
    assert out.disposition == Disposition.SUBMISSION_READY


def test_disposition_for_covers_every_outcome():
    for name in ("VALID_AND_PAYABLE", "VALID_BUT_NOT_PAYABLE",
                 "VALID_WITH_UNVERIFIED_ELIGIBILITY", "INVALID", "OUT_OF_SCOPE",
                 "EXCLUDED_BY_POLICY", "DUPLICATE_OR_KNOWN",
                 "INSUFFICIENT_EVIDENCE", "REPRODUCTION_REQUIRED",
                 "POLICY_UNVERIFIED"):
        outcome = getattr(Outcome, name)
        assert disposition_for(outcome) in Disposition.ORDER, name
    assert disposition_for(Outcome.POLICY_UNVERIFIED) == Disposition.NOT_ASSESSED
    assert disposition_for(Outcome.INVALID, informational=True) == Disposition.INFORMATIONAL


def test_prepare_submission_carries_the_disposition():
    finding = Finding(finding_id="F-1", title="t", target="vault",
                      classification=Classification.CONFIRMED, evidence_ids=["ev-1"])
    ev = evaluate(finding, _policy(snapshot=_snapshot(sha256="0" * 64)))
    assert ev.outcome == Outcome.POLICY_UNVERIFIED
    pkg = prepare_submission(finding, ev)
    assert pkg["disposition"] == Disposition.NOT_ASSESSED
    assert pkg["submission_allowed"] is False
    assert pkg["blockers"]


def test_prepare_submission_marks_informational_as_e():
    finding = Finding(finding_id="F-1", title="t", target="vault",
                      classification=Classification.INFORMATIONAL)
    ev = Evaluation(finding_id="F-1", program="Acme", outcome=Outcome.INVALID)
    pkg = prepare_submission(finding, ev)
    assert pkg["disposition"] == Disposition.INFORMATIONAL
    assert pkg["submission_allowed"] is False


# --------------------------------------------------------------------------- #
# The rule is single-sourced and reaches the doctrine and the CLI
# --------------------------------------------------------------------------- #

def test_blocked_string_is_single_sourced():
    assert POLICY_UNVERIFIED_BLOCKER == doctrine.BOUNTY_POLICY_UNVERIFIED
    assert "BLOCKED" in POLICY_UNVERIFIED_BLOCKER
    assert "NOT VERIFIED" in POLICY_UNVERIFIED_BLOCKER


def test_doctrine_exposes_the_seven_mandatory_gates():
    data = doctrine.doctrine_dict()
    gate = data["bounty_gate"]
    assert [g["name"] for g in gate["gates"]] == [
        "Deployment", "Eligibility", "Reachability", "Security violation",
        "Impact", "Novelty", "Reportability"]
    assert [c["key"] for c in gate["classifications"]] == ["A", "B", "C", "D", "F"]
    assert len(gate["dispositions"]) == 6
    assert gate["policy_unverified"] == POLICY_UNVERIFIED_BLOCKER
    assert "sole authority" in gate["rule"]

    block = doctrine.doctrine_prompt_block()
    assert "official bug bounty policy" in block
    assert "never by an internal score" in block


def test_the_doctrine_forbids_invented_numeric_thresholds():
    """A generic 80/100 bar is not a program requirement and may not be used as one."""
    assert doctrine.BOUNTY_NO_THRESHOLD_RULE in doctrine.doctrine_document()
    doc = doctrine.doctrine_document()
    # The prohibition may *name* the score it bans; it may not *impose* one.
    assert "80-point" not in doc
    for score in ("80/100", "90/100"):
        assert doc.count(score) <= 1, score
    assert "cannot be compensated" in doctrine.BOUNTY_NO_THRESHOLD_RULE


def test_every_disposition_reports_one_of_five_classifications():
    from blackheart.bounty import CLASSIFICATIONS, classification_for

    assert CLASSIFICATIONS == ("A", "B", "C", "D", "F")
    for disposition in Disposition.ORDER:
        assert classification_for(disposition) in CLASSIFICATIONS, disposition


def test_informational_is_class_c_not_a_sixth_class():
    """An observation without a qualifying impact fails Gate 5, so it is C."""
    from blackheart.bounty import classification_for

    assert classification_for(Disposition.INFORMATIONAL) == "C"
    assert classification_for(Disposition.NOT_ASSESSED) == "F"


def test_classification_never_promotes_without_every_gate():
    from blackheart.bounty import classification_for

    for disposition in Disposition.ORDER:
        assert (classification_for(disposition) == "A") == (
            disposition == Disposition.SUBMISSION_READY), disposition


def test_gate_output_carries_the_classification():
    from blackheart.bounty import CLASSIFICATIONS

    out = gate_candidate(_record(asset_scope="out_of_scope"))
    payload = out.to_dict()
    assert payload["classification"] in CLASSIFICATIONS
    assert payload["classification"] == out.classification

    doc = doctrine.doctrine_document()
    assert "## Bounty eligibility gate" in doc
    assert "no candidate needs a minimum score" in doc


def test_priority_score_is_not_an_eligibility_input():
    """The prioritisation model still exists, and its output cannot gate anything."""
    assert doctrine.priority_score({"security_impact": 1.0}) <= 1.0
    # A perfect priority score on a policy-excluded candidate is still rejected.
    rec = _record(vulnerability_class="self-xss")
    rec.research_score = doctrine.priority_score({f.key: 1.0 for f in doctrine.PRIORITY_FACTORS}) * 100
    assert gate_candidate(rec).disposition == Disposition.VALID_NOT_PAYABLE


def _write(tmp_path: Path, name: str, payload: dict) -> Path:
    p = tmp_path / name
    p.write_text(json.dumps(payload), encoding="utf-8")
    return p


def test_cli_gate_exits_zero_for_an_assessed_candidate(tmp_path, capsys):
    rec = _write(tmp_path, "a.json", _record().to_dict())
    rc = cli_main(["bounty", "--dir", str(tmp_path / "ledger"),
                   "gate", "--record", str(rec)])
    out = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert out["disposition"] == Disposition.SUBMISSION_READY


def test_cli_gate_exits_two_when_the_policy_is_unverified(tmp_path, capsys):
    rec = _write(tmp_path, "b.json", _record(policy_sha256="", policy_text="").to_dict())
    rc = cli_main(["bounty", "--dir", str(tmp_path / "ledger"),
                   "gate", "--record", str(rec)])
    out = json.loads(capsys.readouterr().out)
    assert rc == 2
    assert out["disposition"] == Disposition.NOT_ASSESSED
    assert out["blockers"][0] == POLICY_UNVERIFIED_BLOCKER


def test_cli_gate_require_submission_ready_exits_one(tmp_path, capsys):
    rec = _write(tmp_path, "c.json", _record(asset_scope="out_of_scope").to_dict())
    rc = cli_main(["bounty", "--dir", str(tmp_path / "ledger"),
                   "gate", "--record", str(rec), "--require-submission-ready"])
    capsys.readouterr()
    assert rc == 1


def test_no_numeric_acceptance_threshold_is_read_by_the_gate():
    """Guard against a threshold creeping into the gate's source."""
    source = (Path(__file__).resolve().parent.parent
              / "blackheart" / "bounty" / "gate.py").read_text(encoding="utf-8")
    for needle in ("research_score >=", "research_score <=", "research_score >",
                   "research_score <", ">= 80", "> 80", ">= 70", "> 70"):
        assert needle not in source, needle
    # And the module states the rule this test protects.
    assert "never read" in source or "never reads" in source


# --------------------------------------------------------------------------- #
# Payment determinations: the report vocabulary, derived from the gate
# --------------------------------------------------------------------------- #

def test_every_disposition_maps_to_one_payment_determination():
    from blackheart.bounty import PAYMENT_DETERMINATIONS, payment_determination

    assert set(PAYMENT_DETERMINATIONS) == {
        "PAYABLE", "POTENTIALLY PAYABLE", "NOT PAYABLE", "UNRESOLVED"}
    for disposition in Disposition.ORDER:
        assert payment_determination(disposition) in PAYMENT_DETERMINATIONS


def test_payable_comes_only_from_a_submission_ready_disposition():
    from blackheart.bounty import payment_determination

    for disposition in Disposition.ORDER:
        determination = payment_determination(disposition)
        assert (determination == "PAYABLE") == (
            disposition == Disposition.SUBMISSION_READY), disposition


def test_an_unassessed_candidate_is_unresolved_not_not_payable():
    from blackheart.bounty import payment_determination

    assert payment_determination(Disposition.NOT_ASSESSED) == "UNRESOLVED"
    for disposition in (Disposition.VALID_NOT_PAYABLE, Disposition.INVALID,
                        Disposition.INFORMATIONAL):
        assert payment_determination(disposition) == "NOT PAYABLE"


def test_unknown_disposition_is_a_programming_error():
    from blackheart.bounty import payment_determination

    with pytest.raises(ValueError):
        payment_determination("G_SOMETHING_NEW")


def test_doctrine_and_gate_agree_on_the_determinations():
    """One vocabulary: the doctrine's table must match the gate's mapping."""
    from blackheart.bounty import payment_determination

    documented = dict(doctrine.PAYMENT_DETERMINATIONS)
    assert set(documented) == {
        "PAYABLE", "POTENTIALLY PAYABLE", "NOT PAYABLE", "UNRESOLVED"}
    assert len(documented) == len(doctrine.PAYMENT_DETERMINATIONS)
    for disposition in Disposition.ORDER:
        word = payment_determination(disposition)
        assert word in documented, disposition
    # The doctrine text is rendered, not merely stored.
    assert "NOT PAYABLE" in doctrine.doctrine_document()


def test_gate_output_carries_the_determination():
    out = gate_candidate(_record(asset_scope="out_of_scope"))
    payload = out.to_dict()
    assert payload["determination"] == "NOT PAYABLE"
    assert payload["determination"] == out.determination


def test_every_archive_candidate_records_a_payment_determination():
    gates = sorted(ARCHIVE.glob("candidates/*/gate.json"))
    if not gates:
        pytest.skip("archive not present in this checkout")
    allowed = {"PAYABLE", "POTENTIALLY PAYABLE", "NOT PAYABLE", "UNRESOLVED"}
    for path in gates:
        payload = json.loads(path.read_text(encoding="utf-8"))
        assert payload["determination"] in allowed, path
        assert payload["determination"] == gate_candidate(
            CandidateRecord.from_dict(
                json.loads((path.parent / "candidate.json").read_text(encoding="utf-8")))
        ).determination, path


def test_uma_superbond_reassesses_to_not_payable_at_any_score():
    """The historical candidate, re-gated: the determination is not score-driven."""
    path = ARCHIVE / "candidates" / "UMA-SUPERBOND-01" / "candidate.json"
    if not path.exists():
        pytest.skip("archive not present in this checkout")
    payload = json.loads(path.read_text(encoding="utf-8"))
    for score in (None, 0, 65, 80, 95, 100):
        payload["research_score"] = score
        out = gate_candidate(CandidateRecord.from_dict(payload))
        assert out.determination == "NOT PAYABLE", score
        assert not out.submission_ready, score


def test_the_uma_reassessment_quotes_the_policy_it_applies():
    """A reassessment must cite the live policy text, not paraphrase it."""
    doc = ARCHIVE / "candidates" / "UMA-SUPERBOND-01" / "ELIGIBILITY_REASSESSMENT.md"
    policy = (Path(__file__).resolve().parent.parent / "research" / "uma-protocol-03"
              / "evidence" / "bounty_policy_page.txt")
    if not doc.exists() or not policy.exists():
        pytest.skip("reassessment not present in this checkout")
    text = doc.read_text(encoding="utf-8")
    assert "NOT PAYABLE" in text
    assert "726e52e408e221aabad710bd14fb49cb7a495384abd19b393daaf66b0d233880" in text
    # The two clauses the determination rests on, quoted verbatim from the capture.
    # Whitespace and blockquote markers are normalised on both sides because the
    # capture wraps lines and the document quotes them in a blockquote.
    def flat(s: str) -> str:
        stripped = "\n".join(re.sub(r"^\s*>\s?", "", line) for line in s.splitlines())
        return " ".join(stripped.split())

    captured, quoted = flat(policy.read_text(encoding="utf-8")), flat(text)
    for clause in (
        "deployed to mainnet or are otherwise noted as being applicable",
        "Any files, modules or libraries other than the ones mentioned above",
    ):
        assert flat(clause) in captured, clause
        assert flat(clause) in quoted, clause


# --------------------------------------------------------------------------- #
# Submission drafts: prepared, never sent, and never misquoting the policy
# --------------------------------------------------------------------------- #

def test_the_uma_submission_draft_exists_and_is_marked_not_sent():
    base = ARCHIVE / "candidates" / "UMA-SUPERBOND-01"
    draft, body = base / "SUBMISSION_DRAFT.md", base / "submission_email.txt"
    if not draft.exists():
        pytest.skip("draft not present in this checkout")
    assert body.exists()
    assert "NOT SENT" in draft.read_text(encoding="utf-8")
    assert "NOT SENT" in body.read_text(encoding="utf-8")
    # A draft may be sent only with the operator's approval, and says so.
    assert "explicit approval" in draft.read_text(encoding="utf-8")


def test_the_submission_draft_quotes_the_policy_verbatim():
    """No policy sentence may appear in a draft unless it is in the capture."""
    draft = (ARCHIVE / "candidates" / "UMA-SUPERBOND-01" / "SUBMISSION_DRAFT.md")
    policy = (Path(__file__).resolve().parent.parent / "research" / "uma-protocol-03"
              / "evidence" / "bounty_policy_page.txt")
    if not draft.exists() or not policy.exists():
        pytest.skip("draft not present in this checkout")

    def flat(s: str) -> str:
        stripped = "\n".join(re.sub(r"^\s*>\s?", "", line) for line in s.splitlines())
        return " ".join(stripped.split())

    captured = flat(policy.read_text(encoding="utf-8"))
    for clause in (
        "Please email your submissions to <bugs@umaproject.org>.",
        "Keep the details of any discovered vulnerabilities confidential until they "
        "are publicly announced by Risk Labs.",
    ):
        assert flat(clause) in captured, clause
        assert flat(clause) in flat(draft.read_text(encoding="utf-8")), clause


def test_the_submission_draft_makes_no_eligibility_claim():
    body = (ARCHIVE / "candidates" / "UMA-SUPERBOND-01" / "submission_email.txt")
    if not body.exists():
        pytest.skip("draft not present in this checkout")
    text = body.read_text(encoding="utf-8").lower()
    for claim in ("i believe this is in scope", "critical severity", "we claim",
                  "payout of", "bounty reward of"):
        assert claim not in text, claim
    # And it states the honest position up front.
    assert "outside your published scope" in text or "out of scope" in text


def test_the_send_briefing_carries_the_exact_email_body():
    """The briefing must not drift from the mail it tells the operator to send."""
    base = ARCHIVE / "candidates" / "UMA-SUPERBOND-01"
    mail, briefing = base / "submission_email.txt", base / "SEND_BRIEFING.md"
    if not mail.exists() or not briefing.exists():
        pytest.skip("briefing not present in this checkout")
    body = mail.read_text(encoding="utf-8")
    block = body[body.index("Hello UMA team,"):body.index("[CONTACT]") + len("[CONTACT]")]
    assert block in briefing.read_text(encoding="utf-8")


def test_cli_gate_accepts_a_runtime_bound_truth_record(tmp_path, capsys):
    rec = _write(tmp_path, "no-truth.json", _record(deployment_truth={}).to_dict())
    truth = _write(tmp_path, "truth.json", {
        "status": "SOURCE_VERIFIED", "address": "0x" + "1" * 40,
        "chain_id": 1, "source_status": "verified", "source_bound": True,
        "runtime_binding": {"status": "EXACT", "bound": True},
    })
    rc = cli_main(["bounty", "--dir", str(tmp_path / "ledger"), "gate",
                   "--record", str(rec), "--deployment-truth", str(truth)])
    out = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert out["disposition"] == Disposition.SUBMISSION_READY
