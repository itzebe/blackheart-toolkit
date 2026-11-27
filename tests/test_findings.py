"""Tests for the findings documentation engine and repository.

These cover the mission's acceptance criteria that are about findings and
persistence:

  2  an investigation can be created and persisted
  3  attack hypotheses can be recorded and tracked
  4  research results can be attached to an investigation
  5  a reproducible finding can be generated
  6  unverified findings remain unverified
  7  false positives are recorded separately
  8  independent verification can change a finding's status only through valid
     evidence and review
  9  reports are generated from persisted evidence
  10 findings survive application and agent restarts
  11 duplicate detection does not erase distinct vulnerabilities
  12 evidence provenance remains intact
  14 missing or invalid evidence does not produce a confirmed vulnerability

They use a *controlled fixture* (a synthetic finding backed by a real, temp
evidence store) -- never a fabricated real-world exploit.
"""

from __future__ import annotations

import json
import shutil

import pytest

from blackheart.doctrine import FINDING_SECTIONS
from blackheart.evidence import EvidenceStore
from blackheart.findings import (
    FindingRecord,
    FindingRepository,
    FindingVerdict,
    classification_to_verdict,
    confirm_with_evidence,
    verdict_to_classification,
)
from blackheart.models import Classification


# --------------------------------------------------------------------------- #
# Fixtures
# --------------------------------------------------------------------------- #

@pytest.fixture
def repo(tmp_path):
    return FindingRepository(tmp_path / "findings")


@pytest.fixture
def evidence(tmp_path):
    return EvidenceStore(tmp_path / "evidence")


def _candidate(**over) -> FindingRecord:
    """A controlled fixture finding -- a plausible but unverified candidate."""
    base = dict(
        finding_id="BH-TEST-001",
        title="Share minting without a matching deposit drains the vault",
        target="VulnerableVault",
        component="VulnerableVault.deposit",
        category="asset-theft",
        cwe="CWE-840",
        severity="high",
        security_boundary="user -> vault",
        root_cause_file="harnesses/erc4626/src/VulnerableVault.sol",
        root_cause_location="deposit()",
        design_mistake="shares minted before assets are transferred",
        attack_sequence=["deploy", "call deposit(1 wei)", "redeem for more than deposited"],
        repro_environment="local Foundry fixture",
        repro_steps=["forge test --match-test test_depositMintsWithoutAssets"],
        repro_commands=["forge test --match-test test_depositMintsWithoutAssets"],
        expected_behavior="shares == assets * rate",
        observed_behavior="shares minted with no asset transfer",
        execution_result="test PASSED (vulnerability reproduced)",
    )
    base.update(over)
    return FindingRecord(**base)


# --------------------------------------------------------------------------- #
# Criteria 2, 3, 4 -- create, record hypotheses, attach results
# --------------------------------------------------------------------------- #

def test_an_investigation_finding_can_be_created_and_persisted(repo):
    repo.add(_candidate())
    got = repo.get("BH-TEST-001")
    assert got is not None
    assert got.title.startswith("Share minting")
    assert repo.summary()["total"] == 1


def test_hypotheses_and_results_can_be_attached_to_a_finding(repo):
    rec = _candidate(
        hypothesis="minting may precede transfer",
        attack_sequence=["deposit", "redeem"],
    )
    repo.add(rec)
    # Attach a research result (observed behaviour + execution result).
    stored = repo.get("BH-TEST-001")
    assert stored.attack_sequence
    assert stored.execution_result


def test_all_ten_sections_are_addressable_and_grouped():
    rec = _candidate()
    sections = rec.sections()
    assert set(sections) == set("ABCDEFGHIJ")
    # The grouping covers exactly the fields the doctrine names.
    for s in FINDING_SECTIONS:
        assert sections[s.letter]["name"] == s.name
        assert set(sections[s.letter]["fields"]) == set(s.fields)


# --------------------------------------------------------------------------- #
# Criterion 5 -- a reproducible finding can be generated
# --------------------------------------------------------------------------- #

def test_a_reproducible_finding_can_be_generated_and_confirmed(repo, evidence):
    ev = evidence.put_text("forge test output: PASSED", kind="command-output",
                           description="reproduction")
    rec = _candidate(
        evidence_ids=[ev.evidence_id],
        reviewer="independent-verifier",
        verification_result="independently reproduced on a clean checkout",
        verification_methodology="fresh checkout + forge test",
    )
    repo.add(rec)
    ok, reason = confirm_with_evidence(
        repo, "BH-TEST-001",
        evidence_exists=lambda eid: evidence.get(eid) is not None,
    )
    assert ok, reason
    assert repo.get("BH-TEST-001").is_confirmed()


# --------------------------------------------------------------------------- #
# Criterion 6 -- unverified findings remain unverified
# --------------------------------------------------------------------------- #

def test_an_unverified_finding_remains_unverified(repo):
    repo.add(_candidate())  # no evidence, no reviewer
    assert repo.get("BH-TEST-001").status == FindingVerdict.UNCONFIRMED.value
    assert not repo.get("BH-TEST-001").may_be_read_as_vulnerability()
    # A direct attempt to confirm is refused and the record is unchanged.
    assert not repo.get("BH-TEST-001").confirm()
    assert repo.get("BH-TEST-001").status == FindingVerdict.UNCONFIRMED.value


def test_strongly_supported_is_not_confirmed_and_awaits_verification(repo):
    repo.add(_candidate(status=FindingVerdict.STRONGLY_SUPPORTED.value))
    assert repo.get("BH-TEST-001").status == FindingVerdict.STRONGLY_SUPPORTED.value
    assert not repo.get("BH-TEST-001").is_confirmed()
    assert [r.finding_id for r in repo.awaiting_verification()] == ["BH-TEST-001"]


# --------------------------------------------------------------------------- #
# Criterion 7 -- false positives are recorded separately
# --------------------------------------------------------------------------- #

def test_false_positives_are_recorded_separately(repo):
    repo.add(_candidate())
    repo.add(_candidate(finding_id="BH-TEST-002", component="Other",
                        false_positive_analysis="benign: the control also reproduces"))
    repo.set_verdict("BH-TEST-002", FindingVerdict.FALSE_POSITIVE,
                     note="non-discriminating PoC")
    assert [r.finding_id for r in repo.false_positives()] == ["BH-TEST-002"]
    assert repo.get("BH-TEST-002").status == FindingVerdict.FALSE_POSITIVE.value
    # It is not in the confirmed bucket and cannot be read as a vulnerability.
    assert repo.get("BH-TEST-002") not in repo.confirmed()
    assert not repo.get("BH-TEST-002").may_be_read_as_vulnerability()


# --------------------------------------------------------------------------- #
# Criterion 8 -- status changes only through valid evidence and review
# --------------------------------------------------------------------------- #

def test_verdict_cannot_become_confirmed_without_evidence_and_review(repo):
    repo.add(_candidate())
    # Missing evidence_ids, reviewer, verification_result.
    updated = repo.set_verdict("BH-TEST-001", FindingVerdict.CONFIRMED)
    assert updated.status == FindingVerdict.UNCONFIRMED.value  # refused, unchanged
    assert repo.get("BH-TEST-001").missing_confirmation_fields() == [
        "evidence_ids", "verification_result", "reviewer",
    ]


def test_verdict_can_be_confirmed_only_with_evidence_and_review(repo, evidence):
    ev = evidence.put_text("trace", kind="log", description="repro trace")
    repo.add(_candidate(evidence_ids=[ev.evidence_id], reviewer="verifier",
                        verification_result="reproduced"))
    updated = repo.set_verdict("BH-TEST-001", FindingVerdict.CONFIRMED)
    assert updated.is_confirmed()
    # The status change is a recorded event, so history is not lost.
    hist = repo.history("BH-TEST-001")
    assert any(ev["type"] == "verdict" and ev["status"] == "CONFIRMED" for ev in hist)


def test_a_verdict_can_be_downgraded_and_the_history_records_both(repo, evidence):
    ev = evidence.put_text("trace", kind="log", description="trace")
    repo.add(_candidate(evidence_ids=[ev.evidence_id], reviewer="v",
                        verification_result="reproduced"))
    repo.set_verdict("BH-TEST-001", FindingVerdict.CONFIRMED)
    repo.set_verdict("BH-TEST-001", FindingVerdict.FALSE_POSITIVE, note="retest failed")
    assert repo.get("BH-TEST-001").status == FindingVerdict.FALSE_POSITIVE.value
    statuses = [e["status"] for e in repo.history("BH-TEST-001") if e.get("status")]
    assert "CONFIRMED" in statuses and "FALSE_POSITIVE" in statuses


def test_a_record_claiming_confirmed_without_evidence_is_downgraded_on_persistence(repo):
    """No path -- including `add` -- may persist CONFIRMED without the gate fields."""
    rec = _candidate(status=FindingVerdict.CONFIRMED.value)  # no evidence/reviewer/result
    repo.add(rec)
    stored = repo.get("BH-TEST-001")
    assert stored.status == FindingVerdict.STRONGLY_SUPPORTED.value
    assert repo.summary()["confirmed"] == 0
    # A legitimate confirmed record (gate fields present) still persists as CONFIRMED.
    repo.add(_candidate(finding_id="BH-TEST-002", evidence_ids=["ev-1"],
                        reviewer="v", verification_result="reproduced",
                        status=FindingVerdict.CONFIRMED.value))
    assert repo.get("BH-TEST-002").is_confirmed()


# --------------------------------------------------------------------------- #
# Criterion 9 -- reports are generated from persisted evidence
# --------------------------------------------------------------------------- #

def test_reports_render_from_persisted_records(repo, evidence):
    ev = evidence.put_text("trace", kind="log", description="trace")
    repo.add(_candidate(evidence_ids=[ev.evidence_id], reviewer="v",
                        verification_result="reproduced"))
    # Re-open the repository (fresh instance) so the report is provably built
    # from what was persisted, not from in-memory state.
    reopened = FindingRepository(repo.root)
    md = reopened.export_markdown(reopened.get("BH-TEST-001"))
    assert "## A. Identification" in md
    assert "## F. Evidence" in md
    assert ev.evidence_id in md
    js = json.loads(reopened.export_json(reopened.get("BH-TEST-001")))
    assert js["finding_id"] == "BH-TEST-001"
    report = reopened.consolidated_report()
    assert "BLACKHEART research report" in report
    assert "BH-TEST-001" in report


# --------------------------------------------------------------------------- #
# Criterion 10 -- findings survive application and agent restarts
# --------------------------------------------------------------------------- #

def test_findings_survive_a_restart(repo, evidence):
    ev = evidence.put_text("trace", kind="log", description="trace")
    repo.add(_candidate(evidence_ids=[ev.evidence_id], reviewer="v",
                        verification_result="reproduced"))
    repo.set_verdict("BH-TEST-001", FindingVerdict.CONFIRMED)
    # A brand-new repository object over the same directory is a "restart".
    restarted = FindingRepository(repo.root)
    rec = restarted.get("BH-TEST-001")
    assert rec is not None and rec.is_confirmed()
    assert restarted.summary()["confirmed"] == 1


# --------------------------------------------------------------------------- #
# Criterion 11 -- duplicate detection does not erase distinct vulnerabilities
# --------------------------------------------------------------------------- #

def test_duplicate_detection_does_not_erase_distinct_findings(repo):
    a = _candidate()
    b = _candidate(finding_id="BH-TEST-002")  # same root cause -> a duplicate
    c = _candidate(finding_id="BH-TEST-003", component="OtherComponent",
                   root_cause_file="other.sol", design_mistake="different bug")
    repo.add(a)
    repo.add(b)
    repo.add(c)
    dupes = repo.find_duplicates(b)
    assert [d.finding_id for d in dupes] == ["BH-TEST-001"]
    # Distinct findings are NOT reported as duplicates of each other.
    assert repo.find_duplicates(c) == []
    # Linking is additive: nothing is deleted and all three survive.
    repo.link("BH-TEST-002", "BH-TEST-001", relation="duplicate")
    assert repo.summary()["total"] == 3
    assert repo.get("BH-TEST-002").duplicate_of == "BH-TEST-001"
    assert repo.get("BH-TEST-001") is not None


def test_a_finding_with_no_root_cause_is_never_a_duplicate(repo):
    repo.add(_candidate())
    blank = _candidate(finding_id="BH-TEST-002", root_cause_file="",
                       root_cause_location="", design_mistake="")
    assert repo.find_duplicates(blank) == []


# --------------------------------------------------------------------------- #
# Criterion 12 -- evidence provenance remains intact
# --------------------------------------------------------------------------- #

def test_evidence_provenance_is_preserved_and_verifiable(repo, evidence):
    ev = evidence.put_text("the exact bytes", kind="log", description="trace")
    assert evidence.verify_integrity()["ok"]
    # The finding references the content-addressed id; the store re-hashes it.
    repo.add(_candidate(evidence_ids=[ev.evidence_id]))
    assert evidence.read(ev.evidence_id) == b"the exact bytes"
    # The findings log itself is tamper-evident.
    assert repo.verify_integrity()["status"] == "VERIFIED"


def test_findings_log_tamper_is_detected(repo):
    repo.add(_candidate())
    repo.add(_candidate(finding_id="BH-TEST-002", component="X"))
    assert repo.verify_integrity()["ok"]
    # Edit a persisted payload in place; the chain must report the tamper.
    text = repo.path.read_text(encoding="utf-8")
    tampered = text.replace("Share minting", "Altered title", 1)
    repo.path.write_text(tampered, encoding="utf-8")
    result = repo.verify_integrity()
    assert result["status"] == "FAILED"
    assert result["mismatched"]


# --------------------------------------------------------------------------- #
# Criterion 14 -- missing or invalid evidence cannot confirm a vulnerability
# --------------------------------------------------------------------------- #

def test_confirm_refuses_when_evidence_does_not_resolve(repo, evidence):
    repo.add(_candidate(evidence_ids=["ev-does-not-exist"], reviewer="v",
                        verification_result="reproduced"))
    ok, reason = confirm_with_evidence(
        repo, "BH-TEST-001",
        evidence_exists=lambda eid: evidence.get(eid) is not None,
    )
    assert not ok
    assert "does not resolve" in reason
    assert repo.get("BH-TEST-001").status == FindingVerdict.UNCONFIRMED.value


def test_confirm_refuses_when_evidence_fields_are_missing(repo, evidence):
    repo.add(_candidate())  # no evidence_ids at all
    ok, reason = confirm_with_evidence(
        repo, "BH-TEST-001", evidence_exists=lambda eid: True,
    )
    assert not ok
    assert "missing required fields" in reason


# --------------------------------------------------------------------------- #
# Search, mapping, and integrity surface
# --------------------------------------------------------------------------- #

def test_search_filters_conjunctively(repo):
    repo.add(_candidate(hypothesis="minting may precede the asset transfer"))
    repo.add(_candidate(finding_id="BH-TEST-002", target="Other", category="oracle",
                        component="Oracle", hypothesis="price feed can be manipulated",
                        root_cause_file="oracle.sol", design_mistake="spot price"))
    assert {r.finding_id for r in repo.search(target="VulnerableVault")} == {"BH-TEST-001"}
    assert {r.finding_id for r in repo.search(category="oracle")} == {"BH-TEST-002"}
    assert {r.finding_id for r in repo.search(text="precede")} == {"BH-TEST-001"}
    assert {r.finding_id for r in repo.search(text="manipulated")} == {"BH-TEST-002"}
    assert repo.search(severity="critical") == []


def test_verdict_classification_mapping_is_consistent():
    for v in FindingVerdict:
        c = verdict_to_classification(v)
        assert isinstance(c, Classification)
    assert verdict_to_classification(FindingVerdict.CONFIRMED) == Classification.CONFIRMED
    assert verdict_to_classification(FindingVerdict.FALSE_POSITIVE) == Classification.FALSE_POSITIVE
    assert classification_to_verdict(Classification.CONFIRMED) == FindingVerdict.CONFIRMED


def test_export_json_round_trips(repo):
    rec = _candidate(evidence_ids=["ev-1"], reviewer="v", verification_result="ok")
    repo.add(rec)
    payload = json.loads(repo.export_json(repo.get("BH-TEST-001")))
    restored = FindingRecord.from_dict(payload)
    assert restored.finding_id == rec.finding_id
    assert restored.evidence_ids == ["ev-1"]


# --------------------------------------------------------------------------- #
# Criterion 1 & 13 -- the doctrine reaches the orchestrator, and the CLI is the
# one place where an operator drives it. Unauthorized/unsafe paths are blocked.
# --------------------------------------------------------------------------- #

def test_roles_carry_the_persona_and_the_doctrine():
    from blackheart.mindset import BLACKHEART_PERSONA
    from blackheart.providers.roles import ROLES

    for name, role in ROLES.items():
        assert role.system.startswith(BLACKHEART_PERSONA), name
        assert "the lifecycle" in role.system, name
    # The prompts stay distinct (the doctrine is shared, the role question is not).
    assert len({r.system for r in ROLES.values()}) == len(ROLES)


def test_cli_exposes_the_doctrine(capsys):
    from blackheart.cli import main

    assert main(["doctrine", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert len(payload["lifecycle"]) == 6
    assert payload["security_invariants"]

    assert main(["doctrine", "--phase", "TARGET_INTELLIGENCE"]) == 0
    phase = json.loads(capsys.readouterr().out)
    assert phase["number"] == 1


def test_cli_findings_documents_a_fixture_finding(tmp_path, capsys):
    from blackheart.cli import main

    repo_dir = tmp_path / "repo"
    finding = _candidate()
    fpath = tmp_path / "finding.json"
    fpath.write_text(json.dumps(finding.to_dict()), encoding="utf-8")

    assert main(["findings", "--dir", str(repo_dir), "add", "--file", str(fpath)]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["recorded"] == "BH-TEST-001"
    assert out["verdict"] == "UNCONFIRMED"

    assert main(["findings", "--dir", str(repo_dir), "summary"]) == 0
    assert json.loads(capsys.readouterr().out)["unconfirmed"] == 1


def test_cli_set_verdict_refuses_confirmed(tmp_path, capsys):
    """The CLI must not offer a weaker path to CONFIRMED than `confirm`."""
    from blackheart.cli import main

    repo_dir = tmp_path / "repo"
    fpath = tmp_path / "finding.json"
    fpath.write_text(json.dumps(_candidate().to_dict()), encoding="utf-8")
    main(["findings", "--dir", str(repo_dir), "add", "--file", str(fpath)])
    capsys.readouterr()

    rc = main(["findings", "--dir", str(repo_dir), "set-verdict",
               "--finding", "BH-TEST-001", "--verdict", "CONFIRMED"])
    assert rc == 2
    err = capsys.readouterr().err
    assert "confirm" in err

    # The record is still unconfirmed.
    assert main(["findings", "--dir", str(repo_dir), "show",
                 "--finding", "BH-TEST-001"]) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "UNCONFIRMED"


def test_cli_confirm_requires_resolvable_evidence(tmp_path, capsys):
    from blackheart.cli import main

    repo_dir = tmp_path / "repo"
    ev_dir = tmp_path / "evidence"
    fpath = tmp_path / "finding.json"
    fpath.write_text(json.dumps(
        _candidate(evidence_ids=["ev-missing"], reviewer="v",
                   verification_result="reproduced").to_dict()), encoding="utf-8")
    main(["findings", "--dir", str(repo_dir), "add", "--file", str(fpath)])
    capsys.readouterr()

    rc = main(["findings", "--dir", str(repo_dir), "confirm",
               "--finding", "BH-TEST-001", "--evidence", str(ev_dir)])
    assert rc == 1
    out = json.loads(capsys.readouterr().out)
    assert out["confirmed"] is False
    assert "does not resolve" in out["reason"]


def test_cli_confirm_succeeds_with_real_evidence(tmp_path, capsys):
    from blackheart.cli import main
    from blackheart.evidence import EvidenceStore

    repo_dir = tmp_path / "repo"
    ev_dir = tmp_path / "evidence"
    store = EvidenceStore(ev_dir)
    ev = store.put_text("forge test: PASSED", kind="command-output", description="repro")

    fpath = tmp_path / "finding.json"
    fpath.write_text(json.dumps(
        _candidate(evidence_ids=[ev.evidence_id], reviewer="independent-verifier",
                   verification_result="independently reproduced").to_dict()),
        encoding="utf-8")
    main(["findings", "--dir", str(repo_dir), "add", "--file", str(fpath)])
    capsys.readouterr()

    rc = main(["findings", "--dir", str(repo_dir), "confirm",
               "--finding", "BH-TEST-001", "--evidence", str(ev_dir)])
    assert rc == 0
    assert json.loads(capsys.readouterr().out)["confirmed"] is True

    # And the repository integrity holds after the confirmation.
    assert main(["findings", "--dir", str(repo_dir), "integrity"]) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "VERIFIED"


# --------------------------------------------------------------------------- #
# Automatic documentation -- the engine's own Finding is documented for us
# --------------------------------------------------------------------------- #

def test_document_finding_records_an_engine_finding(tmp_path):
    from blackheart.findings import document_finding
    from blackheart.models import Classification, Finding

    repo = FindingRepository(tmp_path / "repo")
    finding = Finding(
        finding_id="ENG-1",
        title="engine finding",
        target="Vault",
        component="Vault.deposit",
        classification=Classification.NEEDS_MORE_EVIDENCE,
        prerequisites=["unprivileged user"],
        reproduction_steps=["call deposit"],
        commands=["forge test"],
        expected_behavior="shares == assets",
        actual_behavior="shares minted without assets",
        impact="attacker drains the vault",
        evidence_ids=["ev-1"],
        limitations=["single fixture"],
    )
    record = document_finding(repo, finding)
    assert record.finding_id == "ENG-1"
    # An unverified engine finding is documented but NOT confirmed.
    assert record.status != "CONFIRMED"
    assert record.evidence_ids == ["ev-1"]
    assert record.observed_behavior == "shares minted without assets"
    assert record.remaining_uncertainty == "single fixture"
    # It survives a restart like any other record.
    assert FindingRepository(repo.root).get("ENG-1") is not None


def test_document_finding_downgrades_when_evidence_does_not_resolve(tmp_path):
    from blackheart.findings import document_finding
    from blackheart.evidence import EvidenceStore
    from blackheart.models import Classification, Finding

    repo = FindingRepository(tmp_path / "repo")
    store = EvidenceStore(tmp_path / "evidence")
    finding = Finding(
        finding_id="ENG-2", title="claims confirmed", target="Vault",
        classification=Classification.CONFIRMED,
        evidence_ids=["ev-missing"],  # does not resolve
    )
    record = document_finding(
        repo, finding, evidence_exists=lambda eid: store.get(eid) is not None
    )
    # The classification claimed CONFIRMED but the evidence gate refused.
    assert record.status == "STRONGLY_SUPPORTED"
    assert not record.is_confirmed()


def test_document_finding_confirms_when_evidence_resolves(tmp_path):
    from blackheart.findings import document_finding
    from blackheart.evidence import EvidenceStore
    from blackheart.models import (
        Classification, Finding, GateResult, GateStatus, ReviewIndependence,
    )

    repo = FindingRepository(tmp_path / "repo")
    store = EvidenceStore(tmp_path / "evidence")
    ev = store.put_text("repro", kind="log", description="trace")
    # A realistic CONFIRMED finding carries the seven gates, with gate 6
    # (verification) passing -- that is what proves a verifier ran. The review was
    # done by a separately authenticated model, so it may be labelled independent,
    # and gate 6 carries the canonical provenance detail that proves it (a legacy
    # free-text detail could not).
    from blackheart.models import gate6_detail

    gates = [GateResult(n, name, GateStatus.PASS, "ok")
             for n, name in enumerate(
                 ["reachability", "control", "defense-bypass", "reproduction",
                  "impact", "independent-verification", "scope"], start=1)]
    gates[5] = GateResult(
        6, "independent-verification", GateStatus.PASS,
        gate6_detail(ReviewIndependence.INDEPENDENT_MODEL)[1],
    )
    finding = Finding(
        finding_id="ENG-3", title="real", target="Vault",
        classification=Classification.CONFIRMED,
        evidence_ids=[ev.evidence_id], gates=gates,
        verification_notes="independently reproduced",
        review_independence=ReviewIndependence.INDEPENDENT_MODEL,
    )
    record = document_finding(
        repo, finding, evidence_exists=lambda eid: store.get(eid) is not None
    )
    assert record.reviewer == "independent-verifier"
    assert record.is_confirmed()


def test_document_finding_does_not_label_a_same_model_review_independent(tmp_path):
    """A same-model review is recorded honestly, never as an independent one."""
    from blackheart.findings import document_finding
    from blackheart.evidence import EvidenceStore
    from blackheart.models import (
        Classification, Finding, GateResult, GateStatus, ReviewIndependence,
    )

    repo = FindingRepository(tmp_path / "repo")
    store = EvidenceStore(tmp_path / "evidence")
    ev = store.put_text("repro", kind="log", description="trace")
    gates = [GateResult(n, name, GateStatus.PASS, "ok")
             for n, name in enumerate(
                 ["reachability", "control", "defense-bypass", "reproduction",
                  "impact", "independent-verification", "scope"], start=1)]
    finding = Finding(
        finding_id="ENG-6", title="real", target="Vault",
        classification=Classification.CONFIRMED,
        evidence_ids=[ev.evidence_id], gates=gates,
        verification_notes="same model reviewed in a fresh context",
        review_independence=ReviewIndependence.SAME_MODEL,
    )
    record = document_finding(
        repo, finding, evidence_exists=lambda eid: store.get(eid) is not None
    )
    assert record.reviewer == "same-model-adversarial-reviewer"
    assert record.reviewer != "independent-verifier"
    # A same-model review is a real review but cannot back a CONFIRMED record.
    assert not record.is_confirmed()
    assert record.status == "STRONGLY_SUPPORTED"


def test_a_contradictory_reviewer_label_cannot_back_a_confirmation(tmp_path):
    """A label naming the same model while the record claims INDEPENDENT_MODEL
    is a contradiction, not evidence: the gate must fail closed."""
    from blackheart.findings import confirm_with_evidence

    repo = FindingRepository(tmp_path / "repo")
    base = {"finding_id": "BH-C1", "title": "t", "target": "T",
            "evidence_ids": ["ev-1"], "verification_result": "reproduced",
            "status": "CONFIRMED"}
    contradictory = FindingRecord.from_dict({
        **base, "reviewer": "same-model-adversarial-reviewer",
        "review_independence": "INDEPENDENT_MODEL",
    })
    assert contradictory.missing_confirmation_fields(), \
        "a self-contradictory record must report a missing field"
    assert contradictory.confirm() is False

    stored = repo.add(contradictory)
    ok, why = confirm_with_evidence(
        repo, stored.finding_id, evidence_exists=lambda _: True
    )
    assert ok is False
    assert "contradicts" in why
    assert repo.get(stored.finding_id).status == "STRONGLY_SUPPORTED"


def test_a_consistent_independent_record_still_confirms(tmp_path):
    """The contradiction check must not block a genuinely independent record."""
    from blackheart.findings import confirm_with_evidence

    repo = FindingRepository(tmp_path / "repo")
    record = FindingRecord.from_dict({
        "finding_id": "BH-C2", "title": "t", "target": "T",
        "evidence_ids": ["ev-1"], "reviewer": "independent-verifier",
        "verification_result": "reproduced",
        "review_independence": "INDEPENDENT_MODEL",
        "status": "CONFIRMED",
    })
    assert record.missing_confirmation_fields() == []
    stored = repo.add(record)
    ok, why = confirm_with_evidence(
        repo, stored.finding_id, evidence_exists=lambda _: True
    )
    assert ok is True, why
    assert repo.get(stored.finding_id).is_confirmed()


def test_record_from_finding_never_returns_a_confirmed_same_model_record():
    """A caller may read the record before it is persisted, so the gate must be
    applied in ``record_from_finding`` too -- not only in ``save``."""
    from blackheart.findings import record_from_finding
    from blackheart.models import (
        Classification, Finding, GateResult, GateStatus, ReviewIndependence,
        gate6_detail,
    )

    gates = [GateResult(n, name, GateStatus.PASS, "ok")
             for n, name in enumerate(
                 ["reachability", "control", "defense-bypass", "reproduction",
                  "impact", "independent-verification", "scope"], start=1)]
    gates[5] = GateResult(
        6, "independent-verification",
        *gate6_detail(ReviewIndependence.SAME_MODEL),
    )
    finding = Finding(
        finding_id="ENG-8", title="real", target="Vault",
        classification=Classification.CONFIRMED,
        evidence_ids=["ev-1"], gates=gates, scope_reference="scope",
        review_independence=ReviewIndependence.SAME_MODEL,
    )
    record = record_from_finding(finding)
    assert record.status == "STRONGLY_SUPPORTED"
    assert not record.is_confirmed()


def test_document_finding_with_unrecorded_provenance_is_not_called_independent(tmp_path):
    """No provenance on the finding must not be read as an independent review."""
    from blackheart.findings import document_finding
    from blackheart.evidence import EvidenceStore
    from blackheart.models import (
        Classification, Finding, GateResult, GateStatus,
    )

    repo = FindingRepository(tmp_path / "repo")
    store = EvidenceStore(tmp_path / "evidence")
    ev = store.put_text("repro", kind="log", description="trace")
    gates = [GateResult(n, name, GateStatus.PASS, "ok")
             for n, name in enumerate(
                 ["reachability", "control", "defense-bypass", "reproduction",
                  "impact", "independent-verification", "scope"], start=1)]
    finding = Finding(
        finding_id="ENG-7", title="real", target="Vault",
        classification=Classification.CONFIRMED,
        evidence_ids=[ev.evidence_id], gates=gates,
    )
    record = document_finding(
        repo, finding, evidence_exists=lambda eid: store.get(eid) is not None
    )
    assert record.reviewer == "deterministic-verifier"
    assert record.reviewer != "independent-verifier"


def test_document_finding_does_not_confirm_without_the_verification_gate(tmp_path):
    from blackheart.findings import document_finding
    from blackheart.evidence import EvidenceStore
    from blackheart.models import Classification, Finding

    repo = FindingRepository(tmp_path / "repo")
    store = EvidenceStore(tmp_path / "evidence")
    ev = store.put_text("repro", kind="log", description="trace")
    # A classification of CONFIRMED with no independent-verification gate is not
    # enough: the record has no reviewer, so the evidence gate refuses and the
    # automatic path downgrades it.
    finding = Finding(
        finding_id="ENG-4", title="claims confirmed, no verifier", target="Vault",
        classification=Classification.CONFIRMED, evidence_ids=[ev.evidence_id],
    )
    record = document_finding(
        repo, finding, evidence_exists=lambda eid: store.get(eid) is not None
    )
    assert not record.is_confirmed()
    assert record.status == "STRONGLY_SUPPORTED"


def test_document_finding_fails_closed_when_evidence_check_is_omitted(tmp_path):
    """Omitting the evidence check must not silently persist CONFIRMED."""
    from blackheart.findings import document_finding
    from blackheart.models import Classification, Finding, GateResult, GateStatus

    repo = FindingRepository(tmp_path / "repo")
    gates = [GateResult(n, nm, GateStatus.PASS, "ok")
             for n, nm in enumerate(
                 ["reachability", "control", "defense-bypass", "reproduction",
                  "impact", "independent-verification", "scope"], start=1)]
    finding = Finding(
        finding_id="ENG-5", title="claims confirmed", target="Vault",
        classification=Classification.CONFIRMED, evidence_ids=["ev-unchecked"],
        gates=gates,
    )
    record = document_finding(repo, finding)  # no evidence_exists
    assert not record.is_confirmed()
    assert record.status == "STRONGLY_SUPPORTED"


@pytest.mark.skipif(
    shutil.which("forge") is None,
    reason="forge not on PATH; the reference engagement needs Foundry",
)
def test_cli_engagement_documents_its_finding(tmp_path, capsys):
    """The full reference engagement must auto-document its confirmed finding."""
    from blackheart.cli import main

    workdir = tmp_path / "eng"
    findings_dir = tmp_path / "findings"
    rc = main(["engagement", "--workdir", str(workdir),
               "--findings-dir", str(findings_dir)])
    assert rc == 0
    capsys.readouterr()
    repo = FindingRepository(findings_dir)
    confirmed = repo.confirmed()
    assert len(confirmed) == 1
    rec = confirmed[0]
    assert rec.finding_id == "ref-erc4626-share-inflation"
    assert rec.reviewer  # an independent verifier ran
    assert rec.evidence_ids
    assert repo.verify_integrity()["status"] == "VERIFIED"


def test_a_forged_independence_claim_cannot_reach_a_confirmed_record():
    """The record path must be no weaker than the report path.

    A finding edited to claim ``INDEPENDENT_MODEL`` while its own gate-6 detail is
    legacy free text (which names no provenance) must not produce a record
    labelled ``independent-verifier`` and must not confirm.
    """
    from blackheart.findings import record_from_finding
    from blackheart.models import (
        Classification, Finding, GateResult, GateStatus, ReviewIndependence,
    )

    gates = [GateResult(n, name, GateStatus.PASS, "ok")
             for n, name in enumerate(
                 ["reachability", "control", "defense-bypass", "reproduction",
                  "impact", "independent-verification", "scope"], start=1)]
    forged = Finding(
        finding_id="BH-FORGE", title="forged", target="Vault",
        classification=Classification.CONFIRMED,
        evidence_ids=["ev-1"], gates=gates,
        verification_notes="n",
        review_independence=ReviewIndependence.INDEPENDENT_MODEL,
    )
    assert forged.gates_pass()  # the gates alone are fooled
    record = record_from_finding(forged)
    assert record.reviewer != "independent-verifier"
    assert record.reviewer == "same-model-adversarial-reviewer"
    assert not record.is_confirmed()


def test_a_hand_set_confirmed_status_cannot_read_back_as_a_vulnerability():
    """``is_confirmed`` re-applies the evidence gate, not just the status flag.

    A record can be hand-built, loaded from an edited file, or carry a review whose
    provenance does not support independence. If ``is_confirmed`` trusted the
    status flag, ``may_be_read_as_vulnerability`` would report such a record as a
    live vulnerability.
    """
    from blackheart.findings import FindingRecord, FindingVerdict

    def record(**kwargs) -> FindingRecord:
        base = dict(finding_id="X", title="t", target="T", severity="high",
                    status=FindingVerdict.CONFIRMED.value, evidence_ids=["e"],
                    reviewer="independent-verifier", verification_result="n",
                    review_independence="INDEPENDENT_MODEL")
        base.update(kwargs)
        return FindingRecord(**base)

    # Genuine: every gate field is present and the provenance is independent.
    assert record().is_confirmed()

    # A same-model reviewer label contradicts the independence claim.
    forged_label = record(reviewer="same-model-adversarial-reviewer")
    assert not forged_label.is_confirmed()
    assert not forged_label.may_be_read_as_vulnerability()

    # An unreadable provenance fails closed to SAME_MODEL, never independent.
    assert not record(review_independence="TRUST_ME").is_confirmed()

    # Missing evidence is still missing evidence.
    assert not record(evidence_ids=[]).is_confirmed()
