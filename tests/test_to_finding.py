"""A PASS reproduction becomes a finding -- STRONGLY_SUPPORTED until independently verified."""

from __future__ import annotations

from blackheart.cli import main
from blackheart.findings import FindingRepository
from blackheart.hypothesis.to_finding import record_reproduction
from blackheart.hypothesis.to_target import target_from_hypothesis
from blackheart.models import ReviewIndependence

VULN = """pragma solidity ^0.8.0;
contract C {
    address public owner;
    function setOwner(address a) external { owner = a; }
}
"""
PASS = {"status": "PASS", "invariant_id": "authorization:owner",
        "detail": "forge test passed", "command": "forge test"}


def _out(tmp_path):
    (tmp_path / "C.sol").write_text(VULN)
    return target_from_hypothesis({"component": "C"}, root=str(tmp_path),
                                  certify_result=True)


def test_pass_without_review_is_strongly_supported(tmp_path):
    r = record_reproduction(_out(tmp_path), PASS, target="C",
                            findings_root=str(tmp_path / "f"),
                            evidence_root=str(tmp_path / "e"))
    assert r.status == "RECORDED" and r.verdict == "STRONGLY_SUPPORTED"
    assert "reviewer" in r.missing_confirmation_fields
    assert FindingRepository(str(tmp_path / "f")).all()[0].status == "STRONGLY_SUPPORTED"


def test_blocked_is_refused_and_nothing_recorded(tmp_path):
    r = record_reproduction(_out(tmp_path),
                            {"status": "BLOCKED", "invariant_id": "authorization:owner"},
                            target="C", findings_root=str(tmp_path / "f"),
                            evidence_root=str(tmp_path / "e"))
    assert r.status == "REFUSED"
    assert FindingRepository(str(tmp_path / "f")).all() == []


def test_genuine_independent_review_confirms(tmp_path):
    r = record_reproduction(
        _out(tmp_path), PASS, target="C", findings_root=str(tmp_path / "f"),
        evidence_root=str(tmp_path / "e"), reviewer="reviewer-2",
        review_independence=ReviewIndependence.INDEPENDENT_MODEL.value,
        verification_result="independently reproduced and confirmed")
    assert r.verdict == "CONFIRMED" and r.missing_confirmation_fields == []


def test_independent_claim_without_a_result_is_refused(tmp_path):
    r = record_reproduction(
        _out(tmp_path), PASS, target="C", findings_root=str(tmp_path / "f"),
        evidence_root=str(tmp_path / "e"), reviewer="reviewer-2",
        review_independence=ReviewIndependence.INDEPENDENT_MODEL.value,
        verification_result="")
    assert r.verdict == "STRONGLY_SUPPORTED"
    assert "verification_result" in r.missing_confirmation_fields


def test_evidence_is_stored(tmp_path):
    r = record_reproduction(_out(tmp_path), PASS, target="C",
                            findings_root=str(tmp_path / "f"),
                            evidence_root=str(tmp_path / "e"))
    assert r.evidence_id.startswith("ev-")


def test_record_finding_flag_requires_a_record(tmp_path, capsys):
    rc = main(["external", "--run", "semgrep", "--target", str(tmp_path),
               "--to-hypotheses", "--to-target", "--certify", "--poc",
               "--record-finding"])
    assert rc == 2
    assert "needs --compatibility" in capsys.readouterr().err
