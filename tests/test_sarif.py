"""Acceptance bar for the SARIF 2.1.0 export.

The export must be structurally valid, round-trip a CONFIRMED finding with its
evidence references, and never upgrade a hand-set CONFIRMED that the evidence
gate refuses. The fingerprint is shared with the baseline, so it must survive a
new id or title for the same root cause.
"""

from __future__ import annotations

import dataclasses
import json
import subprocess
import sys

import pytest

from blackheart.findings import FindingRecord, FindingRepository
from blackheart.findings.fingerprint import finding_fingerprint
from blackheart.findings.sarif import (
    from_sarif,
    result_level,
    to_sarif,
    validate,
)


def _record(**overrides) -> FindingRecord:
    base = FindingRecord(
        finding_id="F-001",
        title="Reentrant withdraw drains the pool",
        target="Bank",
        component="Bank.sol",
        category="reentrancy",
        severity="high",
        root_cause_file="src/Bank.sol",
        root_cause_location="L42",
        design_mistake="state written after the external call",
        evidence_ids=["ev-1"],
        verification_result="reproduced on a local fork",
        reviewer="independent-auditor",
    )
    base = dataclasses.replace(base, **overrides)
    return base


def _confirmed() -> FindingRecord:
    record = _record()
    assert record.confirm()
    return record


def test_confirmed_finding_round_trips_with_evidence():
    record = _confirmed()
    document = to_sarif([record])
    assert validate(document) == []
    assert document["version"] == "2.1.0"
    assert document["runs"][0]["tool"]["driver"]["name"] == "BLACKHEART"
    result = document["runs"][0]["results"][0]
    assert result["ruleId"] == "blackheart/reentrancy"
    assert result["level"] == "error"
    assert "Reentrant withdraw" in result["message"]["text"]
    assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "src/Bank.sol"
    assert result["locations"][0]["physicalLocation"]["region"]["startLine"] == 42
    assert result["properties"]["confirmed"] is True
    assert result["properties"]["verdict"] == "CONFIRMED"
    assert result["properties"]["evidence_ids"] == ["ev-1"]
    assert from_sarif(document) == [record]


def test_a_claimed_confirmed_without_evidence_is_not_upgraded():
    claimed = _record(finding_id="F-X", status="CONFIRMED",
                      evidence_ids=[], verification_result="", reviewer="")
    assert not claimed.is_confirmed()
    result = to_sarif([claimed])["runs"][0]["results"][0]
    assert result["level"] == "warning"
    assert result["properties"]["confirmed"] is False
    recovered = from_sarif(to_sarif([claimed]))[0]
    assert recovered.status == "STRONGLY_SUPPORTED"


def test_fingerprint_is_stable_for_the_same_root_cause():
    first = _confirmed()
    second = dataclasses.replace(first, finding_id="F-999", title="A different title")
    assert finding_fingerprint(first) == finding_fingerprint(second)
    other = dataclasses.replace(first, root_cause_location="L99")
    assert finding_fingerprint(first) != finding_fingerprint(other)


def test_level_is_a_hint_never_a_verdict():
    confirmed_low = dataclasses.replace(_confirmed(), severity="low")
    assert result_level(confirmed_low) == "warning"
    unconfirmed_high = _record(finding_id="F-U", severity="high")
    assert result_level(unconfirmed_high) == "note"
    false_positive = _record(finding_id="F-F", status="FALSE_POSITIVE", severity="critical")
    assert result_level(false_positive) == "none"


def test_validate_rejects_a_broken_document():
    document = to_sarif([_confirmed()])
    document["version"] = "2.0.0"
    document["runs"][0]["results"][0]["level"] = "fatal"
    errors = validate(document)
    assert any("version" in e for e in errors)
    assert any("level" in e for e in errors)


def test_from_sarif_refuses_an_edited_record():
    document = to_sarif([_confirmed()])
    document["runs"][0]["results"][0]["properties"]["record"]["title"] = "Tampered"
    with pytest.raises(ValueError, match="record_sha256|digest mismatch"):
        from_sarif(document)


def test_cli_exports_the_whole_repository_as_sarif(tmp_path):
    root = tmp_path / "findings"
    FindingRepository(root).add(_confirmed())
    out = tmp_path / "out.sarif"
    proc = subprocess.run(
        [sys.executable, "-m", "blackheart", "findings", "--dir", str(root),
         "sarif", "--out", str(out)],
        capture_output=True, text=True, timeout=120,
    )
    assert proc.returncode == 0, proc.stderr
    document = json.loads(out.read_text())
    assert validate(document) == []
    assert document["runs"][0]["results"][0]["properties"]["finding_id"] == "F-001"
    assert document["runs"][0]["results"][0]["properties"]["confirmed"] is True


def test_cli_exports_one_finding_as_sarif(tmp_path):
    root = tmp_path / "findings"
    FindingRepository(root).add(_confirmed())
    proc = subprocess.run(
        [sys.executable, "-m", "blackheart", "findings", "--dir", str(root),
         "export", "--finding", "F-001", "--format", "sarif"],
        capture_output=True, text=True, timeout=120,
    )
    assert proc.returncode == 0, proc.stderr
    document = json.loads(proc.stdout)
    assert validate(document) == []
    assert len(document["runs"][0]["results"]) == 1
