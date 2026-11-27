"""Acceptance bar for the incremental finding baseline.

The baseline must separate a genuinely new defect from a re-recorded one, and a
verdict change must be visible as a change -- not as a new finding and not as
noise. The identity is the same content fingerprint the SARIF export uses.
"""

from __future__ import annotations

import dataclasses
import json
import subprocess
import sys

import pytest

from blackheart.baseline import compare, create, load
from blackheart.findings import FindingRecord, FindingRepository


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
    )
    return dataclasses.replace(base, **overrides)


def _confirmed(**overrides) -> FindingRecord:
    record = _record(evidence_ids=["ev-1"], verification_result="reproduced",
                     reviewer="independent-auditor", **overrides)
    assert record.confirm()
    return record


def test_an_identical_repository_is_unchanged():
    baseline = create([_record()])
    diff = compare(baseline, [_record()])
    assert diff.new == [] and diff.resolved == [] and diff.changed == []
    assert len(diff.unchanged) == 1


def test_a_new_root_cause_is_new():
    baseline = create([_record()])
    other = _record(finding_id="F-002", root_cause_location="L99")
    diff = compare(baseline, [_record(), other])
    assert [e.finding_id for e in diff.new] == ["F-002"]
    assert diff.has_new


def test_a_missing_finding_is_resolved():
    baseline = create([_record()])
    diff = compare(baseline, [])
    assert [e.finding_id for e in diff.resolved] == ["F-001"]


def test_a_verdict_change_is_changed_not_new():
    baseline = create([_record(status="UNCONFIRMED")])
    diff = compare(baseline, [_confirmed()])
    assert diff.new == [] and diff.resolved == []
    assert len(diff.changed) == 1
    before, after = diff.changed[0]
    assert before.status == "UNCONFIRMED"
    assert after.status == "CONFIRMED"


def test_a_new_id_or_title_for_the_same_root_cause_is_unchanged():
    baseline = create([_record()])
    renamed = _record(finding_id="F-999", title="A different title")
    diff = compare(baseline, [renamed])
    assert diff.new == [] and diff.changed == []
    assert diff.unchanged[0].finding_id == "F-999"


def test_create_keeps_the_strongest_duplicate():
    weak = _record()
    strong = _confirmed()
    baseline = create([weak, strong])
    assert len(baseline["entries"]) == 1
    assert baseline["entries"][0]["status"] == "CONFIRMED"


def test_load_rejects_an_unknown_version():
    with pytest.raises(ValueError, match="unsupported baseline version"):
        load({"version": 99, "entries": []})


def test_cli_create_and_compare_fail_on_new(tmp_path):
    root = tmp_path / "findings"
    repo = FindingRepository(root)
    repo.add(_record())
    baseline = tmp_path / "baseline.json"
    proc = subprocess.run(
        [sys.executable, "-m", "blackheart", "baseline", "--findings", str(root),
         "create", "--out", str(baseline)],
        capture_output=True, text=True, timeout=120,
    )
    assert proc.returncode == 0, proc.stderr
    assert json.loads(baseline.read_text())["entries"][0]["finding_id"] == "F-001"

    clean = subprocess.run(
        [sys.executable, "-m", "blackheart", "baseline", "--findings", str(root),
         "compare", "--baseline", str(baseline), "--fail-on-new"],
        capture_output=True, text=True, timeout=120,
    )
    assert clean.returncode == 0, clean.stderr

    repo.add(_record(finding_id="F-002", root_cause_location="L99"))
    dirty = subprocess.run(
        [sys.executable, "-m", "blackheart", "baseline", "--findings", str(root),
         "compare", "--baseline", str(baseline), "--json", "--fail-on-new"],
        capture_output=True, text=True, timeout=120,
    )
    assert dirty.returncode == 1
    payload = json.loads(dirty.stdout)
    assert payload["counts"]["new"] == 1
    assert payload["new"][0]["finding_id"] == "F-002"
