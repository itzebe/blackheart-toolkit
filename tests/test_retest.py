"""Acceptance bar for the vulnerability retest loop.

The retester must classify a real reproduction command honestly: a clean exit is
FIXED, a non-zero exit is STILL_REPRODUCIBLE, and an unrunnable command (missing
binary, timeout) is CANNOT_CONFIRM -- never a guessed verdict.
"""

from __future__ import annotations

import sys

from blackheart.findings import FindingRepository, FindingRecord
from blackheart.retest import (
    RetestRecord,
    RetestVerdict,
    apply_to_record,
    classify,
    run_retest,
)


def test_classify_maps_exit_status():
    assert classify(0) is RetestVerdict.FIXED
    assert classify(1) is RetestVerdict.STILL_REPRODUCIBLE
    assert classify(42) is RetestVerdict.STILL_REPRODUCIBLE
    assert classify(None) is RetestVerdict.CANNOT_CONFIRM
    assert classify(None, error="boom") is RetestVerdict.CANNOT_CONFIRM


def test_run_retest_fixed_on_clean_exit():
    rec = run_retest("F-1", [sys.executable, "-c", "import sys; sys.exit(0)"])
    assert rec.verdict is RetestVerdict.FIXED
    assert rec.exit_code == 0


def test_run_retest_still_reproducible_on_failure_exit():
    rec = run_retest("F-1", [sys.executable, "-c", "import sys; sys.exit(3)"])
    assert rec.verdict is RetestVerdict.STILL_REPRODUCIBLE
    assert rec.exit_code == 3


def test_run_retest_missing_binary_is_cannot_confirm():
    rec = run_retest("F-1", ["definitely-not-a-real-binary-wch01"])
    assert rec.verdict is RetestVerdict.CANNOT_CONFIRM
    assert rec.exit_code is None
    assert "could not run" in rec.note


def test_run_retest_records_evidence_ids():
    rec = run_retest("F-1", [sys.executable, "-c", ""], evidence_ids=["ev-1", "ev-2"])
    assert rec.evidence_ids == ["ev-1", "ev-2"]
    assert rec.to_dict()["verdict"] == "fixed"


def test_apply_to_record_sets_retest_result_only():
    record = FindingRecord(finding_id="F-1", title="t", target="x")
    before_status = record.status
    rec = RetestRecord(
        finding_id="F-1", verdict=RetestVerdict.FIXED, command="forge test", exit_code=0
    )
    apply_to_record(rec, record)
    assert record.retest_result.startswith("fixed")
    assert record.status == before_status  # a fix never rewrites the verdict


def test_retest_roundtrip_through_repository(tmp_path):
    repo = FindingRepository(tmp_path / "findings")
    record = FindingRecord(finding_id="F-9", title="t", target="x")
    repo.add(record)
    rec = run_retest("F-9", [sys.executable, "-c", "import sys; sys.exit(1)"])
    got = repo.get("F-9")
    apply_to_record(rec, got)
    repo.save(got)
    again = repo.get("F-9")
    assert again is not None
    assert again.retest_result.startswith("still-reproducible")
