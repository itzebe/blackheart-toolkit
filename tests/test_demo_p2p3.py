"""Integration test for the P2 -> P3 cycle (deterministic; no forge required).

Runs the demo with ``skip_forge=True`` so it exercises the full lifecycle, the
gates, the honest outcome classification and cross-cycle learning without
depending on a Foundry toolchain. The live-forge path is exercised by running the
demo manually (see docs/RESEARCH_ENGINE.md).
"""

from __future__ import annotations

from blackheart.demo_p2p3 import run_demo


def test_full_cycle_runs_and_reports(tmp_path):
    report = run_demo(tmp_path, skip_forge=True)

    # Cycle 1 produced ranked hypotheses and selected the best.
    assert report["cycle1"]["generated"]["active"] > 0
    assert report["cycle1"]["selected"]["hyp_id"]
    assert report["cycle1"]["selected"]["invariant"]  # a real, stated invariant
    assert report["cycle1"]["selected"]["falsification"]

    # A confirmed finding carried an evidence reference through to VERDICT.
    assert report["cycle1"]["verdict"] == "CONFIRMED"
    assert report["cycle1"]["classification"] == "GENUINE_VIOLATION"
    assert report["cycle1"]["evidence_id"]
    assert report["cycle1"]["final_stage"] == "VERDICT"


def test_negative_result_is_disproven_not_hidden(tmp_path):
    report = run_demo(tmp_path, skip_forge=True)
    assert report["negative_result"]["status"] == "DISPROVEN"
    assert report["negative_result"]["reason"]


def test_environmental_failure_is_retryable(tmp_path):
    report = run_demo(tmp_path, skip_forge=True)
    assert report["environmental_failure"]["status"] == "INCOMPLETE"
    assert report["environmental_failure"]["retryable"] is True


def test_second_cycle_learns_from_the_first(tmp_path):
    report = run_demo(tmp_path, skip_forge=True)
    # Cycle 1 confirmed a class; cycle 2 must not re-propose it as a new lead.
    assert report["cycle2"]["confirmed_classes"]
    assert report["cycle2"]["suppressed_as_known"] >= 1


def test_everything_is_persisted(tmp_path):
    report = run_demo(tmp_path, skip_forge=True)
    p = report["persistence"]
    assert p["investigations_on_disk"] == 3
    assert p["research_records"] == 3
    assert p["evidence_items"] == 3
