"""Phase 3 — tests for the controlled adversarial research-quality suite.

These exercise the *real* engine on local intentionally-vulnerable targets. The
suite is differential: every attack class has a positive control (the vulnerable
target must break) and a negative control (the guarded control must hold).

The meta-control at the end is the most important: it proves the harness can
actually *fail* -- pointing a case at a guarded target as if it were vulnerable
must yield NOT_DETECTED, so a green run is meaningful and not a rubber stamp.
"""

from __future__ import annotations

import json

from blackheart.research_quality import (
    CASES,
    ResearchCase,
    evaluate_case,
    run_evaluation,
    write_evaluation_report,
)

# The mission's ten attack classes must all be represented.
REQUIRED_CLASSES = {
    "Authorization bypass",
    "IDOR / cross-user access",
    "Privilege escalation",
    "Authentication / session boundary",
    "Signature and replay validation",
    "Input validation / trust boundary",
    "Business logic abuse",
    "Cross-function / multi-operation chain",
    "Asset / accounting invariant violation",
    "Agent/tool authorization failure",
}


def test_all_ten_attack_classes_are_defined():
    assert {c.attack_class for c in CASES} == REQUIRED_CLASSES
    assert len(CASES) == 10


def test_every_case_has_the_ten_required_fields():
    for c in CASES:
        assert c.case_id
        assert c.objective and c.hypothesis
        assert c.capabilities and c.preconditions
        assert c.surface
        assert c.expected_secure and c.expected_vulnerable
        assert c.reproduction and c.verification
        assert c.evidence
        assert c.vulnerable and c.guarded


def test_every_case_is_unprivileged_and_has_a_control():
    for c in CASES:
        joined = " ".join(c.capabilities + c.preconditions).lower()
        # the attacker is unprivileged: capabilities must not assume a role/key
        assert "owner" not in joined or "without" in joined or "no " in joined, c.case_id
        # each case names a guarded control target
        assert c.guarded


def test_full_suite_passes_positive_and_negative_controls():
    report = run_evaluation(runs=300, steps_per_run=10)
    assert report["control_failed"] == 0, report
    assert report["detected"] == report["cases"], report
    assert report["all_controls_pass"] is True
    # honesty: shared pairs are disclosed
    assert "pairs_shared_across_classes" in report


def test_every_detected_case_is_attacker_reachable():
    report = run_evaluation(runs=300, steps_per_run=10)
    for r in report["results"]:
        if r["status"] == "DETECTED" and r["case_id"] != "TOOL-01":
            assert r["attacker_reachable"] is True, r


def test_negative_control_holds_for_every_case():
    report = run_evaluation(runs=300, steps_per_run=10)
    for r in report["results"]:
        assert r["guarded_breaks"] == 0, r


# --------------------------------------------------------------------------- #
# Meta-control: the harness can actually report failure (not a rubber stamp)
# --------------------------------------------------------------------------- #

def test_harness_reports_not_detected_when_target_is_guarded():
    """A case pointed at the *guarded* target must NOT be detected.

    This is the control that proves a green suite means something: the same
    machinery that reports DETECTED for a vulnerable target reports NOT_DETECTED
    for a guarded one.
    """
    mislabelled = ResearchCase(
        case_id="META-01",
        attack_class="Asset / accounting invariant violation",
        vulnerable="safe",           # the GUARDED vault, mislabelled as vulnerable
        guarded="safe",
        objective="(meta-control) prove the harness can fail",
        capabilities=["deposit"],
        preconditions=["none"],
        surface="n/a",
        hypothesis="the guarded vault should not break",
        expected_secure="no break",
        expected_vulnerable="(should not happen)",
        reproduction="fuzz the guarded target",
        verification="no attacker-reachable break exists",
        evidence=["none"],
    )
    result = evaluate_case(mislabelled, runs=300, steps_per_run=10)
    assert result.status == "NOT_DETECTED"
    assert result.positive_control is False


def test_harness_reports_control_failed_when_control_is_vulnerable():
    """A case whose 'control' is actually vulnerable must be flagged CONTROL_FAILED."""
    mislabelled = ResearchCase(
        case_id="META-02",
        attack_class="Asset / accounting invariant violation",
        vulnerable="vulnerable",
        guarded="vulnerable",       # the control is NOT guarded
        objective="(meta-control) prove the control check works",
        capabilities=["deposit"],
        preconditions=["none"],
        surface="n/a",
        hypothesis="the vulnerable twin breaks",
        expected_secure="(not actually secure)",
        expected_vulnerable="breaks",
        reproduction="fuzz both",
        verification="the control breaks, invalidating the differential",
        evidence=["none"],
    )
    result = evaluate_case(mislabelled, runs=300, steps_per_run=10)
    assert result.status == "CONTROL_FAILED"


# --------------------------------------------------------------------------- #
# Reproducibility and reporting
# --------------------------------------------------------------------------- #

def test_evaluation_is_deterministic_for_a_fixed_seed():
    a = run_evaluation(runs=200, steps_per_run=8, seed=0)
    b = run_evaluation(runs=200, steps_per_run=8, seed=0)
    assert a["detected"] == b["detected"]
    assert [r["status"] for r in a["results"]] == [r["status"] for r in b["results"]]


def test_report_writes_and_round_trips(tmp_path):
    report = run_evaluation(runs=200, steps_per_run=8)
    path = write_evaluation_report(report, tmp_path)
    assert path.exists()
    loaded = json.loads(path.read_text())
    assert loaded["suite"] == "blackheart-research-quality"
    assert loaded["cases"] == 10


def test_tool_case_is_a_negative_only_control():
    tool = next(c for c in CASES if c.case_id == "TOOL-01")
    # It documents explicitly that it has no unguarded twin.
    assert "negative" in tool.verification.lower()
