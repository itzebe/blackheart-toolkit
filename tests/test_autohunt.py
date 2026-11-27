"""Autonomous hunt controller: stops only for a human reviewer, or when exhausted."""

from __future__ import annotations

import json

from blackheart.autohunt import (
    AutoHuntConfig, Target, run_autohunt, grade_from_gate_outcome, bounty_grade,
)
from blackheart.bounty.gate import Disposition, GateOutcome
from blackheart.cli import main

TARGETS = [Target("A"), Target("B"), Target("C")]


def _runner_with(components=(), status="COMPLETED"):
    def runner(target):
        if status != "COMPLETED":
            return {"status": status, "detail": "blocked", "findings": []}
        findings = []
        if target.component in components:
            findings = [{"component": target.component, "reproduced": True,
                         "finding_id": f"f-{target.component}"}]
        return {"status": "COMPLETED", "findings": findings}
    return runner


def _grader(payable=False, awaiting=True):
    def grade(finding, target):
        return {"disposition": "A_SUBMISSION_READY" if payable else "F_NOT_ASSESSED",
                "payable": payable, "awaiting_review": (not payable) and awaiting,
                "reason": "ok"}
    return grade


def test_payable_found_stops_and_surfaces():
    r = run_autohunt(AutoHuntConfig(targets=TARGETS),
                     runner=_runner_with(("B",)), grader=_grader(payable=True))
    assert r.reason == "PAYABLE_FOUND"
    assert r.targets_tried == 2 and len(r.surfaced) == 1
    assert r.surfaced[0].component == "B" and r.needs_human_review


def test_scope_exhausted_when_nothing_payable():
    r = run_autohunt(AutoHuntConfig(targets=TARGETS),
                     runner=_runner_with(()), grader=_grader(awaiting=False))
    assert r.reason == "SCOPE_EXHAUSTED"
    assert r.targets_tried == 3 and not r.needs_human_review


def test_blocked_when_no_target_runs():
    r = run_autohunt(AutoHuntConfig(targets=TARGETS),
                     runner=_runner_with(status="BLOCKED"), grader=_grader())
    assert r.reason == "BLOCKED"
    assert r.targets_blocked == ["A", "B", "C"]


def test_awaiting_review_stops_early():
    r = run_autohunt(AutoHuntConfig(targets=TARGETS),
                     runner=_runner_with(("A",)), grader=_grader(awaiting=True))
    assert r.reason == "AWAITING_REVIEW" and len(r.surfaced) == 1
    assert "confirm only if you independently agree" in r.surfaced[0].review_hint


def test_collects_all_reviews_when_not_stopping():
    r = run_autohunt(AutoHuntConfig(targets=TARGETS, stop_on_awaiting_review=False),
                     runner=_runner_with(("A", "B")), grader=_grader(awaiting=True))
    assert r.reason == "AWAITING_REVIEW" and len(r.surfaced) == 2


def test_budget_exhausted():
    ticks = [0.0]

    def now():
        ticks[0] += 1000.0
        return ticks[0]
    r = run_autohunt(AutoHuntConfig(targets=TARGETS, max_runtime_s=1),
                     runner=_runner_with(()), grader=_grader(), now=now)
    assert r.reason == "BUDGET_EXHAUSTED"


def test_max_targets_cap():
    seen = []

    def runner(target):
        seen.append(target.component)
        return {"status": "COMPLETED", "findings": []}
    run_autohunt(AutoHuntConfig(targets=TARGETS, max_targets=1),
                 runner=runner, grader=_grader())
    assert seen == ["A"]


def test_grade_mapping_is_policy_not_score():
    payable = grade_from_gate_outcome(
        GateOutcome(candidate_id="x", disposition=Disposition.SUBMISSION_READY),
        reproduced=True)
    possible = grade_from_gate_outcome(
        GateOutcome(candidate_id="x", disposition=Disposition.POTENTIALLY_PAYABLE),
        reproduced=True)
    valid_only = grade_from_gate_outcome(
        GateOutcome(candidate_id="x", disposition=Disposition.VALID_NOT_PAYABLE),
        reproduced=True)
    assert payable["payable"] is True
    assert possible["payable"] is False and possible["awaiting_review"] is True
    assert valid_only["payable"] is False and valid_only["awaiting_review"] is False


def test_bounty_grade_without_policy_is_not_assessed():
    g = bounty_grade({"reproduced": True, "outcome": "bypass a restriction"}, TARGETS[0])
    assert g["disposition"] == "F_NOT_ASSESSED" and g["payable"] is False
    assert g["awaiting_review"] is True


def test_bounty_grade_with_policy_returns_a_disposition():
    policy = {"program": "bnb", "policy_url": "https://x", "retrieved_at": "2026-11-24",
              "revision": "r1", "text": "policy text", "in_scope_assets": ["A"]}
    g = bounty_grade({"reproduced": True, "invariant_id": "authorization:owner",
                      "outcome": "bypass a restriction"},
                     TARGETS[0], policy=policy)
    assert g["disposition"] in Disposition.ORDER


def test_cli_autohunt_needs_targets(capsys):
    assert main(["autohunt"]) == 2
    assert "needs --targets" in capsys.readouterr().err


def test_cli_autohunt_blocks_without_compatibility(tmp_path, capsys):
    targets = tmp_path / "t.json"
    targets.write_text(json.dumps([{"component": "A", "path": str(tmp_path)}]))
    assert main(["autohunt", "--targets", str(targets)]) == 1
    assert "BLOCKED" in capsys.readouterr().out
