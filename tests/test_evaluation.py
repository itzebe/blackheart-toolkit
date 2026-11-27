"""The evaluation system must report honestly and refuse to learn from noise.

These tests target the two ways continuous evaluation goes wrong:

* **Dishonest metrics** -- a precision of ``1.0`` computed from a zero denominator
  reads as a perfect score for an evaluation that decided nothing. Every rate here
  is checked for its denominator and for an explicit ``None`` when undefined.
* **Uncontrolled learning** -- a partial run or an unreproduced counterexample
  must never move a baseline. The gate is tested in both directions.

The authorization gate is tested to fail *closed*, because a gate that defaults to
"allow" when its input is malformed is worse than no gate at all.
"""

from __future__ import annotations

import json

import pytest

from blackheart import deployed_selectors as ds
from blackheart.evaluation import (
    COMPLETE,
    PARTIAL,
    AuthorizationGate,
    CampaignConfig,
    compare_to_baseline,
    compute_metrics,
    load_baseline,
    may_update_baseline,
    run_campaign,
)
from blackheart.evaluation.learning import (
    ACCEPTED,
    PROPOSED,
    REJECTED,
    evaluate_learning,
)
from blackheart.testsparker import get_adapter
from blackheart.testsparker.adapter import (
    DISPOSITION_CONFIRMED_DEFECT,
    DISPOSITION_INCONCLUSIVE,
    DISPOSITION_NO_SIGNAL,
    GeneratedTest,
    TestOutcome,
)


def _outcome(tid: str, disposition: str) -> TestOutcome:
    return TestOutcome(
        test_id=tid,
        disposition=disposition,
        defect_signal=disposition == DISPOSITION_CONFIRMED_DEFECT,
    )


# -- metrics honesty ------------------------------------------------------ #
def test_precision_is_none_not_one_when_nothing_was_reported():
    metrics = compute_metrics([_outcome("a", DISPOSITION_NO_SIGNAL)],
                              known_answer=True, expected_defects=set())
    assert metrics["precision"]["value"] is None
    assert "not 1.0" in metrics["precision"]["unavailable_reason"]


def test_every_rate_carries_its_denominator():
    metrics = compute_metrics(
        [_outcome("a", DISPOSITION_NO_SIGNAL), _outcome("b", DISPOSITION_CONFIRMED_DEFECT)],
        known_answer=True, expected_defects={"b"},
    )
    for key in ("execution_coverage", "precision", "recall"):
        block = metrics[key]
        assert "numerator" in block and "denominator" in block
        if block["value"] is not None:
            assert block["denominator"] > 0


def test_inconclusive_is_never_counted_as_a_pass():
    metrics = compute_metrics([_outcome("a", DISPOSITION_INCONCLUSIVE)])
    assert metrics["inconclusive"] == 1
    assert metrics["tests_executed"] == 0
    assert metrics["evaluation_complete"] is False
    assert metrics["execution_coverage"]["value"] == 0.0


def test_recall_uses_the_declared_ground_truth():
    metrics = compute_metrics(
        [_outcome("a", DISPOSITION_CONFIRMED_DEFECT), _outcome("b", DISPOSITION_NO_SIGNAL)],
        known_answer=True, expected_defects={"a", "b"},
    )
    assert metrics["recall"] == {
        "value": 0.5, "numerator": 1, "denominator": 2,
    }
    assert metrics["false_negatives"] == 1


def test_metrics_without_ground_truth_report_unavailable():
    metrics = compute_metrics([_outcome("a", DISPOSITION_NO_SIGNAL)])
    assert metrics["precision"]["value"] is None
    assert metrics["recall"]["value"] is None
    assert "known-answer" in metrics["recall"]["unavailable_reason"]


# -- campaign determinism ------------------------------------------------- #
def test_a_campaign_is_deterministic():
    a = run_campaign(CampaignConfig(name="d", seed=3, limit=25))
    b = run_campaign(CampaignConfig(name="d", seed=3, limit=25))
    assert [o["test_id"] for o in a.outcomes] == [o["test_id"] for o in b.outcomes]
    assert [o["disposition"] for o in a.outcomes] == [o["disposition"] for o in b.outcomes]


def test_a_clean_campaign_is_complete_and_silent():
    result = run_campaign(CampaignConfig(name="clean", seed=0))
    assert result.status == COMPLETE
    assert result.metrics["defects_reported"] == 0
    assert result.counterexamples == []


def test_the_campaign_detects_an_injected_analyser_regression(monkeypatch):
    """End-to-end: the historic via-IR bug must be caught by the campaign."""
    monkeypatch.setattr(ds, "_SUB", -1)
    result = run_campaign(CampaignConfig(name="regressed", seed=0, known_answer=True))
    assert result.metrics["defects_reported"] > 0
    assert result.counterexamples, "a detected defect must preserve its counterexample"
    assert result.status == PARTIAL or result.metrics["defects_reported"] > 0


# -- authorization gate --------------------------------------------------- #
class _Live:
    requires_live_target = True


class _Offline:
    requires_live_target = False


def test_offline_adapters_need_no_authorization():
    allowed, reason = AuthorizationGate().allows(_Offline())
    assert allowed
    assert "offline" in reason


def test_a_live_adapter_without_a_record_is_refused():
    allowed, reason = AuthorizationGate(allow_live=True).allows(_Live())
    assert not allowed
    assert "fail closed" in reason


def test_a_live_adapter_without_a_target_is_refused():
    allowed, _ = AuthorizationGate(record={"anything": 1}).allows(_Live())
    assert not allowed


def test_a_malformed_record_is_refused_not_raised():
    allowed, reason = AuthorizationGate(
        record={"junk": True}, target="example.com", allow_live=True
    ).allows(_Live())
    assert not allowed
    assert "authorization check raised" in reason


def test_a_campaign_records_a_gate_refusal_rather_than_running():
    class RefusedAdapter:
        name = "refused"
        requires_live_target = True

        def generate(self, **kwargs):  # pragma: no cover - must never be called
            raise AssertionError("generate must not run when the gate refuses")

        def validate(self, test):
            return None

        def execute(self, test):  # pragma: no cover
            raise AssertionError("execute must not run when the gate refuses")

    import blackheart.evaluation as ev

    original = ev.get_adapter
    ev.get_adapter = lambda name: RefusedAdapter()
    try:
        result = run_campaign(CampaignConfig(name="gated", adapters=["refused"]))
    finally:
        ev.get_adapter = original

    assert result.gate["refused"]["allowed"] is False
    assert result.tests == []
    assert any("authorization gate" in e for e in result.errors)


# -- baselines ------------------------------------------------------------ #
def test_baseline_update_is_refused_for_a_partial_run():
    result = run_campaign(CampaignConfig(name="p", seed=0, limit=1))
    result.status = PARTIAL
    ok, why = may_update_baseline(result, {"regressions": []})
    assert not ok
    assert "COMPLETE" in why


def test_baseline_update_is_refused_when_a_regression_exists():
    result = run_campaign(CampaignConfig(name="r", seed=0, limit=1))
    result.status = COMPLETE
    ok, why = may_update_baseline(result, {"regressions": [{"test_id": "x"}]})
    assert not ok
    assert "regression" in why


def test_baseline_update_is_allowed_for_a_clean_complete_run():
    result = run_campaign(CampaignConfig(name="ok", seed=0, limit=5))
    ok, _ = may_update_baseline(result, {"regressions": []})
    assert ok


def test_compare_reports_a_regression_with_evidence(tmp_path):
    result = run_campaign(CampaignConfig(name="cmp", seed=0, limit=5))
    baseline = json.loads(json.dumps(result.to_dict()))
    # Flip one outcome in the baseline to NO_SIGNAL so the current defect reads new.
    baseline["outcomes"][0]["disposition"] = DISPOSITION_NO_SIGNAL
    result.outcomes[0]["disposition"] = DISPOSITION_CONFIRMED_DEFECT
    diff = compare_to_baseline(result, baseline)
    assert diff["regressions"], "a NO_SIGNAL -> defect change must be a regression"
    assert diff["regressions"][0]["now"] == DISPOSITION_CONFIRMED_DEFECT


def test_compare_without_a_baseline_says_so():
    result = run_campaign(CampaignConfig(name="nb", seed=0, limit=2))
    diff = compare_to_baseline(result, None)
    assert diff["baseline"] is None
    assert "establishes one" in diff["reason"]


def test_load_baseline_tolerates_missing_and_corrupt_files(tmp_path):
    assert load_baseline(tmp_path / "nope.json") is None
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    assert load_baseline(bad) is None


# -- controlled learning -------------------------------------------------- #
def test_learning_is_rejected_for_an_incomplete_run():
    result = run_campaign(CampaignConfig(name="inc", seed=0, limit=2))
    result.status = PARTIAL
    record = evaluate_learning(result)
    assert record.decision == REJECTED
    assert "incomplete" in record.reason.lower() or "status" in record.reason.lower()


def test_learning_accepts_a_clean_complete_run():
    result = run_campaign(CampaignConfig(name="ok", seed=0, limit=5))
    record = evaluate_learning(result)
    assert record.decision == ACCEPTED


def test_learning_rejects_an_unreproducible_counterexample():
    """A counterexample that does not reproduce must not move the baseline."""
    result = run_campaign(CampaignConfig(name="fake", seed=0, limit=1))
    result.status = COMPLETE
    adapter = get_adapter("dispatch")
    test = adapter.generate(seed=0, limit=1)[0]
    result.counterexamples = [{
        "test": test.to_dict(),
        "outcome": {"test_id": test.test_id,
                    "disposition": DISPOSITION_CONFIRMED_DEFECT,
                    "detail": "claimed", "defect_signal": True, "observed": {}},
    }]
    record = evaluate_learning(result)
    assert record.decision == REJECTED
    assert "did not reproduce" in record.reason
    assert record.reproductions


def test_learning_proposes_rather_than_applies_a_fresh_defect(monkeypatch):
    monkeypatch.setattr(ds, "_SUB", -1)
    result = run_campaign(CampaignConfig(name="prop", seed=0, known_answer=True))
    assert result.counterexamples
    record = evaluate_learning(result)
    assert record.decision == PROPOSED
    assert record.proposal is not None
    assert "independent review" in record.reason


def test_learning_record_writes_a_json_artefact(tmp_path):
    result = run_campaign(CampaignConfig(name="art", seed=0, limit=3))
    out = tmp_path / "learning.json"
    evaluate_learning(result, out_path=out)
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload["decision"] == ACCEPTED
    assert "created_at" in payload


# -- findings from the same-model adversarial review ---------------------- #
def test_allow_live_is_a_real_gate_not_a_dead_flag():
    """The flag must refuse live execution even when a record would authorize it."""
    class Live:
        requires_live_target = True

    refused, reason = AuthorizationGate(
        record={"anything": 1}, target="example.com", allow_live=False
    ).allows(Live())
    assert not refused
    assert "live execution was not enabled" in reason


def test_allow_live_still_requires_a_record():
    """Enabling live execution is not a substitute for authorization."""
    class Live:
        requires_live_target = True

    refused, reason = AuthorizationGate(allow_live=True).allows(Live())
    assert not refused
    assert "fail closed" in reason


def test_an_unwritable_evidence_store_does_not_raise_and_is_not_complete():
    """A campaign that cannot store its artefact must not claim completeness."""
    result = run_campaign(
        CampaignConfig(name="ev", seed=0, limit=2),
        evidence_root="/proc/nonexistent/cannot/write",
    )
    assert result.status == PARTIAL
    assert result.metrics["evaluation_complete"] is False
    assert any("could not be written" in e for e in result.errors)


def test_a_successful_campaign_records_its_evidence_id(tmp_path):
    result = run_campaign(
        CampaignConfig(name="ev", seed=0, limit=2), evidence_root=tmp_path / "evidence"
    )
    assert result.metrics.get("evidence_id"), "a complete run must cite its artefact"


def test_an_adapter_exception_is_inconclusive_not_a_pass():
    """An adapter that raises must not read as a clean result."""
    class Exploding:
        name = "boom"
        requires_live_target = False

        def generate(self, **kwargs):
            return [GeneratedTest(test_id="t1", adapter="boom", kind="k", code="6001")]

        def validate(self, test):
            return None

        def execute(self, test):
            raise RuntimeError("adapter blew up")

    import blackheart.evaluation as ev

    original = ev.get_adapter
    ev.get_adapter = lambda name: Exploding()
    try:
        result = run_campaign(CampaignConfig(name="boom", adapters=["boom"]))
    finally:
        ev.get_adapter = original

    assert result.status == PARTIAL
    assert result.outcomes[0]["disposition"] == DISPOSITION_INCONCLUSIVE
    assert result.metrics["defects_reported"] == 0
