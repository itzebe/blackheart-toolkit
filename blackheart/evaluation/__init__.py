"""Continuous adversarial evaluation: reproducible campaigns with honest metrics.

This is the orchestration layer the mission asks for, built on the engines that
already exist rather than beside them. A campaign:

1. **selects adapters and targets** (deterministic config, recorded verbatim);
2. **generates** tests through TestSparker adapters (pure, seeded);
3. **gates execution** -- an adapter that needs a live target is refused unless the
   authorization record says the target is AUTHORIZED (see :mod:`blackheart.authz`);
4. **executes** each test and records the real outcome;
5. **computes metrics** with explicit denominators and explicit *unavailable* values;
6. **compares against a stored baseline** and reports regressions with the evidence
   that produced them.

The metric rules are the point of this module, so they are stated where they are
computed:

* A **denominator is always printed with its numerator.** ``precision`` is
  ``defects / (defects + false_positives)``, and when the denominator is zero the
  value is ``None`` with a reason -- never ``1.0``, which would read as a perfect
  score for an evaluation that decided nothing.
* **``INCONCLUSIVE`` is never counted as a pass.** It is reported separately and
  excluded from precision/recall denominators, with the exclusion stated.
* **``recall`` needs ground truth.** This module refuses to invent it: recall is
  only computed for a *known-answer* corpus (cases with a declared expectation),
  and is ``None`` with a reason otherwise.
* **``coverage`` means "tests executed / tests generated"**, and is named
  ``execution_coverage`` to stop anyone reading it as vulnerability coverage.

Baselines are content-addressed JSON. An update is *accepted* only when the run is
complete and every test was executed or explicitly excused -- so an interrupted run
can never silently lower the bar for the next one.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from ..models import utcnow
from ..testsparker import adapter_names, get_adapter
from ..testsparker.adapter import (
    DISPOSITION_CONFIRMED_DEFECT,
    DISPOSITION_INCONCLUSIVE,
    DISPOSITION_NO_SIGNAL,
    DISPOSITION_REGRESSION,
    GeneratedTest,
    TestOutcome,
)

__all__ = [
    "CampaignConfig",
    "CampaignResult",
    "Metrics",
    "AuthorizationGate",
    "run_campaign",
    "compute_metrics",
    "load_baseline",
    "compare_to_baseline",
]

#: A campaign run that executed every generated test is COMPLETE. Anything else is
#: PARTIAL, and a PARTIAL run may not update a baseline.
COMPLETE = "COMPLETE"
PARTIAL = "PARTIAL"


@dataclass
class CampaignConfig:
    """A deterministic, recordable campaign definition.

    ``seed`` fixes generation. ``adapters`` selects TestSparker adapters by name.
    ``allow_live`` is not enough on its own to touch a live target -- the
    authorization gate still has to pass -- but it lets an operator refuse live
    execution outright even when scope permits it.
    """

    name: str = "default"
    adapters: list[str] = field(default_factory=lambda: ["dispatch"])
    seed: int = 0
    limit: Optional[int] = None
    allow_live: bool = False
    #: A known-answer corpus: cases with ``expect_defect: true|false``. Only a
    #: corpus like this can yield recall; without it recall is reported unavailable.
    known_answer: bool = False

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "adapters": list(self.adapters),
            "seed": self.seed,
            "limit": self.limit,
            "allow_live": self.allow_live,
            "known_answer": self.known_answer,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "CampaignConfig":
        return cls(
            name=d.get("name", "default"),
            adapters=d.get("adapters", ["dispatch"]),
            seed=d.get("seed", 0),
            limit=d.get("limit"),
            allow_live=d.get("allow_live", False),
            known_answer=d.get("known_answer", False),
        )


class AuthorizationGate:
    """Refuse live execution unless an authorization record permits the target.

    Offline adapters (``requires_live_target = False``) need no record: they run in
    the local interpreter against fixture bytecode and cannot touch a real system.
    That distinction is why this gate is cheap to satisfy for the common case and
    hard to bypass for the dangerous one.

    Fails **closed**: an unreadable record, a missing record, or an UNKNOWN asset is
    a refusal, never a default-allow.
    """

    def __init__(self, record: Any = None, target: str = "",
                 allow_live: bool = False) -> None:
        self._record = record
        self._target = target
        self._allow_live = allow_live
        self._decision: Optional[dict] = None

    def allows(self, adapter: Any) -> tuple[bool, str]:
        if not getattr(adapter, "requires_live_target", False):
            return True, "offline adapter: local interpreter only, no live target"
        if not self._allow_live:
            return False, (
                "adapter requires a live target but live execution was not enabled "
                "(pass allow_live / --allow-live); refusing to execute"
            )
        if self._record is None:
            return False, (
                "adapter requires a live target but no authorization record was "
                "supplied; refusing to execute (fail closed)"
            )
        if not self._target:
            return False, (
                "adapter requires a live target but no target was named; refusing "
                "to execute (fail closed)"
            )
        try:
            from ..authz import authorize_active_testing

            decision = authorize_active_testing(self._record, self._target)
        except Exception as exc:  # a gate that errors must not become a gate that allows
            return False, f"authorization check raised {type(exc).__name__}: {exc}"
        self._decision = decision.to_dict()
        if not decision.allowed:
            blockers = "; ".join(decision.blockers) or decision.status.value
            return False, f"target {self._target!r} is not authorized: {blockers}"
        return True, f"target {self._target!r} is AUTHORIZED"

    @property
    def decision(self) -> Optional[dict]:
        return self._decision


@dataclass
class CampaignResult:
    """Everything one campaign produced, in a form a reviewer can audit."""

    config: CampaignConfig
    started_at: str = ""
    finished_at: str = ""
    status: str = PARTIAL
    #: Per-adapter gate decisions, so a refusal is visible rather than silent.
    gate: dict = field(default_factory=dict)
    tests: list[dict] = field(default_factory=list)
    outcomes: list[dict] = field(default_factory=list)
    metrics: dict = field(default_factory=dict)
    #: Counterexamples preserved for regression: every test that reported a defect.
    counterexamples: list[dict] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "config": self.config.to_dict(),
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "status": self.status,
            "gate": self.gate,
            "metrics": self.metrics,
            "tests": self.tests,
            "outcomes": self.outcomes,
            "counterexamples": self.counterexamples,
            "errors": self.errors,
        }


def _rate(numerator: int, denominator: int, *, why_empty: str) -> dict:
    """A rate with its own denominator, and an explicit reason when undefined."""
    if denominator == 0:
        return {"value": None, "numerator": numerator, "denominator": 0,
                "unavailable_reason": why_empty}
    return {"value": round(numerator / denominator, 4), "numerator": numerator,
            "denominator": denominator}


def compute_metrics(outcomes: list[TestOutcome], *,
                    known_answer: bool = False,
                    expected_defects: Optional[set[str]] = None) -> dict:
    """Turn raw outcomes into metrics, with every denominator stated.

    ``expected_defects`` is the set of test ids that *should* report a defect. It is
    only meaningful for a known-answer corpus; without it, ``recall`` and
    ``precision`` cannot be computed honestly and are reported as unavailable.
    """
    total = len(outcomes)
    by_disp: dict[str, int] = {}
    for o in outcomes:
        by_disp[o.disposition] = by_disp.get(o.disposition, 0) + 1

    defects = by_disp.get(DISPOSITION_CONFIRMED_DEFECT, 0)
    no_signal = by_disp.get(DISPOSITION_NO_SIGNAL, 0)
    inconclusive = by_disp.get(DISPOSITION_INCONCLUSIVE, 0)
    regressions = by_disp.get(DISPOSITION_REGRESSION, 0)

    executed = defects + no_signal + regressions
    metrics: dict[str, Any] = {
        "tests_generated": total,
        "tests_executed": executed,
        "inconclusive": inconclusive,
        "defects_reported": defects,
        "no_signal": no_signal,
        "regressions": regressions,
        # Named "execution" so nobody reads it as vulnerability coverage.
        "execution_coverage": _rate(
            executed, total,
            why_empty="no tests were generated, so there is nothing to cover",
        ),
        "inconclusive_rate": _rate(
            inconclusive, total,
            why_empty="no tests were generated",
        ),
    }

    if known_answer and expected_defects is not None:
        caught = {
            o.test_id for o in outcomes
            if o.disposition == DISPOSITION_CONFIRMED_DEFECT
        }
        true_positives = len(caught & expected_defects)
        false_positives = len(caught - expected_defects)
        false_negatives = len(expected_defects - caught)
        metrics["precision"] = _rate(
            true_positives, true_positives + false_positives,
            why_empty="no defect was reported, so precision has no denominator "
                      "(it is not 1.0 -- nothing was decided)",
        )
        metrics["recall"] = _rate(
            true_positives, len(expected_defects),
            why_empty="the known-answer corpus declares no expected defects",
        )
        metrics["true_positives"] = true_positives
        metrics["false_positives"] = false_positives
        metrics["false_negatives"] = false_negatives
        metrics["reproduction_success_rate"] = _rate(
            true_positives, true_positives + false_negatives,
            why_empty="no expected defect to reproduce",
        )
    else:
        metrics["precision"] = {
            "value": None, "numerator": 0, "denominator": 0,
            "unavailable_reason": "no known-answer corpus was supplied; precision "
                                  "against ground truth cannot be computed",
        }
        metrics["recall"] = {
            "value": None, "numerator": 0, "denominator": 0,
            "unavailable_reason": "no known-answer corpus was supplied; recall "
                                  "against ground truth cannot be computed",
        }

    # Completeness is a *statement about the run*, not a score.
    metrics["evaluation_complete"] = inconclusive == 0 and total > 0
    metrics["completeness_reason"] = (
        "every generated test was executed"
        if metrics["evaluation_complete"]
        else f"{inconclusive} test(s) were inconclusive, so the evaluation is partial"
    )
    return metrics


def run_campaign(
    config: CampaignConfig,
    *,
    corpus: Optional[list[dict]] = None,
    authz: Optional[AuthorizationGate] = None,
    evidence_root: Optional[str | os.PathLike] = None,
) -> CampaignResult:
    """Run one campaign end to end. Never raises on a test failure -- it records it."""
    gate = authz or AuthorizationGate(allow_live=config.allow_live)
    result = CampaignResult(config=config, started_at=utcnow())
    expected_defects: set[str] = set()

    for name in config.adapters:
        try:
            adapter = get_adapter(name)
        except KeyError as exc:
            result.errors.append(str(exc))
            continue

        allowed, reason = gate.allows(adapter)
        result.gate[name] = {"allowed": allowed, "reason": reason,
                             "requires_live_target": getattr(adapter, "requires_live_target", False)}
        if not allowed:
            result.errors.append(f"adapter {name!r} refused by the authorization gate: {reason}")
            continue

        # A known-answer campaign uses the adapter's own ground-truth corpus, so
        # precision and recall have a real denominator instead of "unavailable".
        effective_corpus = corpus
        if config.known_answer and corpus is None and hasattr(adapter, "known_answer_corpus"):
            effective_corpus = adapter.known_answer_corpus()
        try:
            tests = adapter.generate(
                seed=config.seed, corpus=effective_corpus, limit=config.limit
            )
        except Exception as exc:
            result.errors.append(f"adapter {name!r} failed to generate: {exc}")
            continue

        for test in tests:
            result.tests.append(test.to_dict())
            if test.expectation.get("expect_defect"):
                expected_defects.add(test.test_id)
            try:
                outcome = adapter.execute(test)
            except Exception as exc:
                outcome = TestOutcome(
                    test_id=test.test_id,
                    disposition=DISPOSITION_INCONCLUSIVE,
                    detail=f"adapter raised {type(exc).__name__}: {exc}",
                )
            result.outcomes.append(outcome.to_dict())
            if outcome.defect_signal:
                result.counterexamples.append({
                    "test": test.to_dict(),
                    "outcome": outcome.to_dict(),
                })

    outcomes = [TestOutcome(test_id=o["test_id"], disposition=o["disposition"],
                            observed=o.get("observed", {}), detail=o.get("detail", ""),
                            defect_signal=o.get("defect_signal", False))
                for o in result.outcomes]
    result.metrics = compute_metrics(
        outcomes,
        known_answer=config.known_answer,
        expected_defects=expected_defects if config.known_answer else None,
    )
    result.status = COMPLETE if result.metrics.get("evaluation_complete") else PARTIAL
    result.finished_at = utcnow()

    if evidence_root is not None:
        from ..evidence import EvidenceStore

        try:
            ev = EvidenceStore(evidence_root).put_json(
                result.to_dict(), kind="evaluation-campaign",
                description=f"evaluation campaign {config.name!r} at seed {config.seed}",
            )
            result.metrics["evidence_id"] = ev.evidence_id
        except Exception as exc:  # noqa: BLE001 - the failure must be recorded, not raised
            result.errors.append(
                f"evidence store at {evidence_root!r} could not be written: "
                f"{type(exc).__name__}: {exc}"
            )
            # No artefact means the run cannot honestly claim completeness.
            result.status = PARTIAL
            result.metrics["evaluation_complete"] = False
            result.metrics["completeness_reason"] = (
                "the campaign artefact could not be stored, so completeness cannot be "
                "claimed"
            )
    return result


# -- baselines ------------------------------------------------------------ #
def load_baseline(path: str | os.PathLike) -> Optional[dict]:
    p = Path(path)
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None


def compare_to_baseline(result: CampaignResult, baseline: Optional[dict]) -> dict:
    """Diff a run against a stored baseline, naming regressions with evidence.

    A regression is a test that was ``NO_SIGNAL`` (or absent) in the baseline and
    reports a defect now -- i.e. something the analyser used to get right is now
    wrong. Improvements are reported too, so the diff is not one-sided.
    """
    if not baseline:
        return {"baseline": None, "regressions": [], "improvements": [],
                "reason": "no baseline stored; this run establishes one"}

    old = {o["test_id"]: o for o in baseline.get("outcomes", [])}
    new = {o["test_id"]: o for o in result.outcomes}

    regressions = [
        {
            "test_id": tid,
            "was": old[tid]["disposition"],
            "now": new[tid]["disposition"],
            "detail": new[tid].get("detail", ""),
        }
        for tid in sorted(new)
        if tid in old
        and old[tid]["disposition"] != DISPOSITION_CONFIRMED_DEFECT
        and new[tid]["disposition"] == DISPOSITION_CONFIRMED_DEFECT
    ]
    improvements = [
        {
            "test_id": tid,
            "was": old[tid]["disposition"],
            "now": new[tid]["disposition"],
        }
        for tid in sorted(new)
        if tid in old
        and old[tid]["disposition"] == DISPOSITION_CONFIRMED_DEFECT
        and new[tid]["disposition"] != DISPOSITION_CONFIRMED_DEFECT
    ]
    return {
        "baseline": baseline.get("config", {}).get("name"),
        "baseline_finished_at": baseline.get("finished_at"),
        "regressions": regressions,
        "improvements": improvements,
        "new_tests": sorted(set(new) - set(old)),
        "removed_tests": sorted(set(old) - set(new)),
    }


def may_update_baseline(result: CampaignResult, diff: dict) -> tuple[bool, str]:
    """A baseline may only move when the run is complete and shows no regression.

    An interrupted run lowering the baseline is how a quality bar silently rots.
    """
    if result.status != COMPLETE:
        return False, (
            f"run status is {result.status}; only a COMPLETE run may update a baseline"
        )
    if diff.get("regressions"):
        return False, (
            f"{len(diff['regressions'])} regression(s) present; refusing to accept a "
            "baseline that records them as expected"
        )
    return True, "run is complete and regression-free"
