"""Controlled learning: how an evaluation run may (and may not) change what we trust.

Continuous evaluation only helps if its results can improve the baseline. It only
*stays safe* if an unverified result cannot. This module is the boundary between
the two, and every rule here exists because the opposite behaviour is a known way
automated tooling degrades:

* **A result is not evidence until it is reproducible.** The reproduction gate
  re-runs a counterexample from a *fresh* interpreter instance and requires the
  same disposition. A one-off difference is recorded as ``UNSTABLE`` and may not
  influence anything.
* **Only an accepted observation may move a baseline.** Acceptance requires: the
  run is COMPLETE, the counterexample reproduced, and the observation carries its
  provenance. Anything else is stored as a *proposal* for a human, never applied.
* **Every decision records its reason.** ``LearningRecord.decision`` is
  ``ACCEPTED``, ``REJECTED`` or ``PROPOSED``, with a reason string. There is no
  silent path.
* **The trusted baseline is append-only in spirit.** Updates are written to a new
  file the caller names; this module never rewrites a file it did not create in
  the same call.

What this module deliberately does *not* do: it does not modify source code, it
does not change the analyser, and it does not touch the authorization gate. It
records observations and produces a reviewed baseline artefact.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from ..models import utcnow
from ..testsparker import get_adapter
from ..testsparker.adapter import (
    DISPOSITION_CONFIRMED_DEFECT,
    DISPOSITION_INCONCLUSIVE,
    GeneratedTest,
)

__all__ = [
    "ACCEPTED",
    "REJECTED",
    "PROPOSED",
    "LearningRecord",
    "ReproductionResult",
    "reproduce_counterexample",
    "evaluate_learning",
]

ACCEPTED = "ACCEPTED"
REJECTED = "REJECTED"
PROPOSED = "PROPOSED"


@dataclass
class ReproductionResult:
    """Whether a counterexample reproduces from a clean state."""

    test_id: str
    reproduced: bool
    first_disposition: str
    second_disposition: str
    detail: str = ""

    def to_dict(self) -> dict:
        return {
            "test_id": self.test_id,
            "reproduced": self.reproduced,
            "first_disposition": self.first_disposition,
            "second_disposition": self.second_disposition,
            "detail": self.detail,
        }


def reproduce_counterexample(test: GeneratedTest, *, adapter_name: Optional[str] = None) -> ReproductionResult:
    """Re-run a counterexample through a *fresh* adapter and require the same result.

    A fresh adapter instance matters: an adapter that cached its first result would
    "reproduce" trivially. Building a new one proves the outcome came from the code
    under test, not from retained state.
    """
    name = adapter_name or test.adapter
    try:
        adapter = get_adapter(name)
    except KeyError as exc:
        return ReproductionResult(
            test_id=test.test_id,
            reproduced=False,
            first_disposition=DISPOSITION_CONFIRMED_DEFECT,
            second_disposition=DISPOSITION_INCONCLUSIVE,
            detail=f"cannot reproduce: {exc}",
        )
    outcome = adapter.execute(test)
    return ReproductionResult(
        test_id=test.test_id,
        reproduced=outcome.disposition == DISPOSITION_CONFIRMED_DEFECT,
        first_disposition=DISPOSITION_CONFIRMED_DEFECT,
        second_disposition=outcome.disposition,
        detail=outcome.detail,
    )


@dataclass
class LearningRecord:
    """One controlled-learning decision, with its evidence and its reason."""

    campaign: str
    decision: str
    reason: str
    reproductions: list[dict] = field(default_factory=list)
    #: The proposed baseline payload, present only when ``decision == PROPOSED``.
    proposal: Optional[dict] = None
    created_at: str = ""

    def to_dict(self) -> dict:
        return {
            "campaign": self.campaign,
            "decision": self.decision,
            "reason": self.reason,
            "reproductions": self.reproductions,
            "proposal": self.proposal,
            "created_at": self.created_at or utcnow(),
        }


def evaluate_learning(
    result,
    *,
    out_path: Optional[str | Path] = None,
) -> LearningRecord:
    """Decide whether a campaign's findings may change the trusted baseline.

    ``result`` is a :class:`blackheart.evaluation.CampaignResult`. The decision is
    one of three, and the reason is always populated:

    * ``REJECTED`` -- the run was incomplete, or a counterexample did not reproduce.
    * ``ACCEPTED`` -- complete, every counterexample reproduced, and no regression:
      the baseline may be written.
    * ``PROPOSED`` -- complete and reproducible, but a human must confirm a change
      that the automated gate cannot decide (currently: any fresh defect, since a
      new defect needs independent review before it becomes a trusted expectation).
    """
    from ..evaluation import COMPLETE

    if result.status != COMPLETE:
        return LearningRecord(
            campaign=result.config.name,
            decision=REJECTED,
            reason=(
                f"run status is {result.status}: {result.metrics.get('completeness_reason', '')}. "
                "An incomplete run may not change the baseline."
            ),
        )

    reproductions: list[dict] = []
    for entry in result.counterexamples:
        test = GeneratedTest.from_dict(entry["test"])
        rep = reproduce_counterexample(test)
        reproductions.append(rep.to_dict())
        if not rep.reproduced:
            return LearningRecord(
                campaign=result.config.name,
                decision=REJECTED,
                reason=(
                    f"counterexample {test.test_id} did not reproduce "
                    f"(second run: {rep.second_disposition}). An unstable result may "
                    "not change the baseline."
                ),
                reproductions=reproductions,
            )

    if result.counterexamples:
        record = LearningRecord(
            campaign=result.config.name,
            decision=PROPOSED,
            reason=(
                f"{len(result.counterexamples)} counterexample(s) reproduced, but a new "
                "defect signal needs independent review before it becomes a trusted "
                "expectation. Stored as a proposal, not applied."
            ),
            reproductions=reproductions,
            proposal={"config": result.config.to_dict(), "counterexamples": result.counterexamples},
        )
    else:
        record = LearningRecord(
            campaign=result.config.name,
            decision=ACCEPTED,
            reason=(
                "run is complete, every counterexample reproduced, and no defect was "
                "reported; the baseline may record this clean state."
            ),
            reproductions=reproductions,
            proposal={"config": result.config.to_dict()},
        )

    if out_path is not None:
        path = Path(out_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(record.to_dict(), indent=2, sort_keys=True), encoding="utf-8")
    return record
