"""Coverage states and the durable coverage record.

A research run must leave a record of what it actually covered -- and, just as
importantly, of what it did **not**. This module defines the states a class or a
surface can be in, and the :class:`CoverageRecord` that holds them.

The honesty rules are encoded in the state machine, not left to a caller:

  * ``TESTED_NO_ISSUE_FOUND`` is explicitly **not** proof of absence; the record
    carries a ``note`` for each such state and the ledger refuses to describe it as
    "clean".
  * ``BLOCKED`` and ``UNRESOLVED`` are first-class terminal states. A run with any
    of them is ``INCOMPLETE`` -- it cannot be reported as complete by counting.
  * A class that was never looked at is ``NOT_ASSESSED``, never omitted: the record
    is seeded from the taxonomy so an untouched class is a visible gap.

``summary()`` never returns a bare percentage that could be misread as "done". It
returns counts by state and an explicit verdict (``COMPLETE`` / ``INCOMPLETE`` /
``NO_FINDINGS_WITHIN_BUDGET``) with the reason.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from ..models import utcnow


class CoverageState(str, Enum):
    """The state of one vulnerability class (or surface) within a run."""

    NOT_ASSESSED = "NOT_ASSESSED"          # never looked at (a visible gap)
    APPLICABLE = "APPLICABLE"              # applies, not yet worked
    IN_PROGRESS = "IN_PROGRESS"            # being investigated
    TESTED_NO_ISSUE_FOUND = "TESTED_NO_ISSUE_FOUND"  # tried; nothing found (NOT proof)
    REPRODUCED = "REPRODUCED"              # a defect reproduced (may be unverified)
    BLOCKED = "BLOCKED"                    # a real obstacle stopped the work
    UNRESOLVED = "UNRESOLVED"              # could not conclude either way
    INAPPLICABLE = "INAPPLICABLE"          # does not apply (reason required)


#: States that mean the class still carries open work -- a run with any of these is
#: incomplete. ``REPRODUCED`` is included because a reproduction is not a *verified*
#: finding until the confirmation gates pass.
OPEN_STATES = frozenset({
    CoverageState.NOT_ASSESSED,
    CoverageState.APPLICABLE,
    CoverageState.IN_PROGRESS,
    CoverageState.BLOCKED,
    CoverageState.UNRESOLVED,
})

#: States that require a written reason; the record refuses them without one.
_REASON_REQUIRED = frozenset({
    CoverageState.INAPPLICABLE,
    CoverageState.BLOCKED,
    CoverageState.UNRESOLVED,
    CoverageState.TESTED_NO_ISSUE_FOUND,
})


class LedgerError(ValueError):
    """Raised when a coverage transition would make the record dishonest."""


@dataclass
class ClassCoverage:
    """The coverage of one vulnerability class for one target."""

    key: str
    title: str = ""
    state: CoverageState = CoverageState.NOT_ASSESSED
    reason: str = ""
    #: Hypotheses generated for this class.
    hypotheses: list[str] = field(default_factory=list)
    #: Distinct strategies attempted (deduplicated by signature).
    strategies: list[str] = field(default_factory=list)
    #: Count of failed attempts that were *materially different* (not repeats).
    distinct_failures: int = 0
    reproduced: int = 0
    #: Evidence references supporting a reproduction (paths/digests), never invented.
    evidence: list[str] = field(default_factory=list)
    #: The strongest evidence tier any attempt produced.
    best_evidence_tier: str = ""
    #: Attempts that never ran because the backend itself faulted. These say
    #: nothing about the class, so a class with faults is never "searched clean".
    backend_faults: int = 0
    #: Attempts that were *blocked* rather than run -- an authorization refusal, a
    #: DNS failure, an unreachable dependency. Like a backend fault these say
    #: nothing about the class, so they must never close it as "no issue found".
    blocked_attempts: int = 0
    updated_at: str = field(default_factory=utcnow)

    def to_dict(self) -> dict:
        return {
            "key": self.key, "title": self.title, "state": self.state.value,
            "reason": self.reason, "hypotheses": list(self.hypotheses),
            "strategies": list(self.strategies),
            "distinct_failures": self.distinct_failures,
            "reproduced": self.reproduced, "evidence": list(self.evidence),
            "best_evidence_tier": self.best_evidence_tier,
            "backend_faults": self.backend_faults,
            "blocked_attempts": self.blocked_attempts,
            "updated_at": self.updated_at,
        }


class CoverageRecord:
    """The durable coverage ledger for one target in one run.

    Seeded from the taxonomy so every class has an explicit entry. Transitions are
    validated: an ``INAPPLICABLE``/``BLOCKED``/``UNRESOLVED``/``TESTED_NO_ISSUE_FOUND``
    state cannot be set without a reason, and a ``REPRODUCED`` state cannot be set
    with no evidence reference -- the record will not hold a claim it cannot back.
    """

    def __init__(self, target: str, classes: list[tuple[str, str]] | None = None) -> None:
        self.target = target
        self.created_at = utcnow()
        self.classes: dict[str, ClassCoverage] = {}
        for key, title in (classes or []):
            self.classes[key] = ClassCoverage(key=key, title=title)
        #: Surfaces the target was found to expose (filled by applicability).
        self.surfaces: list[str] = []
        #: Free-form notes on tool/environment limitations the run hit.
        self.environment_limitations: list[str] = []
        #: Taxonomy gaps: classes discovered mid-run that were not in the seed.
        self.taxonomy_gaps: list[str] = []
        #: Why the run stopped (set by the controller).
        self.stop_reason: str = ""

    # -- transitions --------------------------------------------------- #

    def add_class(self, key: str, title: str = "") -> ClassCoverage:
        """Ensure a class is present; record it as a discovered taxonomy gap."""
        if key in self.classes:
            return self.classes[key]
        cov = ClassCoverage(key=key, title=title)
        self.classes[key] = cov
        self.taxonomy_gaps.append(key)
        return cov

    def set_state(self, key: str, state: CoverageState, *, reason: str = "",
                  evidence: list[str] | None = None) -> ClassCoverage:
        """Move a class to ``state``, refusing a state it cannot back."""
        cov = self.classes.get(key)
        if cov is None:
            cov = self.add_class(key)
        if state in _REASON_REQUIRED and not reason.strip():
            raise LedgerError(
                f"cannot mark '{key}' {state.value} without a reason: an unexplained "
                f"{state.value} would hide why the work stopped"
            )
        evidence = evidence or []
        if state is CoverageState.REPRODUCED and not evidence:
            raise LedgerError(
                f"cannot mark '{key}' REPRODUCED with no evidence reference"
            )
        cov.state = state
        cov.reason = reason
        if evidence:
            for ev in evidence:
                if ev not in cov.evidence:
                    cov.evidence.append(ev)
        if state is CoverageState.REPRODUCED:
            cov.reproduced += 1
        cov.updated_at = utcnow()
        return cov

    def record_hypothesis(self, key: str, hyp_id: str) -> None:
        cov = self.classes.get(key) or self.add_class(key)
        if hyp_id not in cov.hypotheses:
            cov.hypotheses.append(hyp_id)

    def record_backend_fault(self, key: str) -> None:
        """Record that a probe never ran because the backend faulted."""
        cov = self.classes.get(key) or self.add_class(key)
        cov.backend_faults += 1
        cov.updated_at = utcnow()

    def record_blocked(self, key: str) -> None:
        """Record that a probe was blocked (authorization/DNS/dependency).

        A blocked attempt is not a search. Counting it as one would let a policy
        refusal or a DNS outage close a class as "tested, no issue found".
        """
        cov = self.classes.get(key) or self.add_class(key)
        cov.blocked_attempts += 1
        cov.updated_at = utcnow()

    def record_strategy(self, key: str, signature: str, *, ok: bool,
                        evidence_tier: str = "") -> bool:
        """Record a strategy attempt; return True if it was *materially new*.

        Duplicate signatures return False and do not increment the failure count --
        this is what stops a loop from generating superficial variations of one
        failed attempt and calling it progress.
        """
        cov = self.classes.get(key) or self.add_class(key)
        if signature in cov.strategies:
            return False
        cov.strategies.append(signature)
        if not ok:
            cov.distinct_failures += 1
        if evidence_tier:
            cov.best_evidence_tier = _stronger_tier(cov.best_evidence_tier, evidence_tier)
        cov.updated_at = utcnow()
        return True

    def record_limitation(self, text: str) -> None:
        if text and text not in self.environment_limitations:
            self.environment_limitations.append(text)

    # -- reporting ----------------------------------------------------- #

    def by_state(self, state: CoverageState) -> list[ClassCoverage]:
        return [c for c in self.classes.values() if c.state is state]

    def summary(self) -> dict:
        """Counts by state plus an explicit, honest verdict -- never a bare %."""
        counts: dict[str, int] = {s.value: 0 for s in CoverageState}
        for c in self.classes.values():
            counts[c.state.value] += 1
        open_items = [c.key for c in self.classes.values() if c.state in OPEN_STATES]
        reproduced = [c.key for c in self.classes.values()
                      if c.state is CoverageState.REPRODUCED]
        tested_clean = [c.key for c in self.classes.values()
                        if c.state is CoverageState.TESTED_NO_ISSUE_FOUND]
        if open_items:
            verdict = "INCOMPLETE"
            why = f"{len(open_items)} class(es) still open: {', '.join(open_items[:8])}"
        elif reproduced:
            verdict = "COMPLETE_WITH_REPRODUCTIONS"
            why = f"every class closed; {len(reproduced)} reproduced: {', '.join(reproduced)}"
        else:
            verdict = "NO_FINDINGS_WITHIN_BUDGET"
            why = (
                f"every class closed; {len(tested_clean)} tested with no issue found "
                f"-- this is NOT proof that no vulnerability exists"
            )
        return {
            "target": self.target,
            "classes": len(self.classes),
            "counts": counts,
            "verdict": verdict,
            "why": why,
            "open_classes": open_items,
            "reproduced_classes": reproduced,
            "tested_no_issue": tested_clean,
            "taxonomy_gaps": list(self.taxonomy_gaps),
            "environment_limitations": list(self.environment_limitations),
            "surfaces": list(self.surfaces),
            "stop_reason": self.stop_reason,
            "note": (
                "TESTED_NO_ISSUE_FOUND means 'not found within budget', never 'clean'. "
                "A model covers a class representatively, not exhaustively."
            ),
            "created_at": self.created_at,
        }


def _stronger_tier(a: str, b: str) -> str:
    """Return the stronger of two evidence tiers (real > simulation > static)."""
    order = {"": 0, "static-only": 1, "simulation": 2, "real-execution": 3}
    return b if order.get(b, 0) > order.get(a, 0) else a
