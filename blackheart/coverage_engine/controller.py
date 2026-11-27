"""The coverage-driven research controller: decide what to investigate next, and stop honestly.

This is the spine of the Universal Vulnerability Coverage Engine. It ties the
pieces together without inventing a new search:

  1. **Applicability** (:mod:`blackheart.coverage_engine.applicability`) decides
     which classes apply and why.
  2. **Surface enumeration** (:mod:`blackheart.coverage_engine.surface`) generates
     hypotheses and multi-stage paths.
  3. **Strategy space** (:mod:`blackheart.coverage_engine.strategy`) supplies
     materially different approaches when one fails.
  4. **Execution adapters** (:mod:`blackheart.environments`) run a probe when the
     caller supplies one -- through the *central authorization gate*, never around
     it.
  5. **Coverage record** (:mod:`blackheart.coverage_engine.record`) accumulates the
     durable, honest ledger.

The controller's job is prioritisation and continuation. It ranks remaining work by
potential impact, program eligibility, exploitability, exposure, hypothesis
strength, dependencies/paths, evidence gaps, prior failures, and remaining budget
-- and it does not declare a run "complete" because one attempt finished. It stops
only for a named reason and records what it did not examine.

Nothing here confirms a finding. A reproduction is recorded with its evidence tier;
only real-execution evidence may later pass the existing confirmation gates, and the
controller never bypasses them.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Optional

from ..objectives import TargetProfile
from .applicability import ApplicabilityEngine, seed_record
from .record import CoverageRecord, CoverageState
from .strategy import Attempt, FailureKind, StrategySpace
from .surface import AttackSurface, SurfaceEnumerator
from .taxonomy import SeverityBand, Taxonomy

#: How much each severity band contributes to priority (ordering only).
_BAND_WEIGHT = {
    SeverityBand.CRITICAL: 1.0,
    SeverityBand.HIGH: 0.8,
    SeverityBand.MEDIUM: 0.55,
    SeverityBand.LOW: 0.3,
    SeverityBand.INFO: 0.1,
}


class StopReason:
    """The named reasons a research run stops."""

    BUDGET_EXHAUSTED = "budget-exhausted"
    STRATEGY_SPACE_EXHAUSTED = "strategy-space-exhausted"
    NO_APPLICABLE_WORK = "no-applicable-work"
    AUTHORIZATION_BLOCKED = "authorization-blocked"
    ENVIRONMENT_BLOCKED = "environment-blocked"
    EXPLICIT_HALT = "explicit-halt"


@dataclass
class ControllerConfig:
    """Every budget the controller uses. Deterministic; explicit; inspectable."""

    #: Hard cap on probes attempted in the run (the primary budget).
    max_probes: int = 200
    #: Cap on attempts per hypothesis before its strategy space is called exhausted.
    max_attempts_per_hypothesis: int = 12
    #: Stop after the first reproduction, or keep hunting other classes?
    stop_after_first_reproduction: bool = False
    #: Program-specific eligibility predicate: (class_key) -> True if the program
    #: pays for it. ``None`` means "not established" and never grants eligibility.
    eligible: Optional[Callable[[str], Optional[bool]]] = None
    #: Deterministic seed (reserved; enumeration is already deterministic).
    seed: int = 0

    def to_dict(self) -> dict:
        return {
            "max_probes": self.max_probes,
            "max_attempts_per_hypothesis": self.max_attempts_per_hypothesis,
            "stop_after_first_reproduction": self.stop_after_first_reproduction,
            "eligible_configured": self.eligible is not None,
            "seed": self.seed,
        }


@dataclass
class ProbeOutcome:
    """What one probe attempt produced, from whichever adapter ran it."""

    ok: bool
    evidence_tier: str = ""
    reproduced: bool = False
    evidence: list[str] = field(default_factory=list)
    #: Set when the failure only invalidates the strategy, not the hypothesis.
    failure_kind: str = FailureKind.STRATEGY_INVALID.value
    failure_reason: str = ""
    limitation: str = ""
    raw_summary: str = ""


#: A probe runner: given (class_key, hypothesis_id, strategy values) -> outcome.
#: Supplied by the caller so the controller stays execution-agnostic; the runner
#: is expected to go through an :class:`~blackheart.environments.adapter.ExecutionAdapter`.
ProbeRunner = Callable[[str, str, dict], ProbeOutcome]


@dataclass
class ControlResult:
    """The outcome of one controller run: the ledger plus the honest stop reason."""

    target: str
    record: CoverageRecord
    surface: AttackSurface
    probes: int = 0
    reproductions: int = 0
    stop_reason: str = ""
    stop_detail: str = ""
    attempts: list[Attempt] = field(default_factory=list)
    priorities: list[dict] = field(default_factory=list)

    def summary(self) -> dict:
        base = self.record.summary()
        base.update({
            "probes": self.probes,
            "reproductions": self.reproductions,
            "stop_reason": self.stop_reason,
            "stop_detail": self.stop_detail,
            "surface": self.surface.to_dict()["counts"],
        })
        return base

    def to_dict(self) -> dict:
        return {
            "summary": self.summary(),
            "record": {k: v.to_dict() for k, v in self.record.classes.items()},
            "surface": self.surface.to_dict(),
            "attempts": [a.to_dict() for a in self.attempts],
            "priorities": list(self.priorities),
        }


class ResearchController:
    """Drive coverage-based, adaptive investigation of one target."""

    def __init__(self, taxonomy: Taxonomy, config: Optional[ControllerConfig] = None):
        self.taxonomy = taxonomy
        self.config = config or ControllerConfig()
        self._applicability = ApplicabilityEngine(taxonomy)
        self._surface = SurfaceEnumerator(taxonomy)

    # -- prioritisation ------------------------------------------------ #

    def _priority(self, class_key: str, hyp_count: int, prior_failures: int,
                  on_path: bool) -> float:
        """A transparent priority score in [0, 1]. Ordering only; never payability.

        Factors, all visible in the returned dict:
          impact (band) x eligibility x exposure(hypotheses) x path-bonus
          minus a prior-failure discount.
        """
        cls = self.taxonomy.get(class_key)
        band = cls.default_band if cls else SeverityBand.MEDIUM
        impact = _BAND_WEIGHT.get(band, 0.5)
        # Eligibility is *additive information*, never assumed: if the program says
        # the class is ineligible, it is deprioritised to zero; if unknown, neutral.
        elig = 1.0
        if self.config.eligible is not None:
            verdict = self.config.eligible(class_key)
            if verdict is False:
                elig = 0.0
            elif verdict is None:
                elig = 0.6   # unknown: still worth work, but below a confirmed class
        exposure = min(1.0, 0.4 + 0.15 * hyp_count)
        # The path bonus is scaled by eligibility: a class the program explicitly
        # excludes must score zero, never be lifted back up by being on a path.
        path_bonus = 0.2 * elig if on_path else 0.0
        failure_discount = min(0.6, 0.15 * prior_failures)
        score = impact * elig * exposure + path_bonus - failure_discount
        return max(0.0, min(1.0, score))

    def _score_all(self, surface: AttackSurface, record: CoverageRecord,
                   space: StrategySpace) -> list[dict]:
        on_path_classes = {k for p in surface.paths for k in p.class_keys}
        hyps_by_class: dict[str, list] = {}
        for h in surface.hypotheses:
            hyps_by_class.setdefault(h.class_key, []).append(h)
        ranked: list[dict] = []
        for key, cov in record.classes.items():
            if cov.state not in (CoverageState.APPLICABLE, CoverageState.IN_PROGRESS):
                continue
            hyps = hyps_by_class.get(key, [])
            failures = cov.distinct_failures
            score = self._priority(key, len(hyps), failures, key in on_path_classes)
            ranked.append({
                "class_key": key,
                "score": round(score, 4),
                "hypotheses": len(hyps),
                "prior_failures": failures,
                "on_attack_path": key in on_path_classes,
                "has_model": bool(self.taxonomy.get(key) and self.taxonomy.get(key).objective_category),
            })
        ranked.sort(key=lambda d: (-d["score"], d["class_key"]))
        return ranked

    # -- the run ------------------------------------------------------- #

    def run(self, profile: TargetProfile, *, probe: Optional[ProbeRunner] = None,
            record: Optional[CoverageRecord] = None) -> ControlResult:
        """Investigate ``profile`` and return the honest ledger.

        ``probe`` is optional. Without it the controller still does the full
        structural work -- applicability, surface enumeration, hypothesis and path
        generation, prioritisation, coverage accounting -- and stops with
        ``NO_APPLICABLE_WORK``/budget reason noting that no execution backend was
        supplied. It never fabricates an execution result.
        """
        applicability = self._applicability.classify(profile)
        rec = record or seed_record(applicability)
        surface = self._surface.build(applicability, profile)
        result = ControlResult(target=profile.name, record=rec, surface=surface)

        space = StrategySpace(max_attempts_per_hypothesis=self.config.max_attempts_per_hypothesis)
        _hyps_by_id = {h.hyp_id: h for h in surface.hypotheses}
        for h in surface.hypotheses:
            rec.record_hypothesis(h.class_key, h.hyp_id)

        # Track which hypotheses remain; iterate deterministically by priority.
        pending_hyp_ids = [h.hyp_id for h in surface.hypotheses]
        if not pending_hyp_ids:
            result.stop_reason = StopReason.NO_APPLICABLE_WORK
            result.stop_detail = (
                "no applicable class produced a hypothesis for this target surface"
            )
            rec.stop_reason = result.stop_reason
            result.priorities = self._score_all(surface, rec, space)
            return result

        if probe is None:
            result.stop_reason = StopReason.ENVIRONMENT_BLOCKED
            result.stop_detail = (
                "no execution backend supplied: structural coverage computed "
                "(applicability, hypotheses, attack paths) but nothing was executed"
            )
            rec.stop_reason = result.stop_reason
            rec.record_limitation(result.stop_detail)
            result.priorities = self._score_all(surface, rec, space)
            return result

        # Probe loop: re-rank each round so a reproduction or a dead end reflows work.
        while True:
            ranked = self._score_all(surface, rec, space)
            result.priorities = ranked
            chosen = None
            for entry in ranked:
                key = entry["class_key"]
                for h in surface.hypotheses:
                    if h.class_key != key or h.hyp_id not in pending_hyp_ids:
                        continue
                    if space.exhausted(h.hyp_id):
                        continue
                    chosen = h
                    break
                if chosen is not None:
                    break
            if chosen is None:
                # Nothing left -- decide honestly why.
                self._finalize_stop(result, rec, space, pending_hyp_ids)
                break

            _cov = rec.classes[chosen.class_key]
            rec.set_state(chosen.class_key, CoverageState.IN_PROGRESS,
                          reason=f"investigating {chosen.hyp_id}")

            strategy = space.next_strategy(chosen.hyp_id)
            if strategy is None:
                # Space exhausted for this hypothesis; mark it and continue.
                pending_hyp_ids.remove(chosen.hyp_id)
                continue

            if result.probes >= self.config.max_probes:
                result.stop_reason = StopReason.BUDGET_EXHAUSTED
                result.stop_detail = (
                    f"probe budget of {self.config.max_probes} reached; "
                    f"{len(pending_hyp_ids)} hypothesis(es) and any open classes remain"
                )
                rec.stop_reason = result.stop_reason
                break

            try:
                outcome = probe(chosen.class_key, chosen.hyp_id, strategy.as_dict())
            except Exception as exc:  # a backend fault must not abort the run
                # Record the failure as a *backend* failure and keep going: the
                # remaining hypotheses and the coverage ledger must survive one
                # broken backend. The class is left open, never marked tested.
                outcome = ProbeOutcome(
                    ok=False,
                    failure_kind=FailureKind.BACKEND_ERROR.value,
                    failure_reason=f"{type(exc).__name__}: {exc}",
                )
                rec.record_backend_fault(chosen.class_key)
                rec.record_limitation(
                    f"backend error probing {chosen.class_key}: "
                    f"{type(exc).__name__}: {exc}"
                )
            if (not outcome.ok
                    and outcome.failure_kind == FailureKind.INCONCLUSIVE.value):
                # Blocked, not searched: a policy refusal or an unreachable
                # dependency. Recorded so the class cannot be closed as clean.
                rec.record_blocked(chosen.class_key)

            result.probes += 1
            attempt = Attempt(
                hyp_id=chosen.hyp_id, strategy=strategy, ok=outcome.ok,
                failure_kind=outcome.failure_kind,
                failure_reason=outcome.failure_reason,
                evidence_tier=outcome.evidence_tier,
            )
            space.record(attempt)
            result.attempts.append(attempt)
            rec.record_strategy(chosen.class_key, strategy.signature(),
                                ok=outcome.ok, evidence_tier=outcome.evidence_tier)
            if outcome.limitation:
                rec.record_limitation(outcome.limitation)

            if outcome.reproduced and outcome.evidence:
                result.reproductions += 1
                rec.set_state(chosen.class_key, CoverageState.REPRODUCED,
                              reason=f"reproduced via {chosen.hyp_id}",
                              evidence=outcome.evidence)
                pending_hyp_ids.remove(chosen.hyp_id)
                if self.config.stop_after_first_reproduction:
                    result.stop_reason = StopReason.EXPLICIT_HALT
                    result.stop_detail = "configured to stop after first reproduction"
                    rec.stop_reason = result.stop_reason
                    break
                continue

            if outcome.failure_kind == FailureKind.HYPOTHESIS_DISPROVEN.value:
                # The claim itself is refuted: drop it, and close the class only if
                # no sibling hypothesis remains for it.
                pending_hyp_ids.remove(chosen.hyp_id)
                self._maybe_close_class(rec, chosen.class_key, surface, pending_hyp_ids, space)
                continue

            if space.exhausted(chosen.hyp_id):
                pending_hyp_ids.remove(chosen.hyp_id)
                self._maybe_close_class(rec, chosen.class_key, surface, pending_hyp_ids, space)
            # else: leave pending; next round proposes a materially different strategy.

        result.priorities = self._score_all(surface, rec, space)
        return result

    def _maybe_close_class(self, rec: CoverageRecord, class_key: str,
                           surface: AttackSurface, pending: list[str],
                           space: StrategySpace) -> None:
        """Close a class to TESTED_NO_ISSUE_FOUND only when all its hyps are closed."""
        remaining = [h for h in surface.hypotheses
                     if h.class_key == class_key and h.hyp_id in pending
                     and not space.exhausted(h.hyp_id)]
        if remaining:
            return
        cov = rec.classes[class_key]
        if cov.state is CoverageState.REPRODUCED:
            return
        if cov.backend_faults:
            # Exhausting the *strategy* space through backend faults is not a
            # search: the backend never ran. Calling that "tested, no issue found"
            # would launder an outage into a clean result, so it stays BLOCKED.
            rec.set_state(
                class_key, CoverageState.BLOCKED,
                reason=(
                    f"{cov.backend_faults} attempt(s) never ran because the backend "
                    "faulted; this class was not searched"
                ),
            )
            return
        if cov.blocked_attempts:
            # The same rule for a *policy* block: an authorization refusal or a DNS
            # failure is not evidence about the class. "Not executed" is not
            # "not vulnerable", so the class stays open rather than closing clean.
            rec.set_state(
                class_key, CoverageState.BLOCKED,
                reason=(
                    f"{cov.blocked_attempts} attempt(s) were blocked before execution "
                    "(authorization, DNS or dependency); this class was not searched"
                ),
            )
            return
        rec.set_state(
            class_key, CoverageState.TESTED_NO_ISSUE_FOUND,
            reason=(
                "every hypothesis for this class was disproven or its bounded strategy "
                "space exhausted -- NOT found, not proof of absence"
            ),
        )

    def _finalize_stop(self, result: ControlResult, rec: CoverageRecord,
                       space: StrategySpace, pending: list[str]) -> None:
        """Set an honest stop reason and leave unresolved classes visible."""
        still_open = [k for k, c in rec.classes.items()
                      if c.state in (CoverageState.APPLICABLE, CoverageState.IN_PROGRESS)]
        for key in still_open:
            # A class whose every hypothesis is exhausted is closed; any other open
            # class is a genuine gap and stays UNRESOLVED with its reason.
            hyps = [h for h in result.surface.hypotheses if h.class_key == key]
            exhausted = all(space.exhausted(h.hyp_id) for h in hyps) if hyps else False
            if exhausted:
                self._maybe_close_class(rec, key, result.surface, pending, space)
            else:
                rec.set_state(
                    key, CoverageState.UNRESOLVED,
                    reason="research stopped before this class could be concluded",
                )
        result.stop_reason = StopReason.STRATEGY_SPACE_EXHAUSTED
        result.stop_detail = (
            "every hypothesis's bounded strategy space was explored; this is a "
            "measured limit, not proof the class is clean"
        )
        rec.stop_reason = result.stop_reason
