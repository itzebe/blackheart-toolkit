"""Adaptive adversarial strategy generation: when a hypothesis fails, change the approach.

When an attack hypothesis fails, the naive response is to retry it slightly
differently -- forever. That produces no information and burns budget. This module
encodes the discipline the doctrine requires:

  * **Record what was attempted.** Every attempt leaves a strategy signature, its
    failure reason, and whether the failure invalidated the *hypothesis* or only the
    *strategy*.
  * **Generate materially different approaches.** A strategy is described by a set
    of *dimensions* (role, state precondition, sequence shape, component
    interaction, timing). A new strategy differs from prior ones in at least one
    dimension; a superficial variation (same dimension values) is refused.
  * **Do not loop.** :class:`StrategySpace` tracks the finite set of dimension
    combinations and reports when it is exhausted, so the controller stops and
    records the limit honestly instead of spinning. The bound is derived from the
    space and configurable -- not an arbitrary small constant.

A failed strategy is *evidence*, and the ledger keeps it: the failure reason is
carried forward so a later pass does not repeat the same dead end.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from enum import Enum


class FailureKind(str, Enum):
    """Whether a failure kills the hypothesis or only the chosen strategy."""

    STRATEGY_INVALID = "strategy-invalid"      # this approach failed; try another
    HYPOTHESIS_DISPROVEN = "hypothesis-disproven"  # the claim itself is wrong
    INCONCLUSIVE = "inconclusive"              # blocked by environment/tool
    #: The backend itself faulted. This says nothing about the hypothesis, so it
    #: must never be recorded as disproof -- the class stays open.
    BACKEND_ERROR = "backend-error"


#: The dimensions along which strategies materially differ. A new strategy must
#: change at least one value from every prior attempt on the same hypothesis.
DIMENSIONS: tuple[str, ...] = (
    "role",            # which actor/privilege level attempts it
    "precondition",    # which state is arranged first
    "sequence_shape",  # single-step vs ordered vs reordered
    "component",       # which component interaction is exercised
    "timing",          # when relative to other operations
)

#: Candidate values per dimension. Deliberately not exhaustive -- a caller can pass
#: more -- but wide enough that "try another" means something.
DEFAULT_VALUES: dict[str, tuple[str, ...]] = {
    "role": ("unprivileged", "self", "low-priv-role", "victim-as-attacker"),
    "precondition": ("empty", "funded", "mid-flight", "boundary", "stale"),
    "sequence_shape": ("single", "ordered", "reordered", "repeated", "interleaved"),
    "component": ("target", "oracle", "callback", "external-dep", "peer"),
    "timing": ("same-block", "next-block", "front-run", "delayed", "deadline-edge"),
}


@dataclass(frozen=True)
class Strategy:
    """One concrete approach: a value for each dimension."""

    values: tuple[tuple[str, str], ...]

    def as_dict(self) -> dict[str, str]:
        return dict(self.values)

    def signature(self) -> str:
        blob = json.dumps(self.as_dict(), sort_keys=True).encode("utf-8")
        return hashlib.sha256(blob).hexdigest()[:16]

    def differ_from(self, other: "Strategy") -> int:
        """How many dimensions differ from ``other`` (0 == a superficial repeat)."""
        a, b = self.as_dict(), other.as_dict()
        return sum(1 for k in DIMENSIONS if a.get(k) != b.get(k))


@dataclass
class Attempt:
    """A recorded attempt: the strategy, its result, and the failure classification."""

    hyp_id: str
    strategy: Strategy
    ok: bool
    failure_kind: str = ""
    failure_reason: str = ""
    evidence_tier: str = ""

    def to_dict(self) -> dict:
        return {
            "hyp_id": self.hyp_id, "strategy": self.strategy.as_dict(),
            "signature": self.strategy.signature(), "ok": self.ok,
            "failure_kind": self.failure_kind, "failure_reason": self.failure_reason,
            "evidence_tier": self.evidence_tier,
        }


class StrategySpace:
    """Track attempts per hypothesis and propose materially different next strategies.

    The space is the cartesian product of the dimension values; a hypothesis is
    *exhausted* when every distinct signature has been tried. That is an honest,
    finite bound -- not proof the class is clean, only that this strategy space is.
    """

    def __init__(self, values: dict[str, tuple[str, ...]] | None = None,
                 *, max_attempts_per_hypothesis: int = 0) -> None:
        self.values = {**DEFAULT_VALUES, **(values or {})}
        #: An optional cap on attempts per hypothesis. 0 means "use the space size".
        self.max_attempts = max_attempts_per_hypothesis
        self.attempts: dict[str, list[Attempt]] = {}

    # -- space size ---------------------------------------------------- #

    def space_size(self) -> int:
        size = 1
        for k in DIMENSIONS:
            size *= max(1, len(self.values.get(k, ())))
        return size

    def _limit(self) -> int:
        return self.max_attempts or self.space_size()

    # -- recording ----------------------------------------------------- #

    def tried(self, hyp_id: str) -> list[Attempt]:
        return list(self.attempts.get(hyp_id, ()))

    def record(self, attempt: Attempt) -> bool:
        """Record an attempt; return False if it is a duplicate signature."""
        sigs = {a.strategy.signature() for a in self.attempts.get(attempt.hyp_id, ())}
        if attempt.strategy.signature() in sigs:
            return False
        self.attempts.setdefault(attempt.hyp_id, []).append(attempt)
        return True

    def hypothesis_disproven(self, hyp_id: str) -> bool:
        return any(a.failure_kind == FailureKind.HYPOTHESIS_DISPROVEN.value
                   for a in self.attempts.get(hyp_id, ()))

    def exhausted(self, hyp_id: str) -> bool:
        """True when the space for this hypothesis has been fully (or cap) explored."""
        if self.hypothesis_disproven(hyp_id):
            return True
        return len(self.attempts.get(hyp_id, ())) >= self._limit()

    # -- next strategy -------------------------------------------------- #

    def next_strategy(self, hyp_id: str) -> Strategy | None:
        """Propose an untried strategy that differs materially from every prior one.

        Returns ``None`` when the space is exhausted (the honest stop). The
        enumeration is deterministic, so the same prior attempts always yield the
        same next proposal -- a run is reproducible.
        """
        if self.exhausted(hyp_id):
            return None
        prior = [a.strategy for a in self.attempts.get(hyp_id, ())]
        tried = {s.signature() for s in prior}
        for combo in self._enumerate():
            if combo.signature() in tried:
                continue
            # A new strategy must differ in at least one dimension from *every* prior
            # attempt; a repeat in disguise is skipped.
            if all(combo.differ_from(p) >= 1 for p in prior) or not prior:
                return combo
        return None

    def _enumerate(self):
        """Deterministically enumerate the dimension combinations."""
        keys = list(DIMENSIONS)
        choices = [self.values.get(k, ("",)) for k in keys]

        def _product(idx: int, acc: tuple[tuple[str, str], ...]):
            if idx == len(keys):
                yield Strategy(values=acc)
                return
            for v in choices[idx]:
                yield from _product(idx + 1, acc + ((keys[idx], v),))

        return _product(0, ())

    # -- reporting ------------------------------------------------------ #

    def diversity(self, hyp_id: str) -> dict:
        """How diverse the attempts on a hypothesis are (distinct dims changed)."""
        prior = [a.strategy for a in self.attempts.get(hyp_id, ())]
        if len(prior) < 2:
            return {"attempts": len(prior), "avg_dim_diff": 0.0, "distinct": len(prior)}
        diffs = [a.differ_from(b) for a, b in zip(prior, prior[1:])]
        return {
            "attempts": len(prior),
            "avg_dim_diff": round(sum(diffs) / len(diffs), 3),
            "distinct": len({s.signature() for s in prior}),
        }
