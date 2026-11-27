"""Differential fuzzing over the invariant engine's ``Target`` model.

The single most productive technique for upgradeable and DeFi code is not
"does this break?" but "do these two things that should agree actually agree?"
A proxy and its implementation, an old and a new deployment, a reference model
and a port -- each pair should produce the *same* observable state for the same
sequence of calls. When they diverge, one of them is wrong, and the divergence
tells you exactly which step and which field to look at.

This module adds that comparison to BLACKHEART without a new engine:

* It drives the *same* ``Target`` protocol, ``OpSpec`` alphabet and
  ``AttackStep`` shape every other search strategy uses, so a target built for
  the explorer or the corpus fuzzer works here unchanged.
* It generates sequences from the reference target's declared alphabet, runs
  each step on both targets, and compares ``snapshot(state)`` after every step.
  The first step whose snapshot differs is the divergence, reported with the
  differing keys and both snapshots.
* It minimises the sequence to the shortest prefix that still diverges, so a
  reviewer gets a two- or three-step reproducer rather than a random walk.

Honesty rules that shape the API:

* **A divergence is a lead, not a finding.** Two snapshots disagreeing means the
  two models differ in *some* way; it does not say which is correct, whether the
  difference is reachable in production, or that it costs anyone money. The
  report says ``DIVERGENCE`` and never names a culprit.
* **The alphabets must match.** Comparing targets whose operations differ is
  meaningless, so a mismatched alphabet is a ``DifferentialError``, not an empty
  result. A clean differential is "no divergence on the sequences tried", never
  "the two are equivalent".
* **Deterministic.** The search is seeded; a run is reproducible from its seed.

It never touches a network or a real system: both sides are local ``Target``s.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from typing import Any, Optional

from ..invariants.engine import Target, _generate_sequence
from ..models import AttackStep
from ..toolchain.enforce import ExecutionTarget, guarded, require_execution_authorized


class DifferentialError(ValueError):
    """The two targets cannot be compared (e.g. different operation alphabets)."""


@dataclass
class Divergence:
    """The first step at which two targets' observable state differs."""

    sequence: list[AttackStep]
    step_index: int
    reference: dict[str, Any]
    candidate: dict[str, Any]
    differing_keys: list[str]
    #: Always ``DIVERGENCE`` -- a lead, never a verdict on which side is wrong.
    verdict: str = "DIVERGENCE"

    def to_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict,
            "step_index": self.step_index,
            "differing_keys": list(self.differing_keys),
            "reference": dict(self.reference),
            "candidate": dict(self.candidate),
            "sequence": [
                {"actor": s.actor, "action": s.action, "params": dict(s.params)}
                for s in self.sequence
            ],
        }


@dataclass
class DifferentialReport:
    runs: int
    steps: int
    seed: int
    compared: int = 0
    divergences: list[Divergence] = field(default_factory=list)

    @property
    def clean(self) -> bool:
        """No divergence on the sequences tried -- never "the targets agree"."""
        return not self.divergences

    def to_dict(self) -> dict[str, Any]:
        return {
            "runs": self.runs,
            "steps": self.steps,
            "seed": self.seed,
            "compared": self.compared,
            "divergences": [d.to_dict() for d in self.divergences],
            "verdict": "NO_DIVERGENCE" if self.clean else "DIVERGENCE",
            "note": ("no divergence on the sequences tried; this is not an "
                     "equivalence proof"),
        }


def _alphabet(target: Target) -> list[str]:
    return sorted(op.name for op in target.ops())


def _validate_alphabet(reference: Target, candidate: Target) -> None:
    a, b = _alphabet(reference), _alphabet(candidate)
    if a != b:
        raise DifferentialError(
            "targets have different operation alphabets: "
            f"reference={a} candidate={b}"
        )


def _snapshot(target: Target, state: Any) -> dict[str, Any]:
    snap = target.snapshot(state)
    return dict(snap) if isinstance(snap, dict) else {}


def _diff_keys(ref: dict[str, Any], cand: dict[str, Any]) -> list[str]:
    return sorted(k for k in set(ref) | set(cand) if ref.get(k) != cand.get(k))


def _run_pair(reference: Target, candidate: Target,
              sequence: list[AttackStep]) -> Optional[Divergence]:
    """Run ``sequence`` on both targets, returning the first divergence or None."""
    rstate = reference.reset()
    cstate = candidate.reset()
    for i, step in enumerate(sequence):
        reference.step(rstate, step.action, step.actor, dict(step.params))
        candidate.step(cstate, step.action, step.actor, dict(step.params))
        rsnap = _snapshot(reference, rstate)
        csnap = _snapshot(candidate, cstate)
        keys = _diff_keys(rsnap, csnap)
        if keys:
            return Divergence(
                sequence=list(sequence[: i + 1]),
                step_index=i,
                reference=rsnap,
                candidate=csnap,
                differing_keys=keys,
            )
    return None


def _gate(name: str, compatibility: object, where: str):
    """Run the body inside the compatibility gate, exactly like ``run_sequence``."""
    if compatibility is not None:
        return guarded(compatibility, ExecutionTarget(name=name), where)
    require_execution_authorized(name, where)
    return _NullContext()


class _NullContext:
    def __enter__(self) -> None:
        return None

    def __exit__(self, *exc: Any) -> bool:
        return False


def compare_sequence(reference: Target, candidate: Target,
                     sequence: list[AttackStep],
                     compatibility: object = None) -> Optional[Divergence]:
    """Compare one explicit sequence on both targets.

    Returns the first divergence, or ``None`` if every step's snapshot agrees.
    Raises :class:`DifferentialError` if the operation alphabets differ.
    """
    _validate_alphabet(reference, candidate)
    name = f"{getattr(reference, 'name', 'ref')}~{getattr(candidate, 'name', 'cand')}"
    with _gate(name, compatibility, "fuzz.differential.compare_sequence"):
        return _run_pair(reference, candidate, list(sequence))


def _minimize(reference: Target, candidate: Target, divergence: Divergence,
              budget: int) -> Divergence:
    """Shrink to the shortest prefix that still diverges."""
    seq = list(divergence.sequence)
    changed = True
    while changed and len(seq) > 1 and budget > 0:
        changed = False
        for i in range(len(seq)):
            if budget <= 0:
                break
            trial = seq[:i] + seq[i + 1:]
            budget -= 1
            found = _run_pair(reference, candidate, trial)
            if found is not None:
                seq = list(found.sequence)
                changed = True
                break
    return _run_pair(reference, candidate, seq) or divergence


def differential_fuzz(reference: Target, candidate: Target, *, runs: int = 200,
                      steps: int = 12, seed: int = 0, minimize_budget: int = 300,
                      compatibility: object = None) -> DifferentialReport:
    """Search for snapshot divergences between two targets with a shared alphabet."""
    _validate_alphabet(reference, candidate)
    name = f"{getattr(reference, 'name', 'ref')}~{getattr(candidate, 'name', 'cand')}"

    def _body() -> DifferentialReport:
        rng = random.Random(seed)
        report = DifferentialReport(runs=runs, steps=steps, seed=seed)
        seen: set[tuple[int, tuple[str, ...]]] = set()
        for _ in range(runs):
            seq = _generate_sequence(reference, rng, steps)
            report.compared += 1
            found = _run_pair(reference, candidate, seq)
            if found is None:
                continue
            key = (found.step_index, tuple(found.differing_keys))
            if key in seen:
                continue
            seen.add(key)
            report.divergences.append(_minimize(reference, candidate, found,
                                                minimize_budget))
        return report

    with _gate(name, compatibility, "fuzz.differential.differential_fuzz"):
        return _body()


__all__ = [
    "DifferentialError",
    "Divergence",
    "DifferentialReport",
    "compare_sequence",
    "differential_fuzz",
]
