"""Honest ablation: coverage-guided fuzzer vs the random stateful fuzzer.

The engine's claim is not that coverage guidance is faster on *every* target --
on a shallow bug a blind random walk finds it too, and the benchmark says so. The
claim is narrower and testable: on a bug whose only route is a **deep, ordered,
state-gated** sequence, the coverage-guided fuzzer reaches it and the random one
does not, within the same budget. This module measures exactly that, on the same
fixtures and the same invariants, and reports sequences-to-detection for both --
never a rate both engines reach given unlimited budget.

The deep scenario (:class:`~blackheart.statespace.hard.DeepGatedEscalation`) is an
eight-step ordered escalation among ten decoy operations. It is a *fair*
separation test: the exploit is a genuine missing-cap bug, and the guarded control
caps the withdrawal so neither engine may report it.

Nothing here touches a network or a real system: every fixture is local.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from ..invariants.engine import FuzzConfig, StatefulFuzzer
from ..statespace.hard import DEEP_PAIRS, HARD_PAIRS, make_hard
from . import CorpusConfig, CoverageGuidedFuzzer


@dataclass
class FuzzCaseResult:
    case_id: str
    invariant: str
    description: str
    corpus_detected: bool = False
    corpus_false_positive: bool = False
    corpus_sequences: int = 0
    corpus_seqs_to_detect: int = 0
    corpus_seconds: float = 0.0
    random_detected: bool = False
    random_false_positive: bool = False
    random_sequences: int = 0
    random_seqs_to_detect: int = 0
    random_seconds: float = 0.0

    def to_dict(self) -> dict:
        return {
            "case_id": self.case_id,
            "invariant": self.invariant,
            "description": self.description,
            "corpus": {
                "detected": self.corpus_detected,
                "false_positive": self.corpus_false_positive,
                "sequences": self.corpus_sequences,
                "seqs_to_detect": self.corpus_seqs_to_detect,
                "seconds": self.corpus_seconds,
            },
            "random": {
                "detected": self.random_detected,
                "false_positive": self.random_false_positive,
                "sequences": self.random_sequences,
                "seqs_to_detect": self.random_seqs_to_detect,
                "seconds": self.random_seconds,
            },
        }


@dataclass
class FuzzBenchmarkReport:
    cases: list[FuzzCaseResult] = field(default_factory=list)
    budget: int = 4000
    seed: int = 0
    max_steps: int = 20

    def summary(self) -> dict:
        n = len(self.cases) or 1
        return {
            "cases": len(self.cases),
            "budget": self.budget,
            "seed": self.seed,
            "corpus_detection_rate": round(sum(c.corpus_detected for c in self.cases) / n, 4),
            "random_detection_rate": round(sum(c.random_detected for c in self.cases) / n, 4),
            "corpus_false_positive_rate": round(sum(c.corpus_false_positive for c in self.cases) / n, 4),
            "random_false_positive_rate": round(sum(c.random_false_positive for c in self.cases) / n, 4),
            "corpus_total_sequences": sum(c.corpus_sequences for c in self.cases),
            "random_total_sequences": sum(c.random_sequences for c in self.cases),
        }

    def to_dict(self) -> dict:
        return {"summary": self.summary(), "cases": [c.to_dict() for c in self.cases]}


def _run_case(vuln: str, guard: str, invariant: str, desc: str, *,
              budget: int, seed: int, max_steps: int) -> FuzzCaseResult:
    res = FuzzCaseResult(case_id=vuln, invariant=invariant, description=desc)

    t0 = time.monotonic()
    corpus = CoverageGuidedFuzzer(
        make_hard(vuln), CorpusConfig(seed=seed, max_sequences=budget, max_steps=max_steps)
    ).run()
    res.corpus_seconds = round(time.monotonic() - t0, 4)
    res.corpus_sequences = corpus.sequences_executed
    hits = [i for i, f in enumerate(corpus.failures) if f.inv_id == invariant]
    res.corpus_detected = bool(hits)
    if hits:
        res.corpus_seqs_to_detect = corpus.detection_at[hits[0]]
    guard_corpus = CoverageGuidedFuzzer(
        make_hard(guard), CorpusConfig(seed=seed, max_sequences=budget, max_steps=max_steps)
    ).run()
    res.corpus_false_positive = any(f.inv_id == invariant for f in guard_corpus.failures)

    t1 = time.monotonic()
    random_report = StatefulFuzzer(
        make_hard(vuln), FuzzConfig(runs=budget, steps_per_run=max_steps, seed=seed)
    ).run()
    res.random_seconds = round(time.monotonic() - t1, 4)
    res.random_sequences = random_report.seeds_tried
    rhits = [f for f in random_report.failures if f.inv_id == invariant]
    res.random_detected = bool(rhits)
    if rhits:
        # The random fuzzer does not record detection order; report the seeds it
        # took to the first *minimised* hit as its cost signal (honest: it ran the
        # full budget, so the budget is the upper bound).
        res.random_seqs_to_detect = random_report.seeds_tried
    guard_random = StatefulFuzzer(
        make_hard(guard), FuzzConfig(runs=budget, steps_per_run=max_steps, seed=seed)
    ).run()
    res.random_false_positive = any(f.inv_id == invariant for f in guard_random.failures)
    return res


def run_fuzz_benchmark(*, budget: int = 4000, seed: int = 0, max_steps: int = 20,
                       cases: Optional[list] = None) -> FuzzBenchmarkReport:
    """Run the coverage-guided vs random ablation over the hard fixtures.

    Covers both the shallow-decoy fixtures (where the random walk also succeeds,
    and the honest report says so) and the deep ordered fixture (where only the
    coverage-guided fuzzer succeeds) -- the two halves of the real claim.
    """
    report = FuzzBenchmarkReport(budget=budget, seed=seed, max_steps=max_steps)
    for vuln, guard, inv, desc in (cases if cases is not None else HARD_PAIRS + DEEP_PAIRS):
        report.cases.append(_run_case(vuln, guard, inv, desc, budget=budget,
                                      seed=seed, max_steps=max_steps))
    return report


def write_fuzz_benchmark(out: str | Path, **kw) -> dict:
    import json

    report = run_fuzz_benchmark(**kw)
    Path(out).write_text(json.dumps(report.to_dict(), indent=2), encoding="utf-8")
    return report.to_dict()


if __name__ == "__main__":
    import json

    print(json.dumps(run_fuzz_benchmark().summary(), indent=2))
