"""Benchmark gates for the GitHub Actions analyzer.

These tests fail if a detector change trades away precision (flags safe
workflows) or recall (misses a reachable chain). They are intentionally strict:
the analyzer's value is that its alerts are reachable, so a false positive is a
regression, not a rounding error.
"""

from __future__ import annotations

import pytest

yaml = pytest.importorskip("yaml")

from blackheart import gha_bench


def test_benchmark_perfect_on_labeled_corpus():
    metrics, notes = gha_bench.run()
    assert metrics.false_negatives == 0, notes
    assert metrics.false_positives == 0, notes
    assert metrics.true_positives >= 3
    assert metrics.recall == 1.0
    assert metrics.precision == 1.0


def test_benchmark_never_flags_safe_workflows():
    metrics, notes = gha_bench.run()
    assert metrics.safe_cases >= 8
    assert metrics.safe_cases_flagged == 0, notes


def test_benchmark_is_fast():
    metrics, _ = gha_bench.run()
    assert metrics.seconds < 5.0


def test_benchmark_covers_every_rule():
    """Each rule must have at least one positive case in the corpus."""
    kinds = {c.id for c in gha_bench.CASES if not c.expected_empty}
    expected_rules = set()
    for case in gha_bench.CASES:
        expected_rules.update(case.expected)
    assert expected_rules == set(gha_bench.gha._ALL_RULES)
    assert len(kinds) >= 3
