"""Tests for the stateful invariant engine and its triage properties."""

from __future__ import annotations

from blackheart.invariants import FuzzConfig, StatefulFuzzer
from blackheart.invariants.engine import run_sequence
from blackheart.invariants.reference_targets import SafeVault, VulnerableVault


def test_vulnerable_vault_breaks_invariant():
    report = StatefulFuzzer(
        VulnerableVault(), FuzzConfig(runs=300, steps_per_run=10, seed=0)
    ).run()
    assert report.failures, "the vulnerable reference must produce counterexamples"
    assert all(f.reproducible for f in report.failures)
    assert all(f.reachable_by_attacker for f in report.failures)
    # The share-inflation attack must be among the material failures.
    assert any("material" in f.inv_id for f in report.failures)


def test_safe_vault_holds_all_invariants():
    """Non-vacuity: the same invariants must hold on the defended reference."""
    report = StatefulFuzzer(
        SafeVault(), FuzzConfig(runs=300, steps_per_run=10, seed=0)
    ).run()
    assert report.failures == [], (
        "safe reference must not trip the invariants; failures="
        + ", ".join(f.inv_id for f in report.failures)
    )


def test_minimal_sequence_is_reproducible_and_shorter():
    report = StatefulFuzzer(
        VulnerableVault(), FuzzConfig(runs=100, steps_per_run=12, seed=0)
    ).run()
    f = report.failures[0]
    assert len(f.minimal_sequence) <= len(f.sequence)
    result = run_sequence(VulnerableVault(), f.minimal_sequence)
    assert f.inv_id in result.violated, "minimal sequence must still violate the invariant"


def test_minimisation_terminates_within_budget():
    """Value-shrinking must not loop forever (regression for the budget fix)."""
    report = StatefulFuzzer(
        VulnerableVault(), FuzzConfig(runs=50, steps_per_run=8, seed=0, minimize_budget=20)
    ).run()
    # Whatever it finds, it must return promptly and reproducibly.
    for f in report.failures:
        assert f.reproducible is True


def test_seed_reproducibility():
    a = StatefulFuzzer(VulnerableVault(), FuzzConfig(runs=40, steps_per_run=8, seed=7)).run()
    b = StatefulFuzzer(VulnerableVault(), FuzzConfig(runs=40, steps_per_run=8, seed=7)).run()
    assert [(f.inv_id, f.seed) for f in a.failures] == [(f.inv_id, f.seed) for f in b.failures]
