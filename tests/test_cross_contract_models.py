"""Acceptance bar for the cross-contract attack models.

The engine's other fixtures model one contract with several operations. These
targets exist because a whole class of real bugs lives *between* two contracts:
a consumer that trusts what a second contract reports about itself. The tests
below hold the two things that make such a model worth anything:

  * the vulnerable variant yields an attacker-reachable invariant violation, and
  * the guarded twin -- identical except for the one trust decision -- holds.

A model that fails the first proves nothing; one that fails the second is not a
control, because a guard that does not discriminate cannot show the bug is real.

They also pin the coverage ledger: ``cross-contract`` and ``cross-protocol-trust``
must resolve to these two-contract models, not to the single-contract reentrancy
model they were previously credited to.
"""

from __future__ import annotations

import pytest

from blackheart.invariants.coverage import coverage_report
from blackheart.invariants.multicontract_targets import (
    GuardedStrategyVault,
    GuardedTrustingMarket,
    StrategyVault,
    TrustingMarket,
)
from blackheart.invariants.registry import DIFFERENTIAL_PAIRS, TARGET_SPECS
from blackheart.statespace.explore import ExploreConfig, StateSpaceExplorer
from blackheart.statespace.hypotheses import HypothesisGenerator

PAIRS = [
    (TrustingMarket, GuardedTrustingMarket,
     "no-borrow-above-true-collateral-value"),
    (StrategyVault, GuardedStrategyVault, "redemption-backed-by-real-assets"),
]


def _violations(target, invariant: str, max_steps: int = 8):
    report = StateSpaceExplorer(target, ExploreConfig(seed=0, max_steps=max_steps)).explore(
        HypothesisGenerator(target.model()).generate().hypotheses)
    return [v for v in report.violations if v.invariant_id == invariant]


@pytest.mark.parametrize("vuln_cls,guard_cls,invariant", PAIRS)
def test_vulnerable_model_is_broken_by_an_unprivileged_actor(vuln_cls, guard_cls, invariant):
    target = vuln_cls()
    hits = _violations(target, invariant)
    assert hits, f"{vuln_cls.__name__}: no violation of {invariant} found"

    for hit in hits:
        for step in hit.sequence:
            actor = target.model().actor(step.actor)
            assert actor is not None and actor.unprivileged, (
                f"{vuln_cls.__name__}: violation relies on privileged actor "
                f"{step.actor!r}; that is not this attacker's attack")


@pytest.mark.parametrize("vuln_cls,guard_cls,invariant", PAIRS)
def test_guarded_twin_holds_the_invariant(vuln_cls, guard_cls, invariant):
    assert not _violations(guard_cls(), invariant), (
        f"{guard_cls.__name__}: the control must hold {invariant}, but the engine "
        "reported a violation -- the pair does not discriminate")


@pytest.mark.parametrize("vuln_cls,guard_cls,invariant,hook", [
    (TrustingMarket, GuardedTrustingMarket,
     "no-borrow-above-true-collateral-value", "_trusted_price"),
    (StrategyVault, GuardedStrategyVault,
     "redemption-backed-by-real-assets", "_pricing_assets"),
])
def test_pair_differs_in_exactly_one_decision(vuln_cls, guard_cls, invariant, hook):
    """The guarded twin must differ only in how it values the other contract."""
    vuln, guard = vuln_cls(), guard_cls()
    assert vuln.ops() == guard.ops(), (
        "a control that changes the operation set proves nothing about the guard")
    # The twin inherits step(); it overrides only the valuation hook. That is the
    # property that makes the pair a control: one decision, isolated.
    assert type(vuln).step is type(guard).step, (
        "the twin must not rewrite step(); it must override the valuation hook only")
    vuln_hook = getattr(type(vuln), hook)
    guard_hook = getattr(type(guard), hook)
    assert guard_hook is not vuln_hook, (
        f"the guarded twin must override {hook}()")
    # And nothing else in the class body differs.
    overridden = {k for k, v in vars(type(guard)).items()
                  if callable(v) and not k.startswith("__")}
    assert overridden <= {hook}, (
        f"the guarded twin overrides {sorted(overridden - {hook})}; only {hook} "
        "may differ, or the control is not isolating the guard")


@pytest.mark.parametrize("vuln_cls,guard_cls,invariant", PAIRS)
def test_violation_is_reproducible(vuln_cls, guard_cls, invariant):
    """Same seed, same sequence: a finding that cannot be replayed is not one."""
    a = _violations(vuln_cls(), invariant)
    b = _violations(vuln_cls(), invariant)
    assert a and b
    seq_a = [(s.action, s.actor) for s in a[0].sequence]
    seq_b = [(s.action, s.actor) for s in b[0].sequence]
    assert seq_a == seq_b


def test_attack_crosses_the_declared_trust_boundary():
    """The model must *name* the boundary, and the winning sequence must use it."""
    target = TrustingMarket()
    model = target.model()
    assert model.trust_boundaries, "a cross-contract model must declare its boundary"
    assert any("oracle" in b for b in model.trust_boundaries)

    hits = _violations(target, "no-borrow-above-true-collateral-value")
    assert hits
    actions = [s.action for s in hits[0].sequence]
    assert "manipulate_oracle" in actions, (
        "the winning sequence must move the external contract, not merely borrow")


def test_registry_has_both_pairs():
    names = {s.name for s in TARGET_SPECS}
    for name in ("cross-contract-oracle", "cross-contract-oracle-guarded",
                 "cross-protocol-strategy", "cross-protocol-strategy-guarded"):
        assert name in names

    pairs = {(a, b) for a, b, _ in DIFFERENTIAL_PAIRS}
    assert ("cross-contract-oracle", "cross-contract-oracle-guarded") in pairs
    assert ("cross-protocol-strategy", "cross-protocol-strategy-guarded") in pairs


@pytest.mark.parametrize("category,kind", [
    ("cross-contract", "cross-contract"),
    ("cross-protocol-trust", "cross-protocol"),
])
def test_coverage_resolves_to_a_two_contract_model(category, kind):
    entry = next(c for c in coverage_report() if c.category == category)
    assert entry.coverage.value == "modelled", (
        f"{category} must be modelled by a real two-contract fixture")
    assert entry.kind == kind, (
        f"{category} resolved to kind {entry.kind!r}; a single-contract model "
        "does not cover a class defined by a boundary between two contracts")
    assert entry.targets, f"{category}: modelled but names no target"
