"""Priority research question: Aave aToken / wrapper-share accounting.

Mission section 6 asks whether a wrapper share can diverge from the underlying
aToken balance in a way that yields unauthorized value extraction. These tests
run a dedicated stateful invariant harness against two models of the same
accounting: the naive version and the version guarded by the ERC4626
virtual-shares offset.

The point of the paired test is *non-vacuity*: if the invariants failed on both
models, they would be worthless (they would flag legitimate behaviour). The naive
model failing while the guarded model holds is what makes the invariants
meaningful and the result interpretable.
"""

from __future__ import annotations

from blackheart.invariants import FuzzConfig, StatefulFuzzer
from blackheart.invariants.engine import run_sequence
from blackheart.invariants.wrapper_targets import GuardedWrapper, WrapperTarget


def _run(target, runs=800, steps=12, seed=0):
    return StatefulFuzzer(target, FuzzConfig(runs=runs, steps_per_run=steps, seed=seed)).run()


def test_naive_wrapper_is_exploitable():
    """Without the virtual-shares offset, the wrapper-share accounting breaks."""
    report = _run(WrapperTarget())
    assert report.failures, "the naive wrapper model must produce counterexamples"
    # A material (not merely rounding-level) attacker-profit or victim-loss break.
    material = [f for f in report.failures if "material" in f.inv_id]
    assert material, "expected a material accounting break, not a dust rounding artefact"
    assert all(f.reproducible for f in report.failures)
    assert any(f.reachable_by_attacker for f in report.failures)


def test_guarded_wrapper_holds_under_fuzzing():
    """The virtual-shares offset defends the same invariants (non-vacuity)."""
    report = _run(GuardedWrapper(), runs=2000)
    assert report.failures == [], (
        "guarded wrapper must not trip the invariants; failures="
        + ", ".join(f.inv_id for f in report.failures)
    )


def test_minimal_counterexample_reproduces():
    report = _run(WrapperTarget(), runs=200)
    assert report.failures
    for f in report.failures:
        result = run_sequence(WrapperTarget(), f.minimal_sequence)
        assert f.inv_id in result.violated


def test_rounding_dust_is_not_flagged_as_material():
    """A 1-wei rounding difference must not be reported as an exploit."""
    # A single deposit then a single withdrawal cannot create material value.
    from blackheart.models import AttackStep

    seq = [
        AttackStep(0, "victim", "deposit", {"amount": 10**18}),
        AttackStep(1, "victim", "withdraw", {"shares": 10**18}),
    ]
    result = run_sequence(GuardedWrapper(), seq)
    assert "no-material-attacker-profit" not in result.violated
    assert "no-material-victim-loss" not in result.violated


def test_solvency_never_breaks():
    """The wrapper must never promise more redeemable value than it holds."""
    for target in (WrapperTarget(), GuardedWrapper()):
        report = _run(target, runs=500)
        assert not any(f.inv_id == "wrapper-solvency" for f in report.failures)
