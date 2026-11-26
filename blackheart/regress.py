"""Regression-test emitter for invariant counterexamples (mission sections 2D, 11).

When the stateful fuzzer finds a failing sequence it records the seed, the exact
sequence, and the minimised sequence. That is evidence, but it is not yet a
*regression test*: nothing re-checks the finding on the next run.

This module turns a captured :class:`~blackheart.models.InvariantFailure` (or an
executable chain) into a **self-contained pytest file** that re-executes the exact
minimal sequence against the target and asserts the invariant still breaks. The
file is deterministic (no randomness: it replays a recorded sequence) and imports
only the standard library plus this package.

The emitted test is written under a private directory by default; it is safe to
run with ``python3 -m pytest <file>`` from the repository root.
"""

from __future__ import annotations

import os
from pathlib import Path

from .models import InvariantFailure

_HEADER = '''"""Auto-generated BLACKHEART regression test -- DO NOT EDIT BY HAND.

Reproduces a recorded invariant counterexample deterministically. Regenerate it
with ``python3 -m blackheart regress --target {target} --invariant {invariant}
--runs {runs} --out <dir>``.

Source of truth: the minimal sequence below, captured from a real fuzz run
(seed {seed}). This file asserts the *counterexample still reproduces*; it is not
a claim that any live system is vulnerable.
"""

from blackheart.invariants.engine import run_sequence
from blackheart.invariants.registry import make_target
from blackheart.models import AttackStep
from blackheart.toolchain.enforce import self_test_authority

TARGET = {target!r}
INVARIANT = {invariant!r}
SEED = {seed}
SEQUENCE = {sequence!r}


def _sequence():
    return [
        AttackStep(
            index=i,
            actor=s["actor"],
            action=s["action"],
            params=dict(s["params"]),
            target_contract=TARGET,
        )
        for i, s in enumerate(SEQUENCE)
    ]


def test_counterexample_still_breaks_the_invariant():
    # This regression test executes a repository fixture, so it declares the same
    # self-test record any other fixture execution uses.
    with self_test_authority(TARGET):
        result = run_sequence(make_target(TARGET), _sequence())
    assert INVARIANT in result.violated, (
        f"recorded counterexample for {{INVARIANT!r}} no longer reproduces "
        f"(seed={{SEED}}); the target may have been fixed or changed"
    )


def test_counterexample_is_attacker_reachable():
    steps = _sequence()
    assert any(s.actor == "attacker" for s in steps), (
        "recorded counterexample has no attacker-controlled step"
    )
'''


def _sequence_to_records(failure: InvariantFailure) -> list[dict]:
    seq = failure.minimal_sequence or failure.sequence
    return [
        {"actor": s.actor, "action": s.action, "params": dict(s.params)}
        for s in seq
    ]


def render_regression_test(
    failure: InvariantFailure, target: str, runs: int = 0
) -> str:
    """Render a pytest module that replays ``failure`` against ``target``."""
    records = _sequence_to_records(failure)
    if not records:
        raise ValueError("failure has no sequence to emit")
    return _HEADER.format(
        target=target,
        invariant=failure.inv_id,
        seed=failure.seed,
        runs=runs,
        sequence=records,
    )


def emit_regression_test(
    failure: InvariantFailure,
    target: str,
    out_dir: str | os.PathLike,
    runs: int = 0,
) -> Path:
    """Write the regression test into ``out_dir`` and return its path."""
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    safe_inv = "".join(c if c.isalnum() or c in "-_" else "-" for c in failure.inv_id)
    safe_target = "".join(c if c.isalnum() or c in "-_" else "-" for c in target)
    path = out / f"test_regression_{safe_target}_{safe_inv}.py"
    path.write_text(render_regression_test(failure, target, runs), encoding="utf-8")
    return path


def emit_from_fuzz_report(
    report, target: str, out_dir: str | os.PathLike
) -> list[Path]:
    """Emit one regression test per distinct invariant failure in a fuzz report."""
    paths: list[Path] = []
    seen: set[str] = set()
    for failure in report.failures:
        if failure.inv_id in seen:
            continue
        seen.add(failure.inv_id)
        paths.append(
            emit_regression_test(failure, target, out_dir, runs=report.runs)
        )
    return paths
