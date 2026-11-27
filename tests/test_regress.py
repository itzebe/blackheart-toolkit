"""Tests for the invariant-failure regression emitter (mission sections 2D, 11)."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from blackheart.invariants import FuzzConfig, StatefulFuzzer
from blackheart.invariants.registry import make_target
from blackheart.models import AttackStep, InvariantFailure
from blackheart.regress import (
    emit_from_fuzz_report,
    emit_regression_test,
    render_regression_test,
)


def _failure():
    return InvariantFailure(
        inv_id="authorization-used-once",
        seed=7,
        sequence=[
            AttackStep(0, "victim", "victim_sign", {"value": 100}),
            AttackStep(1, "attacker", "replay_permit", {}),
        ],
        minimized=True,
        minimal_sequence=[
            AttackStep(0, "victim", "victim_sign", {"value": 100}),
            AttackStep(1, "attacker", "replay_permit", {}),
            AttackStep(2, "attacker", "transfer_from", {"amount": 100}),
            AttackStep(3, "attacker", "replay_permit", {}),
            AttackStep(4, "attacker", "transfer_from", {"amount": 100}),
        ],
    )


def test_render_is_a_valid_python_module():
    src = render_regression_test(_failure(), "permit-replay")
    compile(src, "<regression>", "exec")
    assert "authorization-used-once" in src
    assert "permit-replay" in src


def test_emit_writes_a_file(tmp_path: Path):
    path = emit_regression_test(_failure(), "permit-replay", tmp_path)
    assert path.exists()
    assert path.name.startswith("test_regression_")


def test_emitted_test_actually_passes(tmp_path: Path):
    """The emitted regression test must reproduce the recorded counterexample."""
    path = emit_regression_test(_failure(), "permit-replay", tmp_path)
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", str(path), "-q"],
        capture_output=True, text=True, cwd=str(Path(__file__).resolve().parent.parent),
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_emit_from_fuzz_report_one_per_invariant(tmp_path: Path):
    report = StatefulFuzzer(
        make_target("permit-replay"), FuzzConfig(runs=200, steps_per_run=8, seed=0)
    ).run()
    assert report.failures
    paths = emit_from_fuzz_report(report, "permit-replay", tmp_path)
    names = sorted(p.name for p in paths)
    assert len(names) == len(set(names))
    # Each emitted file must be syntactically valid Python.
    for p in paths:
        compile(p.read_text(), str(p), "exec")


def test_emit_empty_sequence_raises(tmp_path: Path):
    bad = InvariantFailure(inv_id="x", seed=1, sequence=[], minimal_sequence=[])
    try:
        emit_regression_test(bad, "permit-replay", tmp_path)
    except ValueError:
        return
    raise AssertionError("expected ValueError for an empty sequence")
