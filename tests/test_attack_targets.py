"""Tests for the additional executable attack targets and the differential runner.

Each pair must show the expected contrast: the vulnerable model yields an
attacker-reachable invariant violation and the guarded model yields none. This is
the same non-vacuity discipline the reference vaults use, extended to the oracle,
permit, and proxy attack classes.
"""

from __future__ import annotations

import json

from blackheart.cli import main
from blackheart.invariants import (
    DIFFERENTIAL_PAIRS,
    FuzzConfig,
    StatefulFuzzer,
    available_targets,
    make_target,
)
from blackheart.invariants.attack_targets import (
    GuardedLendingPool,
    GuardedProxyVault,
    LendingPool,
    PermitToken,
    ProxyVault,
    SafePermitToken,
)
from blackheart.invariants.engine import run_sequence


def _run(cls):
    return StatefulFuzzer(cls(), FuzzConfig(runs=500, steps_per_run=10, seed=0)).run()


# --------------------------------------------------------------------------- #
# Per-class contrast
# --------------------------------------------------------------------------- #

def test_lending_oracle_is_exploitable_and_guarded_is_not():
    vuln = _run(LendingPool)
    guard = _run(GuardedLendingPool)
    assert vuln.failures, "borrowing against a manipulable oracle must be findable"
    assert all(f.reachable_by_attacker for f in vuln.failures)
    assert any(f.inv_id == "no-actor-over-borrows" for f in vuln.failures)
    assert guard.failures == [], "the guarded pool must not allow over-borrowing"


def test_permit_replay_is_findable_and_guarded_is_not():
    vuln = _run(PermitToken)
    guard = _run(SafePermitToken)
    assert vuln.failures
    assert any(f.inv_id == "authorization-used-once" for f in vuln.failures)
    assert guard.failures == [], "single-use permits must not be replayable"


def test_proxy_initializer_is_findable_and_guarded_is_not():
    vuln = _run(ProxyVault)
    guard = _run(GuardedProxyVault)
    assert vuln.failures
    assert any(f.inv_id == "no-material-attacker-profit" for f in vuln.failures)
    assert guard.failures == [], "a one-shot initializer must not be re-callable"


# --------------------------------------------------------------------------- #
# Reproduction of a minimal sequence on the new targets
# --------------------------------------------------------------------------- #

def test_minimal_sequence_reproduces_on_new_target():
    report = _run(PermitToken)
    f = report.failures[0]
    assert len(f.minimal_sequence) <= len(f.sequence)
    result = run_sequence(PermitToken(), f.minimal_sequence)
    assert f.inv_id in result.violated


# --------------------------------------------------------------------------- #
# Registry + CLI
# --------------------------------------------------------------------------- #

def test_registry_exposes_pairs_and_resolves_names():
    names = available_targets()
    for vuln, guard, _hypothesis in DIFFERENTIAL_PAIRS:
        assert vuln in names and guard in names
    assert make_target("lending-oracle").name == "lending-oracle"
    assert make_target("permit-guarded").name == "permit-guarded"


def test_cli_targets_lists_all(repo_root, capsys):
    assert main(["targets"]) == 0
    out = capsys.readouterr().out
    assert "lending-oracle" in out and "permit-replay" in out and "proxy-initializer" in out


def test_cli_differential_all_pairs_pass(tmp_path, capsys):
    out = tmp_path / "diff.json"
    rc = main(["differential", "--runs", "400", "--out", str(out)])
    assert rc == 0, "every vulnerable/guarded pair must behave as expected"
    results = json.loads(out.read_text())
    assert len(results) == len(DIFFERENTIAL_PAIRS)
    for r in results:
        assert r["passed"], f"pair {r['pair']} did not show the expected contrast"
        assert r["vulnerable_attacker_reachable"] >= 1
        assert r["guarded_failures"] == 0


def test_cli_fuzz_accepts_new_target(capsys):
    assert main(["fuzz", "--target", "proxy-initializer", "--runs", "100"]) == 0
    assert "invariant failures found" in capsys.readouterr().out
