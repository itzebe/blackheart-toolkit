"""Multi-engine adversarial harness tests (mission sections 2C, 3, 12, 13).

These tests exercise the *real* engines on the local harness, not mocks. The
fast engines (forge PoC + stateful invariants) always run when forge is present;
the slow engines (echidna, medusa, halmos, mythril, slither) and the fork test
are gated on the binary/network being available and are skipped honestly when it
is not. A skip is never reported as a pass.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from blackheart.adversarial import HARNESS, AdversarialHarness, EngineResult

pytestmark = pytest.mark.skipif(
    shutil.which("forge") is None,
    reason="forge not on PATH; the adversarial harness needs Foundry",
)


def _installed(tool: str) -> bool:
    """Is the engine actually available to the engine layer?

    `shutil.which` only sees PATH. `blackheart engines bootstrap` installs into
    isolated venvs and `~/.blackheart/bin`, neither of which is on PATH, so a
    `which`-based gate skipped every engine test on a host where the engines were
    installed and working -- the worst possible outcome for a verification test.
    """
    from blackheart.engines.solidity.base import resolve_tool

    return resolve_tool(tool) is not None


def _harness_ready(root: Path) -> bool:
    return (root / HARNESS / "lib" / "forge-std").is_dir()


@pytest.fixture
def harness(repo_root: Path) -> AdversarialHarness:
    if not _harness_ready(repo_root):
        pytest.skip("harness forge-std missing; run: cd harnesses/adversarial && forge install foundry-rs/forge-std")
    return AdversarialHarness(repo_root / "research/private/_adv-test")


def test_poc_proves_all_attack_classes_with_controls(harness: AdversarialHarness):
    """The deterministic PoC must pass for every class AND its negative control.

    A pass here means: exploit works on the vulnerable target and the identical
    attack is blocked on the defended control (reentrancy, oracle, tx.origin,
    unprotected initializer). The count of 8 encodes 4 exploits + 4 controls.
    """
    res = harness.forge_test("ExploitPoC")
    assert res.facts.get("failed") == 0, res.output
    assert res.facts.get("passed") == 8, res.output


def test_stateful_invariant_breaks_on_vulnerable_and_holds_on_safe(harness: AdversarialHarness):
    """Differential invariant: vulnerable breaks, defended control holds."""
    vuln = harness.forge_test("VulnerableVaultInvariants")
    safe = harness.forge_test("SafeVaultInvariants")
    assert vuln.facts.get("failed", 0) >= 1, "vulnerable invariant must break"
    assert vuln.facts.get("fuzz_seed"), "a fuzz seed must be reported for reproduction"
    assert safe.facts.get("failed", 0) == 0 and safe.facts.get("passed", 0) >= 1, "safe control must hold"


def test_fuzz_seed_reproduces_the_same_counterexample(harness: AdversarialHarness):
    """Deterministic reproduction: the reported seed replays the same failure."""
    first = harness.forge_test("VulnerableVaultInvariants")
    seed = first.facts["fuzz_seed"]
    again = harness.forge_test("VulnerableVaultInvariants", seed=seed)
    assert again.facts.get("failed", 0) >= 1
    assert again.facts.get("fuzz_seed") == seed


@pytest.mark.skipif(not _installed("echidna"), reason="echidna not installed")
@pytest.mark.slow
def test_echidna_falsifies_the_property(harness: AdversarialHarness):
    res = harness.echidna(limit=8000)
    assert res.facts.get("falsified") is True, res.output
    assert res.facts.get("seed"), "echidna must report a seed"


@pytest.mark.skipif(not _installed("medusa"), reason="medusa not installed")
@pytest.mark.slow
def test_medusa_falsifies_the_property(harness: AdversarialHarness):
    res = harness.medusa(limit=20000)
    assert res.facts.get("property_failed") is True, res.output


@pytest.mark.skipif(not _installed("halmos"), reason="halmos not installed")
@pytest.mark.slow
def test_halmos_proves_safe_and_finds_counterexample(harness: AdversarialHarness):
    res = harness.halmos()
    assert res.facts.get("passed", 0) >= 2, "two proofs must succeed"
    assert res.facts.get("counterexamples", 0) >= 1, "one counterexample must be found"
    assert res.facts.get("witnesses"), "a concrete witness address must be returned"


@pytest.mark.skipif(not _installed("slither"), reason="slither not installed")
@pytest.mark.slow
def test_slither_flags_the_reentrancy(harness: AdversarialHarness):
    res = harness.slither()
    assert res.facts.get("reentrancy") is True, res.output


@pytest.mark.skipif(not _installed("myth"), reason="mythril not installed")
@pytest.mark.slow
def test_mythril_flags_state_access_after_external_call(harness: AdversarialHarness):
    harness.build()
    res = harness.mythril()
    if res.returncode == 127:
        pytest.skip(res.output)
    assert res.facts.get("medium_state_access_after_call") is True, res.output
    assert "107" in res.facts.get("swc_ids", [])


def test_missing_tool_is_reported_unavailable_not_failed(tmp_path: Path, repo_root: Path):
    """A missing engine is reported returncode 127, never as a pass or a crash."""
    h = AdversarialHarness(tmp_path, repo_root=repo_root)
    res = EngineResult("ghost", "ghost --version", 127, "ghost: not found")
    assert res.available is False
    # And a real call to a nonexistent binary behaves the same.
    from blackheart.adversarial import _run
    rc, out = _run(["definitely-not-a-real-binary-xyz"], repo_root, 5)
    assert rc == 127 and "not found" in out
