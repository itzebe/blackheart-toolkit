"""Generated Foundry invariant tests discriminate the ERC4626 pair.

The generator is not a test template: it reads the recovered surface, deploys
the vault and its asset, and fuzzes the public operations. The vulnerable vault
must fail the invariant; the guarded twin must survive it. The test is skipped
when forge is absent, and the skip is not a pass.
"""

import shutil
from pathlib import Path

import pytest

from blackheart.ingest.generated_invariant import (
    infer_asset, render_erc4626_invariant, run_generated_invariant,
)
from blackheart.toolchain.enforce import self_test_record

FIXTURES = Path(__file__).resolve().parents[1] / "harnesses" / "erc4626" / "src"


def _files():
    return {path.name: path.read_text(encoding="utf-8")
            for path in FIXTURES.glob("*.sol")}


def test_generator_reads_the_surface_and_refuses_an_unknown_contract():
    files = _files()
    assert infer_asset(files, "VulnerableVault") == "MockERC20"
    generated = render_erc4626_invariant(files, "VulnerableVault", "MockERC20")
    assert "invariant_nonzero_shares" in generated.solidity
    assert "try vault.deposit" in generated.solidity
    with pytest.raises(ValueError):
        render_erc4626_invariant(files, "NoSuchVault", "MockERC20")


@pytest.mark.skipif(shutil.which("forge") is None, reason="forge is not installed")
def test_vulnerable_vault_fails_the_generated_invariant():
    generated = render_erc4626_invariant(_files(), "VulnerableVault", "MockERC20")
    outcome = run_generated_invariant(
        generated, compatibility=self_test_record(),
        target_component="VulnerableVault", repository="blackheart", timeout=300)
    assert outcome.status == "PASS", outcome.detail
    assert "invariant" in outcome.detail.lower()


@pytest.mark.skipif(shutil.which("forge") is None, reason="forge is not installed")
def test_guarded_vault_survives_the_generated_invariant():
    generated = render_erc4626_invariant(_files(), "SafeVault", "MockERC20")
    outcome = run_generated_invariant(
        generated, compatibility=self_test_record(),
        target_component="SafeVault", repository="blackheart", timeout=300)
    assert outcome.status == "NO_FINDINGS", outcome.detail
