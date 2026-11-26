"""The invariant generator is not limited to ERC4626.

It reads an explicit owner getter or a caller-supplied property, fuzzes every
state-changing function it can model, and refuses a surface it cannot support.
"""

from __future__ import annotations

import shutil

import pytest

from blackheart.ingest.generated_invariant import (
    applicable_invariants, render_surface_invariant, run_generated_invariant,
)
from blackheart.toolchain.enforce import self_test_record

PAIR = """pragma solidity ^0.8.20;

contract OwnerVulnerable {
    address private _owner;
    constructor() { _owner = msg.sender; }
    function owner() external view returns (address) { return _owner; }
    function setOwner(address next) external { _owner = next; }
}

contract OwnerSafe {
    address private _owner;
    constructor() { _owner = msg.sender; }
    modifier onlyOwner() { require(msg.sender == _owner, "owner"); _; }
    function owner() external view returns (address) { return _owner; }
    function setOwner(address next) external onlyOwner { _owner = next; }
}
"""


def _files():
    return {"src/OwnerPair.sol": PAIR}


def test_the_surface_selects_the_owner_invariant():
    assert applicable_invariants(_files(), "OwnerVulnerable") == (
        "authorization:owner-unchanged",
    )
    generated = render_surface_invariant(_files(), "OwnerVulnerable")
    assert generated.template == "authorization:owner-unchanged"
    assert "originalOwner" in generated.solidity
    assert "try vault.setOwner" in generated.solidity


def test_a_caller_supplied_property_is_wrapped_in_a_handler():
    generated = render_surface_invariant(
        _files(), "OwnerVulnerable",
        invariant_body="require(vault.owner() != address(0), \"owner lost\");")
    assert generated.template == "generic"
    assert "function call_setOwner" in generated.solidity
    assert "owner lost" in generated.solidity


def test_a_surface_with_no_supported_invariant_is_refused():
    source = """
contract Plain {
    uint public x;
    function bump() external { x += 1; }
}
"""
    with pytest.raises(ValueError, match="no built-in invariant"):
        render_surface_invariant({"Plain.sol": source}, "Plain")


@pytest.mark.skipif(shutil.which("forge") is None, reason="forge is not installed")
def test_the_owner_invariant_reproduces_the_unguarded_setter():
    generated = render_surface_invariant(_files(), "OwnerVulnerable")
    outcome = run_generated_invariant(
        generated, compatibility=self_test_record(),
        target_component="OwnerVulnerable", repository="blackheart", timeout=300)
    assert outcome.status == "PASS", outcome.detail


@pytest.mark.skipif(shutil.which("forge") is None, reason="forge is not installed")
def test_the_owner_invariant_survives_the_guarded_twin():
    generated = render_surface_invariant(_files(), "OwnerSafe")
    outcome = run_generated_invariant(
        generated, compatibility=self_test_record(),
        target_component="OwnerSafe", repository="blackheart", timeout=300)
    assert outcome.status == "NO_FINDINGS", outcome.detail
