"""Deployment planning never invents a constructor argument."""

from __future__ import annotations

from blackheart.ingest.deploy import (
    EIP1967_ADMIN, EIP1967_IMPLEMENTATION, constructor_params, plan_deployment,
)

FILES = {"Vault.sol": """
contract Token {
    uint256 public supply;
    constructor(uint256 initial) { supply = initial; }
    function mint(uint256 amount) external { supply += amount; }
}
contract Vault {
    address public owner;
    constructor(address owner_, uint256 seed) { owner = owner_; }
    function deposit(uint256 amount) external {}
}
"""}


def test_constructor_parameters_are_read_from_the_right_contract():
    assert constructor_params(FILES["Vault.sol"], "Vault") == (
        "address owner_", "uint256 seed")
    assert constructor_params(FILES["Vault.sol"], "Token") == ("uint256 initial",)


def test_missing_arguments_block_the_plan_without_defaulting_to_zero():
    plan = plan_deployment(FILES, "Vault")
    assert plan.status == "BLOCKED"
    assert not plan.ready
    assert "owner_" in plan.steps[0].reason
    assert plan.steps[0].constructor_args == ()


def test_supplied_arguments_and_helpers_make_a_ready_plan():
    plan = plan_deployment(
        FILES, "Vault", constructor_args=["0x" + "11" * 20, 7],
        helper_deployments=(("Token", [1000]),), proxy=True)
    assert plan.status == "READY"
    assert [s.name for s in plan.steps] == ["Vault", "Token", "BHProxy"]
    assert plan.steps[1].constructor_args == (1000,)


def test_proxy_slots_are_reported_when_supplied():
    storage = {EIP1967_IMPLEMENTATION: int("22" * 20, 16),
               EIP1967_ADMIN: int("33" * 20, 16)}
    plan = plan_deployment(FILES, "Vault", constructor_args=["0x" + "11" * 20, 7],
                           proxy=True, runtime_code=b"\x60", storage=storage)
    assert plan.proxy_implementation == "0x" + "22" * 20
    assert plan.proxy_admin == "0x" + "33" * 20
    assert any("EIP-1967" in note for note in plan.notes)
