"""The SSA-lite taint pass must find unprivileged flows and respect guards."""

from __future__ import annotations

from blackheart.dataflow import analyse_source


VAULT = """
contract Vault {
    address public owner;
    mapping(address => uint256) public balances;

    function withdraw(address to, uint256 amount) external {
        (bool ok,) = to.call{value: amount}("");
        require(ok);
    }

    function setOwner(address newOwner) external {
        owner = newOwner;
    }

    function safeSetOwner(address newOwner) external {
        require(msg.sender == owner);
        owner = newOwner;
    }
}
"""


def test_attacker_parameter_reaches_an_external_call_and_a_state_write():
    result = analyse_source({"Vault.sol": VAULT}, contract_name="Vault")
    flows = result.to_dict()["flows"]
    assert result.ssa_nodes > 0
    assert any(f["sink"] == "to.call" and f["unprivileged"] for f in flows)
    assert any(f["sink"] == "owner" and f["function"] == "setOwner"
               and f["unprivileged"] for f in flows)
    assert any(f["sink"] == "owner" and f["function"] == "safeSetOwner"
               and not f["unprivileged"] for f in flows)


def test_taint_propagates_through_an_internal_call():
    source = """
contract Inner {
    address public owner;
    function outer(address x) external { inner(x); }
    function inner(address y) internal { owner = y; }
    function guarded(address x) external {
        require(msg.sender == owner);
        inner(x);
    }
}
"""
    result = analyse_source({"Inner.sol": source}, contract_name="Inner")
    unprivileged = result.to_dict()["unprivileged_flows"]
    assert any(f["path"] and f["path"][0] == "Inner.outer" for f in unprivileged)
    assert all(f["path"][0] != "Inner.guarded" for f in unprivileged)


def test_an_unmapped_function_is_never_invented():
    result = analyse_source({"Vault.sol": VAULT}, contract_name="Vault")
    assert result.contracts == ["Vault"]
    assert result.functions == 3


def test_array_of_struct_member_write_is_parsed_not_dropped():
    source = """
contract Pools {
    struct Pool { uint256 amount; }
    Pool[] public pools;
    function set(uint256 i, uint256 a) external { pools[i].amount = a; }
}
"""
    result = analyse_source({"Pools.sol": source}, contract_name="Pools")
    assert result.ssa_nodes > 0
    assert result.to_dict()["unsupported"] == []
