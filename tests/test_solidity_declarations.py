"""An interface declaration is an entry point, not an implementation.

The Solidity scanner used to drop `function f(...) external;` entirely, so an
interface-only contract was reported as having no functions and the synthesis
step silently lost the surface. The declaration is now retained with
``declaration_only=True`` and synthesis records it as unmodelled.
"""

from __future__ import annotations

from blackheart.ingest.solidity import scan_source
from blackheart.ingest.synthesize import synthesize

SOURCE = """
pragma solidity ^0.8.20;

interface IVault {
    function deposit(uint256 amount) external;
    function balanceOf(address who) external view returns (uint256);
}

abstract contract Base {
    function hook() internal virtual;
}

contract Vault is Base {
    mapping(address => uint256) public balance;
    uint256 public total;

    function deposit(uint256 amount) external {
        balance[msg.sender] += amount;
        total += amount;
    }

    function hook() internal override {}
}
"""


def test_interface_declarations_are_retained_and_not_modelled():
    contracts = scan_source(SOURCE, "Vault.sol")
    vault = next(c for c in contracts if c.name == "Vault")
    names = {f.name for f in vault.functions}
    assert "deposit" in names
    assert all(not f.declaration_only for f in vault.functions if f.name == "deposit")

    interface = next(c for c in contracts if c.name == "IVault")
    decl = {f.name: f for f in interface.functions}
    assert decl["deposit"].declaration_only is True
    assert decl["deposit"].body == ""
    assert decl["balanceOf"].declaration_only is True

    target, _ = synthesize(vault)
    assert target.ops()
    _, declaration_synthesis = synthesize(interface)
    assert any("interface declaration" in n for n in declaration_synthesis.notes)
