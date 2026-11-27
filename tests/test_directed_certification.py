"""Directed certification spends the budget on the path an attacker would take."""

from __future__ import annotations

from blackheart.control import load_source_tree
from blackheart.discovery.certify import certify_directed
from blackheart.ingest.protocol import Link, build_protocol
from blackheart.ingest.solidity import scan_source


def _protocol(contract: str = "VulnerableVault"):
    files = load_source_tree("harnesses/erc4626/src")
    surfaces = {c.name: c for path, text in files.items() for c in scan_source(text, path)}
    selected = {contract: surfaces[contract], "MockERC20": surfaces["MockERC20"]}
    protocol, _ = build_protocol(selected, infer_links=True)
    return protocol


def test_directed_search_finds_the_first_depositor_path():
    cert = certify_directed(
        _protocol(), max_depth=4, max_states=150_000, beam_width=500,
        param_sets=32,
    )
    assert cert.proven
    assert cert.invariant_id == "VulnerableVault:erc4626:nonzero-shares"
    actions = [step.action for step in cert.witness]
    assert actions == [
        "MockERC20.mint", "MockERC20.mint", "MockERC20.approve",
        "VulnerableVault.deposit",
    ]
    assert cert.exhausted is False
    assert cert.bound["exhaustive"] is False
    assert "not a proof" in cert.reason or "reproduced" in cert.reason


def test_directed_search_does_not_call_a_bounded_miss_a_proof():
    cert = certify_directed(
        _protocol("SafeVault"), max_depth=4, max_states=40_000,
        beam_width=300, param_sets=32,
    )
    assert not cert.proven
    assert cert.exhausted is False
    assert cert.bound["exhaustive"] is False
    assert "not a proof" in cert.reason


def test_a_link_without_matching_parameters_does_not_fabricate_a_call():
    """A missing link parameter is not zero.

    ``Vault.deposit(amount)`` links to ``Token.transfer(to, amount)``; the
    callee's ``to`` name is absent. Applying ``transfer(0, amount)`` would
    invent a state change and can make an invariant fail for a call that never
    happened.
    """
    token = scan_source("""
contract Token {
    mapping(address => uint) balance;
    function transfer(address to, uint amount) external {
        balance[msg.sender] -= amount;
        balance[to] += amount;
    }
}
""", "Token.sol")[0]
    vault = scan_source("""
contract Vault {
    uint public total;
    function deposit(uint amount) external { total += amount; }
}
""", "Vault.sol")[0]
    protocol, _ = build_protocol(
        {"Token": token, "Vault": vault},
        links=(Link("Vault", "deposit", "Token", "transfer"),),
    )
    state = protocol.reset()
    protocol.step(state, "Vault.deposit", "attacker", {"amount": 5})
    assert state["Token"]["balance"] == {}
