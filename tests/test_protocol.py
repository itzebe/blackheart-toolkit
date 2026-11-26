"""Multi-contract composition: a call in one contract can move another's state."""

from __future__ import annotations

from blackheart.discovery.certify import certify_exhaustive
from blackheart.ingest.protocol import Link, build_protocol
from blackheart.ingest.solidity import scan_source

TOKEN = """
contract Token {
    mapping(address => uint) balance;
    uint totalSupply;
    function mint(uint amount) external { balance[msg.sender] += amount; }
}
"""

VAULT = """
contract Vault {
    mapping(address => uint) shares;
    uint totalShares;
    function deposit(uint amount) external { shares[msg.sender] += amount; totalShares += amount; }
}
"""


def _surfaces():
    token = scan_source(TOKEN, "Token.sol")[0]
    vault = scan_source(VAULT, "Vault.sol")[0]
    return {"Token": token, "Vault": vault}


def test_a_declared_cross_contract_link_carries_a_violation():
    protocol, report = build_protocol(
        _surfaces(), links=(Link("Vault", "deposit", "Token", "mint"),))
    assert protocol.to_dict()["contracts"] == ["Token", "Vault"]
    assert {op.name for op in protocol.ops()} == {"Token.mint", "Vault.deposit"}
    assert any(i.inv_id.startswith("Token:conservation:") for i in protocol.invariants())
    cert = certify_exhaustive(protocol, max_depth=2)
    assert cert.proven
    assert cert.invariant_id.startswith("Token:conservation:")


def test_without_the_link_the_other_contract_is_not_moved():
    protocol, _ = build_protocol(_surfaces())
    state = protocol.reset()
    protocol.step(state, "Vault.deposit", "attacker", {"amount": 5})
    assert state["Token"]["totalSupply"] == 0
    assert state["Vault"]["totalShares"] == 5


def test_a_link_moves_the_callee_state():
    protocol, _ = build_protocol(
        _surfaces(), links=(Link("Vault", "deposit", "Token", "mint"),))
    state = protocol.reset()
    protocol.step(state, "Vault.deposit", "attacker", {"amount": 5})
    assert state["Token"]["totalSupply"] == 0  # this Token's mint is the broken twin
    assert state["Token"]["balance"]["attacker"] == 5


def test_an_unknown_link_is_reported_not_silently_ignored():
    _, report = build_protocol(
        _surfaces(), links=(Link("Vault", "deposit", "Missing", "mint"),))
    assert any("unknown contract" in note for note in report.notes)


def test_a_fresh_protocol_instance_has_independent_substates():
    protocol, _ = build_protocol(_surfaces())
    state = protocol.reset()
    fresh = protocol.fresh_instance()
    fresh_state = fresh.reset()
    state["Token"]["totalSupply"] = 99
    assert fresh_state["Token"]["totalSupply"] == 0


EXTERNAL = """
contract Callee {
    uint256 public x;
    function bump(uint256 a) external { x += a; }
}
contract Caller {
    Callee public callee;
    function go(uint256 a) external { callee.bump(a); }
}
"""


def test_a_statement_level_external_call_moves_the_receiver_state():
    surfaces = {c.name: c for c in scan_source(EXTERNAL, "External.sol")}
    protocol, report = build_protocol(surfaces)
    assert report.contracts["Caller"].external_calls == ("go->callee.bump",)
    assert report.contracts["Caller"].modelled_ops == ("go",)
    state = protocol.reset()
    protocol.step(state, "Caller.go", "attacker", {"a": 7})
    assert state["Callee"]["x"] == 7


def test_a_reverting_external_call_reverts_the_caller_too():
    source = """
    contract Callee {
        uint256 public x;
        function bump(uint256 a) external { require(a > 0); x += a; }
    }
    contract Caller {
        uint256 public touched;
        Callee public callee;
        function go(uint256 a) external { touched = 1; callee.bump(a); }
    }
    """
    surfaces = {c.name: c for c in scan_source(source, "External.sol")}
    protocol, _ = build_protocol(surfaces)
    state = protocol.reset()
    protocol.step(state, "Caller.go", "attacker", {"a": 0})
    assert state["Caller"]["touched"] == 0
    assert state["Callee"]["x"] == 0


def test_a_call_argument_reads_the_caller_state_at_the_call_site():
    source = """
    contract Callee {
        uint256 public y;
        function bump(uint256 a) external { y += a; }
    }
    contract Caller {
        uint256 public x;
        Callee public callee;
        function go() external { x = 5; callee.bump(x); x = 0; }
    }
    """
    surfaces = {c.name: c for c in scan_source(source, "External.sol")}
    protocol, _ = build_protocol(surfaces)
    state = protocol.reset()
    protocol.step(state, "Caller.go", "attacker", {})
    assert state["Callee"]["y"] == 5
    assert state["Caller"]["x"] == 0


def test_a_call_return_value_is_assigned_in_the_caller():
    source = """
    contract Oracle {
        uint256 public answer;
        function get() external view returns (uint256) { return answer + 7; }
    }
    contract Consumer {
        uint256 public seen;
        Oracle public oracle;
        function read() external { seen = oracle.get(); }
    }
    """
    surfaces = {c.name: c for c in scan_source(source, "Return.sol")}
    protocol, report = build_protocol(surfaces)
    assert report.contracts["Consumer"].external_calls == ("read->oracle.get",)
    state = protocol.reset()
    protocol.step(state, "Consumer.read", "attacker", {})
    assert state["Consumer"]["seen"] == 7
