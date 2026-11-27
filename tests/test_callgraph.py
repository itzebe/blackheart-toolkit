"""Inferred cross-contract links are leads, resolved only when unambiguous."""

from __future__ import annotations

from blackheart.ingest.callgraph import infer_calls
from blackheart.ingest.protocol import build_protocol
from blackheart.ingest.solidity import scan_source

SOURCE = """
contract Token {
    function mint(address to, uint amount) external {}
}
contract Vault {
    function deposit(uint amount) external { token.mint(msg.sender, amount); }
    function deploy() external { new Helper(); }
}
contract Helper { function ping() external {} }
"""


def _contracts(src: str = SOURCE):
    return {c.name: c for c in scan_source(src, "Protocol.sol")}


def test_a_unique_receiver_function_infers_a_link():
    graph = infer_calls(_contracts())
    edges = {(e.caller, e.caller_op, e.callee, e.callee_op) for e in graph.edges}
    assert ("Vault", "deposit", "Token", "mint") in edges
    assert graph.deployments[0]["contract"] == "Helper"


def test_an_explicit_receiver_type_resolves_even_when_the_name_is_unknown():
    source = """
    contract Token { function mint(address to, uint amount) external {} }
    contract Vault {
        function deposit(address token, uint amount) external {
            Token(token).mint(msg.sender, amount);
        }
    }
    """
    graph = infer_calls(_contracts(source))
    assert [(e.caller, e.callee, e.callee_op) for e in graph.edges] == [
        ("Vault", "Token", "mint")]


def test_an_ambiguous_receiver_is_reported_not_guessed():
    source = """
    contract A { function mint(address to, uint amount) external {} }
    contract B { function mint(address to, uint amount) external {} }
    contract Vault {
        function deposit(uint amount) external { token.mint(msg.sender, amount); }
    }
    """
    graph = infer_calls(_contracts(source))
    assert graph.edges == ()
    assert graph.unresolved
    assert "cannot be resolved" in graph.unresolved[0]["reason"]


def test_build_protocol_can_use_inferred_links():
    target, report = build_protocol(_contracts(), infer_links=True)
    assert ("Vault", "deposit", "Token", "mint") in {
        (l.caller, l.caller_op, l.callee, l.callee_op) for l in report.links}
    assert report.callgraph["edges"]
    assert "Vault.deposit" in {op.name for op in target.ops()}


def test_slither_dot_graph_recovers_compiler_edges_and_drops_internal_calls():
    from blackheart.ingest.callgraph import parse_slither_call_graph
    dot = '''strict digraph {
subgraph cluster_14_B {
label = "B"
"14_bump" [label="bump"]
}subgraph cluster_30_A {
label = "A"
"30_go" [label="go"]
}subgraph cluster_solidity {
label = "[Solidity]"
}
"30_go" -> "14_bump"
"30_go" -> "30_go"
}'''
    edges = parse_slither_call_graph(dot)
    assert [(e.caller, e.caller_op, e.callee, e.callee_op, e.kind) for e in edges] == [
        ("A", "go", "B", "bump", "compiler")]


def test_an_interface_typed_receiver_resolves_to_its_single_implementation():
    source = """
    interface IOracle { function get() external view returns (uint256); }
    contract Oracle is IOracle {
        function get() external view returns (uint256) { return 1; }
    }
    contract Vault {
        IOracle public oracle;
        function read() external { oracle.get(); }
    }
    """
    graph = infer_calls(_contracts(source))
    assert [(e.caller, e.caller_op, e.callee, e.callee_op) for e in graph.edges] == [
        ("Vault", "read", "Oracle", "get")]


def test_an_ambiguous_interface_receiver_is_reported_with_both_candidates():
    source = """
    interface IOracle { function get() external view returns (uint256); }
    contract A is IOracle { function get() external view returns (uint256) { return 1; } }
    contract B is IOracle { function get() external view returns (uint256) { return 2; } }
    contract Vault {
        IOracle public oracle;
        function read() external { oracle.get(); }
    }
    """
    graph = infer_calls(_contracts(source))
    assert graph.edges == ()
    assert any("ambiguous interface/base IOracle" in item["reason"]
               and "A, B" in item["reason"] for item in graph.unresolved)
