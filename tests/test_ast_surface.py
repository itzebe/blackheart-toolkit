"""The compiler AST is a first-class source of the same ContractSurface model."""

from __future__ import annotations

from blackheart.ingest.ast_surface import surfaces_from_ast

SOURCE = """contract Base {
    address public owner;
    modifier onlyOwner() { require(msg.sender == owner); _; }
}

contract Vault is Base {
    struct Acct { uint256 bal; uint256 debt; }
    mapping(address => uint256) public balanceOf;
    uint256 public totalSupply;

    function deposit(uint256 amount) external {
        balanceOf[msg.sender] += amount;
        totalSupply += amount;
    }

    function ownerOf(address who) external view returns (uint256) {
        return balanceOf[who];
    }
}
"""


def _span(text: str) -> str:
    start = SOURCE.index(text)
    return f"{start}:{len(text)}:0"



def _param(name: str, typ: str):
    return {"nodeType": "VariableDeclaration", "name": name,
            "typeDescriptions": {"typeString": typ}}


def _ast():
    return {"nodeType": "SourceUnit", "nodes": [
        {
            "nodeType": "ContractDefinition", "name": "Base",
            "contractKind": "contract", "src": _span("contract Base {\n    address public owner;\n    modifier onlyOwner() { require(msg.sender == owner); _; }\n}"),
            "baseContracts": [],
            "nodes": [
                {"nodeType": "VariableDeclaration", "name": "owner",
                 "stateVariable": True, "src": _span("address public owner;"),
                 "typeDescriptions": {"typeString": "address"}},
                {"nodeType": "ModifierDefinition", "name": "onlyOwner",
                 "src": _span("modifier onlyOwner() { require(msg.sender == owner); _; }")},
            ],
        },
        {
            "nodeType": "ContractDefinition", "name": "Vault",
            "contractKind": "contract",
            "src": _span("contract Vault is Base {\n    struct Acct { uint256 bal; uint256 debt; }\n    mapping(address => uint256) public balanceOf;\n    uint256 public totalSupply;\n\n    function deposit(uint256 amount) external {\n        balanceOf[msg.sender] += amount;\n        totalSupply += amount;\n    }\n\n    function ownerOf(address who) external view returns (uint256) {\n        return balanceOf[who];\n    }\n}"),
            "baseContracts": [{"baseName": {"name": "Base"}}],
            "nodes": [
                {"nodeType": "StructDefinition", "name": "Acct",
                 "src": _span("struct Acct { uint256 bal; uint256 debt; }"),
                 "members": [
                     {"nodeType": "VariableDeclaration", "name": "bal",
                      "typeDescriptions": {"typeString": "uint256"}},
                     {"nodeType": "VariableDeclaration", "name": "debt",
                      "typeDescriptions": {"typeString": "uint256"}},
                 ]},
                {"nodeType": "VariableDeclaration", "name": "balanceOf",
                 "stateVariable": True,
                 "src": _span("mapping(address => uint256) public balanceOf;"),
                 "typeDescriptions": {"typeString": "mapping(address => uint256)"}},
                {"nodeType": "VariableDeclaration", "name": "totalSupply",
                 "stateVariable": True, "src": _span("uint256 public totalSupply;"),
                 "typeDescriptions": {"typeString": "uint256"}},
                {"nodeType": "FunctionDefinition", "name": "deposit",
                 "kind": "function", "visibility": "external",
                 "stateMutability": "nonpayable",
                 "src": _span("function deposit(uint256 amount) external {\n        balanceOf[msg.sender] += amount;\n        totalSupply += amount;\n    }"),
                 "parameters": {"parameters": [_param("amount", "uint256")]},
                 "returnParameters": {"parameters": []},
                 "modifiers": []},
                {"nodeType": "FunctionDefinition", "name": "ownerOf",
                 "kind": "function", "visibility": "external",
                 "stateMutability": "view",
                 "src": _span("function ownerOf(address who) external view returns (uint256) {\n        return balanceOf[who];\n    }"),
                 "parameters": {"parameters": [_param("who", "address")]},
                 "returnParameters": {"parameters": [_param("", "uint256")]},
                 "modifiers": [{"modifierName": {"name": "onlyOwner"}}]},
            ],
        },
    ]}


def test_the_ast_surface_matches_the_scanner_shape():
    contracts = surfaces_from_ast(_ast(), {"Vault.sol": SOURCE})
    assert [c.name for c in contracts] == ["Base", "Vault"]
    base, vault = contracts
    assert base.modifiers_defined == ("onlyOwner",)
    assert base.state_types == (("owner", "address"),)
    assert vault.bases == ("Base",)
    assert vault.state_types == (
        ("balanceOf", "mapping(address => uint256)"),
        ("totalSupply", "uint256"),
    )
    assert vault.structs == (("Acct", (("bal", "uint256"), ("debt", "uint256"))),)
    deposit = next(f for f in vault.functions if f.name == "deposit")
    assert deposit.signature == "deposit(uint256)"
    assert deposit.params == ("uint256 amount",)
    assert "balanceOf[msg.sender] += amount" in deposit.body
    assert deposit.line == 11
    owner_of = next(f for f in vault.functions if f.name == "ownerOf")
    assert owner_of.returns == ("uint256",)
    assert owner_of.modifiers == ("onlyOwner",)
    assert "return balanceOf[who]" in owner_of.body


def test_an_unresolvable_body_stays_empty_instead_of_guessed():
    ast = _ast()
    ast["nodes"][1]["nodes"][3]["src"] = "999999:10:0"
    vault = surfaces_from_ast(ast, {"Vault.sol": SOURCE})[1]
    assert next(f for f in vault.functions if f.name == "deposit").body == ""
