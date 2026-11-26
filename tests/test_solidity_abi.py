"""The ABI reader must be compiler-accurate and invent nothing.

The lexer can miss constructs a compiler resolves. When a compiler is present its
ABI is the better surface, so these tests pin that the ABI reader: keeps only
callable functions, treats only mutating functions as attacker operations, gives
sensible sample domains for scalar types, and gives an array or struct *no* domain
rather than a fabricated scalar.
"""

from __future__ import annotations

from blackheart.solidity.abi import (
    AbiFunction,
    operations_from_abi,
    param_domain,
    parse_abi,
    propose_model_from_abi,
)

ABI = [
    {"type": "constructor", "inputs": [], "stateMutability": "nonpayable"},
    {"type": "event", "name": "Transfer", "inputs": []},
    {"type": "function", "name": "transfer", "stateMutability": "nonpayable",
     "inputs": [{"name": "to", "type": "address"}, {"name": "amount", "type": "uint256"}],
     "outputs": [{"name": "", "type": "bool"}]},
    {"type": "function", "name": "balanceOf", "stateMutability": "view",
     "inputs": [{"name": "who", "type": "address"}], "outputs": [{"name": "", "type": "uint256"}]},
    {"type": "function", "name": "deposit", "stateMutability": "payable",
     "inputs": [], "outputs": []},
    {"type": "function", "name": "setBatch", "stateMutability": "nonpayable",
     "inputs": [{"name": "items", "type": "uint256[]"}], "outputs": []},
]


def test_parse_abi_keeps_only_callable_functions():
    functions = parse_abi(ABI)
    assert [f.name for f in functions] == ["transfer", "balanceOf", "deposit", "setBatch"]
    assert isinstance(functions[0], AbiFunction)
    assert functions[0].signature() == "transfer(address,uint256)"


def test_only_mutating_functions_become_operations():
    ops = operations_from_abi(parse_abi(ABI))
    names = [o["name"] for o in ops]
    assert "balanceOf" not in names, "a view function cannot change state"
    assert names == ["transfer", "deposit", "setBatch"]


def test_scalar_domains_are_samples_not_guesses():
    assert param_domain("uint256") == [0, 1, 100, 10 ** 18]
    assert param_domain("address") == ["attacker", "victim", "admin"]
    assert param_domain("bool") == [False, True]
    assert param_domain("string") == [""]
    # An array or struct has no single scalar sample.
    assert param_domain("uint256[]") == []
    assert param_domain("tuple") == []


def test_array_parameter_is_omitted_rather_than_faked():
    ops = {o["name"]: o for o in operations_from_abi(parse_abi(ABI))}
    assert ops["setBatch"]["param_domain"] == {}
    assert ops["transfer"]["param_domain"] == {
        "to": ["attacker", "victim", "admin"],
        "amount": [0, 1, 100, 10 ** 18],
    }


def test_propose_model_from_abi_records_provenance():
    model = propose_model_from_abi(ABI, target_name="Token")
    assert model.target == "Token"
    assert {a.name for a in model.actors} == {"attacker", "victim"}
    assert {o.name for o in model.operations} == {"transfer", "deposit", "setBatch"}
    assert all(o.source == "abi:Token" for o in model.operations)
    assert all(o.sensitive for o in model.operations)
