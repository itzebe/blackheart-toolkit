"""Acceptance bar for model synthesis.

The claim this module makes is narrow and must be tested narrowly: from a
contract surface it builds a model whose operations are the contract's own
functions, and the existing certifier can then discriminate a vulnerable
contract from its guarded twin. It must also stay honest -- an operation it
cannot interpret must not move state, and a clean result must be phrased as a
bound, never as proof.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from blackheart.assurance.certify import CertifyConfig, certify
from blackheart.ingest.solidity import scan_source
from blackheart.ingest.synthesize import interpret, synthesize

VULNERABLE = """
pragma solidity 0.8.20;
contract Bank {
    address public owner;
    mapping(address => uint256) public balances;
    uint256 public totalSupply;

    function deposit(uint256 amount) external {
        balances[msg.sender] += amount;
        totalSupply += amount;
    }
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount);
        balances[msg.sender] -= amount;
        totalSupply -= amount;
    }
    function setOwner(address who) external { owner = who; }
    function rescue(address to) external {
        require(msg.sender == owner);
        balances[to] = totalSupply;
    }
}
"""

GUARDED = VULNERABLE.replace(
    "function setOwner(address who) external { owner = who; }",
    "modifier onlyOwner() { require(msg.sender == owner); _; }\n"
    "    function setOwner(address who) external onlyOwner { owner = who; }",
)


def _contract(src: str):
    return scan_source(src, "Bank.sol")[0]


def _contracts(src: str):
    return scan_source(src, "Bank.sol")


def _certify(src: str, depth: int = 3):
    target, report = synthesize(_contract(src))
    return target, report, certify(target, CertifyConfig(max_depth=depth, price_findings=False))


# --------------------------------------------------------------------------- #
# The discrimination that makes the model worth having
# --------------------------------------------------------------------------- #

def test_vulnerable_contract_is_broken_within_depth_three():
    _, _, cert = _certify(VULNERABLE)
    assert cert.broke, cert.verdict_line()
    first = cert.violations[0]
    assert first["invariant_id"] == "authorization:owner"
    assert [step["action"] for step in first["minimal_sequence"]] == ["setOwner"]
    conservation = [v for v in cert.violations
                    if v["invariant_id"].startswith("conservation:")]
    assert any("rescue" in [step["action"] for step in v["minimal_sequence"]]
               for v in conservation)


def test_guarded_twin_is_clean_to_the_same_depth():
    _, _, cert = _certify(GUARDED)
    assert not cert.broke, cert.verdict_line()
    assert "CERTIFIED CLEAN" in cert.verdict_line()


def test_the_counterexample_is_an_unprivileged_actor():
    _, _, cert = _certify(VULNERABLE)
    actors = {step["actor"] for step in cert.violations[0]["minimal_sequence"]}
    assert actors <= {"attacker", "victim"}
    assert "admin" not in actors


# --------------------------------------------------------------------------- #
# Honesty: unmodelled work is not simulated
# --------------------------------------------------------------------------- #

UNMODELLED = """
pragma solidity 0.8.20;
contract Opaque {
    uint256 public total;
    function bump() external {
        for (uint256 i = 0; i < total; i++) { total += 1; }
    }
}
"""


def test_unmodelled_operation_is_flagged_and_does_not_move_state():
    target, report = synthesize(_contract(UNMODELLED))
    assert "bump" in report.unmodelled_ops
    assert report.unmodelled_statements
    state = target.reset()
    target.step(state, "bump", "attacker", {})
    assert state["total"] == 0


def test_report_says_when_nothing_could_be_modelled():
    _, report = synthesize(_contract("contract Empty { uint256 public x; }"))
    assert report.invariants == ()
    assert any("no conservation invariant" in note for note in report.notes)


# --------------------------------------------------------------------------- #
# Guards, domains and invariants
# --------------------------------------------------------------------------- #

def test_only_modifier_becomes_an_owner_guard():
    func = next(f for f in _contract(GUARDED).functions if f.name == "setOwner")
    model = interpret(func, "owner")
    assert model.guard_text and "msg.sender == owner" in model.guard_text[0]


def test_parameter_domains_are_typed_not_blanket():
    target, _ = synthesize(_contract(VULNERABLE))
    domains = {op.name: op.param_domain for op in target.ops()}
    assert domains["deposit"]["amount"] == [0, 1, 2, 100]
    assert domains["setOwner"]["who"] == ["attacker", "victim", "admin"]


def test_conservation_invariant_is_derived():
    _, report = synthesize(_contract(VULNERABLE))
    assert "conservation:balances-totalSupply" in report.invariants


def test_model_only_uses_unprivileged_actors():
    target, _ = synthesize(_contract(VULNERABLE))
    for op in target.ops():
        assert op.actors == ["attacker", "victim"]


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def test_cli_synthesize_reports_a_broken_model(tmp_path):
    target = tmp_path / "Bank.sol"
    target.write_text(VULNERABLE)
    proc = subprocess.run(
        [sys.executable, "-m", "blackheart", "ingest", str(target), "--synthesize", "--json"],
        capture_output=True, text=True, timeout=300,
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert payload["synthesis"][0]["broke"] is True
    assert payload["synthesis"][0]["modelled_ops"]


def _loop_function(body: str):
    from blackheart.ingest.solidity import FunctionSurface

    return FunctionSurface(contract="C", name="f", signature="f()",
                           visibility="external", mutability="nonpayable",
                           modifiers=(), params=(), body=body, line=1)


def test_a_bounded_loop_is_unrolled_into_its_effects():
    model = interpret(_loop_function(
        "for (uint i = 0; i < 3; i++) { balances[msg.sender] += 1; }"), "owner")
    assert model.modelled
    assert len(model.effects) == 3


def test_an_out_of_bound_loop_stays_unmodelled():
    model = interpret(_loop_function(
        "for (uint i = 0; i < 100; i++) { balances[msg.sender] += 1; }"), "owner")
    assert not model.modelled


def test_a_loop_that_reads_its_index_stays_unmodelled():
    model = interpret(_loop_function(
        "for (uint i = 0; i < 3; i++) { balances[msg.sender] += i; }"), "owner")
    assert not model.modelled


def test_cli_symbolic_reachability_finds_the_guarded_path(tmp_path):
    target = tmp_path / "Bank.sol"
    target.write_text(VULNERABLE)
    proc = subprocess.run(
        [sys.executable, "-m", "blackheart", "ingest", str(target),
         "--synthesize", "--symbolic", "--json"],
        capture_output=True, text=True, timeout=300,
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    item = payload["symbolic_reachability"][0]
    assert "setOwner" in item["reachable"]
    assert "rescue" in item["reachable"]
    assert item["reachable"]["rescue"]["sequence"][0].startswith("setOwner")


def test_symbolic_output_is_opt_in(tmp_path):
    target = tmp_path / "Bank.sol"
    target.write_text(VULNERABLE)
    proc = subprocess.run(
        [sys.executable, "-m", "blackheart", "ingest", str(target),
         "--synthesize", "--json"],
        capture_output=True, text=True, timeout=300,
    )
    assert proc.returncode == 0, proc.stderr
    assert "symbolic_reachability" not in json.loads(proc.stdout)


WIDE = """
pragma solidity 0.8.20;
contract Wide {
    uint256 public x;
    uint256 public y;
    function math(uint256 a) external {
        x *= 2;
        x += a;
        x++;
        if (a > 1) { y = 5; } else { y = 7; }
    }
    function clear() external { delete y; }
    function guarded(uint256 a) external {
        if (a > 0) { x = 9; require(a < 5); }
    }
}
"""


def test_compound_assignment_unary_delete_and_branches_are_modelled():
    target, report = synthesize(_contract(WIDE))
    assert set(report.modelled_ops) == {"math", "clear", "guarded"}
    state = target.reset()
    target.step(state, "math", "attacker", {"a": 3})
    assert state["x"] == 4  # 0 * 2 + 3 + 1
    assert state["y"] == 5
    target.step(state, "clear", "attacker", {})
    assert state["y"] == 0


def test_a_conditional_require_reverts_the_whole_call_atomically():
    target, _ = synthesize(_contract(WIDE))
    state = target.reset()
    target.step(state, "guarded", "attacker", {"a": 6})
    assert state["x"] == 0  # the branch's require failed; no half-applied write
    target.step(state, "guarded", "attacker", {"a": 2})
    assert state["x"] == 9


ELSE_IF = """
pragma solidity 0.8.20;
contract ElseIf {
    uint256 public total;
    function choose(uint256 x) external {
        if (x > 0) { total += 1; }
        else if (x == 0) { total += 2; }
    }
}
"""


def test_else_if_is_modelled_instead_of_dropped():
    target, report = synthesize(_contract(ELSE_IF))
    assert report.modelled_ops == ("choose",)
    model = target.op_models()[0]
    assert model.modelled
    assert model.has_conditional_effects
    assert len(model.effects) == 2
    state = target.reset()
    target.step(state, "choose", "attacker", {"x": 0})
    assert state["total"] == 2


def test_cli_symbolic_handles_a_branch_gated_operation(tmp_path):
    target = tmp_path / "ElseIf.sol"
    target.write_text(ELSE_IF)
    proc = subprocess.run(
        [sys.executable, "-m", "blackheart", "ingest", str(target),
         "--synthesize", "--symbolic", "--json"],
        capture_output=True, text=True, timeout=300,
    )
    assert proc.returncode == 0, proc.stderr
    item = json.loads(proc.stdout)["symbolic_reachability"][0]
    assert "choose" in item["reachable"]
    assert item["unsupported"] == []


SOURCE_ORDER = """
pragma solidity 0.8.20;
contract Ordered {
    address public owner;
    uint256 public x;
    uint256 public y;
    function guarded(uint256 a) external {
        x = a;
        require(x < 5);
        y = 1;
    }
    function precondition() external {
        require(msg.sender == owner);
        x = 1;
    }
}
"""


def test_require_after_a_write_is_source_ordered_and_atomic():
    target, _ = synthesize(_contract(SOURCE_ORDER))
    state = target.reset()
    target.step(state, "guarded", "attacker", {"a": 5})
    assert state["x"] == 0 and state["y"] == 0
    target.step(state, "guarded", "attacker", {"a": 4})
    assert state["x"] == 4 and state["y"] == 1


def test_a_leading_require_stays_a_reachability_guard():
    target, _ = synthesize(_contract(SOURCE_ORDER))
    model = next(m for m in target.op_models() if m.name == "precondition")
    assert model.guard_text
    assert all(e.kind != "require" for e in model.effects)


SHAPES = """
pragma solidity 0.8.20;
contract Base {
    uint256 public total;
    function inherited(uint256 a) external { total += a; }
}
contract Shapes is Base {
    struct Acct { uint256 bal; uint256 debt; }
    Acct public acct;
    uint256[] public arr;
    function bump(uint256 a) external {
        acct.bal += a;
        arr.push(a);
    }
    function capped(uint256 a) external {
        require(arr.length < 3);
        arr.push(a);
    }
}
"""


def test_struct_fields_and_arrays_are_modelled():
    contracts = {c.name: c for c in _contracts(SHAPES)}
    target, report = synthesize(contracts["Shapes"], registry=contracts)
    assert report.modelled_ops == ("inherited", "bump", "capped")
    state = target.reset()
    target.step(state, "bump", "attacker", {"a": 5})
    assert state["acct.bal"] == 5
    assert state["arr"] == {0: 5}
    target.step(state, "capped", "attacker", {"a": 7})
    target.step(state, "capped", "attacker", {"a": 8})
    target.step(state, "capped", "attacker", {"a": 9})
    assert state["arr"] == {0: 5, 1: 7, 2: 8}


def test_inherited_functions_and_state_are_in_the_derived_model():
    contracts = {c.name: c for c in _contracts(SHAPES)}
    target, _ = synthesize(contracts["Shapes"], registry=contracts)
    names = {model.name for model in target.op_models()}
    assert {"inherited", "bump", "capped"} <= names
    state = target.reset()
    target.step(state, "inherited", "attacker", {"a": 4})
    assert state["total"] == 4


def test_an_unguarded_owner_write_breaks_the_authorization_invariant():
    from blackheart.discovery.certify import certify_exhaustive

    source = """
    contract Vault {
        address public owner;
        function takeover() external { owner = msg.sender; }
    }
    """
    contracts = {c.name: c for c in _contracts(source)}
    target, report = synthesize(contracts["Vault"])
    assert "authorization:owner" in report.invariants
    cert = certify_exhaustive(target, max_depth=1)
    assert cert.proven


def test_an_only_owner_write_is_unreachable_for_an_unprivileged_actor():
    from blackheart.discovery.certify import certify_exhaustive

    source = """
    contract Vault {
        address public owner;
        modifier onlyOwner() { require(msg.sender == owner); _; }
        function takeover() external onlyOwner { owner = msg.sender; }
    }
    """
    contracts = {c.name: c for c in _contracts(source)}
    target, report = synthesize(contracts["Vault"])
    assert "authorization:owner" in report.invariants
    cert = certify_exhaustive(target, max_depth=1)
    assert not cert.proven


ARRAY_OF_STRUCTS = """
pragma solidity 0.8.20;
contract Pools {
    struct Pool { uint256 amount; }
    Pool[] public pools;
    mapping(address => uint256) public balances;

    function add(uint256 i, uint256 a) external { pools[i].amount += a; }
    function take(uint256 i, uint256 a) external { pools[i].amount -= a; }
    function deposit() external payable { balances[msg.sender] += msg.value; }
}
"""


def test_array_of_struct_member_write_is_modelled_and_underflow_reverts():
    target, report = synthesize(_contract(ARRAY_OF_STRUCTS))
    assert {"add", "take", "deposit"} <= set(report.modelled_ops)
    assert "pools[i].amount" not in " ".join(report.unmodelled_statements)

    state = target.reset()
    assert target.step(state, "add", "attacker", {"i": 1, "a": 5})
    assert state["pools"] == {1: {"amount": 5}}
    assert target.step(state, "take", "attacker", {"i": 1, "a": 3})
    assert state["pools"] == {1: {"amount": 2}}
    # Solidity 0.8 reverts on underflow; the model must not wrap to a huge value.
    assert not target.step(state, "take", "attacker", {"i": 1, "a": 99})
    assert state["pools"] == {1: {"amount": 2}}


def test_unchecked_wrapper_does_not_hide_state_writes():
    contract = _contract("""
pragma solidity 0.8.20;
contract Counter {
    uint256 public total;
    function bump() external { unchecked { total += 1; } }
}
""")
    func = next(f for f in contract.functions if f.name == "bump")
    model = interpret(func, "owner")
    assert not model.unmodelled
    assert any(effect.kind == "add" and effect.target == "total"
               for effect in model.effects)


def test_assert_is_a_guard_like_require():
    contract = _contract("""
pragma solidity 0.8.20;
contract Counter {
    uint256 public total;
    function reset() external { assert(total < 10); total = 0; }
}
""")
    func = next(f for f in contract.functions if f.name == "reset")
    model = interpret(func, "owner")
    assert not model.unmodelled
    assert model.guard_text
    assert any(effect.kind == "assign" and effect.target == "total"
               for effect in model.effects)


# --------------------------------------------------------------------------- #
# Function-local scalars are per-call values, not contract slots
# --------------------------------------------------------------------------- #

LOCAL_VARIABLES = """
pragma solidity 0.8.20;
contract Counter {
    uint256 public total;

    function bump(uint256 amount) external {
        uint256 before = total;
        total = before + amount;
    }

    function reset() external {
        uint256 zero;
        total = zero;
    }
}
"""


def test_a_local_scalar_is_modelled_without_becoming_contract_state():
    target, report = synthesize(_contract(LOCAL_VARIABLES))
    assert "bump" in report.modelled_ops
    assert "reset" in report.modelled_ops
    assert not report.unmodelled_ops

    state = target.reset()
    assert target.step(state, "bump", "attacker", {"amount": 3})
    assert state["total"] == 3
    assert "before" not in state

    assert target.step(state, "reset", "attacker", {})
    assert state["total"] == 0
    assert "zero" not in state


EARLY_RETURN = """
pragma solidity 0.8.20;
contract Early {
    uint256 public x;
    function maybe(bool stop) external {
        if (stop) return;
        x = 1;
    }
}
"""


def test_an_early_return_stops_the_writes_after_it():
    target, report = synthesize(_contract(EARLY_RETURN))
    assert "maybe" in report.modelled_ops
    state = target.reset()
    assert target.step(state, "maybe", "attacker", {"stop": True})
    assert state["x"] == 0
    assert target.step(state, "maybe", "attacker", {"stop": False})
    assert state["x"] == 1


DIRECT_REVERT = """
pragma solidity 0.8.20;
contract DirectRevert {
    uint256 public x;
    function maybe(bool stop) external {
        if (stop) revert();
        x = 1;
    }
}
"""


def test_a_direct_revert_stops_the_path_instead_of_becoming_unmodelled():
    target, report = synthesize(_contract(DIRECT_REVERT))
    assert "maybe" in report.modelled_ops
    state = target.reset()
    assert not target.step(state, "maybe", "attacker", {"stop": True})
    assert state["x"] == 0
    assert target.step(state, "maybe", "attacker", {"stop": False})
    assert state["x"] == 1
