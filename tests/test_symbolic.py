"""The symbolic layer must solve what it can and say UNKNOWN when it cannot.

These tests pin the three-valued contract: SAT only with a verified witness, UNSAT
only when interval propagation empties a domain, UNKNOWN otherwise. They also pin
that the executor finds a numeric-window violation symbolically and clears the
guarded twin.
"""

from __future__ import annotations

from blackheart.ingest.synthesize import OpModel, _Effect
from blackheart.symbolic import (
    Bin,
    Const,
    Index,
    SymOp,
    Var,
    concretize_indices,
    eq,
    eval_expr,
    execute,
    from_op_models,
    ge,
    gt,
    implies,
    le,
    lt,
    reachable_operations,
    solve,
    subst,
)


def test_solver_finds_a_value_inside_a_window():
    result = solve([gt(Var("x"), 750), le(Var("x"), 800)], {"x": (0, 1000)})
    assert result.status == "SAT"
    assert 750 < result.assignment["x"] <= 800


def test_solver_proves_an_empty_interval_unsat():
    result = solve([gt(Var("x"), 1000), lt(Var("x"), 0)], {"x": (0, 1000)})
    assert result.status == "UNSAT"


def test_solver_returns_unknown_for_a_non_linear_unsatisfiable_claim():
    result = solve([eq(Bin("*", Var("x"), Var("x")), Const(3))], {"x": (0, 100)})
    assert result.status == "UNKNOWN"


def test_solver_finds_a_non_linear_witness_by_enumeration():
    result = solve([eq(Bin("*", Var("x"), Var("x")), Const(4))], {"x": (0, 100)})
    assert result.status == "SAT"
    assert result.assignment["x"] == 2


def _borrow_op():
    return OpModel(
        name="borrow",
        params=("amount",),
        guards=(("bin", "<=",
                 ("bin", "+", ("id", "debt"), ("id", "amount")), ("num", 800)),),
        effects=(_Effect("add", "debt", None, ("id", "amount")),),
    )


def test_from_op_models_converts_the_ingest_ir():
    ops, unsupported = from_op_models([_borrow_op()])
    assert unsupported == []
    assert ops[0].name == "borrow"
    assert ops[0].effects[0][0] == "add"


def _vulnerable_ops():
    return [
        from_op_models([_borrow_op()])[0][0],
        # liquidate fires at the borrow LTV (750) instead of the threshold (800)
        SymOp(name="liquidate", guards=(gt(Var("debt"), 750),),
              effects=(("add", "seized", Const(100)),)),
    ]


def _patched_ops():
    return [
        from_op_models([_borrow_op()])[0][0],
        SymOp(name="liquidate", guards=(gt(Var("debt"), 800),),
              effects=(("add", "seized", Const(100)),)),
    ]


INVARIANT = implies(gt(Var("seized"), 0), gt(Var("debt"), 800))


def test_executor_finds_the_numeric_window_symbolically():
    result = execute(_vulnerable_ops(), invariant=INVARIANT,
                     domains={"amount": (0, 1000)}, max_depth=2)
    assert result.violations, "the symbolic executor must reach the window"
    witness = result.violations[0].assignment
    assert 750 < witness.get("amount", 0) <= 800


def test_executor_clears_the_guarded_twin():
    result = execute(_patched_ops(), invariant=INVARIANT,
                     domains={"amount": (0, 1000)}, max_depth=2)
    assert result.violations == []
    assert result.exhausted


# --------------------------------------------------------------------------- #
# Mapping reads and writes: the balance-mapping shape
# --------------------------------------------------------------------------- #

def test_mapping_write_is_modelled_and_a_bad_withdraw_is_found():
    deposit = SymOp("deposit", effects=(("add", "balances", Var("amount"), Var("sender")),),
                    params=("amount",))
    withdraw = SymOp("withdraw",
                     effects=(("sub", "balances", Var("withdraw_amount"), Var("sender")),),
                     params=("withdraw_amount",))
    invariant = ge(Var("balances[attacker]"), 0)
    result = execute([deposit, withdraw], invariant=invariant,
                     domains={"amount": (0, 10), "withdraw_amount": (0, 10)},
                     max_depth=2)
    assert result.violations, "a mapping write must be symbolically executable"
    sequence = result.violations[0].sequence
    assert any("deposit" in step for step in sequence)
    assert any("withdraw" in step for step in sequence)


def test_symbolic_mapping_key_is_reported_unsupported_not_applied():
    op = SymOp("write", effects=(("assign", "balances", Const(1), Var("who")),),
               params=("who",))
    result = execute([op], invariant=ge(Var("balances[attacker]"), 0),
                     domains={}, max_depth=1)
    assert result.violations == []
    assert any("symbolic mapping key" in note for note in result.unsupported)


def test_index_concretizes_to_a_state_variable():
    expr = Index("balances", Var("sender"))
    resolved = concretize_indices(subst(expr, {"sender": Const("attacker")}))
    assert resolved == Var("balances[attacker]")
    assert eval_expr(resolved, {"balances[attacker]": 7}) == 7


def test_from_op_models_keeps_a_mapping_write():
    op = OpModel(
        name="deposit",
        params=("amount",),
        effects=(_Effect("add", "balances", ("sender",), ("id", "amount")),),
    )
    ops, unsupported = from_op_models([op])
    assert unsupported == []
    assert len(ops[0].effects[0]) == 4
    assert ops[0].effects[0][3] == Var("sender")
    assert ops[0].params == ("amount",)


# --------------------------------------------------------------------------- #
# Symbolic reachability
# --------------------------------------------------------------------------- #

def test_reachability_finds_a_guarded_operation_after_an_unguarded_owner_take():
    set_owner = SymOp("setOwner", effects=(("assign", "owner", Var("sender")),))
    mint = SymOp("mint", guards=(eq(Var("sender"), Var("owner")),),
                 effects=(("add", "total", Const(1)),))
    result = reachable_operations([mint, set_owner], domains={}, max_depth=2)
    assert "setOwner" in result.reachable
    assert "mint" in result.reachable
    assert result.reachable["mint"]["sequence"] == ["setOwner(attacker)", "mint(attacker)"]


def test_reachability_does_not_claim_an_unknown_guard():
    mint = SymOp("mint", guards=(eq(Var("sender"), Var("owner")),))
    result = reachable_operations([mint], domains={}, max_depth=1)
    assert "mint" not in result.reachable
    assert result.unknown >= 1


def test_reachability_expands_a_finite_identity_domain():
    set_owner = SymOp("setOwner", effects=(("assign", "owner", Var("who")),),
                      params=("who",))
    mint = SymOp("mint", guards=(eq(Var("sender"), Var("owner")),))
    result = reachable_operations([mint, set_owner], domains={},
                                  values={"who": ("attacker", "victim")}, max_depth=2)
    assert "mint" in result.reachable
    assert result.reachable["mint"]["sequence"][0].startswith("setOwner")


# --------------------------------------------------------------------------- #
# Path-sensitive conditional effects
# --------------------------------------------------------------------------- #

def test_from_op_models_keeps_a_conditional_effect():
    op = OpModel(
        name="branch",
        params=("x",),
        effects=(_Effect("add", "total", None, ("num", 10),
                         ("bin", ">", ("id", "x"), ("num", 5))),),
    )
    ops, unsupported = from_op_models([op])
    assert unsupported == []
    assert len(ops[0].effects[0]) == 5
    assert ops[0].effects[0][4] is not None


def test_executor_splits_on_a_conditional_effect():
    vulnerable = OpModel(
        name="branch",
        params=("x",),
        effects=(_Effect("add", "total", None, ("num", 10),
                         ("bin", ">", ("id", "x"), ("num", 5))),),
    )
    patched = OpModel(
        name="branch",
        params=("x",),
        effects=(_Effect("add", "total", None, ("num", 10),
                         ("bin", ">", ("id", "x"), ("num", 100))),),
    )
    invariant = eq(Var("total"), Const(0))
    bad = execute(from_op_models([vulnerable])[0], invariant=invariant,
                  domains={"x": (0, 10)}, max_depth=1)
    assert bad.violations
    assert bad.violations[0].assignment["x"] > 5
    clean = execute(from_op_models([patched])[0], invariant=invariant,
                    domains={"x": (0, 10)}, max_depth=1)
    assert clean.violations == []
    assert clean.exhausted


def test_conditional_require_reverts_only_its_branch():
    op = SymOp(
        name="guarded",
        effects=(
            ("assign", "x", Const(9), None, gt(Var("a"), 0)),
            ("require", "", lt(Var("a"), Const(5)), None, gt(Var("a"), 0)),
        ),
        params=("a",),
    )
    # a=6 takes the branch, writes x=9, then fails its require: no path survives.
    bad = execute([op], invariant=eq(Var("x"), Const(0)),
                  domains={"a": (0, 10)}, max_depth=1)
    assert all(v.assignment.get("a", 0) <= 5 for v in bad.violations)
    # a in 1..4 takes the branch and satisfies the require; x=9 is a violation.
    assert any(0 < v.assignment.get("a", 0) < 5 for v in bad.violations)


def test_struct_fields_and_array_push_are_symbolically_executable():
    from blackheart.ingest.solidity import scan_source
    from blackheart.ingest.synthesize import synthesize

    source = """
    contract Shapes {
        struct Acct { uint256 bal; uint256 debt; }
        Acct public acct;
        uint256[] public arr;
        function bump(uint256 a) external { acct.bal += a; arr.push(a); }
        function capped(uint256 a) external { require(arr.length < 2); arr.push(a); }
    }
    """
    contracts = {c.name: c for c in scan_source(source, "Shapes.sol")}
    target, _ = synthesize(contracts["Shapes"], registry=contracts)
    ops, unsupported = from_op_models(target.op_models())
    assert unsupported == []
    state = {"acct.bal": Const(0), "arr.__len__": Const(0)}
    result = execute(ops, invariant=eq(Var("acct.bal"), Const(0)),
                     domains={"a": (0, 5)}, max_depth=1)
    assert result.violations
    assert any(op.name == "capped" for op in ops)


def test_external_calls_are_reported_unsupported_instead_of_silently_skipped():
    from blackheart.ingest.solidity import scan_source
    from blackheart.ingest.synthesize import synthesize

    source = """
    contract Token { function mint(uint256 a) external { } }
    contract Vault {
        Token public token;
        function deposit(uint256 a) external { token.mint(a); }
    }
    """
    contracts = {c.name: c for c in scan_source(source, "Calls.sol")}
    target, _ = synthesize(contracts["Vault"], registry=contracts)
    ops, unsupported = from_op_models(target.op_models())
    assert any("external call" in reason for reason in unsupported)
    assert all(op.name != "deposit" for op in ops)
