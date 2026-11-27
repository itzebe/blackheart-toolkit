"""The SMT seam must be optional and never turn absence into a false negative."""

from __future__ import annotations

from blackheart.symbolic import Var, gt, le
from blackheart.symbolic.smt import smt_available, solve_with_smt, use_smt
from blackheart.symbolic.solver import solve


def test_smt_unavailable_is_unknown_with_a_reason():
    if smt_available():
        return
    result = solve_with_smt([gt(Var("x"), 750), le(Var("x"), 800)],
                            {"x": (0, 1000)})
    assert result.status == "UNKNOWN"
    assert "z3" in result.reason


def test_smt_never_returns_unsat_for_a_satisfiable_problem():
    result = solve_with_smt([gt(Var("x"), 750), le(Var("x"), 800)],
                            {"x": (0, 1000)})
    assert result.status in {"SAT", "UNKNOWN"}
    if result.status == "SAT":
        assert 750 < result.assignment["x"] <= 800


def test_context_manager_does_not_change_the_default_solver():
    with use_smt(True):
        result = solve([gt(Var("x"), 750), le(Var("x"), 800)], {"x": (0, 1000)})
    assert result.status in {"SAT", "UNKNOWN"}


def test_z3_proves_a_non_linear_unsat_when_installed():
    if not smt_available():
        return
    from blackheart.symbolic import Bin, Const, eq

    result = solve_with_smt([eq(Bin("*", Var("x"), Var("x")), Const(3))],
                            {"x": (0, 10)})
    assert result.status == "UNSAT"
