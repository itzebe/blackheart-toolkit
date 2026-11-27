"""The solver must prove multi-variable linear UNSAT, not just fail to sample."""

from __future__ import annotations

from blackheart.symbolic.expr import Bin, Const, Var, ge, le
from blackheart.symbolic.linear import linear_unsat
from blackheart.symbolic.solver import solve

X, Y, Z = Var("x"), Var("y"), Var("z")


def _add(a, b):
    return Bin("+", a, b)


def _sub(a, b):
    return Bin("-", a, b)


def test_a_two_variable_contradiction_is_proved_unsat():
    constraints = [le(_add(X, Y), 5), ge(_add(X, Y), 6)]
    assert linear_unsat(constraints, {"x": (0, 10), "y": (0, 10)}) is True
    result = solve(constraints, {"x": (0, 10), "y": (0, 10)})
    assert result.status == "UNSAT"
    assert "linear" in result.reason


def test_a_difference_contradiction_is_proved_unsat():
    constraints = [le(_sub(X, Y), 2), ge(_sub(X, Y), 3)]
    assert linear_unsat(constraints, {"x": (0, 10), "y": (0, 10)}) is True
    assert solve(constraints, {"x": (0, 10), "y": (0, 10)}).status == "UNSAT"


def test_three_variables_with_domain_floor_are_proved_unsat():
    domains = {"x": (0, 10), "y": (0, 10), "z": (0, 10)}
    constraints = [le(_add(_add(X, Y), Z), 2), ge(X, 1), ge(Y, 1), ge(Z, 1)]
    assert linear_unsat(constraints, domains) is True
    assert solve(constraints, domains).status == "UNSAT"


def test_a_feasible_system_is_not_called_unsat():
    constraints = [le(_add(X, Y), 5), ge(X, 0), ge(Y, 0)]
    assert linear_unsat(constraints, {"x": (0, 10), "y": (0, 10)}) is False
    result = solve(constraints, {"x": (0, 10), "y": (0, 10)})
    assert result.status == "SAT"


def test_a_non_linear_constraint_is_unknown_not_unsat():
    product = Bin("*", X, Y)
    assert linear_unsat([le(product, 5)], {"x": (0, 10), "y": (0, 10)}) is None


def test_a_negated_conjunction_is_not_claimed_unsat():
    from blackheart.symbolic.expr import Not, and_

    negated = Not(and_(le(X, 1), le(Y, 1)))
    assert linear_unsat([negated], {"x": (0, 10), "y": (0, 10)}) is None


def test_equality_is_two_inequalities():
    constraints = [Bin("==", X, Const(3)), le(X, 2)]
    assert linear_unsat(constraints, {"x": (0, 10)}) is True
