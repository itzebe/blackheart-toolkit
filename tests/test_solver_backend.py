"""An external SMT backend may accelerate SAT, never weaken the honesty rules."""

from __future__ import annotations

from blackheart.symbolic.expr import Var, gt
from blackheart.symbolic.solver import SolveResult, solve


def _constraint():
    return [gt(Var("x"), 10)]


def test_a_backend_sat_is_reverified_before_it_is_believed():
    def lying(constraints, domains):
        return SolveResult("SAT", assignment={"x": 5}, reason="made up")

    result = solve(_constraint(), {"x": (0, 100)}, backend=lying)
    assert result.sat
    assert result.assignment["x"] > 10
    assert not result.reason.startswith("external backend")


def test_a_valid_backend_sat_is_accepted():
    def honest(constraints, domains):
        return SolveResult("SAT", assignment={"x": 42}, reason="z3")

    result = solve(_constraint(), {"x": (0, 100)}, backend=honest)
    assert result.sat
    assert result.assignment == {"x": 42}
    assert result.reason.startswith("external backend")


def test_a_backend_unsat_is_ignored_unless_explicitly_trusted():
    def unsat(constraints, domains):
        return SolveResult("UNSAT", reason="z3")

    default = solve(_constraint(), {"x": (0, 100)}, backend=unsat)
    assert default.sat

    trusted = solve(_constraint(), {"x": (0, 100)}, backend=unsat,
                    trust_backend_unsat=True)
    assert trusted.status == "UNSAT"


def test_a_failing_backend_falls_back_to_the_built_in_solver():
    def broken(constraints, domains):
        raise RuntimeError("no solver here")

    result = solve(_constraint(), {"x": (0, 100)}, backend=broken)
    assert result.sat
    assert result.assignment["x"] > 10
