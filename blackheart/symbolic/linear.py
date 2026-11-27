"""Exact linear feasibility: a real UNSAT proof, not a sample that found nothing.

The three-valued solver in :mod:`blackheart.symbolic.solver` tightens one-variable
intervals and then samples a ladder. That is sound for SAT (a witness is checked)
but cannot prove a *multi-variable* system unsatisfiable. This module adds the
missing direction: Fourier--Motzkin elimination over exact rationals.

A system that is infeasible over the reals is infeasible over the integers too, so
``UNSAT`` here is a proof for the integer problem. The converse is deliberately
not claimed: a real-feasible system may have no integer point, so this module only
answers ``True`` (proved UNSAT), ``False`` (feasible over the reals), or ``None``
(not a linear system, or the elimination grew past its cap). It never guesses.
"""

from __future__ import annotations

from fractions import Fraction
from typing import Optional

from .expr import Bin, Const, Expr, Neg, Not, Var

MAX_INEQUALITIES = 256


def _form(expr: Expr) -> Optional[tuple[dict[str, Fraction], Fraction]]:
    """``(coefficients, constant)`` for a linear expression, or ``None``."""
    if isinstance(expr, Const):
        if isinstance(expr.value, bool):
            return {}, Fraction(int(expr.value))
        if isinstance(expr.value, (int, float)):
            return {}, Fraction(expr.value)
        return None
    if isinstance(expr, Var):
        return {expr.name: Fraction(1)}, Fraction(0)
    if isinstance(expr, Neg):
        inner = _form(expr.operand)
        if inner is None:
            return None
        coeffs, const = inner
        return {name: -c for name, c in coeffs.items()}, -const
    if isinstance(expr, Bin):
        left, right = _form(expr.left), _form(expr.right)
        if left is None or right is None:
            return None
        lc, lk = left
        rc, rk = right
        if expr.op == "+":
            return _add(lc, rc), lk + rk
        if expr.op == "-":
            return _add(lc, {n: -c for n, c in rc.items()}), lk - rk
        if expr.op == "*":
            if not lc:
                return {n: c * lk for n, c in rc.items()}, rk * lk
            if not rc:
                return {n: c * rk for n, c in lc.items()}, lk * rk
            return None
        if expr.op == "/":
            if not rc and rk != 0:
                return {n: c / rk for n, c in lc.items()}, lk / rk
            return None
    return None


def _clean(coeffs: dict[str, Fraction]) -> dict[str, Fraction]:
    return {name: coeff for name, coeff in coeffs.items() if coeff}


def _add(left: dict[str, Fraction], right: dict[str, Fraction]) -> dict[str, Fraction]:
    out = dict(left)
    for name, coeff in right.items():
        out[name] = out.get(name, Fraction(0)) + coeff
    return {name: coeff for name, coeff in out.items() if coeff}


def _le(expr: Expr, bound: Fraction) -> Optional[list[tuple[dict[str, Fraction], Fraction]]]:
    """``expr <= bound`` as one inequality, or ``None`` when non-linear."""
    form = _form(expr)
    if form is None:
        return None
    coeffs, const = form
    return [(coeffs, bound - const)]


def _inequalities(expr: Expr) -> Optional[list[tuple[dict[str, Fraction], Fraction]]]:
    """All constraints as ``sum(coeff * var) <= constant``, or ``None``."""
    if isinstance(expr, Bin) and expr.op == "&&":
        left = _inequalities(expr.left)
        right = _inequalities(expr.right)
        if left is None or right is None:
            return None
        return left + right
    if isinstance(expr, Not):
        return _negated(expr.operand)
    if isinstance(expr, Bin) and expr.op in ("<", "<=", ">", ">=", "=="):
        left, right = _form(expr.left), _form(expr.right)
        if left is None or right is None:
            return None
        diff = Bin("-", expr.left, expr.right)
        if expr.op == "<":
            return _le(diff, Fraction(-1))
        if expr.op == "<=":
            return _le(diff, Fraction(0))
        if expr.op == ">":
            return _le(Neg(diff), Fraction(-1))
        if expr.op == ">=":
            return _le(Neg(diff), Fraction(0))
        first = _le(diff, Fraction(0))
        second = _le(Neg(diff), Fraction(0))
        if first is None or second is None:
            return None
        return first + second
    return None


def _negated(expr: Expr) -> Optional[list[tuple[dict[str, Fraction], Fraction]]]:
    """``not expr`` as inequalities; only a negated comparison is linear."""
    if isinstance(expr, Not):
        return _inequalities(expr.operand)
    if isinstance(expr, Bin):
        flip = {"<": ">=", "<=": ">", ">": "<=", ">=": "<"}
        if expr.op in flip:
            return _inequalities(Bin(flip[expr.op], expr.left, expr.right))
    return None


def _eliminate(
    inequalities: list[tuple[dict[str, Fraction], Fraction]],
    variables: list[str],
) -> Optional[list[tuple[dict[str, Fraction], Fraction]]]:
    for variable in variables:
        lower: list[tuple[dict[str, Fraction], Fraction]] = []
        upper: list[tuple[dict[str, Fraction], Fraction]] = []
        rest: list[tuple[dict[str, Fraction], Fraction]] = []
        for coeffs, bound in inequalities:
            coeff = coeffs.get(variable, Fraction(0))
            if coeff > 0:
                upper.append((coeffs, bound))
            elif coeff < 0:
                lower.append((coeffs, bound))
            else:
                rest.append((_clean(coeffs), bound))
        combined = list(rest)
        for lc, lk in lower:
            for uc, uk in upper:
                c_l = -lc[variable]      # > 0
                c_u = uc[variable]       # > 0
                coeffs: dict[str, Fraction] = {}
                for name, coeff in lc.items():
                    if name != variable:
                        coeffs[name] = coeffs.get(name, Fraction(0)) + coeff * c_u
                for name, coeff in uc.items():
                    if name != variable:
                        coeffs[name] = coeffs.get(name, Fraction(0)) + coeff * c_l
                bound = lk * c_u + uk * c_l
                combined.append((_clean(coeffs), bound))
        inequalities = combined
        if len(inequalities) > MAX_INEQUALITIES:
            return None
    return inequalities


def linear_unsat(
    constraints: list[Expr],
    domains: dict[str, tuple[int, int]],
) -> Optional[bool]:
    """``True`` proves the conjunction has no real solution; ``None`` is unknown."""
    inequalities: list[tuple[dict[str, Fraction], Fraction]] = []
    for constraint in constraints:
        parsed = _inequalities(constraint)
        if parsed is None:
            return None
        inequalities.extend(parsed)
    for name, (lo, hi) in domains.items():
        inequalities.append(({name: Fraction(1)}, Fraction(hi)))
        inequalities.append(({name: Fraction(-1)}, Fraction(-lo)))

    variables: list[str] = []
    for coeffs, _ in inequalities:
        for name in coeffs:
            if name not in variables:
                variables.append(name)
    reduced = _eliminate(inequalities, variables)
    if reduced is None:
        return None
    for coeffs, bound in reduced:
        if not coeffs and bound < 0:
            return True
    return False
