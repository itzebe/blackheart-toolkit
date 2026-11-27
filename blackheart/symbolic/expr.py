"""A small, immutable integer/boolean expression AST."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable


class Expr:
    """Base class. Expressions are immutable and hashable."""


@dataclass(frozen=True)
class Const(Expr):
    value: Any


@dataclass(frozen=True)
class Var(Expr):
    name: str


@dataclass(frozen=True)
class Bin(Expr):
    op: str
    left: Expr
    right: Expr


@dataclass(frozen=True)
class Not(Expr):
    operand: Expr


@dataclass(frozen=True)
class Neg(Expr):
    operand: Expr


@dataclass(frozen=True)
class Index(Expr):
    """A mapping read: ``base[index]``. ``base`` is the mapping's name."""

    base: str
    index: Expr


def _as_expr(value: Any) -> Expr:
    return value if isinstance(value, Expr) else Const(value)


def _bin(op: str, left: Any, right: Any) -> Expr:
    return Bin(op, _as_expr(left), _as_expr(right))


def eq(a, b) -> Expr: return _bin("==", a, b)
def ne(a, b) -> Expr: return _bin("!=", a, b)
def lt(a, b) -> Expr: return _bin("<", a, b)
def le(a, b) -> Expr: return _bin("<=", a, b)
def gt(a, b) -> Expr: return _bin(">", a, b)
def ge(a, b) -> Expr: return _bin(">=", a, b)
def and_(a, b) -> Expr: return _bin("&&", a, b)
def or_(a, b) -> Expr: return _bin("||", a, b)
def not_(a) -> Expr: return Not(_as_expr(a))
def implies(a, b) -> Expr: return or_(not_(a), b)


def free_vars(expr: Expr) -> set[str]:
    if isinstance(expr, Var):
        return {expr.name}
    if isinstance(expr, Bin):
        return free_vars(expr.left) | free_vars(expr.right)
    if isinstance(expr, (Not, Neg)):
        return free_vars(expr.operand)
    if isinstance(expr, Index):
        return {expr.base} | free_vars(expr.index)
    return set()


def subst(expr: Expr, env: dict[str, Expr]) -> Expr:
    """Replace free variables from ``env``, recursively."""
    if isinstance(expr, Var):
        return env.get(expr.name, expr)
    if isinstance(expr, Bin):
        return Bin(expr.op, subst(expr.left, env), subst(expr.right, env))
    if isinstance(expr, Not):
        return Not(subst(expr.operand, env))
    if isinstance(expr, Neg):
        return Neg(subst(expr.operand, env))
    if isinstance(expr, Index):
        return Index(expr.base, subst(expr.index, env))
    return expr


def concretize_indices(expr: Expr) -> Expr:
    """Turn a mapping read with a concrete key into a state variable.

    ``Index("balances", Const("attacker"))`` becomes ``Var("balances[attacker]")``
    so the state substitution and the solver treat it like any other variable. A
    symbolic key stays an ``Index`` and the caller must report it unsupported.
    """
    if isinstance(expr, Index):
        index = concretize_indices(expr.index)
        if isinstance(index, Const) and isinstance(index.value, (int, str)) \
                and not isinstance(index.value, bool):
            return Var(f"{expr.base}[{index.value}]")
        return Index(expr.base, index)
    if isinstance(expr, Bin):
        return Bin(expr.op, concretize_indices(expr.left), concretize_indices(expr.right))
    if isinstance(expr, Not):
        return Not(concretize_indices(expr.operand))
    if isinstance(expr, Neg):
        return Neg(concretize_indices(expr.operand))
    return expr


def eval_expr(expr: Expr, env: dict[str, Any]) -> Any:
    if isinstance(expr, Const):
        return expr.value
    if isinstance(expr, Var):
        if expr.name not in env:
            raise KeyError(f"unbound variable {expr.name!r}")
        return env[expr.name]
    if isinstance(expr, Not):
        return not eval_expr(expr.operand, env)
    if isinstance(expr, Neg):
        return -eval_expr(expr.operand, env)
    if isinstance(expr, Index):
        key = eval_expr(expr.index, env)
        name = f"{expr.base}[{key}]"
        if name not in env:
            raise KeyError(f"unbound mapping slot {name!r}")
        return env[name]
    if isinstance(expr, Bin):
        left = eval_expr(expr.left, env)
        right = eval_expr(expr.right, env)
        op = expr.op
        if op == "&&": return bool(left) and bool(right)
        if op == "||": return bool(left) or bool(right)
        if op == "==": return left == right
        if op == "!=": return left != right
        if op == "<": return left < right
        if op == "<=": return left <= right
        if op == ">": return left > right
        if op == ">=": return left >= right
        if op == "+": return left + right
        if op == "-": return left - right
        if op == "*": return left * right
        if op == "/":
            if right == 0:
                raise ZeroDivisionError("division by zero")
            return left // right
        if op == "%":
            if right == 0:
                raise ZeroDivisionError("modulo by zero")
            return left % right
        if op == "&": return left & right
        if op == "|": return left | right
        if op == "^": return left ^ right
    raise ValueError(f"cannot evaluate {expr!r}")


def evaluate_all(exprs: Iterable[Expr], env: dict[str, Any]) -> bool:
    return all(bool(eval_expr(e, env)) for e in exprs)
