"""Optional SMT discharge for the symbolic path conditions.

The built-in solver is deliberately bounded: it finds a witness by ladder search
and proves UNSAT only by interval/linear reasoning. This module adds the optional
next step: translate the same expression fragment to Z3 when it is installed.

Z3 is never a dependency. When it is absent the answer is ``UNKNOWN`` with a
reason, never a false "safe". A Z3 ``SAT`` is re-evaluated by
:func:`blackheart.symbolic.solver.solve` against every constraint and domain; a
Z3 ``UNSAT`` is accepted only because the translation adds the declared finite
domains, so it is a proof over exactly the same bounded problem.
"""

from __future__ import annotations

import contextlib
import contextvars
from typing import Any, Iterable, Optional

from .expr import Bin, Const, Expr, Index, Neg, Not, Var
from .solver import SolveResult, solve

try:  # optional, never a runtime dependency
    import z3  # type: ignore
except Exception:  # noqa: BLE001 -- absent or broken installation
    z3 = None  # type: ignore


def smt_available() -> bool:
    return z3 is not None


def smt_version() -> str:
    if z3 is None:
        return ""
    try:
        return str(z3.get_version_string())
    except Exception:  # noqa: BLE001
        return "unknown"


def _int(value: Any) -> Any:
    if isinstance(value, bool):
        return z3.IntVal(1 if value else 0)
    if isinstance(value, int):
        return z3.IntVal(value)
    raise ValueError(f"unsupported SMT constant {value!r}")


def _as_bool(expr: Any) -> Any:
    if z3.is_bool(expr):
        return expr
    return expr != 0


def _translate(expr: Expr) -> Any:
    if isinstance(expr, Const):
        if isinstance(expr.value, (int, bool)):
            return _int(expr.value)
        raise ValueError(f"unsupported SMT constant {expr.value!r}")
    if isinstance(expr, Var):
        return z3.Int(expr.name)
    if isinstance(expr, Index):
        raise ValueError("symbolic mapping indices are not translated to SMT")
    if isinstance(expr, Neg):
        return -_translate(expr.operand)
    if isinstance(expr, Not):
        return z3.Not(_as_bool(_translate(expr.operand)))
    if isinstance(expr, Bin):
        left = _translate(expr.left)
        right = _translate(expr.right)
        op = expr.op
        if op == "&&":
            return z3.And(_as_bool(left), _as_bool(right))
        if op == "||":
            return z3.Or(_as_bool(left), _as_bool(right))
        if op in ("==", "!=", "<", "<=", ">", ">="):
            return {"==": left == right, "!=": left != right, "<": left < right,
                    "<=": left <= right, ">": left > right,
                    ">=": left >= right}[op]
        if op == "+":
            return left + right
        if op == "-":
            return left - right
        if op == "*":
            return left * right
        if op in ("/", "%"):
            # Solidity reverts on a zero divisor. Only translate when the
            # divisor is a known non-zero constant; otherwise this path is not
            # in the SMT fragment and stays UNKNOWN.
            if isinstance(expr.right, Const) and expr.right.value:
                return left / right if op == "/" else left % right
            raise ValueError("symbolic division/modulo is outside the SMT fragment")
    raise ValueError(f"unsupported SMT expression {expr!r}")


def z3_backend(constraints: Iterable[Expr], domains: dict[str, tuple[int, int]],
               *, timeout_ms: int = 5_000) -> Optional[SolveResult]:
    """Decide the conjunction with Z3, or return ``None`` when out of fragment."""
    if z3 is None:
        return None
    try:
        translated = [_as_bool(_translate(c)) for c in constraints]
    except (ValueError, TypeError, AttributeError):
        return None
    solver = z3.Solver()
    solver.set("timeout", timeout_ms)
    names = sorted({name for name in domains})
    variables = {name: z3.Int(name) for name in names}
    for name in names:
        lo, hi = domains[name]
        solver.add(variables[name] >= int(lo), variables[name] <= int(hi))
    if translated:
        solver.add(z3.And(*translated))
    result = solver.check()
    if result == z3.sat:
        model = solver.model()
        assignment: dict[str, int] = {}
        for name, variable in variables.items():
            value = model.eval(variable, model_completion=True)
            try:
                assignment[name] = int(value.as_long())
            except Exception:  # noqa: BLE001
                return None
        return SolveResult("SAT", assignment=assignment,
                           reason=f"z3 {smt_version()} model over the declared domains")
    if result == z3.unsat:
        return SolveResult("UNSAT", reason=f"z3 {smt_version()} proved UNSAT")
    return SolveResult("UNKNOWN", reason=f"z3 {smt_version()} returned unknown")


def solve_with_smt(constraints: Iterable[Expr], domains: dict[str, tuple[int, int]],
                   **kwargs: Any) -> SolveResult:
    """Solve with Z3 when present, otherwise report why SMT was not used."""
    if z3 is None:
        return SolveResult("UNKNOWN", reason="z3 is not installed; SMT backend unavailable")
    return solve(constraints, domains, backend=z3_backend,
                 trust_backend_unsat=True, **kwargs)


_SMT_ENABLED: contextvars.ContextVar[bool] = contextvars.ContextVar(
    "blackheart_symbolic_smt", default=False)


@contextlib.contextmanager
def use_smt(enabled: bool = True):
    """Enable the optional SMT backend for the enclosed symbolic run."""
    token = _SMT_ENABLED.set(bool(enabled))
    try:
        yield
    finally:
        _SMT_ENABLED.reset(token)


def current_backend():
    return z3_backend if _SMT_ENABLED.get() and z3 is not None else None


def current_trust_unsat() -> bool:
    return bool(_SMT_ENABLED.get() and z3 is not None)


__all__ = [
    "smt_available", "smt_version", "z3_backend", "solve_with_smt",
    "use_smt", "current_backend", "current_trust_unsat",
]
