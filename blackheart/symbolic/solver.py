"""A bounded integer constraint solver: interval propagation plus a verified witness.

It is deliberately not a general SMT solver. It decides a useful fragment -- a
conjunction of comparisons over integer variables with finite domains -- soundly:

* ``UNSAT`` only when interval propagation empties a domain (sound for this
  fragment);
* ``SAT`` only with a concrete assignment that re-evaluates every constraint;
* ``UNKNOWN`` otherwise, never "safe".

That is enough to target a numeric window (``x > 750 and x <= 800``) without
enumerating the whole domain, and it refuses to guess when it cannot decide.
"""

from __future__ import annotations

import itertools
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Optional

from .expr import Bin, Const, Expr, Index, Neg, Not, Var, eval_expr
from .linear import linear_unsat

INF = float("inf")

#: The fragment this solver understands; anything else falls back to UNKNOWN.
_FLIP = {"<": ">", "<=": ">=", ">": "<", ">=": "<=", "==": "==", "!=": "!="}
_NEGATE = {"<": ">=", "<=": ">", ">": "<=", ">=": "<", "==": "!=", "!=": "=="}


@dataclass
class SolveResult:
    status: str  # "SAT" | "UNSAT" | "UNKNOWN"
    assignment: dict[str, int] = field(default_factory=dict)
    reason: str = ""

    @property
    def sat(self) -> bool:
        return self.status == "SAT"

    def to_dict(self) -> dict:
        return {"status": self.status, "assignment": dict(self.assignment),
                "reason": self.reason}


def _truth_interval(value: tuple[float, float]) -> tuple[float, float]:
    lo, hi = value
    if lo == hi:
        b = 1.0 if lo else 0.0
        return (b, b)
    return (0.0, 1.0)


def interval(expr: Expr, bounds: dict[str, tuple[float, float]]) -> tuple[float, float]:
    """A sound over-approximation of ``expr``'s value over ``bounds``."""
    if isinstance(expr, Const):
        v = expr.value
        return (float(v), float(v)) if isinstance(v, (int, bool)) else (-INF, INF)
    if isinstance(expr, Var):
        return bounds.get(expr.name, (-INF, INF))
    if isinstance(expr, Index):
        return (-INF, INF)
    if isinstance(expr, Neg):
        lo, hi = interval(expr.operand, bounds)
        return (-hi, -lo)
    if isinstance(expr, Not):
        lo, hi = _truth_interval(interval(expr.operand, bounds))
        return (1 - hi, 1 - lo)
    if isinstance(expr, Bin):
        op = expr.op
        if op in ("&&", "||"):
            a = _truth_interval(interval(expr.left, bounds))
            b = _truth_interval(interval(expr.right, bounds))
            if op == "&&":
                return (min(a[0], b[0]), min(a[1], b[1]))
            return (max(a[0], b[0]), max(a[1], b[1]))
        if op in ("==", "!=", "<", "<=", ">", ">="):
            a = interval(expr.left, bounds)
            b = interval(expr.right, bounds)
            if a[0] == a[1] and b[0] == b[1]:
                return _truth_interval((1.0 if _compare(op, a[0], b[0]) else 0.0,) * 2)
            if a[1] < b[0]:
                return _truth_interval((1.0 if op in ("<", "<=", "!=") else 0.0,) * 2)
            if a[0] > b[1]:
                return _truth_interval((1.0 if op in (">", ">=", "!=") else 0.0,) * 2)
            return (0.0, 1.0)
        a = interval(expr.left, bounds)
        b = interval(expr.right, bounds)
        if op == "+":
            return (a[0] + b[0], a[1] + b[1])
        if op == "-":
            return (a[0] - b[1], a[1] - b[0])
        if op == "*":
            if -INF < a[0] and a[1] < INF and -INF < b[0] and b[1] < INF:
                products = (a[0] * b[0], a[0] * b[1], a[1] * b[0], a[1] * b[1])
                return (min(products), max(products))
            return (-INF, INF)
        if op in ("/", "%"):
            if b[0] <= 0 <= b[1]:
                return (-INF, INF)
            if op == "/" and -INF < a[0] and a[1] < INF and -INF < b[0] and b[1] < INF:
                qs = (a[0] / b[0], a[0] / b[1], a[1] / b[0], a[1] / b[1])
                return (min(qs), max(qs))
            return (-INF, INF)
        if op in ("&", "|", "^"):
            if a[0] >= 0 and b[0] >= 0 and -INF < a[1] and a[1] < INF \
                    and -INF < b[1] and b[1] < INF:
                if op == "&":
                    return (0, min(a[1], b[1]))
                if a[1] == 0 or b[1] == 0:
                    return (0, max(a[1], b[1]))
                width = max(int(a[1]).bit_length(), int(b[1]).bit_length())
                return (0, (1 << width) - 1)
            return (-INF, INF)
    return (-INF, INF)


def _compare(op: str, a: float, b: float) -> bool:
    return {"==": a == b, "!=": a != b, "<": a < b, "<=": a <= b,
            ">": a > b, ">=": a >= b}[op]


def _linear(expr: Expr) -> Optional[tuple[str, int, int]]:
    """``(var, offset, sign)`` for ``Var`` or ``Var ± Const``; else ``None``."""
    if isinstance(expr, Var):
        return expr.name, 0, 1
    if isinstance(expr, Bin) and expr.op in ("+", "-"):
        if isinstance(expr.left, Var) and isinstance(expr.right, Const) \
                and isinstance(expr.right.value, int):
            k = expr.right.value if expr.op == "+" else -expr.right.value
            return expr.left.name, k, 1
        if expr.op == "+" and isinstance(expr.left, Const) and isinstance(expr.right, Var) \
                and isinstance(expr.left.value, int):
            return expr.right.name, expr.left.value, 1
    if isinstance(expr, Neg) and isinstance(expr.operand, Var):
        return expr.operand.name, 0, -1
    return None


def _const_value(expr: Expr, bounds: dict[str, tuple[float, float]]) -> Optional[float]:
    if isinstance(expr, Const) and isinstance(expr.value, (int, bool)):
        return float(expr.value)
    if isinstance(expr, Var) and expr.name in bounds and bounds[expr.name][0] == bounds[expr.name][1]:
        return bounds[expr.name][0]
    return None


def _apply(name: str, op: str, bound: float, bounds: dict[str, tuple[float, float]]) -> bool:
    lo, hi = bounds[name]
    if op == "<":
        hi = min(hi, bound - 1)
    elif op == "<=":
        hi = min(hi, bound)
    elif op == ">":
        lo = max(lo, bound + 1)
    elif op == ">=":
        lo = max(lo, bound)
    elif op == "==":
        lo = max(lo, bound)
        hi = min(hi, bound)
    elif op == "!=":
        if lo == hi == bound:
            return False
        if lo == bound:
            lo += 1
        elif hi == bound:
            hi -= 1
    bounds[name] = (lo, hi)
    return lo <= hi


def _tighten(expr: Expr, bounds: dict[str, tuple[float, float]]) -> bool:
    """Tighten bounds in place; return False on a proven contradiction."""
    if isinstance(expr, Bin) and expr.op == "&&":
        return _tighten(expr.left, bounds) and _tighten(expr.right, bounds)
    if isinstance(expr, Not) and isinstance(expr.operand, Bin) \
            and expr.operand.op in _NEGATE:
        return _tighten(Bin(_NEGATE[expr.operand.op], expr.operand.left,
                            expr.operand.right), bounds)
    if not isinstance(expr, Bin) or expr.op not in _FLIP:
        return True
    left, right = _linear(expr.left), _linear(expr.right)
    if left is not None and right is None:
        constant = _const_value(expr.right, bounds)
        if constant is None:
            return True
        name, offset, sign = left
        if sign == -1:
            constant = -constant
        return _apply(name, expr.op, constant - offset, bounds)
    if right is not None and left is None:
        constant = _const_value(expr.left, bounds)
        if constant is None:
            return True
        name, offset, sign = right
        if sign == -1:
            constant = -constant
        return _apply(name, _FLIP[expr.op], constant - offset, bounds)
    if left is not None and right is not None:
        lv, lo, ls = left
        rv, ro, rs = right
        if ls == 1 and rs == 1:
            # x - y <= k is not a single-variable bound; leave it to the witness search.
            return True
    return True


def _ladder(lo: int, hi: int) -> list[int]:
    if lo > hi:
        return []
    span = hi - lo
    values = {lo, hi, lo + span // 2, lo + 1, hi - 1}
    for d in (2, 3, 4, 5, 8, 10):
        values.add(lo + span // d)
        values.add(hi - span // d)
    p = 1
    while p <= hi:
        values.add(p)
        p *= 2
    return sorted(v for v in values if lo <= v <= hi)


def _satisfies(exprs: Iterable[Expr], env: dict[str, Any]) -> bool:
    try:
        return all(bool(eval_expr(e, env)) for e in exprs)
    except (ZeroDivisionError, KeyError, ValueError):
        return False


def solve(
    constraints: Iterable[Expr],
    domains: dict[str, tuple[int, int]],
    *,
    max_candidates: int = 4096,
    backend: Optional[Callable[..., SolveResult]] = None,
    trust_backend_unsat: bool = False,
) -> SolveResult:
    """Decide a conjunction over bounded integer variables, three-valued.

    ``backend`` is the SMT seam: an external solver may be injected. Its ``SAT``
    is never trusted on its own -- the assignment is re-evaluated against every
    constraint and the declared domain, and a bad witness is ignored. Its
    ``UNSAT`` is ignored unless ``trust_backend_unsat=True``, because this module's
    contract is that ``UNSAT`` is only reported when the built-in interval analysis
    proves it. A future proof-carrying SMT can set the flag.
    """
    constraints = list(constraints)
    if backend is not None:
        try:
            proposal = backend(constraints, domains)
        except Exception:  # noqa: BLE001 -- a backend failure falls back to the built-in
            proposal = None
        if proposal is not None and proposal.status == "SAT":
            assignment = dict(proposal.assignment or {})
            in_domain = all(domains[n][0] <= v <= domains[n][1]
                            for n, v in assignment.items() if n in domains)
            if in_domain and _satisfies(constraints, assignment):
                return SolveResult("SAT", assignment=assignment,
                                   reason="external backend: " + (proposal.reason or "verified witness"))
        elif proposal is not None and proposal.status == "UNSAT" and trust_backend_unsat:
            return SolveResult("UNSAT",
                               reason="external backend: " + (proposal.reason or "unsat"))
    bounds: dict[str, tuple[float, float]] = {
        name: (float(lo), float(hi)) for name, (lo, hi) in domains.items()
    }
    for _ in range(max(1, len(domains) + 1)):
        before = dict(bounds)
        for constraint in constraints:
            if not _tighten(constraint, bounds):
                return SolveResult("UNSAT", reason="interval propagation emptied a domain")
        if bounds == before:
            break

    for name, (lo, hi) in bounds.items():
        if lo > hi:
            return SolveResult("UNSAT", reason=f"no value for {name!r} satisfies the constraints")

    try:
        proof = linear_unsat(constraints, domains)
    except Exception:  # noqa: BLE001 -- a malformed constraint must not hide the solver
        proof = None
    if proof is True:
        return SolveResult("UNSAT",
                           reason="linear feasibility: the system has no real solution")

    names = [n for n in bounds if n in {v.name for e in constraints for v in _vars(e)}]
    names = names or list(bounds)
    candidate_lists = [_ladder(int(bounds[n][0]), int(bounds[n][1])) for n in names]
    tried = 0
    for combo in itertools.product(*candidate_lists):
        tried += 1
        if tried > max_candidates:
            break
        env = dict(zip(names, combo))
        if _satisfies(constraints, env):
            return SolveResult("SAT", assignment=dict(env),
                               reason="a concrete assignment satisfies every constraint")

    # If interval analysis proved every constraint true, any in-bound point works.
    if all(interval(c, bounds)[0] >= 1 for c in constraints):
        env = {n: int((bounds[n][0] + bounds[n][1]) // 2) for n in names}
        if _satisfies(constraints, env):
            return SolveResult("SAT", assignment=env,
                               reason="every constraint was decided true by interval analysis")
    return SolveResult("UNKNOWN",
                       reason="interval propagation neither emptied a domain nor "
                              "found a verified witness within the candidate budget")


def _vars(expr: Expr) -> set[Var]:
    if isinstance(expr, Var):
        return {expr}
    if isinstance(expr, Bin):
        return _vars(expr.left) | _vars(expr.right)
    if isinstance(expr, (Not, Neg)):
        return _vars(expr.operand)
    return set()
