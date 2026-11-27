"""Bounded symbolic execution over the ingest statement IR.

This is not a bytecode-level symbolic executor and does not claim to be: Halmos
remains the external engine for real EVM bytecode. It is a symbolic layer over the
same declarative model :mod:`blackheart.ingest.synthesize` already builds --
scalar assignments, ``+=``/``-=``, mapping reads and writes, and
``require``/``if-revert`` guards -- so a numeric window that concrete enumeration
misses can be *solved* rather than sampled, and reachability can be asked per
operation.

Three-valued throughout: a constraint is ``SAT`` only with a verified concrete
witness, ``UNSAT`` only when interval propagation empties a domain, and
``UNKNOWN`` otherwise. An ``UNKNOWN`` is never rendered as safe.
"""

from .expr import (
    Bin,
    Const,
    Expr,
    Index,
    Neg,
    Not,
    Var,
    and_,
    concretize_indices,
    eq,
    eval_expr,
    free_vars,
    ge,
    gt,
    implies,
    le,
    lt,
    ne,
    not_,
    or_,
    subst,
)
from .executor import (
    ReachabilityResult,
    SymOp,
    SymbolicResult,
    Violation,
    execute,
    from_op_models,
    reachable_operations,
)
from .solver import SolveResult, solve

__all__ = [
    "Expr", "Const", "Var", "Bin", "Not", "Neg", "Index",
    "eval_expr", "subst", "free_vars", "concretize_indices",
    "and_", "or_", "not_", "implies",
    "eq", "ne", "lt", "le", "gt", "ge",
    "SolveResult", "solve",
    "SymOp", "SymbolicResult", "ReachabilityResult", "Violation",
    "execute", "from_op_models", "reachable_operations",
]
