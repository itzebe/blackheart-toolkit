"""Bounded symbolic execution over declarative operations.

An operation is a list of guards and scalar effects. Execution explores both the
guard-taken and guard-failed branch, inlines the symbolic state into the guards
and the invariant, and asks :mod:`blackheart.symbolic.solver` whether a violation
is reachable. A path is pruned only when the solver proves it infeasible; an
``UNKNOWN`` is counted and kept, never treated as safe.

The converter :func:`from_op_models` reads the same ``OpModel`` the ingest
synthesiser builds, so the symbolic and concrete paths reason about one model.
Mapping reads and writes are modelled when their key is concrete under the
current actor and state; a symbolic key is reported as ``unsupported`` and the
operation is not half-applied.
"""

from __future__ import annotations

import itertools
from collections import deque
from dataclasses import dataclass, field, replace
from typing import Any, Iterable, Optional

from .expr import (
    Bin,
    Const,
    Expr,
    Index,
    Not,
    Var,
    and_,
    concretize_indices,
    eval_expr,
    free_vars,
    not_,
    subst,
)
from .solver import SolveResult, solve


@dataclass(frozen=True)
class SymOp:
    name: str
    guards: tuple[Expr, ...] = ()
    #: ``(kind, target, value)``, ``(kind, target, value, index)`` or
    #: ``(kind, target, value, index, condition)`` with kind in
    #: ``assign | add | sub | mul | div | mod | require``. A mapping write names
    #: its index expression; a condition makes the effect path-dependent.
    effects: tuple[tuple, ...] = ()
    actors: tuple[str, ...] = ("attacker", "victim")
    params: tuple[str, ...] = ()


class UnsupportedEffect(Exception):
    """The effect cannot be applied under the current state (e.g. a symbolic key)."""


@dataclass
class Violation:
    sequence: list[str]
    assignment: dict[str, int]
    reason: str

    def to_dict(self) -> dict:
        return {"sequence": list(self.sequence), "assignment": dict(self.assignment),
                "reason": self.reason}


@dataclass
class SymbolicResult:
    violations: list[Violation] = field(default_factory=list)
    paths: int = 0
    pruned: int = 0
    unknown: int = 0
    unsupported: list[str] = field(default_factory=list)
    exhausted: bool = True
    bound: dict = field(default_factory=dict)
    solver: str = "builtin"

    def to_dict(self) -> dict:
        return {
            "violations": [v.to_dict() for v in self.violations],
            "paths": self.paths, "pruned": self.pruned, "unknown": self.unknown,
            "unsupported": list(self.unsupported),
            "exhausted": self.exhausted, "bound": dict(self.bound),
            "solver": self.solver,
        }


@dataclass
class ReachabilityResult:
    """Which operations an unprivileged actor can reach, and with what input."""

    reachable: dict[str, dict] = field(default_factory=dict)
    paths: int = 0
    pruned: int = 0
    unknown: int = 0
    unsupported: list[str] = field(default_factory=list)
    exhausted: bool = True
    bound: dict = field(default_factory=dict)
    solver: str = "builtin"

    def to_dict(self) -> dict:
        return {
            "reachable": {name: dict(value) for name, value in sorted(self.reachable.items())},
            "paths": self.paths, "pruned": self.pruned, "unknown": self.unknown,
            "unsupported": list(self.unsupported),
            "exhausted": self.exhausted, "bound": dict(self.bound),
            "solver": self.solver,
        }


def _and_all(exprs: Iterable[Expr]) -> Expr:
    exprs = list(exprs)
    if not exprs:
        return Const(True)
    out = exprs[0]
    for e in exprs[1:]:
        out = and_(out, e)
    return out


def _decide(constraints: list[Expr], domains: dict[str, tuple[int, int]]) -> SolveResult:
    """Decide a constant conjunction exactly before asking the solver."""
    if not any(free_vars(c) for c in constraints):
        try:
            truth = all(bool(eval_expr(c, {})) for c in constraints)
        except (KeyError, ZeroDivisionError, ValueError):
            pass
        else:
            if truth:
                return SolveResult("SAT", reason="every constraint is constant true")
            return SolveResult("UNSAT", reason="a constant constraint is false")
    from .smt import current_backend, current_trust_unsat

    return solve(constraints, domains, backend=current_backend(),
                 trust_backend_unsat=current_trust_unsat())


def _resolve(expr: Expr, state: dict[str, Expr], actor: str) -> Expr:
    """Substitute the actor, then concretize a mapping read, then the state."""
    resolved = subst(expr, {"sender": Const(actor)})
    return subst(concretize_indices(resolved), state)


def _mapping_key(expr: Expr, state: dict[str, Expr], actor: str) -> int | str:
    key = _resolve(expr, state, actor)
    if isinstance(key, Const) and isinstance(key.value, (int, str)) \
            and not isinstance(key.value, bool):
        return key.value
    raise UnsupportedEffect(f"symbolic mapping key {key!r}")


class PathRevert(Exception):
    """A symbolic ``require`` is provably false on this path."""


def _effect_condition(effect: tuple) -> Optional[Expr]:
    return effect[4] if len(effect) > 4 else None


def _apply_effect(state: dict[str, Expr], effect: tuple, actor: str) -> dict[str, Expr]:
    kind, target, value = effect[0], effect[1], effect[2]
    index = effect[3] if len(effect) > 3 else None
    v = _resolve(value, state, actor)
    if kind == "require":
        if isinstance(v, Const):
            if not v.value:
                raise PathRevert()
            return state
        raise UnsupportedEffect("symbolic require needs a path split")
    if kind == "push":
        length_key = f"{target}.__len__"
        length = _resolve(Var(length_key), state, actor)
        if not isinstance(length, Const) or not isinstance(length.value, int):
            raise UnsupportedEffect("symbolic array push needs a concrete length")
        new = dict(state)
        new[f"{target}[{length.value}]"] = v
        new[length_key] = Const(length.value + 1)
        return new
    if index is None:
        target_key = target
    else:
        target_key = f"{target}[{_mapping_key(index, state, actor)}]"
    new = dict(state)
    if kind == "assign":
        new[target_key] = v
    elif kind == "add":
        new[target_key] = Bin("+", new.get(target_key, Const(0)), v)
    elif kind == "sub":
        new[target_key] = Bin("-", new.get(target_key, Const(0)), v)
    elif kind == "mul":
        new[target_key] = Bin("*", new.get(target_key, Const(0)), v)
    elif kind == "div":
        new[target_key] = Bin("/", new.get(target_key, Const(0)), v)
    elif kind == "mod":
        new[target_key] = Bin("%", new.get(target_key, Const(0)), v)
    else:
        raise UnsupportedEffect(f"effect kind {kind!r} is not modelled")
    return new


def _apply(state: dict[str, Expr], op: SymOp, actor: str) -> dict[str, Expr]:
    """Apply an unconditional operation; a conditional one needs ``_apply_paths``."""
    new = dict(state)
    for effect in op.effects:
        if _effect_condition(effect) is not None:
            raise UnsupportedEffect("conditional effect needs a path split")
        new = _apply_effect(new, effect, actor)
    return new


def _apply_paths(
    state: dict[str, Expr],
    op: SymOp,
    actor: str,
    constraints: list[Expr],
    domains: dict[str, tuple[int, int]],
    *,
    max_branches: int = 256,
) -> list[tuple[dict[str, Expr], list[Expr]]]:
    """Apply an operation's effects in order, splitting on every condition.

    A condition is decided against the state *at that point in the statement
    sequence*, not the operation's entry state. A path whose condition is
    unsatisfiable is dropped; an unknown condition keeps both branches. A
    symbolic ``require`` splits into a continuing path and a reverting path,
    and the reverting path is not returned.
    """
    results: list[tuple[dict[str, Expr], list[Expr]]] = []

    def rec(i: int, st: dict[str, Expr], cons: list[Expr]) -> None:
        if len(results) >= max_branches:
            raise UnsupportedEffect("conditional effect branch budget exceeded")
        if i >= len(op.effects):
            results.append((st, cons))
            return
        effect = op.effects[i]
        condition = _effect_condition(effect)
        if condition is None:
            branches = [(True, None)]
        else:
            c = _resolve(condition, st, actor)
            branches = [(True, c), (False, not_(c))]
        for applies, guard in branches:
            branch = cons if guard is None else cons + [guard]
            if guard is not None and _decide(branch, domains).status == "UNSAT":
                continue
            if not applies:
                rec(i + 1, st, branch)
                continue
            if effect[0] == "require":
                value = _resolve(effect[2], st, actor)
                if isinstance(value, Const):
                    if value.value:
                        rec(i + 1, st, branch)
                    continue
                for truth, guard_value in ((True, value), (False, not_(value))):
                    decided = _decide(branch + [guard_value], domains)
                    if decided.status == "UNSAT":
                        continue
                    if truth:
                        rec(i + 1, st, branch + [guard_value])
                continue
            try:
                rec(i + 1, _apply_effect(st, effect, actor), branch)
            except PathRevert:
                continue

    rec(0, state, list(constraints))
    return results


def _op_vars(op: SymOp) -> set[str]:
    names = set(op.params)
    for guard in op.guards:
        names |= free_vars(guard)
    for effect in op.effects:
        names |= free_vars(effect[2])
        if len(effect) > 3 and effect[3] is not None:
            names |= free_vars(effect[3])
        condition = _effect_condition(effect)
        if condition is not None:
            names |= free_vars(condition)
    return names


def _state_vars(ops: Iterable[SymOp], invariant: Expr) -> set[str]:
    ops = list(ops)
    names = set(free_vars(invariant))
    mappings: set[str] = set()
    for op in ops:
        for effect in op.effects:
            target, value = effect[1], effect[2]
            if effect[0] == "require":
                names |= free_vars(value)
                condition = _effect_condition(effect)
                if condition is not None:
                    names |= free_vars(condition)
                continue
            if effect[0] == "push":
                names.add(f"{target}.__len__")
                names |= free_vars(value)
                condition = _effect_condition(effect)
                if condition is not None:
                    names |= free_vars(condition)
                continue
            index = effect[3] if len(effect) > 3 else None
            if index is None:
                names.add(target)
            else:
                mappings.add(target)
                if isinstance(index, Var) and index.name == "sender":
                    names |= {f"{target}[{actor}]" for actor in op.actors}
                elif isinstance(index, Const) and isinstance(index.value, (int, str)):
                    names.add(f"{target}[{index.value}]")
                # A symbolic key is not a state variable: the effect is
                # unsupported until the key is concrete, and must not be
                # initialised to 0.
            names |= free_vars(value)
            condition = _effect_condition(effect)
            if condition is not None:
                names |= free_vars(condition)
    # A mapping name is not a scalar slot: an unwritten slot stays unknown
    # rather than being initialised to 0 and read as a real balance. A parameter
    # without a declared domain is not state either; leaving it unbound keeps the
    # verdict UNKNOWN instead of inventing a value for it.
    targets = {effect[1] for op in ops for effect in op.effects
               if effect[0] not in ("require", "push")
               and (len(effect) <= 3 or effect[3] is None)}
    targets |= set(free_vars(invariant))
    params = {name for op in ops for name in op.params} - targets
    return names - mappings - params - {"sender"}


def execute(
    ops: Iterable[SymOp],
    *,
    invariant: Expr,
    domains: dict[str, tuple[int, int]],
    initial: Optional[dict[str, int]] = None,
    max_depth: int = 3,
    max_paths: int = 500,
) -> SymbolicResult:
    """Explore symbolic paths up to ``max_depth``; a SAT witness is a violation."""
    ops = list(ops)
    from .smt import current_backend
    result = SymbolicResult(bound={"max_depth": max_depth, "max_paths": max_paths},
                            solver="z3" if current_backend() is not None else "builtin")
    state_names = _state_vars(ops, invariant) - set(domains)
    state: dict[str, Expr] = {
        name: Const((initial or {}).get(name, 0)) for name in sorted(state_names)
    }

    def walk(current: dict[str, Expr], constraints: list[Expr], path: list[str], depth: int) -> None:
        if depth >= max_depth or result.paths >= max_paths:
            if result.paths >= max_paths:
                result.exhausted = False
            return
        for op in ops:
            for actor in op.actors:
                result.paths += 1
                if result.paths > max_paths:
                    result.exhausted = False
                    return
                guards = [_resolve(g, current, actor) for g in op.guards]
                taken = constraints + guards
                decision = _decide(taken, domains)
                if decision.status == "UNSAT":
                    result.pruned += 1
                else:
                    try:
                        applied = _apply_paths(current, op, actor, taken, domains)
                    except UnsupportedEffect as exc:
                        if str(exc) not in result.unsupported:
                            result.unsupported.append(str(exc))
                    else:
                        for new_state, branch_constraints in applied:
                            bad = not_(subst(invariant, new_state))
                            check = _decide(branch_constraints + [bad], domains)
                            if check.sat:
                                result.violations.append(
                                    Violation(path + [f"{op.name}({actor})"], check.assignment,
                                              "a concrete input reaches an invariant violation"))
                            elif check.status == "UNKNOWN":
                                result.unknown += 1
                            if check.status != "SAT":
                                walk(new_state, branch_constraints,
                                     path + [f"{op.name}({actor})"], depth + 1)

                if guards:
                    failed = constraints + [not_(_and_all(guards))]
                    if _decide(failed, domains).status != "UNSAT":
                        walk(current, failed, path + [f"{op.name}!guard({actor})"], depth + 1)

    walk(state, [], [], 0)
    return result


# --------------------------------------------------------------------------- #
# Bridge from the ingest synthesiser's OpModel
# --------------------------------------------------------------------------- #

def _convert(node: tuple) -> Expr:
    kind = node[0]
    if kind == "num":
        return Const(node[1])
    if kind == "sender":
        return Var("sender")
    if kind == "id":
        return Var(node[1])
    if kind == "not":
        return Not(_convert(node[1]))
    if kind == "neg":
        from .expr import Neg
        return Neg(_convert(node[1]))
    if kind == "bin":
        return Bin(node[1], _convert(node[2]), _convert(node[3]))
    if kind == "index":
        if not isinstance(node[1], tuple) or node[1][0] != "id":
            raise ValueError(f"nested index base {node[1]!r} is not modelled")
        return Index(node[1][1], _convert(node[2]))
    if kind == "member":
        base = node[1]
        if not isinstance(base, tuple) or base[0] != "id":
            raise ValueError(f"nested member base {base!r} is not modelled")
        if node[2] == "length":
            return Var(f"{base[1]}.__len__")
        return Var(f"{base[1]}.{node[2]}")
    raise ValueError(f"unsupported expression node {node!r}")


def from_op_models(
    op_models: Iterable[Any],
    *,
    domains: Optional[dict[str, tuple[int, int]]] = None,
    actors: tuple[str, ...] = ("attacker", "victim"),
) -> tuple[list[SymOp], list[str]]:
    """Convert modelled ``OpModel``s to :class:`SymOp`s.

    Returns ``(ops, unsupported)``. An operation with an unmodelled statement is
    skipped and named in ``unsupported`` -- it is never half-simulated. A mapping
    write is kept with its index expression; whether the key is concrete is
    decided per state by :func:`execute`.
    """
    ops: list[SymOp] = []
    unsupported: list[str] = []
    for model in op_models:
        if not getattr(model, "modelled", True):
            unsupported.append(f"{model.name}: unmodelled statement(s)")
            continue
        if getattr(model, "calls", ()):
            unsupported.append(f"{model.name}: external call(s) are not modelled "
                              "symbolically")
            continue
        try:
            guards = tuple(_convert(g) for g in model.guards)
            effects = []
            for effect in model.effects:
                if getattr(effect, "member", ""):
                    raise ValueError(
                        f"array-of-struct member write {effect.target}[...]."
                        f"{effect.member} is not modelled symbolically"
                    )
                value = _convert(effect.value)
                condition = (_convert(effect.condition)
                             if effect.condition is not None else None)
                index = _convert(effect.index) if effect.index is not None else None
                if condition is None and index is None:
                    effects.append((effect.kind, effect.target, value))
                elif condition is None:
                    effects.append((effect.kind, effect.target, value, index))
                else:
                    effects.append((effect.kind, effect.target, value, index, condition))
        except ValueError as exc:
            unsupported.append(f"{model.name}: {exc}")
            continue
        ops.append(SymOp(name=model.name, guards=guards,
                         effects=tuple(effects), actors=tuple(actors),
                         params=tuple(model.params)))
    return ops, unsupported


# --------------------------------------------------------------------------- #
# Symbolic reachability
# --------------------------------------------------------------------------- #

MAX_VALUE_COMBINATIONS = 64


def _specialize(op: SymOp, fixed: dict[str, Any]) -> tuple[SymOp, dict[str, Any]]:
    env = {name: Const(value) for name, value in fixed.items()}
    effects = []
    for effect in op.effects:
        kind, target, value = effect[0], effect[1], effect[2]
        index = effect[3] if len(effect) > 3 else None
        condition = _effect_condition(effect)
        if condition is None and index is None:
            effects.append((kind, target, subst(value, env)))
        elif condition is None:
            effects.append((kind, target, subst(value, env), subst(index, env)))
        else:
            effects.append((kind, target, subst(value, env),
                            subst(index, env) if index is not None else None,
                            subst(condition, env)))
    return replace(
        op,
        guards=tuple(subst(g, env) for g in op.guards),
        effects=tuple(effects),
        params=tuple(p for p in op.params if p not in fixed),
    ), dict(fixed)


def _variants(op: SymOp, values: dict[str, tuple[Any, ...]]) -> list[tuple[SymOp, dict]]:
    names = [p for p in op.params if p in values]
    if not names:
        return [(op, {})]
    choices = [tuple(values[name]) for name in names]
    total = 1
    for choice in choices:
        total *= len(choice)
    if total == 0 or total > MAX_VALUE_COMBINATIONS:
        return []
    return [_specialize(op, dict(zip(names, combo)))
            for combo in itertools.product(*choices)]


def reachable_operations(
    ops: Iterable[SymOp],
    *,
    domains: dict[str, tuple[int, int]],
    values: Optional[dict[str, tuple[Any, ...]]] = None,
    initial: Optional[dict[str, int]] = None,
    max_depth: int = 4,
    max_paths: int = 2000,
) -> ReachabilityResult:
    """Which operations an unprivileged actor can reach, and with what input.

    Numeric parameters stay symbolic over ``domains``; a finite non-numeric
    domain (an address enumerated as ``attacker`` / ``victim`` / ...) is expanded
    concretely, because the integer solver cannot reason about identities. The
    walk is breadth-first, so the first witness for an operation is the shortest
    one the search finds. An operation is reported reachable only when the solver
    returns a **verified** witness for the whole path; an ``UNKNOWN`` is counted
    and never claimed.
    """
    values = values or {}
    variants: list[tuple[SymOp, dict]] = []
    unsupported: list[str] = []
    for op in ops:
        expanded = _variants(op, values)
        if not expanded:
            unsupported.append(f"{op.name}: parameter values could not be enumerated")
        variants.extend(expanded)

    from .smt import current_backend
    result = ReachabilityResult(
        solver="z3" if current_backend() is not None else "builtin",
        unsupported=unsupported,
        bound={"max_depth": max_depth, "max_paths": max_paths},
    )
    state_names = _state_vars([op for op, _ in variants], Const(True)) - set(domains)
    state: dict[str, Expr] = {
        name: Const((initial or {}).get(name, 0)) for name in sorted(state_names)
    }

    def step_label(op: SymOp, actor: str, assignment: dict[str, Any]) -> str:
        args = [f"{name}={assignment[name]}" for name in op.params if name in assignment]
        suffix = ", " + ", ".join(args) if args else ""
        return f"{op.name}({actor}{suffix})"

    all_ops = {op.name for op, _ in variants}
    queue: deque[tuple[dict[str, Expr], list[Expr], list[str], dict[str, Any], int]] = deque(
        [(state, [], [], {}, 0)])
    while queue:
        if all_ops and len(result.reachable) == len(all_ops):
            return result
        current, constraints, path, bindings, depth = queue.popleft()
        if depth >= max_depth:
            continue
        for op, fixed in variants:
            for actor in op.actors:
                if result.paths >= max_paths:
                    result.exhausted = False
                    return result
                result.paths += 1
                guards = [_resolve(g, current, actor) for g in op.guards]
                taken = constraints + guards
                decision = _decide(taken, domains)
                if decision.status == "UNSAT":
                    result.pruned += 1
                else:
                    solved = {name: value for name, value in decision.assignment.items()
                              if name in _op_vars(op)}
                    assignment = {**bindings, **fixed, **solved}
                    for name in op.params:
                        if name in domains and name not in assignment:
                            assignment[name] = domains[name][0]
                    step = step_label(op, actor, assignment)
                    if decision.status == "UNKNOWN":
                        result.unknown += 1
                    elif op.name not in result.reachable:
                        result.reachable[op.name] = {
                            "actor": actor,
                            "sequence": path + [step],
                            "assignment": dict(assignment),
                        }
                    try:
                        applied = _apply_paths(current, op, actor, taken, domains)
                    except UnsupportedEffect as exc:
                        if str(exc) not in result.unsupported:
                            result.unsupported.append(str(exc))
                    else:
                        for new_state, branch_constraints in applied:
                            queue.append((new_state, branch_constraints,
                                          path + [step], assignment, depth + 1))

                if guards:
                    failed = constraints + [not_(_and_all(guards))]
                    if _decide(failed, domains).status != "UNSAT":
                        queue.append((current, failed, path + [f"{op.name}!guard({actor})"],
                                      bindings, depth + 1))

    return result
