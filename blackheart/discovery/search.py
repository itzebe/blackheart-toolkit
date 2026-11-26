"""Enhanced stateful attack exploration (mission 3.D).

The state-space engine added by PR #47 enumerates operation *orderings* and actor
substitutions, but it fixes each step's parameters to a single default value. That
blind spot is real: the classic first-depositor inflation attack needs a *small*
first deposit (1 wei) followed by a *large* donation, and a fixed "largest value"
default never tries the small deposit. This module closes that gap without
touching the existing engine:

  * :func:`enhanced_candidates` -- enumerate operation sequences over the model's
    relevant operations, across actors, **and across parameter boundaries**
    (min/max and a small canonical set per value-like parameter). Bounded and
    deterministic.
  * :func:`discover` -- drive a target through the enhanced candidate set, detect
    invariant violations, minimise them, and return the same
    :class:`~blackheart.statespace.explore.Violation` objects the rest of the
    pipeline already consumes.

Prioritisation (mission 3.D) is explicit and ordered: sequences that cross actors,
end on a sensitive operation, or pair a *small* value with a *large* one (the
inflation / rounding shape) are tried first, so a budget-limited search reaches the
high-value shapes early. State deduplication is by canonical (actor, op, params)
key, so equivalent states are not re-run.

Nothing here asserts a vulnerability. It returns sequences that broke a stated
invariant on a model, for the independent verifier to judge.
"""

from __future__ import annotations

import itertools
from typing import Any, Optional

from ..statespace.explore import (
    ExploreConfig,
    Violation,
    _Budget,
    _reachable_by_attacker,
    minimize,
    run_sequence,
)
from ..statespace.hypotheses import Hypothesis
from ..statespace.model import SystemModel
from ..models import AttackStep


# Parameter values worth trying for a value-like parameter, in priority order.
def _param_values(domain: list[Any]) -> list[Any]:
    """Declared values first, then canonical small values, bounded.

    Collapsing a declared domain to ``{min, max, 1, 2}`` discards every interior
    value the author declared -- including the numeric window a bug lives in. The
    declared values are kept, in order, up to the same small cap, so the search
    still bounds its branching.
    """
    numeric = [v for v in domain if isinstance(v, int) and not isinstance(v, bool)]
    if not numeric:
        return list(domain[:1]) if domain else [None]
    vals: list[Any] = []
    for value in numeric:
        if value not in vals:
            vals.append(value)
    # Small canonical values matter for rounding / inflation shapes.
    for c in (1, 2):
        if c not in vals:
            vals.append(c)
    return vals[:6]


def _param_assignments(op, *, cap: int = 6) -> list[dict[str, Any]]:
    """A small set of parameter assignments for one operation (bounded)."""
    domain = getattr(op, "param_domain", {}) or {}
    if not domain:
        return [{}]
    keys = list(domain)
    value_lists = [_param_values(domain[k]) for k in keys]
    out: list[dict[str, Any]] = []
    for combo in itertools.product(*value_lists):
        out.append(dict(zip(keys, combo)))
        if len(out) >= cap:
            break
    return out or [{}]


def enhanced_candidates(model: SystemModel, op_specs: dict,
                        cfg: Optional[ExploreConfig] = None) -> list[list[AttackStep]]:
    """Enumerate prioritised candidate sequences with parameter variation.

    ``op_specs`` maps operation name -> the ``OpSpec`` (for its param domain).
    Returns a deterministic, de-duplicated, priority-ordered list of sequences.
    """
    cfg = cfg or ExploreConfig(seed=0, max_steps=4)

    names = [o.name for o in model.operations]
    actors_for: dict[str, list[str]] = {}
    for op in model.operations:
        allowed = [a.name for a in model.actors_for(op)]
        actors_for[op.name] = allowed or [a.name for a in model.actors]
    sensitive = {o.name for o in model.sensitive_operations()}

    # Deduplicate operations that share a name (a model may list one).
    seen_names: list[str] = []
    for n in names:
        if n not in seen_names:
            seen_names.append(n)
    names = seen_names

    # Single-step candidates first (cheapest, and many bugs are single-step).
    candidates: list[list[AttackStep]] = []
    seen_keys: set[tuple] = set()

    def add(seq: list[AttackStep]) -> None:
        key = tuple((s.actor, s.action, tuple(sorted(s.params.items()))) for s in seq)
        if key in seen_keys:
            return
        seen_keys.add(key)
        candidates.append(seq)

    lengths = list(range(1, min(cfg.max_steps, 4) + 1))
    for length in lengths:
        for names_sel in itertools.product(names, repeat=length):
            # Keep only sequences touching at least one sensitive op (bounded).
            if length > 1 and not any(n in sensitive for n in names_sel):
                continue
            for actors_sel in itertools.product(*(actors_for[n] for n in names_sel)):
                param_options = [_param_assignments(op_specs.get(n)) for n in names_sel]
                for params_sel in itertools.product(*param_options):
                    seq = [
                        AttackStep(index=i, actor=a, action=n, params=dict(p))
                        for i, (n, a, p) in enumerate(zip(names_sel, actors_sel, params_sel))
                    ]
                    add(seq)

    # Prioritise: cross-actor sequences, ending on a sensitive op, with a small
    # value present (the inflation/rounding shape), come first.
    def rank(seq: list[AttackStep]) -> tuple:
        distinct_actors = len({s.actor for s in seq})
        ends_sensitive = 1 if seq and seq[-1].action in sensitive else 0
        has_small = 1 if any(
            isinstance(v, int) and not isinstance(v, bool) and v <= 2
            for s in seq for v in s.params.values()) else 0
        return (-distinct_actors, -ends_sensitive, -has_small, len(seq))

    candidates.sort(key=rank)
    return candidates


def discover(target, *, cfg: Optional[ExploreConfig] = None,
             hypotheses: Optional[list[Hypothesis]] = None,
             extra_seeds: Optional[list[list[AttackStep]]] = None) -> list[Violation]:
    """Search a target with the enhanced candidate set; return violations.

    ``target`` must expose ``model``/``ops``/``invariants``/``reset``/``step``/
    ``snapshot`` (the ``SequenceTarget`` protocol). The returned violations carry
    the exact sequence, the minimised form, and attacker reachability -- the same
    contract the existing pipeline consumes.

    ``extra_seeds`` are sequences to try *first* -- e.g. proven attacks transferred
    from a similar target by :mod:`blackheart.learning.transfer`. A transferred seed
    is only a lead: it runs through the same execution, minimisation and reporting
    as any other candidate, so a bad transfer costs a little budget and can never
    produce a finding on its own.
    """
    cfg = cfg or ExploreConfig(seed=0, max_steps=4)
    model = target.model()
    op_specs = {op.name: op for op in target.ops()}
    invs = target.invariants()
    inv_ids = [i.inv_id for i in invs]

    candidates = enhanced_candidates(model, op_specs, cfg)
    if extra_seeds:
        # Deduplicate transferred seeds against the enumerated set and put them at
        # the front, preserving their order (nearest-first from the memory).
        seen = {tuple((s.actor, s.action, tuple(sorted(s.params.items()))) for s in c)
                for c in candidates}
        front: list[list[AttackStep]] = []
        for seq in extra_seeds:
            if not seq:
                continue
            key = tuple((s.actor, s.action, tuple(sorted(s.params.items()))) for s in seq)
            if key in seen:
                continue
            seen.add(key)
            front.append(seq)
        candidates = front + candidates

    violations: list[Violation] = []
    seen_inv: set[str] = set()
    steps_evaluated = 0
    seqs_tried = 0
    max_per_inv = cfg.max_failures_per_invariant

    for seq in candidates:
        if all(i in seen_inv for i in inv_ids):
            break
        seqs_tried += 1
        steps_evaluated += len(seq)
        state, bad = run_sequence(target, seq)
        if not bad:
            continue
        for inv_id in bad:
            if inv_id in seen_inv and sum(1 for v in violations if v.invariant_id == inv_id) >= max_per_inv:
                continue
            budget = _Budget(cfg.minimize_budget)
            minimal = minimize(target, seq, inv_id, budget)
            final_state, minimal_bad = run_sequence(target, minimal)
            violations.append(Violation(
                invariant_id=inv_id,
                sequence=seq,
                minimal_sequence=minimal,
                seed=cfg.seed,
                actor_roles=[s.actor for s in seq],
                observed=target.snapshot(final_state),
                reproducible=inv_id in minimal_bad,
                reachable_by_attacker=_reachable_by_attacker(minimal),
                steps_evaluated=steps_evaluated,
            ))
            seen_inv.add(inv_id)

    # Attach counts for the caller's metrics.
    for v in violations:
        v._seqs_tried = seqs_tried  # type: ignore[attr-defined]
    return violations
