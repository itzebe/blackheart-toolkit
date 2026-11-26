"""Adaptive, feedback-driven adversarial exploration (Mission 06, Phase B).

The Mission-06 diagnosis (``research/mission06/DIAGNOSIS.md``) found the guided
explorer's weakness is *not* its structural guidance -- it enumerates the right
operation orderings and actor substitutions -- but two things it never does:

  1. **Parameter-boundary variation.** Every step's parameters are fixed to a
     single default value (``_default_params`` picks ``max`` for value-like
     params). The classic boundary bugs (a 1-wei first deposit; a fee charged on
     the balance) need the *smallest* value, so the guided search can never reach
     them, while the random baseline occasionally does. That is the reproduced
     0.88 (guided) versus 0.94 (baseline) gap.

  2. **Execution feedback.** The candidate list is built once and iterated in a
     fixed order; nothing a sequence *reveals* changes what is tried next, and a
     prefix that makes progress is never extended.

This module closes both gaps without changing the existing engines. It reuses the
same ``Violation`` type, the same ``run_sequence``/``minimize`` minimiser, the
same ``_reachable_by_attacker`` reachability rule and the same independent
verifier. It is a *controller* around the existing machinery:

  * it deepens **iteratively** -- every candidate of length 1, then 2, ... over the
    target's operations x actors x boundary parameters -- so a shallow exploit is
    never starved by a longer, higher-ranked one;
  * it scores every pending candidate by how much *new* behaviour it would
    exercise (unreached actor/operation pairs, unreached operation adjacencies, a
    boundary value present), executes the best, folds the observed feedback back
    into the coverage set, and **re-ranks the pending list** -- so the order of
    what it tries next is a function of what it has already seen (a static
    ordering disguised as adaptive search would not do this).

Nothing here asserts a vulnerability: it returns sequences that broke a stated
invariant, for the independent verifier to judge.
"""

from __future__ import annotations

import copy
import itertools
from dataclasses import dataclass, field
from typing import Any, Optional

from ..models import AttackStep
from ..value import ValueModel, analyse, victim_loss
from .explore import (
    Violation,
    _Budget,
    _reachable_by_attacker,
    minimize,
)
from .model import SequenceTarget, violated

# --------------------------------------------------------------------------- #
# Parameter boundaries
# --------------------------------------------------------------------------- #

def _boundary_values(domain: list[Any]) -> list[Any]:
    """Boundary + canonical values for a parameter's declared domain.

    The declared min/max are always included; the canonical small values ``1`` and
    ``2`` are added because they are the boundary an off-by-one / rounding / fee
    bug lives on, and a declared domain may not list them.
    """
    numeric = [v for v in domain if isinstance(v, int) and not isinstance(v, bool)]
    if not numeric:
        return list(domain[:1]) if domain else [None]
    vals: list[Any] = []
    for value in numeric:
        if value not in vals:
            vals.append(value)
    for c in (1, 2):
        if c not in vals:
            vals.append(c)
    return vals[:6]


def _assignments(op: Any, *, cap: int = 6) -> list[dict[str, Any]]:
    """A small, deterministic set of parameter assignments for one operation."""
    domain = getattr(op, "param_domain", {}) or {}
    if not domain:
        return [{}]
    keys = list(domain)
    value_lists = [_boundary_values(domain[k]) for k in keys]
    out: list[dict[str, Any]] = []
    for combo in itertools.product(*value_lists):
        out.append(dict(zip(keys, combo)))
        if len(out) >= cap:
            break
    return out or [{}]


def _key(seq: list[AttackStep]) -> tuple:
    return tuple((s.actor, s.action, tuple(sorted(s.params.items()))) for s in seq)


def _has_small(seq: list[AttackStep]) -> bool:
    return any(
        isinstance(v, int) and not isinstance(v, bool) and v <= 2
        for s in seq for v in s.params.values()
    )


# --------------------------------------------------------------------------- #
# Configuration + feedback records
# --------------------------------------------------------------------------- #

@dataclass
class AdaptiveConfig:
    """Budgets for the adaptive controller. Deterministic; no wall-clock use."""

    seed: int = 0
    max_steps: int = 4                 # cap on a single sequence's length
    max_sequences: int = 2000          # sequences executed before the budget ends
    minimize_budget: int = 400         # target re-runs allowed per minimisation
    max_failures_per_invariant: int = 3
    #: Exact prefix-state reuse. When the target's state is a self-contained value
    #: (declared via ``state_is_isolated()``), a sequence's final state equals its
    #: prefix's final state with one more step applied, so the prefix need not be
    #: replayed. This changes no result -- only how many times ``step`` is called.
    #: Off by default for any target that does not declare isolated state.
    reuse_prefix_states: bool = True
    #: Price every candidate's economic consequence (attacker profit, victim loss,
    #: value created) and prefer the sequences that move value toward the attacker.
    #: This is what turns the search from "find a broken invariant" into "find a
    #: sequence that makes the attacker money": a sequence that profits is explored
    #: first, and every reported violation carries its priced account. On by
    #: default because deriving value is the point of the operation; a caller may
    #: disable it for a target whose snapshot exposes no value fields.
    profit_guided: bool = True


@dataclass
class Feedback:
    """What one executed sequence revealed."""

    changed: bool = False              # did the final snapshot differ from reset?
    reverted: bool = False             # did any step raise (invalid transaction)?
    pairs: set = field(default_factory=set)        # (actor, operation) exercised
    adjacencies: set = field(default_factory=set)  # (op_i, op_{i+1}) transitions
    #: The attacker's realised net profit for the sequence (see
    #: :mod:`blackheart.value`). Zero when the target exposes no value fields or the
    #: sequence moved nothing toward the attacker.
    profit: int = 0
    #: Value absorbed from non-attacker participants by the sequence. Non-zero even
    #: when the attacker's own net is flat or negative (a sequence can harm a victim
    #: without enriching the attacker), so it is a second, independent signal that
    #: value moved. This is what lets the search prefer an extraction on a target
    #: whose own-account accounting is confounded by nominal-vs-valued holdings.
    victim_loss: int = 0


@dataclass
class AdaptiveReport:
    target: str
    violations: list[Violation] = field(default_factory=list)
    sequences_tried: int = 0
    steps_evaluated: int = 0
    priority_divergences: int = 0      # selections that differed from the static order
    coverage_pairs: int = 0
    coverage_adjacencies: int = 0
    decisions: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "sequences_tried": self.sequences_tried,
            "steps_evaluated": self.steps_evaluated,
            "priority_divergences": self.priority_divergences,
            "coverage_pairs": self.coverage_pairs,
            "coverage_adjacencies": self.coverage_adjacencies,
            "violations": [v.to_dict() for v in self.violations],
            "decisions": list(self.decisions),
        }


# --------------------------------------------------------------------------- #
# The adaptive explorer
# --------------------------------------------------------------------------- #

class AdaptiveExplorer:
    """Feedback-driven sequence search over a target's operation space."""

    def __init__(self, target: SequenceTarget,
                 config: Optional[AdaptiveConfig] = None) -> None:
        self.target = target
        self.config = config or AdaptiveConfig()
        # Exact prefix-state reuse is enabled only when the target declares its
        # state self-contained; a real-runtime target never declares this, so it
        # always replays in full.
        fn = getattr(target, "state_is_isolated", None)
        self._reuse_enabled = bool(fn()) if callable(fn) else False
        self._prefix_cache: dict[tuple, tuple[Any, tuple, bool]] = {}
        self._reset_snapshot_cache: Optional[dict] = None
        self._start_model_cache: Optional[ValueModel] = None

    # -- scoring: a function of *current* coverage, so it changes as we learn -- #
    def _score(self, seq: list[AttackStep], cov_pairs: set, cov_adj: set,
               profit_pairs: Optional[set] = None) -> int:
        pairs = {(s.actor, s.action) for s in seq}
        new_pairs = len(pairs - cov_pairs)
        adj = {(seq[i].action, seq[i + 1].action) for i in range(len(seq) - 1)}
        new_adj = len(adj - cov_adj)
        actors = len({s.actor for s in seq})
        # Coverage drives exploration; a (actor, operation) pair already *known*
        # to move value toward the attacker dominates it. The bonus is on the
        # discovered-profit pairs, so the controller re-ranks the pending work
        # toward sequences that use what it has learned pays.
        profit_bonus = 0
        if self.config.profit_guided and profit_pairs:
            profit_bonus = 4 * len(pairs & profit_pairs)
        return (4 * new_pairs + 2 * new_adj + actors
                + (2 if _has_small(seq) else 0) + profit_bonus)

    def _execute(self, seq: list[AttackStep]) -> tuple[Any, list[str], Feedback]:
        invs = self.target.invariants()
        state = self.target.reset()
        before = self._reset_snapshot()
        fb = Feedback()
        bad: set[str] = set()
        prev_op: Optional[str] = None
        for step in seq:
            try:
                self.target.step(state, step.action, step.actor, dict(step.params))
            except Exception:  # noqa: BLE001 -- an invalid step is feedback, not a crash
                fb.reverted = True
            fb.pairs.add((step.actor, step.action))
            if prev_op is not None:
                fb.adjacencies.add((prev_op, step.action))
            prev_op = step.action
            bad.update(violated(state, invs))
        fb.changed = self.target.snapshot(state) != before
        if self.config.profit_guided:
            fb.profit, fb.victim_loss = self._value_signals(state)
        return state, sorted(bad), fb

    def _value_signals(self, state: Any) -> tuple[int, int]:
        """(attacker net profit, value absorbed from other participants).

        Reuses the state the explorer just produced and the universal value model,
        so pricing a candidate costs one snapshot read. A target whose snapshot
        exposes no attacker-identifiable value yields ``(0, 0)`` -- the search then
        falls back to structural coverage, exactly as before.
        """
        start = self._start_model()
        try:
            end = ValueModel(self.target.snapshot(state))
        except Exception:  # noqa: BLE001 -- a target that cannot snapshot has no value
            return 0, 0
        attacker = start.attacker_actor() or end.attacker_actor()
        if attacker is None:
            return 0, 0
        return end.attacker_total() - start.attacker_total(), victim_loss(start, end, attacker)

    def _start_model(self) -> ValueModel:
        """The value model of a fresh reset, computed once and cached.

        The explorer prices many candidates against the same initial state; caching
        the model avoids a ``reset`` per candidate.
        """
        if self._start_model_cache is None:
            try:
                self._start_model_cache = ValueModel(
                    self.target.snapshot(self.target.reset()))
            except Exception:  # noqa: BLE001 -- a target that cannot snapshot has no value
                self._start_model_cache = ValueModel({})
        return self._start_model_cache

    def _extracts(self, seq: list[AttackStep]) -> bool:
        """True when executing ``seq`` moves value (attacker gain or victim loss)."""
        try:
            profit, victim = self._value_signals(self._execute(seq)[0])
        except Exception:  # noqa: BLE001
            return False
        return profit > 0 or victim > 0

    @staticmethod
    def _moves_value(acct: Any) -> bool:
        """True when a priced account shows a realised extraction.

        Uses the same definition the search does: the attacker nets a gain, or a
        counterparty loses value. A pure state change or a positive conservation
        residual alone does not count (see :mod:`blackheart.value`).
        """
        return bool(acct.attacker_profit > 0 or acct.victim_loss > 0)

    def _execute_sequence(self, seq: list[AttackStep]) -> tuple[Any, list[str], Feedback]:
        """Execute ``seq``, reusing a cached prefix state when exact and available.

        Correctness: reuse is applied only when the target declares isolated state
        and the *exact* prefix (same actor/action/params at every step) has already
        been executed this run. The cached outcome carries the prefix's cumulative
        violation set and revert flag, so the union of violations, the coverage
        pairs/adjacencies (a pure function of the sequence), and ``changed`` are
        identical to a full replay. A miss falls back to a full replay.
        """
        if (not self.config.reuse_prefix_states or len(seq) <= 1
                or not self._reuse_enabled):
            out = self._execute(seq)
            self._cache_outcome(seq, out)
            return out
        base = self._prefix_cache.get(_key(seq[:-1]))
        if base is None:
            out = self._execute(seq)
            self._cache_outcome(seq, out)
            return out
        base_state, base_bad, base_reverted = base
        state = copy.deepcopy(base_state)
        last = seq[-1]
        bad = set(base_bad)
        reverted = base_reverted
        try:
            self.target.step(state, last.action, last.actor, dict(last.params))
        except Exception:  # noqa: BLE001 -- an invalid step is feedback, not a crash
            reverted = True
        bad.update(violated(state, self.target.invariants()))
        profit, victim = (self._value_signals(state) if self.config.profit_guided
                          else (0, 0))
        fb = Feedback(
            changed=self.target.snapshot(state) != self._reset_snapshot(),
            reverted=reverted,
            pairs={(s.actor, s.action) for s in seq},
            adjacencies={(seq[i].action, seq[i + 1].action) for i in range(len(seq) - 1)},
            profit=profit,
            victim_loss=victim,
        )
        out = (state, sorted(bad), fb)
        self._cache_outcome(seq, out)
        return out

    def _cache_outcome(self, seq: list[AttackStep], out: tuple[Any, list[str], Feedback]) -> None:
        if not self._reuse_enabled:
            return
        self._prefix_cache[_key(seq)] = (out[0], tuple(out[1]), out[2].reverted)

    def _reset_snapshot(self) -> dict:
        """The snapshot of a freshly reset target -- a per-target constant."""
        if self._reset_snapshot_cache is None:
            self._reset_snapshot_cache = self.target.snapshot(self.target.reset())
        return self._reset_snapshot_cache

    def _sequences_at_depth(self, depth: int) -> list[list[AttackStep]]:
        """All candidate sequences of exactly ``depth`` steps.

        Complete over the target's operations x actors x boundary parameters, so a
        shallow exploit is never missed. Ordered by a static, structure-based rank
        (cross-actor, ending on a sensitive operation, a boundary value present)
        so a budget-limited run reaches the high-value shapes first; the controller
        re-ranks this list against live coverage as it runs.
        """
        choices: list[tuple[str, str, dict]] = []
        for op in self.target.ops():
            for actor in (getattr(op, "actors", []) or []):
                for params in _assignments(op):
                    choices.append((op.name, actor, params))
        if not choices:
            return []
        seqs: list[list[AttackStep]] = []
        for combo in itertools.product(choices, repeat=depth):
            seq = [AttackStep(index=i, actor=a, action=n, params=dict(p))
                   for i, (n, a, p) in enumerate(combo)]
            seqs.append(seq)
        return seqs

    def _static_rank(self, seq: list[AttackStep]) -> tuple:
        """A fixed, coverage-independent preference: **higher is better**.

        Cross-actor sequences and ones carrying a boundary value are preferred, so
        a budget-limited run reaches the high-value shapes first. The sequence key
        makes the order total and deterministic.
        """
        actors = len({s.actor for s in seq})
        small = 1 if _has_small(seq) else 0
        return (actors, small, _key(seq))

    def explore(self, hypotheses: Optional[list] = None) -> AdaptiveReport:
        cfg = self.config
        report = AdaptiveReport(target=getattr(self.target, "name", "target"))

        tried: set[tuple] = set()
        seen_failures: set[tuple] = set()
        per_invariant: dict[str, int] = {}
        cov_pairs: set = set()
        cov_adj: set = set()
        # (actor, operation) pairs observed to move value toward the attacker.
        profit_pairs: set = set()

        def record(seq: list[AttackStep], bad: list[str], fb: Feedback) -> None:
            for inv_id in bad:
                if per_invariant.get(inv_id, 0) >= cfg.max_failures_per_invariant:
                    continue
                fkey = (inv_id, tuple((s.actor, s.action) for s in seq))
                if fkey in seen_failures:
                    continue
                seen_failures.add(fkey)
                # When the sequence moves value, shrink it while *keeping* the
                # value movement: the smallest sequence that still extracts is the
                # finding. Fall back to the invariant-only minimum otherwise.
                preserve = None
                if cfg.profit_guided and (fb.profit > 0 or fb.victim_loss > 0):
                    preserve = lambda cand: self._extracts(cand)  # noqa: E731
                budget = _Budget(cfg.minimize_budget)
                minimal = minimize(self.target, seq, inv_id, budget, preserve=preserve)
                _, min_bad, _ = self._execute(minimal)
                if inv_id not in min_bad:
                    continue
                per_invariant[inv_id] = per_invariant.get(inv_id, 0) + 1
                min_state, _, _ = self._execute(minimal)
                economic = None
                if cfg.profit_guided:
                    acct = analyse(self.target, minimal, inv_id)
                    # If shrinking dropped the value movement, price the original
                    # sequence instead -- never report an "extraction" whose minimal
                    # form is worthless.
                    if (fb.profit > 0 or fb.victim_loss > 0) and not self._moves_value(acct):
                        alt = analyse(self.target, seq, inv_id)
                        if self._moves_value(alt):
                            minimal = seq
                            min_state = self._execute(seq)[0]
                            acct = alt
                    economic = acct.to_dict()
                report.violations.append(Violation(
                    invariant_id=inv_id,
                    sequence=seq,
                    minimal_sequence=minimal,
                    seed=cfg.seed,
                    actor_roles=[s.actor for s in minimal],
                    observed=self.target.snapshot(min_state),
                    reproducible=True,
                    reachable_by_attacker=_reachable_by_attacker(minimal),
                    steps_evaluated=report.steps_evaluated,
                    economic=economic,
                ))

        # Iterative deepening: complete at each depth (so the shallowest exploit is
        # always reachable), with the pending order re-ranked against live
        # coverage whenever execution reveals new behaviour (so feedback changes
        # what is tried next).
        for depth in range(1, cfg.max_steps + 1):
            if report.sequences_tried >= cfg.max_sequences:
                break
            pool = self._sequences_at_depth(depth)
            remaining = [s for s in pool if _key(s) not in tried]
            if not remaining:
                continue
            # The static order is fixed for the depth; a pointer over it tells us
            # what a non-adaptive search would pick next, cheaply. Best first.
            static_order = sorted(remaining, key=self._static_rank, reverse=True)
            remaining_keys = {_key(s) for s in remaining}
            sp = 0

            def static_next(_order=static_order, _keys=remaining_keys) -> tuple:
                nonlocal sp
                while sp < len(_order) and _key(_order[sp]) not in _keys:
                    sp += 1
                return _key(_order[sp]) if sp < len(_order) else ()

            remaining.sort(key=lambda s: (self._score(s, cov_pairs, cov_adj, profit_pairs),
                                          self._static_rank(s)))
            dirty = False
            while remaining and report.sequences_tried < cfg.max_sequences:
                if dirty:
                    remaining.sort(key=lambda s: (self._score(s, cov_pairs, cov_adj, profit_pairs),
                                                  self._static_rank(s)))
                    dirty = False
                # The static pick among what is still pending, versus the adaptive
                # pick. When they differ, coverage feedback changed the decision.
                static_key = static_next()
                seq = remaining.pop()
                key = _key(seq)
                remaining_keys.discard(key)
                if key in tried:
                    continue
                tried.add(key)

                if static_key != key:
                    report.priority_divergences += 1

                report.sequences_tried += 1
                report.steps_evaluated += len(seq)
                _state, bad, fb = self._execute_sequence(seq)
                new_pairs = fb.pairs - cov_pairs
                new_adj = fb.adjacencies - cov_adj
                cov_pairs |= fb.pairs
                cov_adj |= fb.adjacencies
                report.coverage_pairs = len(cov_pairs)
                report.coverage_adjacencies = len(cov_adj)
                # A value-moving step teaches the controller which (actor,
                # operation) pairs extract value. Re-rank the pending work only
                # when that *signal* grows -- re-ranking on every such step would
                # re-sort the whole pool needlessly.
                if (fb.profit > 0 or fb.victim_loss > 0) and (fb.pairs - profit_pairs):
                    profit_pairs |= fb.pairs
                    dirty = True
                report.decisions.append({
                    "depth": depth,
                    "seq": [s.to_dict() for s in seq],
                    "score": self._score(seq, cov_pairs, cov_adj, profit_pairs),
                    "changed": fb.changed,
                    "reverted": fb.reverted,
                    "new_pairs": len(new_pairs),
                    "new_adjacencies": len(new_adj),
                    "profit": fb.profit,
                })
                if new_pairs or new_adj:
                    dirty = True
                record(seq, bad, fb)

        return report


def discover_adaptive(target: SequenceTarget, *,
                      cfg: Optional[AdaptiveConfig] = None) -> AdaptiveReport:
    """Convenience entry point mirroring ``discovery.search.discover``."""
    return AdaptiveExplorer(target, cfg).explore()
