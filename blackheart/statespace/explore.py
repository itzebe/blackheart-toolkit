"""Adversarial state-space exploration and sequence minimisation.

The explorer drives a :class:`~blackheart.statespace.model.SequenceTarget` along
the sequences the hypothesis generator proposed -- and, crucially, along *variants*
of them -- looking for a sequence that violates a stated invariant. It is
model-guided, not random: the transitions and guards in the model tell it which
operations are worth trying and in which order, so it spends its budget on
plausible attack shapes rather than on uniform noise. (The existing random fuzzer
remains available and is used as the benchmark baseline.)

Three properties the mission demands, enforced here:

  * **Sequence-level, not function-level.** Every result is a *sequence*; a single
    operation is never reported as an attack.
  * **Deterministic and reproducible.** Every run is driven by an explicit seed and
    returns the exact sequence and parameter values, so the counterexample can be
    replayed byte-for-byte.
  * **Minimised.** When a sequence violates an invariant, the explorer reduces it
    (delta-debugging on operations, then on numeric parameters) while preserving
    the violation, so the reported attack is the smallest one that works.

Nothing here decides that a vulnerability exists. It returns *violations* -- a
sequence that broke a stated invariant -- which are then handed to the
independent verifier. A violation on a deliberately-vulnerable fixture is not a
production finding, and the report says so.
"""

from __future__ import annotations

import math
import random
from dataclasses import dataclass, field
from typing import Any, Callable, Optional, Sequence

from ..models import AttackStep
from ..toolchain.enforce import ExecutionTarget, guarded, require_execution_authorized
from .hypotheses import Hypothesis, SequenceStep
from .model import SequenceTarget, unevaluable, violated

# --------------------------------------------------------------------------- #
# Result records
# --------------------------------------------------------------------------- #

@dataclass
class Violation:
    """A concrete sequence that broke a stated invariant, with its evidence."""

    invariant_id: str
    sequence: list[AttackStep]
    minimal_sequence: list[AttackStep]
    seed: int
    actor_roles: list[str]
    observed: dict[str, Any]
    hypothesis_id: str = ""
    strategy_id: str = ""
    reproducible: bool = False
    reachable_by_attacker: bool = False
    steps_evaluated: int = 0
    #: The priced economic consequence of this violation (see
    #: :mod:`blackheart.value`). Populated when a caller asks the engine to price
    #: its findings, so a "broken invariant" and a "demonstrated extraction" are
    #: never confused. ``None`` means not priced -- never "no impact".
    economic: Optional[dict] = None

    def to_dict(self) -> dict:
        return {
            "invariant_id": self.invariant_id,
            "sequence": [s.to_dict() for s in self.sequence],
            "minimal_sequence": [s.to_dict() for s in self.minimal_sequence],
            "seed": self.seed,
            "actor_roles": list(self.actor_roles),
            "observed": dict(self.observed),
            "hypothesis_id": self.hypothesis_id,
            "strategy_id": self.strategy_id,
            "reproducible": self.reproducible,
            "reachable_by_attacker": self.reachable_by_attacker,
            "steps_evaluated": self.steps_evaluated,
            "economic": self.economic,
        }


@dataclass
class ExploreConfig:
    """Budgets. Deterministic; no wall-clock dependence in the search itself."""

    seed: int = 0
    max_steps: int = 6                 # cap on a single sequence's length
    variants_per_hypothesis: int = 24  # how many permutations/actors to try
    minimize_budget: int = 400         # target re-runs allowed per minimisation
    max_failures_per_invariant: int = 3
    expand: bool = True                # try length-varying and actor-varying variants


@dataclass
class ExploreReport:
    target: str
    violations: list[Violation] = field(default_factory=list)
    sequences_tried: int = 0
    steps_evaluated: int = 0
    hypotheses_explored: int = 0
    elapsed_seconds: float = 0.0
    #: Invariants the search reached a state for but could not evaluate. Non-empty
    #: means the run cannot be described as "no violation found": the search could
    #: not tell, and that is a different fact.
    unevaluable: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "sequences_tried": self.sequences_tried,
            "steps_evaluated": self.steps_evaluated,
            "hypotheses_explored": self.hypotheses_explored,
            "elapsed_seconds": self.elapsed_seconds,
            "unevaluable": list(self.unevaluable),
            "violations": [v.to_dict() for v in self.violations],
        }


# --------------------------------------------------------------------------- #
# Sequence execution
# --------------------------------------------------------------------------- #

def _target_name(target: SequenceTarget) -> str:
    return str(getattr(target, "name", "") or "")


def run_sequence(target: SequenceTarget, sequence: Sequence[AttackStep],
                 compatibility: object = None) -> tuple[Any, list[str]]:
    """Run a concrete sequence from a fresh state; return (final_state, violated_ids).

    This is where a target is actually acted upon, so it is a compatibility
    chokepoint: it runs only inside an authorised execution -- one started by an
    engine entry point with a validated record -- or with a record supplied here.
    """
    state, bad, _ = run_sequence_full(target, sequence, compatibility)
    return state, bad


def run_sequence_full(target: SequenceTarget, sequence: Sequence[AttackStep],
                      compatibility: object = None) -> tuple[Any, list[str], list[str]]:
    """Like :func:`run_sequence`, also returning the invariants it could not evaluate.

    A search that reports "no violation" while this list is non-empty has not
    shown the invariants hold -- it has shown it could not tell, and the caller
    must say so rather than claim a clean result.
    """
    if compatibility is not None:
        with guarded(compatibility, ExecutionTarget(name=_target_name(target)),
                     "statespace.run_sequence"):
            return _run_sequence(target, sequence)
    require_execution_authorized(_target_name(target), "statespace.run_sequence")
    return _run_sequence(target, sequence)


def _run_sequence(target: SequenceTarget, sequence: Sequence[AttackStep]
                  ) -> tuple[Any, list[str], list[str]]:
    state = target.reset()
    invs = target.invariants()
    bad: set[str] = set()
    unknown: set[str] = set()
    for step in sequence:
        target.step(state, step.action, step.actor, dict(step.params))
        bad.update(violated(state, invs))
        unknown.update(unevaluable(state, invs))
    return state, sorted(bad), sorted(unknown)


def _to_attack_steps(steps: list[SequenceStep], target_name: str, op_params: dict) -> list[AttackStep]:
    out: list[AttackStep] = []
    for i, s in enumerate(steps):
        params = dict(s.params) or _default_params(op_params.get(s.operation, {}))
        out.append(AttackStep(index=i, actor=s.actor, action=s.operation, params=params,
                              target_contract=target_name))
    return out


def attack_steps_for(target: SequenceTarget, steps: list[SequenceStep]) -> list[AttackStep]:
    """Public: convert hypothesis steps into concrete attack steps for a target."""
    op_params = {op.name: getattr(op, "param_domain", {}) for op in target.ops()}
    return _to_attack_steps(steps, target.name, op_params)


def enumerate_candidates(target: SequenceTarget, hypotheses: list[Hypothesis],
                         cfg: ExploreConfig) -> list[list[SequenceStep]]:
    """Public: the ordered candidate list the explorer searches.

    Exposed so the benchmark can measure *sequences-to-first-detection* (the
    efficiency axis) without duplicating the search order.
    """
    op_actors = {op.name: list(getattr(op, "actors", [])) for op in target.ops()}
    work: list[list[SequenceStep]] = []
    model = target.model() if hasattr(target, "model") else None
    # The model's direct predictions go first: they are the highest-value
    # candidates, so a budget-limited search hits them before the heuristic
    # perturbations of the hypotheses.
    if model is not None and cfg.expand:
        work.extend(_candidate_sequences(model, cfg, hypotheses))
    for hi, hyp in enumerate(hypotheses):
        rng = random.Random(cfg.seed + hi)
        work.extend(_variants(hyp, cfg, rng, op_actors))
    return work


# Parameter names that select *which* object/resource an operation acts on. For
# these the smallest value is the most interesting (the first/oldest object is the
# one most likely to belong to someone else); for value-like params the largest is
# (it makes any accounting effect observable). This is a deterministic heuristic,
# not a guess: minimization later shrinks whatever actually matters.
_SELECTOR_PARAMS = {"obj", "object", "id", "index", "target", "token_id", "account", "user"}


def _default_params(domain: dict[str, list[Any]]) -> dict[str, Any]:
    """Pick a small, deterministic param value from an op's domain."""
    out: dict[str, Any] = {}
    for name, values in domain.items():
        if not values:
            continue
        numeric = [v for v in values if isinstance(v, int) and not isinstance(v, bool)]
        if not numeric:
            out[name] = values[0]
        elif name in _SELECTOR_PARAMS:
            out[name] = min(numeric)
        else:
            out[name] = max(numeric)
    return out


# --------------------------------------------------------------------------- #
# Candidate sequence generation -- model-guided enumeration
# --------------------------------------------------------------------------- #

def _variants(hyp: Hypothesis, cfg: ExploreConfig, rng: random.Random,
              op_actors: Optional[dict[str, list[str]]] = None) -> list[list[SequenceStep]]:
    """Produce candidate sequences from a hypothesis.

    The hypothesis gives the *shape*; the variants perturb it the way an attacker
    would -- reorder independent steps, substitute actors, extend with a repeat,
    and shorten -- so the search explores genuinely different sequences rather
    than re-testing one. ``op_actors`` restricts actor substitution to actors that
    can actually invoke each operation (so we do not waste the budget on a
    sequence the target would reject as unreachable).
    """
    base = list(hyp.vulnerable_sequence)
    out: list[list[SequenceStep]] = [base]
    if not cfg.expand or len(base) < 2:
        return out
    op_actors = op_actors or {}

    # 1. Reorder: swap adjacent steps (a legal permutation of the same ops).
    for i in range(len(base) - 1):
        v = list(base)
        v[i], v[i + 1] = v[i + 1], v[i]
        out.append(v)

    # 2. Actor substitution: vary which actor performs each step.
    for i in range(len(base)):
        allowed = op_actors.get(base[i].operation) or [s.actor for s in base]
        for alt in allowed:
            if alt != base[i].actor:
                v = [SequenceStep(s.actor, s.operation, dict(s.params)) for s in base]
                v[i] = SequenceStep(alt, base[i].operation, dict(base[i].params))
                out.append(v)

    # 3. Repeat a step (idempotency / replay shape).
    if len(base) < cfg.max_steps:
        for i in range(len(base)):
            v = list(base)
            v.insert(i, SequenceStep(base[i].actor, base[i].operation, dict(base[i].params)))
            out.append(v)

    # 4. Shorter prefixes (does the violation already appear earlier?).
    for k in range(1, len(base)):
        out.append(list(base[:k]))

    # 5. Random permutations within budget.
    for _ in range(max(0, cfg.variants_per_hypothesis - len(out))):
        v = list(base)
        rng.shuffle(v)
        out.append(v)

    # de-duplicate while preserving order
    seen: set[tuple] = set()
    uniq: list[list[SequenceStep]] = []
    for v in out:
        if not v or len(v) > cfg.max_steps:
            continue
        key = tuple((s.actor, s.operation) for s in v)
        if key in seen:
            continue
        seen.add(key)
        uniq.append(v)
    return uniq[: cfg.variants_per_hypothesis]


def relevant_operations(model: SystemModel,  # noqa: F821  annotation-only
                        hypotheses: Optional[list[Hypothesis]] = None) -> list[str]:
    """The operations worth enumerating: sensitive ops, transition ops, and the ops
    the hypotheses already reference.

    This is the model-guidance that makes the search tractable when a target has
    many decoy operations. A pure brute force over the whole operation space is
    diluted by operations that cannot participate in any stated invariant; this
    set keeps the enumeration on the operations the *model* says matter (the ones
    an invariant is stated about, the ones a declared transition names, and the
    ones a strategy already suspected), which is exactly the information random
    search does not use.
    """
    names: list[str] = [o.name for o in model.sensitive_operations()]
    for t in model.transitions:
        if t.operation and t.operation not in names:
            names.append(t.operation)
    for hyp in hypotheses or []:
        for s in hyp.vulnerable_sequence:
            if s.operation not in names:
                names.append(s.operation)
    return names


def _candidate_sequences(model: SystemModel, cfg: ExploreConfig,  # noqa: F821  annotation-only
                         hypotheses: Optional[list[Hypothesis]] = None) -> list[list[SequenceStep]]:
    """Enumerate short sequences over the model's *relevant* operation space.

    Ordered pairs and triples of the relevant operations (see
    :func:`relevant_operations`), each step assigned to every actor that can
    invoke it. Bounded, deterministic, and decoy-free -- this is what finds a
    multi-step bug that random selection rarely stumbles onto in a small budget.
    """
    import itertools

    names = relevant_operations(model, hypotheses)
    if not names:
        return []
    by_name = {o.name: o for o in model.operations}
    actors_for: dict[str, list[str]] = {
        n: [a.name for a in model.actors_for(by_name[n])] for n in names if n in by_name
    }
    names = [n for n in names if n in actors_for]
    sensitive = {o.name for o in model.sensitive_operations()}

    seqs: list[list[SequenceStep]] = []
    for length in (2, 3):
        if length > cfg.max_steps:
            continue
        for names_sel in itertools.product(names, repeat=length):
            for actors_sel in itertools.product(*(actors_for[n] for n in names_sel)):
                seqs.append([SequenceStep(a, n) for n, a in zip(names_sel, actors_sel)])
    # Keep only sequences that invoke at least one sensitive op.
    seqs = [s for s in seqs if any(step.operation in sensitive for step in s)]

    # Rank the high-value shapes first: a sequence that ends on a sensitive
    # operation, and that uses more than one actor (the cross-user / privilege
    # pattern), is the most likely to violate an invariant, so a budget-limited
    # search should reach it before the homogeneous permutations.
    def rank(seq: list[SequenceStep]) -> tuple:
        distinct_actors = len({s.actor for s in seq})
        ends_sensitive = 1 if seq and seq[-1].operation in sensitive else 0
        return (-distinct_actors, -ends_sensitive, len(seq))

    return sorted(seqs, key=rank)


# --------------------------------------------------------------------------- #
# Minimisation -- delta debugging on ops, then on numeric values
# --------------------------------------------------------------------------- #

class _Budget:
    def __init__(self, limit: int) -> None:
        self.limit = limit
        self.used = 0

    def check(self, target: SequenceTarget, seq: Sequence[AttackStep], inv_id: str) -> bool:
        if self.used >= self.limit:
            return False
        self.used += 1
        _, bad = run_sequence(target, seq)
        return inv_id in bad

    def exhausted(self) -> bool:
        return self.used >= self.limit


def minimize(target: SequenceTarget, seq: list[AttackStep], inv_id: str, budget: _Budget,
             preserve: Optional[Callable[[list[AttackStep]], bool]] = None) -> list[AttackStep]:
    """Reduce a violating sequence while preserving the violation (delta debugging).

    ``preserve`` is an optional extra predicate a reduced candidate must also
    satisfy -- used to keep an *economic* property (the attacker still profits)
    while shrinking the attack. When no candidate satisfies both, the search falls
    back to the invariant-only reduction, so a profitable sequence is never
    discarded in favour of a smaller but worthless one: the caller prices the
    minimal sequence and, if it lost the profit, re-prices the original.
    """
    seq = list(seq)
    n = 2

    def ok(candidate: list[AttackStep]) -> bool:
        if not budget.check(target, candidate, inv_id):
            return False
        return preserve(candidate) if preserve is not None else True

    while len(seq) >= 2 and not budget.exhausted():
        chunk = math.ceil(len(seq) / n)
        reduced = False
        for start in range(0, len(seq), chunk):
            candidate = seq[:start] + seq[start + chunk:]
            if candidate and ok(candidate):
                seq = candidate
                n = max(n - 1, 2)
                reduced = True
                break
        if not reduced:
            if n >= len(seq):
                break
            n = min(n * 2, len(seq))
    # shrink numeric params toward a canonical small set
    for step in seq:
        for key, value in list(step.params.items()):
            if not isinstance(value, int) or isinstance(value, bool) or value <= 1:
                continue
            candidates = [10 ** p for p in range(len(str(value)))]
            candidates = [c for c in candidates if c < value]
            for candidate in reversed(candidates):
                if budget.exhausted():
                    break
                trial = [AttackStep(**s.to_dict()) for s in seq]
                for t in trial:
                    if t.index == step.index and t.action == step.action:
                        t.params[key] = candidate
                if ok(trial):
                    step.params[key] = candidate
                    break
    # reindex
    for i, s in enumerate(seq):
        s.index = i
    return seq


def _reachable_by_attacker(seq: Sequence[AttackStep]) -> bool:
    return any(s.actor in {"attacker", "user", "anonymous"} for s in seq)


# --------------------------------------------------------------------------- #
# The explorer
# --------------------------------------------------------------------------- #

class StateSpaceExplorer:
    """Model-guided sequence search over a target's operation space."""

    def __init__(self, target: SequenceTarget, config: Optional[ExploreConfig] = None) -> None:
        self.target = target
        self.config = config or ExploreConfig()

    def explore(self, hypotheses: list[Hypothesis],
                compatibility: object = None) -> ExploreReport:
        """Search the target's operation space. Compatibility-gated at the boundary."""
        with guarded(compatibility, ExecutionTarget(name=_target_name(self.target)),
                     "StateSpaceExplorer.explore"):
            return self._explore(hypotheses)

    def _explore(self, hypotheses: list[Hypothesis]) -> ExploreReport:
        import time

        cfg = self.config
        start = time.monotonic()
        op_params = {op.name: getattr(op, "param_domain", {}) for op in self.target.ops()}
        op_actors = {op.name: list(getattr(op, "actors", [])) for op in self.target.ops()}
        model = self.target.model() if hasattr(self.target, "model") else None
        report = ExploreReport(target=self.target.name)
        seen_failures: set[tuple] = set()
        per_invariant: dict[str, int] = {}

        # Build the candidate set: the hypothesis-driven variants PLUS (when a
        # model is available) a model-guided enumeration of short sequences over
        # the whole operation space. The enumeration is what finds a multi-step
        # bug the hypothesis shape alone might not express.
        work: list[tuple[Hypothesis, list[SequenceStep]]] = []
        if model is not None and cfg.expand:
            anchor = hypotheses[0] if hypotheses else None
            for seq in _candidate_sequences(model, cfg, hypotheses):
                work.append((anchor, seq))
        for hi, hyp in enumerate(hypotheses):
            rng = random.Random(cfg.seed + hi)
            for variant in _variants(hyp, cfg, rng, op_actors):
                work.append((hyp, variant))

        for hi, (hyp, variant) in enumerate(work):
            report.hypotheses_explored += 1
            attack_steps = _to_attack_steps(variant, self.target.name, op_params)
            _, bad, unknown = run_sequence_full(self.target, attack_steps)
            report.sequences_tried += 1
            report.steps_evaluated += len(attack_steps)
            for inv_id in unknown:
                if inv_id not in report.unevaluable:
                    report.unevaluable.append(inv_id)
            for inv_id in bad:
                if per_invariant.get(inv_id, 0) >= cfg.max_failures_per_invariant:
                    continue
                key = (inv_id, tuple((s.actor, s.action) for s in attack_steps))
                if key in seen_failures:
                    continue
                seen_failures.add(key)
                budget = _Budget(cfg.minimize_budget)
                minimal = minimize(self.target, attack_steps, inv_id, budget)
                _, bad_min = run_sequence(self.target, minimal)
                if inv_id not in bad_min:
                    continue
                per_invariant[inv_id] = per_invariant.get(inv_id, 0) + 1
                min_state, _ = run_sequence(self.target, minimal)
                report.violations.append(Violation(
                    invariant_id=inv_id,
                    sequence=attack_steps,
                    minimal_sequence=minimal,
                    seed=cfg.seed + hi,
                    actor_roles=[s.actor for s in minimal],
                    observed=self.target.snapshot(min_state),
                    hypothesis_id=hyp.hyp_id if hyp else "",
                    strategy_id=hyp.strategy_id if hyp else "",
                    reproducible=True,
                    reachable_by_attacker=_reachable_by_attacker(minimal),
                    steps_evaluated=report.steps_evaluated,
                ))
        report.elapsed_seconds = round(time.monotonic() - start, 4)
        return report

    def explore_baseline(self, config: Optional[ExploreConfig] = None) -> ExploreReport:
        """Random search baseline for the ablation: no model guidance.

        Mirrors :class:`blackheart.invariants.engine.StatefulFuzzer`'s shape (random
        op/actor selection) but reports in the same :class:`ExploreReport` form so
        the two are directly comparable. Used only to *measure* the model-guided
        engine's incremental value -- never to make a claim of superiority on its
        own.
        """
        import time

        cfg = config or self.config
        start = time.monotonic()
        ops = self.target.ops()
        op_params = {op.name: getattr(op, "param_domain", {}) for op in ops}
        report = ExploreReport(target=self.target.name)
        rng = random.Random(cfg.seed)
        seen_failures: set[tuple] = set()
        per_invariant: dict[str, int] = {}
        for i in range(cfg.variants_per_hypothesis * 8):
            steps: list[AttackStep] = []
            for j in range(rng.randint(1, cfg.max_steps)):
                op = rng.choice(ops)
                actor = rng.choice(op.actors)
                steps.append(AttackStep(index=j, actor=actor, action=op.name,
                                        params=_default_params(op_params.get(op.name, {})),
                                        target_contract=self.target.name))
            state, bad = run_sequence(self.target, steps)
            report.sequences_tried += 1
            report.steps_evaluated += len(steps)
            for inv_id in bad:
                if per_invariant.get(inv_id, 0) >= cfg.max_failures_per_invariant:
                    continue
                key = (inv_id, tuple((s.actor, s.action) for s in steps))
                if key in seen_failures:
                    continue
                seen_failures.add(key)
                budget = _Budget(cfg.minimize_budget)
                minimal = minimize(self.target, steps, inv_id, budget)
                _, bad_min = run_sequence(self.target, minimal)
                if inv_id not in bad_min:
                    continue
                per_invariant[inv_id] = per_invariant.get(inv_id, 0) + 1
                min_state, _ = run_sequence(self.target, minimal)
                report.violations.append(Violation(
                    invariant_id=inv_id, sequence=steps, minimal_sequence=minimal,
                    seed=cfg.seed + i, actor_roles=[s.actor for s in minimal],
                    observed=self.target.snapshot(min_state), reproducible=True,
                    reachable_by_attacker=_reachable_by_attacker(minimal),
                    steps_evaluated=report.steps_evaluated,
                ))
        report.elapsed_seconds = round(time.monotonic() - start, 4)
        return report
