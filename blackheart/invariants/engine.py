"""Stateful invariant-breaking engine (mission section 2D) -- priority capability.

This engine does not test whether a single function returns an expected value. It
defines *properties that must remain true across arbitrary sequences of
operations*, generates random operation sequences with adversarial actors, and
searches for a sequence that violates a property.

When an invariant fails the engine:
  1. saves the seed,
  2. saves the exact sequence,
  3. minimises the failing sequence (delta debugging on operations, then on
     parameter values),
  4. reproduces the failure deterministically,
  5. reports whether the failure is reachable by an attacker-controlled actor.

The engine is target-agnostic: a target implements :class:`Target`, so the same
engine drives a Python reference model (for fast, cheap search) or a Solidity
harness (via generated Foundry invariant tests). A failed test is *not* a
vulnerability -- that determination is made by the verification agent.
"""

from __future__ import annotations

import math
import random
from dataclasses import dataclass, field
from typing import Any, Callable, Optional, Protocol, Sequence

from ..models import AttackStep, InvariantFailure
from ..toolchain.enforce import ExecutionTarget, guarded, require_execution_authorized


# --------------------------------------------------------------------------- #
# Target protocol
# --------------------------------------------------------------------------- #

@dataclass
class OpSpec:
    """Specification of one callable operation an attacker or victim may invoke."""

    name: str
    actors: list[str]                       # roles permitted to invoke
    param_domain: dict[str, list[Any]]      # param name -> candidate values
    weight: int = 1                         # relative selection weight
    description: str = ""


@dataclass
class InvariantSpec:
    """A property that must hold for all reachable states."""

    inv_id: str
    title: str
    predicate: Callable[[Any], bool]
    severity_if_broken: str = "high"

    def evaluate(self, state: Any) -> Optional[bool]:
        """True / False / None (``None`` = could not evaluate on this state).

        A predicate that raises is *unevaluable*, not satisfied. The engine and
        every search strategy read this, so an evaluation failure can never be
        reported as "the invariant holds".
        """
        try:
            return bool(self.predicate(state))
        except Exception:
            return None

    def holds(self, state: Any) -> bool:
        """True unless the predicate *demonstrably* fails.

        Kept for callers that cannot carry a third value. It is deliberately
        permissive, so a strategy that must not miss an unevaluable predicate has
        to use :meth:`evaluate` (the engine does).
        """
        return self.evaluate(state) is not False


def evaluate_invariant(inv: Any, state: Any) -> Optional[bool]:
    """Evaluate one invariant, honouring the tri-state contract when available.

    ``None`` means "could not evaluate on this state" -- never a pass.
    """
    evaluate = getattr(inv, "evaluate", None)
    if callable(evaluate):
        return evaluate(state)
    try:
        return bool(inv.holds(state))
    except Exception:  # noqa: BLE001 -- a raising predicate is unevaluable
        return None


def partition(state: Any, invariants: list[Any]) -> tuple[list[str], list[str]]:
    """Split ``invariants`` into (violated, unevaluable) ids for ``state``.

    The one definition every strategy uses, so "no violation" can never mean
    "could not tell" anywhere in the pipeline.
    """
    violated: set[str] = set()
    unevaluable: set[str] = set()
    for inv in invariants:
        outcome = evaluate_invariant(inv, state)
        if outcome is False:
            violated.add(inv.inv_id)
        elif outcome is None:
            unevaluable.add(inv.inv_id)
    return sorted(violated), sorted(unevaluable)


def unevaluable(state: Any, invariants: list[Any]) -> list[str]:
    """Ids of the invariants whose predicate could not be evaluated on ``state``."""
    return partition(state, invariants)[1]


class Target(Protocol):
    """A system under test."""

    name: str

    def reset(self) -> Any: ...
    def ops(self) -> list[OpSpec]: ...
    def invariants(self) -> list[InvariantSpec]: ...
    def step(self, state: Any, op_name: str, actor: str, params: dict[str, Any]) -> None: ...
    def snapshot(self, state: Any) -> dict[str, Any]: ...


class PureState:
    """Mixin for targets whose ``step`` mutates only the passed-in state object.

    A pure-state target reads and writes only its state argument (plus immutable
    class constants), never a shared global or an external system. That lets the
    adaptive engine reuse a prefix's final state instead of replaying the prefix,
    which is an *exact* transformation -- a differential test asserts the reused
    and replayed states are identical. A target that does not opt in (any
    real-runtime adapter, which has external effects) keeps full replay.
    """

    def state_is_isolated(self) -> bool:
        return True


# --------------------------------------------------------------------------- #
# Runner: execute an explicit sequence deterministically
# --------------------------------------------------------------------------- #

@dataclass
class RunResult:
    state: Any
    violated: list[str]                     # invariant ids that failed
    actor_roles: list[str]
    #: Invariant ids whose predicate could not be evaluated on some state reached
    #: by this sequence. Reported, never folded into "held" or "violated": a
    #: negative result is only sound when this list is empty.
    unevaluable: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"violated": list(self.violated), "actor_roles": list(self.actor_roles),
                "unevaluable": list(self.unevaluable)}


def run_sequence(
    target: Target, sequence: Sequence[AttackStep], compatibility: object = None,
    *, repository: str = "", commit: str = "",
) -> RunResult:
    """Execute a concrete sequence from a fresh state and report violations.

    The invariant engine's execution primitive, and therefore a compatibility
    chokepoint: it runs only inside an authorised execution or with a record
    supplied here.
    """
    if compatibility is not None:
        with guarded(compatibility, ExecutionTarget(
                name=str(getattr(target, "name", "")), repository=repository,
                commit=commit), "invariants.run_sequence"):
            return _run_sequence(target, sequence)
    require_execution_authorized(str(getattr(target, "name", "")),
                                 "invariants.run_sequence")
    return _run_sequence(target, sequence)


def _run_sequence(target: Target, sequence: Sequence[AttackStep]) -> RunResult:
    state = target.reset()
    actors: list[str] = []
    violated: list[str] = []
    unevaluable: list[str] = []
    for step in sequence:
        actors.append(step.actor)
        target.step(state, step.action, step.actor, dict(step.params))
        for inv in target.invariants():
            outcome = inv.evaluate(state)
            if outcome is False:
                violated.append(inv.inv_id)
            elif outcome is None:
                unevaluable.append(inv.inv_id)
    return RunResult(state=state, violated=sorted(set(violated)), actor_roles=actors,
                     unevaluable=sorted(set(unevaluable)))


# --------------------------------------------------------------------------- #
# Fuzzer
# --------------------------------------------------------------------------- #

@dataclass
class FuzzConfig:
    runs: int = 200
    steps_per_run: int = 12
    seed: int = 0
    shrink_values: bool = True
    max_failures_per_invariant: int = 3
    """Minimisation is expensive; keep a few distinct counterexamples per invariant."""
    minimize_budget: int = 300
    """Maximum target re-runs allowed per minimisation."""


@dataclass
class FuzzReport:
    runs: int
    steps_per_run: int
    base_seed: int
    failures: list[InvariantFailure] = field(default_factory=list)
    seeds_tried: int = 0
    #: Invariants that could not be evaluated on at least one reached state. A
    #: fuzz run that reports no failure while this is non-empty has *not* shown
    #: the invariants hold -- it has shown it could not tell.
    unevaluable: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "runs": self.runs,
            "steps_per_run": self.steps_per_run,
            "base_seed": self.base_seed,
            "seeds_tried": self.seeds_tried,
            "failures": [f.to_dict() for f in self.failures],
            "unevaluable": list(self.unevaluable),
        }


def _pick_params(op: OpSpec, rng: random.Random) -> dict[str, Any]:
    return {name: rng.choice(values) for name, values in op.param_domain.items()}


def _generate_sequence(target: Target, rng: random.Random, steps: int) -> list[AttackStep]:
    ops = target.ops()
    weights = [max(1, o.weight) for o in ops]
    seq: list[AttackStep] = []
    for i in range(steps):
        op = rng.choices(ops, weights=weights, k=1)[0]
        actor = rng.choice(op.actors)
        seq.append(
            AttackStep(
                index=i,
                actor=actor,
                action=op.name,
                params=_pick_params(op, rng),
                target_contract=target.name,
                expected_effect=op.description,
            )
        )
    return seq


def _violates(target: Target, seq: Sequence[AttackStep], inv_id: str) -> bool:
    if not seq:
        return False
    return inv_id in run_sequence(target, seq).violated


class _Budget:
    """Caps how many times minimisation may re-run the target.

    Value minimisation on 1e18-scale parameters could otherwise halve forever;
    the budget keeps minimisation bounded and deterministic.
    """

    def __init__(self, limit: int) -> None:
        self.limit = limit
        self.used = 0

    def check(self, target: Target, seq: Sequence[AttackStep], inv_id: str) -> bool:
        if self.used >= self.limit:
            return False
        self.used += 1
        return _violates(target, seq, inv_id)

    def exhausted(self) -> bool:
        return self.used >= self.limit


def _minimize_ops(
    target: Target, seq: list[AttackStep], inv_id: str, budget: "_Budget"
) -> list[AttackStep]:
    """Delta-debug the operation list while preserving the violation."""
    seq = list(seq)
    n = 2
    while len(seq) >= 2 and not budget.exhausted():
        chunk = math.ceil(len(seq) / n)
        reduced = False
        for start in range(0, len(seq), chunk):
            candidate = seq[:start] + seq[start + chunk:]
            if candidate and budget.check(target, candidate, inv_id):
                seq = candidate
                n = max(n - 1, 2)
                reduced = True
                break
        if not reduced:
            if n >= len(seq):
                break
            n = min(n * 2, len(seq))
    return seq


def _minimize_values(
    target: Target, seq: list[AttackStep], inv_id: str, budget: "_Budget"
) -> list[AttackStep]:
    """Shrink numeric parameter values toward a canonical small set."""
    seq = [AttackStep(**s.to_dict()) for s in seq]
    for step in seq:
        for key, value in list(step.params.items()):
            if not isinstance(value, int) or isinstance(value, bool) or value <= 1:
                continue
            # Candidate set: powers of ten up to the value, then binary search down.
            candidates = [10 ** p for p in range(0, len(str(value)))]
            candidates = [c for c in candidates if c < value]
            for candidate in reversed(candidates):
                if budget.exhausted():
                    return seq
                trial = [AttackStep(**s.to_dict()) for s in seq]
                for t in trial:
                    if t.index == step.index and t.action == step.action:
                        t.params[key] = candidate
                if budget.check(target, trial, inv_id):
                    step.params[key] = candidate
                    break
    return seq


def _reachable_by_attacker(seq: Sequence[AttackStep]) -> bool:
    """A failure is attacker-reachable if the violating sequence uses an
    attacker-controlled actor (not only victim/internal actors)."""
    attacker_roles = {"attacker"}
    return any(s.actor in attacker_roles for s in seq)


class StatefulFuzzer:
    def __init__(self, target: Target, config: Optional[FuzzConfig] = None) -> None:
        self.target = target
        self.config = config or FuzzConfig()

    def run(self) -> FuzzReport:
        cfg = self.config
        report = FuzzReport(runs=cfg.runs, steps_per_run=cfg.steps_per_run, base_seed=cfg.seed)
        seen: set[tuple[str, tuple]] = set()
        per_invariant: dict[str, int] = {}
        for i in range(cfg.runs):
            seed = cfg.seed + i
            rng = random.Random(seed)
            seq = _generate_sequence(self.target, rng, cfg.steps_per_run)
            result = run_sequence(self.target, seq)
            report.seeds_tried += 1
            for inv_id in result.unevaluable:
                if inv_id not in report.unevaluable:
                    report.unevaluable.append(inv_id)
            for inv_id in result.violated:
                if per_invariant.get(inv_id, 0) >= cfg.max_failures_per_invariant:
                    continue
                key = (inv_id, tuple((s.actor, s.action) for s in seq))
                if key in seen:
                    continue
                seen.add(key)
                budget = _Budget(cfg.minimize_budget)
                minimal = _minimize_ops(self.target, seq, inv_id, budget)
                if cfg.shrink_values:
                    minimal = _minimize_values(self.target, minimal, inv_id, budget)
                reproducible = _violates(self.target, minimal, inv_id)
                per_invariant[inv_id] = per_invariant.get(inv_id, 0) + 1
                failure = InvariantFailure(
                    inv_id=inv_id,
                    seed=seed,
                    sequence=seq,
                    actor_roles=result.actor_roles,
                    observed=self.target.snapshot(run_sequence(self.target, minimal).state),
                    minimized=True,
                    minimal_sequence=minimal,
                    reproduction_command=(
                        f"python -m blackheart.invariants reproduce --seed {seed} "
                        f"--invariant {inv_id} --steps {len(minimal)}"
                    ),
                    reproducible=reproducible,
                    reachable_by_attacker=_reachable_by_attacker(minimal),
                )
                report.failures.append(failure)
        return report
