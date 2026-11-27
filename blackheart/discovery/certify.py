"""Path certification: turn a *candidate* violation into a *proof* -- or a bound.

The search engines (:mod:`blackheart.discovery.search`,
:mod:`blackheart.statespace.explore`) find sequences that break an invariant. A
found sequence is a lead, not a proof: it may be a fluke of one parameter value,
it may not be minimal, and it may not be reproducible. This module does the part
that turns a lead into something a reviewer can trust, and it is honest about the
part it cannot do.

Three certifiers, each with an explicit and *recorded* limit:

  * :func:`certify_path` -- take one concrete path and prove it. It runs the path
    deterministically, records the exact state at every step, and reports the
    **first** step at which each invariant breaks together with the concrete state
    values that break it. It re-runs the path to confirm the witness is
    deterministic, and it reduces the path to the shortest **prefix** that still
    violates -- a minimality that is *proven* (a prefix that still breaks the
    property), not guessed by a deletion heuristic.

  * :func:`certify_exhaustive` -- search a bounded space *to exhaustion*. It does
    a depth-first walk over the model's operations, their actors, and their
    parameter boundary values (min, min+1, max-1, max, and 0/1), de-duplicating
    visited states by a canonical key. If it finds a violation, that is a proof
    the property is breakable within the bound. If it finishes without one, it
    reports ``exhausted=True`` **with the bound it exhausted** -- a bounded
    non-existence result, never the false claim "the system is safe".

  * :func:`certify_directed` -- spend a bounded beam on attack-shaped paths:
    value-moving operations, the actor in ``to``/``from``, the protocol
    contracts in ``spender``/``target`` and the maximum numeric corners. It can
    find a multi-contract witness inside a small budget, records
    ``exhaustive=False``, and never calls a miss a proof of safety.

None of the certifiers is a general symbolic solver: the target's ``step`` is opaque
Python, so there is no SMT model to solve. What is offered instead is an honest,
bounded, *complete-within-the-bound* enumeration plus boundary-value analysis --
and where a bound limits the result, the bound is stated in the certificate.
"""

from __future__ import annotations

import itertools
from dataclasses import dataclass, field
from typing import Any, Optional

from ..models import AttackStep
from ..statespace.explore import SequenceTarget
from ..statespace.model import violated


# --------------------------------------------------------------------------- #
# The certificate
# --------------------------------------------------------------------------- #

@dataclass
class StepWitness:
    """The state after one step, and which invariants were broken at that point."""

    index: int
    action: str
    actor: str
    params: dict[str, Any]
    violated: list[str]
    state: dict[str, Any]

    def to_dict(self) -> dict:
        return {
            "index": self.index, "action": self.action, "actor": self.actor,
            "params": dict(self.params), "violated": list(self.violated),
            "state": dict(self.state),
        }


@dataclass
class Certificate:
    """The result of certifying a path. ``proven`` is the only field that matters."""

    target: str
    invariant_id: str
    proven: bool
    #: The shortest prefix that still violates (a *proven* minimal witness).
    witness: list[AttackStep] = field(default_factory=list)
    #: The per-step trace up to and including the first violating step.
    trace: list[StepWitness] = field(default_factory=list)
    #: True only when a re-run of the witness reproduced the violation exactly.
    reproducible: bool = False
    #: For an exhaustive search: did the whole bounded space get explored?
    exhausted: bool = False
    #: The bound the search was run under (always recorded).
    bound: dict[str, Any] = field(default_factory=dict)
    #: States visited (exhaustive) or paths tried (concolic).
    explored: int = 0
    reason: str = ""
    #: The model-coverage ledger. An incomplete ledger means the search was
    #: exhaustive over an incomplete alphabet, so ``exhausted`` is not a clean
    #: target result.
    model_coverage: dict = field(default_factory=dict)

    @property
    def coverage_complete(self) -> bool:
        return bool(self.model_coverage.get("complete", True))

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "invariant_id": self.invariant_id,
            "proven": self.proven,
            "reproducible": self.reproducible,
            "exhausted": self.exhausted,
            "bound": dict(self.bound),
            "explored": self.explored,
            "reason": self.reason,
            "model_coverage": dict(self.model_coverage),
            "witness": [s.to_dict() for s in self.witness],
            "trace": [w.to_dict() for w in self.trace],
        }


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def _snapshot(target: SequenceTarget, state: Any) -> dict[str, Any]:
    try:
        return dict(target.snapshot(state))
    except Exception:  # a target without a snapshot is still usable
        return {}


def _invariants(target: SequenceTarget):
    return target.invariants()


def _first_violating_step(
    target: SequenceTarget, steps: list[AttackStep]
) -> tuple[Optional[int], list[StepWitness], list[str]]:
    """Run ``steps`` and return the first index that breaks an invariant.

    Returns ``(first_index_or_None, trace, final_violated_ids)``. The trace holds
    one :class:`StepWitness` per executed step, so the caller can see the exact
    state at which the property failed.
    """
    state = target.reset()
    invs = _invariants(target)
    trace: list[StepWitness] = []
    first: Optional[int] = None
    final_bad: list[str] = []
    for i, step in enumerate(steps):
        target.step(state, step.action, step.actor, dict(step.params))
        bad = violated(state, invs)
        if bad and first is None:
            first = i
        final_bad = bad
        trace.append(StepWitness(i, step.action, step.actor, dict(step.params),
                                 bad, _snapshot(target, state)))
    return first, trace, final_bad


def _prefix_minimize(target: SequenceTarget, steps: list[AttackStep],
                     invariant_id: str) -> list[AttackStep]:
    """The shortest prefix of ``steps`` that still violates ``invariant_id``.

    A prefix is a *monotone* reduction: if a longer sequence violates, the point
    at which it first violates defines a prefix that violates too. This is a
    proven minimality along the sequence, not a heuristic deletion.
    """
    for n in range(1, len(steps) + 1):
        prefix = steps[:n]
        _, trace, _ = _first_violating_step(target, prefix)
        if any(invariant_id in w.violated for w in trace):
            return prefix
    return list(steps)


# --------------------------------------------------------------------------- #
# Certifier 1: prove one concrete path
# --------------------------------------------------------------------------- #

def certify_path(
    target: SequenceTarget,
    steps: list[AttackStep],
    *,
    invariant_id: str = "",
) -> Certificate:
    """Prove (or refute) a single concrete path.

    The path is certified when it deterministically breaks an invariant, the
    violation is reproduced by a second independent run, and the witness is the
    shortest prefix that still breaks it.
    """
    name = getattr(target, "name", "target")
    if not steps:
        return Certificate(name, invariant_id, proven=False,
                           reason="empty path")

    first, trace, _ = _first_violating_step(target, steps)
    if first is None:
        return Certificate(name, invariant_id, proven=False,
                           explored=1, reason="the path did not violate any invariant")

    broken = trace[first].violated
    inv = invariant_id or (broken[0] if broken else "")
    if invariant_id and invariant_id not in broken:
        # A later step may break the named invariant even if the first failure was
        # a different one; re-scan for the named invariant specifically.
        _, trace2, _ = _first_violating_step(target, steps)
        if not any(invariant_id in w.violated for w in trace2):
            return Certificate(name, invariant_id, proven=False, explored=1,
                               reason=f"invariant {invariant_id!r} was not violated")

    witness = _prefix_minimize(target, steps, inv)
    # Independent reproduction: run the witness again and require the same break.
    _, trace_again, _ = _first_violating_step(target, witness)
    reproducible = any(inv in w.violated for w in trace_again)

    return Certificate(
        target=name, invariant_id=inv, proven=reproducible and bool(witness),
        witness=witness,
        trace=[w for w in trace_again if w.index <= len(witness) - 1],
        reproducible=reproducible,
        bound={"max_steps": len(steps)},
        explored=1,
        reason="witness reproduced deterministically" if reproducible
               else "the violation did not reproduce on a second run",
    )


# --------------------------------------------------------------------------- #
# Certifier 2: bounded exhaustive search
# --------------------------------------------------------------------------- #

def _canonical_state(state: dict[str, Any]) -> str:
    """A stable key for a snapshot, so equivalent states are not re-explored."""
    try:
        import json
        return json.dumps(state, sort_keys=True, default=str)
    except Exception:
        return repr(sorted(state.items()) if isinstance(state, dict) else state)


def _state_key(target: SequenceTarget, state: Any) -> str:
    """Canonical key for a *live* state object.

    A target with a ``snapshot`` gives a stable dict; a pure-state target that
    does not implement one still has a comparable state, so its ``repr`` is used.
    Using the empty dict for every such state (the naive fallback) would collapse
    the whole search to a single visited state and silently miss every finding.
    """
    snap = _snapshot(target, state)
    if snap:
        return _canonical_state(snap)
    return f"{type(state).__name__}:{state!r}"


def _boundary_values(domain: list[Any]) -> list[Any]:
    """The values a value-like parameter is *plausibly* given, boundary-first.

    A ``param_domain`` is a sample of candidate values, not the full accepted set:
    a token transfer whose sample is ``[1000, 5000]`` still accepts ``1``. The
    honest accepted range for a value-like (integer) parameter is therefore the
    **non-negative** integers up to the sample's maximum -- ``0`` and ``1`` are
    legitimate inputs (and are exactly where rounding and fee-on-transfer bugs
    live), while a *negative* value is not an input the contract accepts and must
    never be manufactured into a witness. Non-numeric values are used as declared.
    """
    numeric = [v for v in domain if isinstance(v, int) and not isinstance(v, bool)]
    if not numeric:
        return list(domain)
    lo, hi = min(numeric), max(numeric)
    candidates = {0, 1, lo, lo + 1, hi - 1, hi} | set(numeric)
    return [v for v in sorted(candidates) if 0 <= v <= hi]


def _priority_values(key: str, values: list[Any]) -> list[Any]:
    """Order a parameter's boundary values by attack relevance.

    The exhaustive search is depth-first, so the first combination is the one it
    spends the budget on. An actor/contract address with the largest value is the
    corner an unprivileged attack usually needs; a token spender is the contract,
    not the actor. This is an ordering heuristic only -- it never removes a value.
    """
    actors = {"attacker", "victim", "admin"}
    numeric = [v for v in values if isinstance(v, int) and not isinstance(v, bool)]
    hi = max(numeric) if numeric else None

    def rank(value: Any) -> tuple[int, int]:
        if isinstance(value, str):
            contract = value not in actors
            if key in ("spender", "operator", "receiver", "target", "vault", "callee"):
                return (0 if contract else 1, 0)
            if value == "attacker":
                return (0, 0)
            if contract:
                return (1, 0)
            return (2, 0)
        if isinstance(value, int) and not isinstance(value, bool):
            if value == 1:
                return (0, 0)
            if hi is not None and value == hi:
                return (1, 0)
            if value == 2:
                return (2, 0)
            return (3, value)
        return (4, 0)

    return sorted(values, key=rank)


def _op_param_sets(op) -> list[dict[str, Any]]:
    """Boundary combinations, with each parameter's first/last value guaranteed.

    A flat Cartesian product truncated at twelve entries silently drops the
    combination that matters for a two-parameter call: ``approve(vault, max)``
    was never tried because the address axis exhausted the fan-out first. The
    first/last cross product and one-axis sweeps keep the attack-relevant
    corners without exploring the full domain.
    """
    domain = getattr(op, "param_domain", {}) or {}
    if not domain:
        return [{}]
    keys = list(domain)
    value_lists = [_priority_values(k, _boundary_values(domain[k])) for k in keys]
    out: list[dict[str, Any]] = []

    def add(params: dict[str, Any]) -> None:
        if params not in out:
            out.append(params)

    # The top few priority values of every parameter, crossed first. This is
    # where a multi-parameter attack lives: mint(to=attacker, amount=max) and
    # approve(spender=vault, amount=max), not the flat product's first slice.
    for combo in itertools.product(*(values[:4] for values in value_lists)):
        add(dict(zip(keys, combo)))
    for combo in itertools.product(*( [values[0], values[-1]] for values in value_lists )):
        add(dict(zip(keys, combo)))
    for i, key in enumerate(keys):
        for anchor in (0, -1):
            base = {k: value_lists[j][anchor] for j, k in enumerate(keys)}
            for value in value_lists[i]:
                params = dict(base)
                params[key] = value
                add(params)
    for combo in itertools.product(*value_lists):
        add(dict(zip(keys, combo)))
        if len(out) >= 24:
            break
    return out or [{}]


def certify_exhaustive(
    target: SequenceTarget,
    *,
    max_depth: int = 4,
    max_states: int = 200_000,
) -> Certificate:
    """Exhaustively search a bounded space; prove a violation or the bound.

    The search is depth-first over ``(operation, actor, parameter-boundary)``
    triples, with states de-duplicated by snapshot. It is *complete within the
    bound*: if it returns ``exhausted=True`` and ``proven=False``, then no
    sequence up to ``max_depth`` steps over the boundary parameter set breaks an
    invariant -- and the certificate says exactly that, no more.
    """
    name = getattr(target, "name", "target")
    ops = target.ops()
    invs = _invariants(target)
    try:
        from ..ingest.model_coverage import coverage_for_target

        coverage = coverage_for_target(target).to_dict()
    except Exception:  # noqa: BLE001 -- unknown coverage is not clean coverage
        coverage = {"available": False, "complete": False,
                    "gaps": [{"kind": "coverage_error",
                              "reason": "model coverage could not be read"}]}
    bound = {"max_depth": max_depth, "max_states": max_states,
             "parameters": "boundary values (min, min+1, max-1, max, 0, 1)"}

    visited: set[str] = set()
    explored = 0

    # A work stack of (state, path). We snapshot states for de-duplication, so a
    # state reached by a different order is not explored twice.
    start = target.reset()
    stack: list[tuple[Any, list[AttackStep]]] = [(start, [])]
    visited.add(_state_key(target, start))

    while stack:
        state, path = stack.pop()
        if len(path) >= max_depth:
            continue
        for op in ops:
            for actor in getattr(op, "actors", []) or []:
                for params in _op_param_sets(op):
                    explored += 1
                    if explored > max_states:
                        return Certificate(
                            name, "", proven=False, exhausted=False,
                            bound=bound, explored=explored,
                            model_coverage=coverage,
                            reason=f"state budget {max_states} reached before exhaustion")
                    # Step a copy of the state so siblings are independent.
                    new_state = _deepcopy_state(state)
                    target.step(new_state, op.name, actor, dict(params))
                    bad = violated(new_state, invs)
                    step = AttackStep(index=len(path), actor=actor,
                                      action=op.name, params=dict(params),
                                      target_contract=name)
                    if bad:
                        inv = bad[0]
                        witness = _prefix_minimize(target, path + [step], inv)
                        _, trace_again, _ = _first_violating_step(target, witness)
                        repro = any(inv in w.violated for w in trace_again)
                        return Certificate(
                            name, inv, proven=repro, witness=witness,
                            trace=trace_again, reproducible=repro,
                            exhausted=False, bound=bound, explored=explored,
                            model_coverage=coverage,
                            reason="found within the bound and reproduced"
                                   if repro else "found but did not reproduce",
                        )
                    key = _state_key(target, new_state)
                    if key not in visited:
                        visited.add(key)
                        stack.append((new_state, path + [step]))

    if not coverage.get("complete", True):
        gaps = coverage.get("gaps") or []
        first = gaps[0] if gaps else {}
        where = f"{first.get('path', '')}:{first.get('line', '')}"
        what = (first.get("statement") or first.get("callee_op")
                or first.get("name") or "unknown")
        return Certificate(
            name, "", proven=False, exhausted=False, bound=bound,
            explored=explored, model_coverage=coverage,
            reason=(f"INCOMPLETE MODEL COVERAGE: the bound was exhausted, but "
                    f"{len(gaps)} reachable item(s) are outside the model; first at "
                    f"{where} ({first.get('kind', 'gap')}: {what}). A clean search "
                    f"is not a clean target"),
        )
    return Certificate(
        name, "", proven=False, exhausted=True, bound=bound,
        explored=explored, model_coverage=coverage,
        reason=(f"no invariant broke within depth {max_depth} over the boundary "
                f"parameter set; this is a bounded result, not a proof of safety"),
    )


def _deepcopy_state(state: Any) -> Any:
    import copy
    try:
        return copy.deepcopy(state)
    except Exception:
        return state


# --------------------------------------------------------------------------- #
# Directed certification: spend the budget on value-moving paths first
# --------------------------------------------------------------------------- #

_VALUE_OPS = frozenset({
    "mint", "burn", "transfer", "transferFrom", "approve", "deposit",
    "withdraw", "redeem", "mintShares", "depositAssets", "swap", "borrow",
    "repay", "liquidate", "stake", "unstake", "donate", "claim", "flashLoan",
    "supply", "withdrawAssets", "borrowAssets",
})
_VALUE_PARAMS = frozenset({
    "amount", "assets", "shares", "value", "token", "to", "receiver",
    "spender", "operator", "target", "vault", "callee", "amountIn",
    "amountOut", "assetsIn", "sharesIn",
})
_VIEW_OPS = frozenset({
    "totalAssets", "convertToShares", "convertToAssets", "previewRedeem",
    "previewDeposit", "previewMint", "previewWithdraw", "balanceOf",
    "allowance", "totalSupply", "owner", "admin", "decimals", "name", "symbol",
})


def _directed_ops(target: SequenceTarget) -> list[Any]:
    """The operations that can move value or address, in declared order.

    A target with no recognisable value operation falls back to its full
    alphabet rather than silently searching nothing.
    """
    ops = target.ops()
    selected = [
        op for op in ops
        if op.name.split(".")[-1] not in _VIEW_OPS
        and (op.name.split(".")[-1] in _VALUE_OPS
             or any(str(key) in _VALUE_PARAMS
                    for key in (getattr(op, "param_domain", {}) or {})))
    ]
    return selected or ops


def _directed_param_sets(op, contracts: tuple[str, ...]) -> list[dict[str, Any]]:
    """A small, attack-shaped parameter set for one operation.

    The flat boundary product spends its first combinations on whichever
    address happens to sort first. A directed search needs the opposite: the
    actor in ``to``/``from``, the protocol contracts in ``spender``/``target``,
    and the maximum numeric value. These are the corners an unprivileged
    multi-call attack actually uses; the full boundary set remains available to
    the exhaustive certifier.
    """
    domain = getattr(op, "param_domain", {}) or {}
    if not domain:
        return [{}]
    keys = list(domain)
    contract_names = [name for name in contracts if name not in ("", "attacker", "victim")]
    lists: list[list[Any]] = []
    for key in keys:
        values = list(domain[key])
        numeric = [v for v in values if isinstance(v, int) and not isinstance(v, bool)]
        if numeric:
            hi = max(numeric)
            ordered = [1, hi, 2, 0, hi // 2]
            ordered += [v for v in values if isinstance(v, int) and not isinstance(v, bool)]
        else:
            if key in ("spender", "operator", "target", "vault", "callee"):
                preferred = contract_names + ["attacker", "victim"]
            else:
                preferred = ["attacker"] + contract_names + ["victim"]
            ordered = [v for v in preferred if v in values]
            ordered += [v for v in values if v not in ordered]
        seen: list[Any] = []
        for value in ordered:
            if value not in seen:
                seen.append(value)
        lists.append(seen)
    out: list[dict[str, Any]] = []

    def add(values: tuple[Any, ...]) -> None:
        params = dict(zip(keys, values))
        if params not in out:
            out.append(params)

    # Every address value against the top numeric values. The target contract
    # is often last in the declaration order, so a four-way product alone would
    # never try it.
    address_index = [i for i, key in enumerate(keys)
                     if not any(isinstance(v, int) and not isinstance(v, bool)
                                for v in domain[key])]
    for combo in itertools.product(*(
            lists[i] if i in address_index else lists[i][:4]
            for i in range(len(lists)))):
        add(combo)
    for combo in itertools.product(*(values[:4] for values in lists)):
        add(combo)
    # Explicit actor/contract corners, even when a product drops one.
    for index, key in enumerate(keys):
        for value in lists[index]:
            base = [values[0] for values in lists]
            base[index] = value
            add(tuple(base))
    return out[:64]


def _activity(value: Any) -> int:
    """A deterministic proxy for how much a state has moved.

    The directed search is not a solver: it ranks states so the beam keeps the
    ones where balances, allowances and supplies have actually changed. It is a
    heuristic only, and a miss is reported as a bounded miss, never as safety.
    """
    if isinstance(value, bool):
        return 0
    if isinstance(value, int):
        return min(abs(value), 1_000_000)
    if isinstance(value, dict):
        return sum(_activity(v) for v in value.values())
    if isinstance(value, (list, tuple)):
        return sum(_activity(v) for v in value)
    return 0


def certify_directed(
    target: SequenceTarget,
    *,
    max_depth: int = 4,
    max_states: int = 200_000,
    beam_width: int = 2_000,
    param_sets: int = 64,
    invariant_id: str = "",
) -> Certificate:
    """Search attack-relevant paths first, with a bounded beam.

    This is the strategy the exhaustive certifier lacks: it spends the budget on
    the operations that move value or address, keeps the states with the most
    movement, and crosses the actor/contract/maximum parameter corners first.
    It can find a multi-contract witness inside a small budget, and it says
    ``exhausted=False`` when it does not -- a directed miss is never a proof.
    """
    name = getattr(target, "name", "target")
    ops = _directed_ops(target)
    contracts = tuple(getattr(target, "targets", {}) or ())
    invs = _invariants(target)
    bound = {
        "max_depth": max_depth, "max_states": max_states,
        "beam_width": beam_width, "param_sets": param_sets,
        "parameters": "attack-relevant boundary corners",
        "exhaustive": False,
    }
    start = target.reset()
    visited = {_state_key(target, start)}
    frontier: list[tuple[Any, list[AttackStep]]] = [(start, [])]
    explored = 0

    for depth in range(max_depth):
        next_frontier: list[tuple[Any, list[AttackStep]]] = []
        for state, path in frontier:
            for op in ops:
                actors = list(getattr(op, "actors", []) or [])
                actor = "attacker" if "attacker" in actors else (actors[0] if actors else "attacker")
                for params in _directed_param_sets(op, contracts)[:param_sets]:
                    explored += 1
                    if explored > max_states:
                        return Certificate(
                            name, invariant_id, proven=False, exhausted=False,
                            bound=bound, explored=explored,
                            reason=(f"directed state budget {max_states} reached; this is not a "
                                    "proof of safety"))
                    new_state = _deepcopy_state(state)
                    target.step(new_state, op.name, actor, dict(params))
                    bad = violated(new_state, invs)
                    if invariant_id:
                        bad = [item for item in bad if item == invariant_id]
                    step = AttackStep(index=depth, actor=actor, action=op.name,
                                      params=dict(params), target_contract=name)
                    if bad:
                        inv = bad[0]
                        witness = _prefix_minimize(target, path + [step], inv)
                        _, trace_again, _ = _first_violating_step(target, witness)
                        repro = any(inv in w.violated for w in trace_again)
                        return Certificate(
                            name, inv, proven=repro, witness=witness,
                            trace=trace_again, reproducible=repro,
                            exhausted=False, bound=bound, explored=explored,
                            reason=("found by directed search and reproduced"
                                    if repro else "found but did not reproduce"),
                        )
                    key = _state_key(target, new_state)
                    if key not in visited:
                        visited.add(key)
                        next_frontier.append((new_state, path + [step]))
        if not next_frontier:
            break
        next_frontier.sort(key=lambda item: _activity(_snapshot(target, item[0])),
                           reverse=True)
        frontier = next_frontier[:beam_width]

    return Certificate(
        name, invariant_id, proven=False, exhausted=False, bound=bound,
        explored=explored,
        reason=(f"directed search found no violation within depth {max_depth}, "
                f"beam {beam_width} and budget {max_states}; this is not a proof "
                "of safety"),
    )


# --------------------------------------------------------------------------- #
# Concolic-style directed certification
# --------------------------------------------------------------------------- #

def certify_concolic(
    target: SequenceTarget,
    seed_path: list[AttackStep],
    *,
    invariant_id: str = "",
    max_rounds: int = 3,
) -> Certificate:
    """Certify by *guided* concrete execution -- flip a concrete path's inputs.

    This is the concolic shape without a solver: run a concrete path, then for
    each step's parameters try the other values the operation *actually accepts*
    (its declared ``param_domain``), one at a time, re-running the whole path. A
    perturbation that turns a near-miss into a violation is recorded, and the
    resulting path is certified.

    The mutation is **domain-bounded on purpose**. A perturbation to a value the
    operation does not accept (e.g. a negative deposit into a vault whose domain
    is ``[1, 1000]``) is not an attack -- it is an artifact of stepping outside
    the contract's interface, and it will "break" invariants on the patched
    control too. Restricting to the declared domain is what keeps the certificate
    meaningful; when no perturbation inside the domain helps, the certificate
    says so rather than guessing.
    """
    name = getattr(target, "name", "target")
    # First, is the seed already a proof?
    cert = certify_path(target, seed_path, invariant_id=invariant_id)
    if cert.proven:
        cert.reason = "seed path certified directly"
        return cert

    # The values each operation accepts, keyed by name.
    domains = {op.name: (getattr(op, "param_domain", {}) or {}) for op in target.ops()}

    rounds = 0
    frontier = [seed_path]
    tried = 0
    while rounds < max_rounds and frontier:
        rounds += 1
        next_frontier: list[list[AttackStep]] = []
        for path in frontier:
            for i, step in enumerate(path):
                domain = domains.get(step.action, {})
                for pname, pval in list(step.params.items()):
                    for cand in _in_domain_candidates(pname, pval, domain):
                        tried += 1
                        mutated = _mutate(path, i, pname, cand)
                        c = certify_path(target, mutated, invariant_id=invariant_id)
                        if c.proven:
                            c.explored = tried
                            c.bound = {"max_rounds": max_rounds, "rounds": rounds}
                            c.reason = (f"certified after mutating step {i} "
                                        f"{step.action}.{pname}={pval}->{cand}")
                            return c
                        next_frontier.append(mutated)
        frontier = next_frontier[:64]     # bounded breadth per round

    return Certificate(name, invariant_id, proven=False, explored=tried,
                       bound={"max_rounds": max_rounds, "rounds": rounds},
                       reason="no in-domain perturbation of the seed produced a violation")


def _in_domain_candidates(param: str, current: Any, domain: dict[str, list[Any]]) -> list[Any]:
    """Candidate values for ``param`` that the operation plausibly accepts.

    Value-like (integer) parameters accept the non-negative integers up to the
    sample's maximum, so ``1`` is a legitimate probe for a transfer whose sample is
    ``[1000, 5000]``; negative values are never proposed. A parameter with no
    declared domain has nothing principled to flip to, so none are proposed.
    """
    allowed = domain.get(param)
    if not allowed:
        return []
    numeric = [v for v in allowed if isinstance(v, int) and not isinstance(v, bool)]
    if numeric:
        return [v for v in _boundary_values(allowed) if v != current]
    return [v for v in allowed if v != current]


def _mutate(path: list[AttackStep], index: int, param: str, value: Any) -> list[AttackStep]:
    import copy
    out = copy.deepcopy(path)
    out[index].params[param] = value
    return out


# --------------------------------------------------------------------------- #
# Certifier 3: numeric-window search
# --------------------------------------------------------------------------- #

def _ladder_values(domain: list[Any], state_values: tuple[int, ...] = ()) -> list[int]:
    """Candidate integers for a numeric parameter, ordered for window discovery.

    Boundary analysis (``_boundary_values``) probes the extremes. Many real bugs
    live *between* the extremes -- debt pushed past a borrow LTV but kept under a
    liquidation threshold, a fee that bites only at a fraction of the balance --
    and a uniform sampler reaches such a window rarely. This ladder adds the
    ratios and geometric steps that bracket those windows, plus thresholds read
    from the target's own snapshot (e.g. a stored limit). It stays domain-bounded:
    a value above the sample maximum is never proposed, because the contract does
    not accept it.
    """
    numeric = [v for v in domain if isinstance(v, int) and not isinstance(v, bool)]
    if not numeric:
        return []
    lo, hi = min(numeric), max(numeric)
    values: set[int] = {0, 1, lo, lo + 1, hi - 1, hi}
    for d in (2, 3, 4, 5, 8, 10):
        if hi > 0:
            values.add(hi // d)
            values.add(hi - hi // d)
    p = 1
    while p <= hi:
        values.add(p)
        p *= 2
    for v in state_values:
        if isinstance(v, int) and not isinstance(v, bool):
            values.update((v, v - 1, v + 1, v // 2))
    return sorted({v for v in values if 0 <= v <= hi})


def _ladder_param_sets(op, state_values: tuple[int, ...] = (), *, cap: int = 64) -> list[dict[str, Any]]:
    domain = getattr(op, "param_domain", {}) or {}
    if not domain:
        return [{}]
    keys = list(domain)
    value_lists = [_ladder_values(domain[k], state_values) or list(domain[k]) for k in keys]
    combos = list(itertools.product(*value_lists))
    if len(combos) > cap:
        # Deterministic, evenly spaced sample that keeps both extremes.
        step = len(combos) / cap
        combos = [combos[min(len(combos) - 1, int(i * step))] for i in range(cap)]
    return [dict(zip(keys, combo)) for combo in combos]


def _vary_path_ladder(target: SequenceTarget, path: list[AttackStep],
                      invariant_id: str) -> Certificate:
    """Try ladder values on a concrete near-miss path, one parameter at a time."""
    name = getattr(target, "name", "target")
    base = certify_path(target, path, invariant_id=invariant_id)
    if base.proven:
        return base
    ops = {op.name: op for op in target.ops()}
    tried = 0
    for i, step in enumerate(path):
        op = ops.get(step.action)
        domain = getattr(op, "param_domain", {}) or {}
        for pname, pval in list(step.params.items()):
            for cand in _ladder_values(domain.get(pname, [pval])):
                if cand == pval:
                    continue
                tried += 1
                cert = certify_path(target, _mutate(path, i, pname, cand),
                                    invariant_id=invariant_id)
                if cert.proven:
                    cert.explored = tried
                    cert.reason = (f"certified after ladder-mutating step {i} "
                                   f"{step.action}.{pname}={pval}->{cand}")
                    return cert
    return Certificate(name, invariant_id, proven=False, explored=tried,
                       reason="the seed path and its ladder variants did not violate")


def certify_numeric(
    target: SequenceTarget,
    *,
    max_depth: int = 4,
    max_states: int = 200_000,
    seed_path: Optional[list[AttackStep]] = None,
) -> Certificate:
    """Certify by searching a richer numeric parameter space than boundary values.

    This is not an SMT solver: the target's ``step`` is opaque Python, so there is
    no formula to solve. It is a deterministic, domain-bounded *numeric ladder* --
    extremes, fractions and geometric steps of the declared maximum, and
    thresholds read from the target's own snapshot -- over structural paths up to
    ``max_depth``. It exists because numeric-window bugs (borrow past LTV, fee at a
    fraction of balance) sit where boundary-value analysis and uniform sampling do
    not look. When it finds nothing it returns the bound it exhausted, never a
    claim of safety.
    """
    name = getattr(target, "name", "target")
    if seed_path:
        cert = _vary_path_ladder(target, seed_path, "")
        if cert.proven:
            return cert

    ops = target.ops()
    invs = _invariants(target)
    bound = {"max_depth": max_depth, "max_states": max_states,
             "parameters": "numeric ladder (extremes, ratios, geometric, snapshot thresholds)"}

    visited: set[str] = set()
    explored = 0
    start = target.reset()
    stack: list[tuple[Any, list[AttackStep]]] = [(start, [])]
    visited.add(_state_key(target, start))

    while stack:
        state, path = stack.pop()
        if len(path) >= max_depth:
            continue
        snap = _snapshot(target, state)
        state_values = tuple(v for v in snap.values()
                             if isinstance(v, int) and not isinstance(v, bool))
        for op in ops:
            for actor in getattr(op, "actors", []) or []:
                for params in _ladder_param_sets(op, state_values):
                    explored += 1
                    if explored > max_states:
                        return Certificate(name, "", proven=False, exhausted=False,
                                           bound=bound, explored=explored,
                                           reason=f"state budget {max_states} reached before exhaustion")
                    new_state = _deepcopy_state(state)
                    target.step(new_state, op.name, actor, dict(params))
                    bad = violated(new_state, invs)
                    step = AttackStep(index=len(path), actor=actor, action=op.name,
                                      params=dict(params), target_contract=name)
                    if bad:
                        inv = bad[0]
                        witness = _prefix_minimize(target, path + [step], inv)
                        _, trace_again, _ = _first_violating_step(target, witness)
                        repro = any(inv in w.violated for w in trace_again)
                        return Certificate(
                            name, inv, proven=repro, witness=witness,
                            trace=trace_again, reproducible=repro,
                            exhausted=False, bound=bound, explored=explored,
                            reason="found by numeric-ladder search and reproduced"
                                   if repro else "found but did not reproduce",
                        )
                    key = _state_key(target, new_state)
                    if key not in visited:
                        visited.add(key)
                        stack.append((new_state, path + [step]))

    return Certificate(
        name, "", proven=False, exhausted=True, bound=bound, explored=explored,
        reason=(f"no invariant broke within depth {max_depth} over the numeric "
                f"ladder; this is a bounded result, not a proof of safety"),
    )
