"""Bounded-exhaustive certification: prove the *absence* of a bug, up to a bound.

Every other search in BLACKHEART -- the random fuzzer, the coverage-guided
corpus fuzzer, the adaptive explorer, the model-guided explorer -- is
*incomplete*: it samples a space, and a negative result means only "not found
within budget". None of them can honestly say "there is no bug here". The only
way to say that is to enumerate the entire space and run all of it.

This module does exactly that, and *only* that. It enumerates **every sequence**
of length 1..D over a target's declared attack alphabet (operations x the actors
allowed to invoke them x the distinct parameter assignments), runs each one, and
checks every declared invariant. Because it is exhaustive, its result is a
statement the stochastic searches cannot make:

  * if it finds a violating sequence, that is a *length-optimal* counterexample
    (the shortest one in the alphabet, because it is discovered breadth-first);
  * if it finds nothing, then **no declared invariant is broken by any sequence
    of length <= D over the declared alphabet** -- and the certificate says so
    verbatim, with the exact space size it covered.

Two enumeration methods, chosen automatically and reported on the certificate:

  * **state-dedup** -- for a target that declares a self-contained state
    (``state_is_isolated``), the *state space* is explored breadth-first and a
    state already reached is never re-expanded, because the target's future
    depends only on its state. This is sound (a violation is a function of state)
    and it collapses the sequence explosion, so a deeper bound is affordable. If
    the reachable state space closes before the depth bound, the certificate is
    then complete for **every** sequence length, not merely the bound.
  * **sequences** -- for any other target (a real-runtime adapter with external
    effects), every sequence is enumerated in full. This is the reference
    semantics the state-dedup path is asserted equal to.

It is equally honest about the bound. A clean certificate is **not** a proof that
the target is secure. It says nothing about:
  * bugs that need a sequence *longer* than D (unless the state space closed);
  * operations or parameter values *outside* the declared alphabet;
  * properties that are not expressed as a declared invariant.

Those three limits are printed on the certificate itself, so a clean result can
never be mistaken for "no bugs". The doctrine: a *bounded-exhaustive* search is
the only search allowed to return "no counterexample found"; the *stochastic*
searches are never allowed to say more than "not found within budget".

Nothing here touches a network or a real system: it drives a local ``Target``.
"""

from __future__ import annotations

import copy
import dataclasses
import itertools
from dataclasses import dataclass, field
from typing import Any, Iterator, Optional

from ..invariants.engine import partition
from ..models import AttackStep
from ..value import analyse

#: Cap on distinct parameter assignments kept per operation. A domain can be
#: large (or unbounded); the alphabet is the *declared* interesting values, so
#: the cap keeps the space finite without silently dropping the declared min/max.
DEFAULT_MAX_ASSIGNMENTS = 8


@dataclass
class CertifyConfig:
    """Budgets for the bounded-exhaustive search. Deterministic."""

    #: Maximum sequence length enumerated. The certificate is exact to this depth.
    max_depth: int = 3
    #: Distinct parameter assignments kept per operation (min/max/interesting).
    max_assignments: int = DEFAULT_MAX_ASSIGNMENTS
    #: Hard cap on sequences executed, so a large alphabet cannot run away.
    max_sequences: int = 200_000
    #: Price each counterexample with the universal value engine.
    price_findings: bool = True
    #: Restrict to these invariant ids (empty = every declared invariant).
    invariant_filter: tuple[str, ...] = ()
    #: Per-invariant counterexample cap (shortest first).
    max_failures_per_invariant: int = 3

    def to_dict(self) -> dict:
        return {
            "max_depth": self.max_depth,
            "max_assignments": self.max_assignments,
            "max_sequences": self.max_sequences,
            "price_findings": self.price_findings,
            "invariant_filter": list(self.invariant_filter),
            "max_failures_per_invariant": self.max_failures_per_invariant,
        }


@dataclass
class AlphabetEntry:
    """One symbol of the attack alphabet: an actor invoking an operation."""

    actor: str
    op: str
    params: dict[str, Any]

    def to_dict(self) -> dict:
        return {"actor": self.actor, "op": self.op, "params": dict(self.params)}


@dataclass
class CoverageCertificate:
    """What the bounded-exhaustive search covered, and what it found.

    ``complete_to_depth`` is the depth to which the space was *fully* explored.
    ``exhaustive`` is true only when that depth equals the requested ``max_depth``
    with no truncation -- i.e. the space really was covered. A certificate is the
    only result allowed to assert "no counterexample exists" (up to the bound).
    """

    target: str
    alphabet_size: int = 0
    alphabet: list[dict] = field(default_factory=list)
    max_depth: int = 0
    complete_to_depth: int = 0
    sequences_tested: int = 0
    sequences_in_space: int = 0
    exhaustive: bool = False
    truncated_reason: str = ""
    #: ``"state-dedup"`` when the target declared isolated state and the *state*
    #: space was explored (``sequences_tested`` then counts step-executions, and
    #: ``states_reached`` the distinct states); ``"sequences"`` when every sequence
    #: was enumerated in full (``sequences_tested`` counts sequences).
    method: str = "sequences"
    states_reached: int = 0
    #: True when the reachable state space closed before the depth bound, so the
    #: result is complete for *every* sequence length, not merely the bound.
    complete_for_all_depths: bool = False
    per_invariant: dict[str, int] = field(default_factory=dict)
    #: Invariants whose predicate raised on a reached state. Non-empty voids the
    #: completeness claim: the space was enumerated, but some invariant could not
    #: be evaluated over it, so "no counterexample exists" was never established.
    unevaluable: list[str] = field(default_factory=list)
    violations: list[dict] = field(default_factory=list)
    economic: list[dict] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    #: The source/model coverage ledger. ``complete=False`` means the alphabet
    #: itself is incomplete, so a clean search is not a clean target.
    model_coverage: dict = field(default_factory=dict)

    @property
    def broke(self) -> bool:
        return bool(self.violations)

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "alphabet_size": self.alphabet_size,
            "alphabet": self.alphabet,
            "max_depth": self.max_depth,
            "complete_to_depth": self.complete_to_depth,
            "sequences_tested": self.sequences_tested,
            "sequences_in_space": self.sequences_in_space,
            "exhaustive": self.exhaustive,
            "truncated_reason": self.truncated_reason,
            "method": self.method,
            "states_reached": self.states_reached,
            "complete_for_all_depths": self.complete_for_all_depths,
            "per_invariant": self.per_invariant,
            "unevaluable": list(self.unevaluable),
            "violations": self.violations,
            "economic": self.economic,
            "notes": self.notes,
            "model_coverage": dict(self.model_coverage),
        }

    def verdict_line(self) -> str:
        """The one honest sentence the certificate entitles us to state."""
        if self.broke:
            n = len(self.violations)
            return (
                f"BROKEN: {n} length-optimal counterexample(s) found within "
                f"{self.sequences_tested} sequences (depth <= {self.complete_to_depth})."
            )
        if self.unevaluable:
            return (
                f"INCOMPLETE: the space was enumerated to depth "
                f"{self.complete_to_depth}, but {len(self.unevaluable)} declared "
                f"invariant(s) could not be evaluated on reached states "
                f"({', '.join(self.unevaluable)}). No completeness claim is made "
                f"for them -- this is 'could not tell', not 'clean'."
            )
        if self.model_coverage and not self.model_coverage.get("complete", True):
            gaps = self.model_coverage.get("gaps") or []
            first = gaps[0] if gaps else {}
            where = f"{first.get('path', '')}:{first.get('line', '')}"
            what = (first.get("statement") or first.get("callee_op")
                    or first.get("name") or "unknown")
            stopped = ("the search exhausted its bound"
                       if self.exhaustive else
                       "the search stopped without a counterexample")
            return (
                f"INCOMPLETE MODEL COVERAGE: {stopped}, but "
                f"{len(gaps)} reachable item(s) are outside the model; first at "
                f"{where} ({first.get('kind', 'gap')}: {what}). A clean search is "
                f"not a clean target -- model the gap before trusting a negative."
            )
        if self.exhaustive:
            if self.complete_for_all_depths:
                return (
                    f"CERTIFIED CLEAN for ALL sequence lengths: no declared invariant "
                    f"is broken by any reachable sequence, over the declared alphabet "
                    f"of {self.alphabet_size} symbols (the reachable state space "
                    f"closed at {self.states_reached} distinct states). This does NOT "
                    f"cover undeclared operations/parameters or undeclared properties."
                )
            return (
                f"CERTIFIED CLEAN to depth {self.complete_to_depth}: no declared "
                f"invariant is broken by any of the {self.sequences_in_space} sequences "
                f"of length <= {self.complete_to_depth} over the declared alphabet "
                f"(of {self.alphabet_size} symbols). This does NOT cover longer "
                f"sequences, undeclared operations/parameters, or undeclared properties."
            )
        return (
            f"INCONCLUSIVE: the space was not fully explored (stopped at depth "
            f"{self.complete_to_depth}: {self.truncated_reason}). No counterexample "
            f"found in the {self.sequences_tested} sequences tested -- this is "
            f"'not found within budget', not a proof of absence."
        )


def _boundary_values(domain: list[Any], cap: int) -> list[Any]:
    """The distinct parameter values worth enumerating for one op parameter.

    The declared min and max are always kept (a boundary bug lives there); a
    deterministic set of canonical small values (0, 1, 2) is added because an
    off-by-one / rounding / fee bug lives there and a declared domain may not list
    them; a middle value rounds it out. Capped so the alphabet stays finite.
    """
    if not domain:
        return [None]
    numeric = [v for v in domain if isinstance(v, int) and not isinstance(v, bool)]
    if not numeric:
        # Non-numeric domain: keep the declared values, capped.
        seen: list[Any] = []
        for v in domain:
            if v not in seen:
                seen.append(v)
        return seen[:cap] or [domain[0]]
    lo, hi = min(numeric), max(numeric)
    out: list[Any] = []
    for v in [lo, hi, 0, 1, 2]:
        if v not in out and lo <= v <= hi:
            out.append(v)
    mid = sorted(set(numeric))[len(set(numeric)) // 2]
    if mid not in out:
        out.append(mid)
    return out[:cap]


def build_alphabet(target: Any, max_assignments: int = DEFAULT_MAX_ASSIGNMENTS
                   ) -> list[AlphabetEntry]:
    """The declared attack alphabet: every reachable (actor, op, params) symbol.

    A symbol is an operation invoked by an actor *allowed* to invoke it (per the
    op's declared ``actors``; an op with no declared actors is assumed invokable
    by the unprivileged ``attacker``, matching the rest of the engine). Each
    parameter takes its boundary values, and the per-symbol assignments are the
    cartesian product, capped. The result is a finite, deterministic alphabet.
    """
    alphabet: list[AlphabetEntry] = []
    for op in target.ops():
        actors = list(getattr(op, "actors", []) or ["attacker"])
        domain = getattr(op, "param_domain", {}) or {}
        names = list(domain.keys())
        value_lists = [_boundary_values(domain[n], max_assignments) for n in names]
        if not names:
            combos: list[dict[str, Any]] = [{}]
        else:
            combos = [dict(zip(names, vals)) for vals in itertools.product(*value_lists)]
            combos = combos[:max_assignments]
        for actor in actors:
            for params in combos:
                alphabet.append(AlphabetEntry(actor=actor, op=op.name, params=params))
    # Deterministic order (stable, so a run is reproducible and diffable).
    alphabet.sort(key=lambda e: (e.actor, e.op, tuple(sorted(e.params.items(), key=str))))
    return alphabet


def _sequence_of(symbols: list[AlphabetEntry], target_name: str) -> list[AttackStep]:
    return [
        AttackStep(index=i, actor=s.actor, action=s.op, params=dict(s.params),
                   target_contract=target_name)
        for i, s in enumerate(symbols)
    ]


def _enumerate(alphabet: list[AlphabetEntry], depth: int) -> Iterator[list[AlphabetEntry]]:
    """Every sequence of exactly ``depth`` symbols, in a deterministic order."""
    for combo in itertools.product(alphabet, repeat=depth):
        yield list(combo)


def _check(target: Any, state: Any, invs: list[Any]) -> tuple[set[str], set[str]]:
    """Split ``state`` into (violated, unevaluable) invariant ids.

    An unevaluable predicate is not a hit -- but it is not a pass either. The
    second set is carried to the certificate, which refuses its completeness
    claim while it is non-empty.
    """
    bad, unknown = partition(state, invs)
    return set(bad), set(unknown)


def _replay(target: Any, symbols: list[AlphabetEntry],
            invs: list[Any]) -> tuple[Any, set[str], set[str]]:
    """Run ``symbols`` from a fresh state; return the final state and violations.

    Checks every invariant after every step, so a violation that is transient (a
    state that breaks and then recovers) is still caught. This is the reference
    semantics the prefix-reuse fast path must reproduce exactly.
    """
    state = target.reset()
    bad: set[str] = set()
    unknown: set[str] = set()
    for s in symbols:
        try:
            target.step(state, s.op, s.actor, dict(s.params))
        except Exception:  # noqa: BLE001 -- an invalid step is a dead branch
            continue
        bad_step, unknown_step = _check(target, state, invs)
        bad |= bad_step
        unknown |= unknown_step
    return state, bad, unknown


def _supports_state_dedup(target: Any) -> bool:
    """True when the target declares a self-contained state, so dedup is sound.

    A target that opts in (via ``state_is_isolated``) reads and writes only its
    state argument, so the final state of a sequence is a pure function of the
    sequence -- which means a search that *deduplicates states* still reaches
    exactly the same set of states, and a violation (a function of state) is never
    lost. A real-runtime adapter never opts in, so it always enumerates sequences
    in full. Dedup is a pure optimisation: the differential test asserts the
    deduplicated and full-enumeration certificates are identical.
    """
    fn = getattr(target, "state_is_isolated", None)
    try:
        return bool(fn()) if callable(fn) else False
    except Exception:  # noqa: BLE001 -- a target that errors on the probe enumerates in full
        return False


def _state_key(state: Any) -> Any:
    """A hashable canonical key for a state value (dataclass/dict/list/scalar).

    Two structurally equal states hash identically, so the frontier collapses to
    the distinct states. Only ever used when the target declares isolated state.
    """
    if isinstance(state, bool) or state is None or isinstance(state, (int, str, float)):
        return state
    if dataclasses.is_dataclass(state) and not isinstance(state, type):
        return (type(state).__name__,
                tuple((f.name, _state_key(getattr(state, f.name))) for f in dataclasses.fields(state)))
    if isinstance(state, dict):
        return tuple(sorted((str(k), _state_key(v)) for k, v in state.items()))
    if isinstance(state, (list, tuple)):
        return tuple(_state_key(v) for v in state)
    return repr(state)


def certify(target: Any, config: Optional[CertifyConfig] = None) -> CoverageCertificate:
    """Exhaustively enumerate the attack space up to ``max_depth`` and check it.

    Runs every sequence of length 1..max_depth over the declared alphabet against
    the target, breadth-first (so a found counterexample is length-optimal), and
    returns a :class:`CoverageCertificate` stating exactly what was covered and
    what was found. Honest by construction: it never claims more than the bound.

    When the target declares isolated state, the *state space* is explored instead
    of the raw sequence space: a state already reached at a shorter or equal
    sequence length is never expanded again, because the target's future depends
    only on its state. This is sound (a violation is a function of state, so no
    violation is lost) and it is what makes a deeper bound affordable -- it is a
    pure optimisation, and the differential test asserts the certificate is
    identical to the full sequence enumeration.
    """
    cfg = config or CertifyConfig()
    name = getattr(target, "name", "target")
    cert = CoverageCertificate(target=name, max_depth=cfg.max_depth)
    try:
        from ..ingest.model_coverage import coverage_for_target

        cert.model_coverage = coverage_for_target(target).to_dict()
    except Exception:  # noqa: BLE001 -- a coverage failure must not fake completeness
        cert.model_coverage = {"available": False, "complete": False,
                               "gaps": [{"kind": "coverage_error",
                                         "reason": "model coverage could not be read"}],
                               "notes": ["model coverage could not be read"]}

    alphabet = build_alphabet(target, cfg.max_assignments)
    cert.alphabet = [e.to_dict() for e in alphabet]
    cert.alphabet_size = len(alphabet)

    if not alphabet:
        cert.notes.append("target declares no operations; nothing to enumerate")
        cert.truncated_reason = "empty alphabet"
        return cert

    invs = target.invariants()
    if cfg.invariant_filter:
        keep = set(cfg.invariant_filter)
        invs = [i for i in invs if i.inv_id in keep]

    if _supports_state_dedup(target):
        cert.method = "state-dedup"
        _certify_states(target, cert, cfg, alphabet, invs)
    else:
        cert.method = "sequences"
        _certify_sequences(target, cert, cfg, alphabet, invs)

    cert.sequences_in_space = sum(cert.alphabet_size ** d
                                  for d in range(1, cert.complete_to_depth + 1))
    cert.exhaustive = (cert.complete_to_depth == cfg.max_depth) and not cert.truncated_reason
    if cert.unevaluable:
        cert.notes.append(
            f"{len(cert.unevaluable)} invariant(s) could not be evaluated on reached "
            f"states ({', '.join(cert.unevaluable)}); the certificate makes no "
            f"completeness claim for them"
        )
    if not cert.violations:
        cert.notes.append(
            "no declared invariant broken within the enumerated bound; see the "
            "bound's limits on the certificate before reading this as secure"
        )
    return cert


def _record_violation(cert: CoverageCertificate, cfg: CertifyConfig, target: Any,
                      inv_id: str, symbols: list[AlphabetEntry], state: Any,
                      seen_failures: set[tuple], name: str) -> None:
    cert.per_invariant[inv_id] = cert.per_invariant.get(inv_id, 0) + 1
    if len([v for v in cert.violations if v["invariant_id"] == inv_id]) \
            >= cfg.max_failures_per_invariant:
        return
    key = (inv_id, tuple((s.actor, s.op) for s in symbols))
    if key in seen_failures:
        return
    seen_failures.add(key)
    # Breadth-first: the first time we see this invariant, this is the shortest
    # sequence that breaks it, so it is already length-optimal.
    steps = _sequence_of(symbols, name)
    entry: dict[str, Any] = {
        "invariant_id": inv_id,
        "minimal_sequence": [s.to_dict() for s in steps],
        "length": len(steps),
        "observed": target.snapshot(state),
        "reachable_by_attacker": any(s.actor == "attacker" for s in steps),
    }
    if cfg.price_findings:
        acct = analyse(target, steps, inv_id, name)
        entry["economic"] = acct.to_dict()
        cert.economic.append(acct.to_dict())
    cert.violations.append(entry)


def _certify_states(target: Any, cert: CoverageCertificate, cfg: CertifyConfig,
                    alphabet: list[AlphabetEntry], invs: list[Any]) -> None:
    """Breadth-first exploration of the *state* space (isolated targets only).

    The frontier holds distinct states at the current depth; a state already seen
    at a shorter-or-equal length is never re-expanded, because the target's future
    depends only on its state. Each frontier entry carries the shortest symbol
    sequence that reaches it, so a found counterexample is length-optimal. The
    initial state is checked, so a depth-0 violation (a target that starts broken)
    is reported too.
    """
    name = getattr(target, "name", "target")
    seen_failures: set[tuple] = set()
    start = target.reset()
    seen = {_state_key(start)}
    frontier: list[tuple[Any, list[AlphabetEntry]]] = [(start, [])]
    cert.states_reached = 1

    start_bad, start_unknown = _check(target, start, invs)
    for inv_id in sorted(start_unknown):
        if inv_id not in cert.unevaluable:
            cert.unevaluable.append(inv_id)
    for inv_id in sorted(start_bad):
        _record_violation(cert, cfg, target, inv_id, [], start, seen_failures, name)

    for depth in range(1, cfg.max_depth + 1):
        nxt: list[tuple[Any, list[AlphabetEntry]]] = []
        budget_hit = False
        for state, seq in frontier:
            for entry in alphabet:
                if cert.sequences_tested >= cfg.max_sequences:
                    budget_hit = True
                    break
                child = copy.deepcopy(state)
                cert.sequences_tested += 1
                try:
                    target.step(child, entry.op, entry.actor, dict(entry.params))
                except Exception:  # noqa: BLE001 -- an invalid step is a dead branch
                    continue
                child_seq = seq + [entry]
                child_bad, child_unknown = _check(target, child, invs)
                for inv_id in sorted(child_unknown):
                    if inv_id not in cert.unevaluable:
                        cert.unevaluable.append(inv_id)
                for inv_id in sorted(child_bad):
                    _record_violation(cert, cfg, target, inv_id, child_seq, child,
                                      seen_failures, name)
                key = _state_key(child)
                if key in seen:
                    continue
                seen.add(key)
                cert.states_reached = len(seen)
                nxt.append((child, child_seq))
            if budget_hit:
                break
        if budget_hit:
            cert.truncated_reason = (
                f"sequence budget {cfg.max_sequences} reached at depth {depth}")
            return
        frontier = nxt
        cert.complete_to_depth = depth
        if not frontier:
            # The reachable state space is closed before the depth bound: every
            # sequence of any length leads only to states already enumerated, so
            # the certificate is complete for *all* depths, not merely this one.
            cert.complete_to_depth = cfg.max_depth
            cert.complete_for_all_depths = True
            cert.notes.append(
                f"the reachable state space closed at depth {depth} "
                f"({len(seen)} distinct states); the result is complete for all "
                f"sequence lengths, not only the bound")
            return


def _certify_sequences(target: Any, cert: CoverageCertificate, cfg: CertifyConfig,
                       alphabet: list[AlphabetEntry], invs: list[Any]) -> None:
    """Full enumeration of every sequence of length 1..max_depth (the reference path).

    Used for any target that does not declare isolated state (a real-runtime
    adapter with external effects). It is the reference semantics the state-dedup
    fast path must reproduce exactly.
    """
    name = getattr(target, "name", "target")
    seen_failures: set[tuple] = set()
    for depth in range(1, cfg.max_depth + 1):
        budget_hit = False
        for symbols in _enumerate(alphabet, depth):
            if cert.sequences_tested >= cfg.max_sequences:
                budget_hit = True
                break
            state, violated, unknown = _replay(target, symbols, invs)
            cert.sequences_tested += 1
            for inv_id in sorted(unknown):
                if inv_id not in cert.unevaluable:
                    cert.unevaluable.append(inv_id)
            for inv_id in sorted(violated):
                _record_violation(cert, cfg, target, inv_id, symbols, state,
                                  seen_failures, name)
        if budget_hit:
            cert.truncated_reason = (
                f"sequence budget {cfg.max_sequences} reached at depth {depth}")
            return
        cert.complete_to_depth = depth
