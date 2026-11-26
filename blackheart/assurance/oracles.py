"""Oracle audit: is a declared invariant *able* to catch anything at all?

Every search in BLACKHEART -- the random fuzzer, the coverage-guided corpus
fuzzer, the adaptive explorer, the model-guided explorer, and the
bounded-exhaustive certifier -- checks a target's **declared invariants**. So the
strength of the whole engine is bounded by the strength of those oracles. A weak
oracle makes every search report "clean", and the hunter walks away from a real
bug with a green result.

The audit decides, by **direct experiment on the oracle itself**, target-agnostic,
whether each declared invariant is wired to the state at all:

  1. **Evaluation census.** Run a shallow bounded exploration (the same alphabet
     the certifier uses), evaluate the predicate on every reachable state, and
     record how often it was evaluable, how often it was false, and whether it
     ever changed value.
  2. **Mutation sensitivity.** Deep-copy each reachable state, perturb its numeric
     leaves, and ask whether the predicate ever flips. Two perturbation families
     are tried: *local* (``+1, -1, +2, *2`` -- a rounding/off-by-one/fee bug) and
     *cross-leaf* (set one leaf to a sibling's value, or to that value plus one --
     the shape of a balance-vs-withdrawn or shares-vs-underlying comparison). A
     predicate that flips under either is demonstrably tracking the state; one that
     flips under neither is reported as unable to catch a numeric bug, with the
     state paths it ignored.

It classifies each invariant into one of:

  * **DISCRIMINATING** -- some perturbation of a reachable state flips it. It can
    catch a violation, so a clean search result on it is a bounded negative.
  * **VACUOUS** -- evaluable everywhere in the sample, never false, and no
    perturbation flips it. It cannot report a violation *in the sample*.
  * **INERT** -- it fired on a sampled state, but no perturbation flips it: it
    reacts to a discrete flag or an unreached path, not to the numeric state.
  * **UNEVALUABLE** -- it raised on every state probed, so it was never checked.
  * **NO_STATES** -- no reachable state could be sampled.

**Every "weak" verdict is a bounded, sample-relative statement, and it is reported
as one.** "VACUOUS" means "vacuous within the sampled states under the tried
perturbations" -- *not* a proof that the oracle is dead. A predicate that reacts
only to a shape the perturbation families do not produce (a tuple reorder, a
string, a value reachable only at a depth beyond the sample) will be reported
weak, and that is the honest outcome: the audit could not establish it is live, so
no clean result on it may be trusted. The audit never asserts a vulnerability (that
is the verifier's job) and never claims an oracle is *good* -- only that it is
*demonstrably live* or *not demonstrably live*.

Nothing here touches a network or a real system: every state is a local value.
"""

from __future__ import annotations

import copy
import dataclasses
import itertools
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Iterator, Optional


#: Perturbations applied to each numeric leaf when probing sensitivity. Small and
#: canonical: a rounding/off-by-one/fee bug lives at ``+/-1``; ``*2`` catches a
#: predicate that only reacts to order-of-magnitude changes.
_PERTURBATIONS = ("+1", "-1", "+2", "*2")


class OracleVerdict(str, Enum):
    """What the audit could establish about one declared invariant."""

    DISCRIMINATING = "discriminating"   # flips under a reachable-state mutation
    INERT = "inert"                     # evaluable, but no mutation flips it
    VACUOUS = "vacuous"                 # evaluable everywhere, never false anywhere
    UNEVALUABLE = "unevaluable"         # raises on every state probed
    NO_STATES = "no-states"             # no reachable state could be sampled


@dataclass
class OracleFinding:
    """The audit of one declared invariant."""

    inv_id: str
    title: str = ""
    verdict: str = OracleVerdict.NO_STATES.value
    evaluations: int = 0               # states on which the predicate evaluated
    raised: int = 0                    # states on which the predicate raised
    falses: int = 0                    # states on which the predicate returned False
    ever_true: bool = False
    ever_false: bool = False
    mutation_probes: int = 0           # mutations tried across sampled states
    mutation_flips: int = 0            # mutations that flipped the predicate
    first_flip: Optional[str] = None   # "path=value" of the first flip, for the report
    ignored_paths: list[str] = field(default_factory=list)
    note: str = ""

    @property
    def trustworthy(self) -> bool:
        """True only when the oracle is *demonstrably* wired to the state.

        DISCRIMINATING means a perturbation of a reachable state flipped it, so a
        clean search result on it is a bounded negative. Any other verdict is a
        sample-relative "not shown to be live": the search's "clean" on that oracle
        cannot be read as safety, and the finding says so.
        """
        return self.verdict == OracleVerdict.DISCRIMINATING.value

    def to_dict(self) -> dict:
        return {
            "inv_id": self.inv_id,
            "title": self.title,
            "verdict": self.verdict,
            "trustworthy": self.trustworthy,
            "evaluations": self.evaluations,
            "raised": self.raised,
            "falses": self.falses,
            "ever_true": self.ever_true,
            "ever_false": self.ever_false,
            "mutation_probes": self.mutation_probes,
            "mutation_flips": self.mutation_flips,
            "first_flip": self.first_flip,
            "ignored_paths": self.ignored_paths,
            "note": self.note,
        }


@dataclass
class OracleAuditConfig:
    """Budgets for the audit. Deterministic."""

    max_depth: int = 3
    max_sequences: int = 4000
    max_states: int = 1500          # cap on sampled states fed to mutation
    max_probes_per_state: int = 200
    max_mutations_per_invariant: int = 20000
    #: Cross-leaf mutations are O(leaves^2) per state, so they get their own,
    #: smaller budget and are tried on the first few states only.
    max_cross_states: int = 40
    max_cross_mutations: int = 20000
    ignored_paths_cap: int = 12

    def to_dict(self) -> dict:
        return {
            "max_depth": self.max_depth,
            "max_sequences": self.max_sequences,
            "max_states": self.max_states,
            "max_probes_per_state": self.max_probes_per_state,
            "max_mutations_per_invariant": self.max_mutations_per_invariant,
            "max_cross_states": self.max_cross_states,
            "max_cross_mutations": self.max_cross_mutations,
            "ignored_paths_cap": self.ignored_paths_cap,
        }


@dataclass
class OracleAudit:
    """The audit of a whole target: one finding per declared invariant."""

    target: str
    states_sampled: int = 0
    numeric_paths: int = 0
    findings: list[OracleFinding] = field(default_factory=list)
    config: Optional[OracleAuditConfig] = None

    @property
    def weak(self) -> list[OracleFinding]:
        """Invariants the audit could not establish as trustworthy."""
        return [f for f in self.findings if not f.trustworthy]

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "states_sampled": self.states_sampled,
            "numeric_paths": self.numeric_paths,
            "findings": [f.to_dict() for f in self.findings],
            "weak_invariants": [f.inv_id for f in self.weak],
            "config": self.config.to_dict() if self.config else None,
        }

    def verdict_line(self) -> str:
        """The honest one sentence about the target's oracles."""
        if not self.findings:
            return "NO ORACLES: the target declares no invariant, so no search can find anything."
        weak = self.weak
        if not weak:
            return (f"ORACLES WIRED: all {len(self.findings)} declared invariant(s) "
                    f"flip under a reachable-state mutation; a clean search result is "
                    f"a bounded negative on a live oracle.")
        names = ", ".join(f.inv_id for f in weak)
        return (f"WEAK ORACLES: {len(weak)}/{len(self.findings)} declared invariant(s) "
                f"were not shown to be able to catch anything in the sample ({names}). "
                f"A clean result on these proves nothing -- strengthen the oracle or "
                f"widen the audit before trusting it.")


# --------------------------------------------------------------------------- #
# Structural walk: every numeric leaf of an arbitrary state value
# --------------------------------------------------------------------------- #

def _iter_numeric_paths(obj: Any, prefix: tuple = (), _seen: Optional[set] = None
                        ) -> Iterator[tuple]:
    """Every path to a numeric (int, non-bool) leaf in a nested state value.

    Handles dataclasses, dicts, lists, tuples and plain objects (via ``__dict__``
    or ``__slots__``) -- the shapes the engine's targets actually use -- so it is
    target-agnostic. A repeated object (a cycle, or a shared sub-object) is visited
    once by identity, so the walk always terminates; each distinct path is still a
    distinct leaf to perturb.
    """
    if _seen is None:
        _seen = set()
    if isinstance(obj, bool):
        return
    if isinstance(obj, int):
        yield prefix
        return
    if isinstance(obj, (str, bytes, type(None), float)):
        return
    if id(obj) in _seen:
        return
    if _is_dc(obj):
        _seen.add(id(obj))
        for f in dataclasses.fields(obj):
            yield from _iter_numeric_paths(getattr(obj, f.name), prefix + (f.name,), _seen)
    elif isinstance(obj, dict):
        _seen.add(id(obj))
        for k, v in obj.items():
            yield from _iter_numeric_paths(v, prefix + (k,), _seen)
    elif isinstance(obj, (list, tuple)):
        _seen.add(id(obj))
        for i, v in enumerate(obj):
            yield from _iter_numeric_paths(v, prefix + (i,), _seen)
    elif hasattr(obj, "__dict__"):
        _seen.add(id(obj))
        for k, v in vars(obj).items():
            yield from _iter_numeric_paths(v, prefix + (k,), _seen)
    elif hasattr(obj, "__slots__"):
        _seen.add(id(obj))
        for k in obj.__slots__:
            if hasattr(obj, k):
                yield from _iter_numeric_paths(getattr(obj, k), prefix + (k,), _seen)


def _get_path(obj: Any, path: tuple) -> Any:
    for p in path:
        if _is_dc(obj):
            obj = getattr(obj, p)
        elif isinstance(obj, (dict, list, tuple)):
            obj = obj[p]
        else:
            obj = getattr(obj, p)
    return obj


def _set_path(obj: Any, path: tuple, value: Any) -> None:
    parent = obj
    for p in path[:-1]:
        if _is_dc(parent):
            parent = getattr(parent, p)
        elif isinstance(parent, (dict, list, tuple)):
            parent = parent[p]
        else:
            parent = getattr(parent, p)
    last = path[-1]
    if _is_dc(parent) or isinstance(parent, (dict, list)):
        if isinstance(parent, list):
            parent[last] = value
        elif isinstance(parent, dict):
            parent[last] = value
        else:
            setattr(parent, last, value)
    else:
        setattr(parent, last, value)


def _is_dc(obj: Any) -> bool:
    return dataclasses.is_dataclass(obj) and not isinstance(obj, type)


def _perturb(value: int, how: str) -> int:
    if how == "+1":
        return value + 1
    if how == "-1":
        return value - 1
    if how == "+2":
        return value + 2
    return value * 2


# --------------------------------------------------------------------------- #
# Sampling reachable states
# --------------------------------------------------------------------------- #

def _sample_states(target: Any, config: OracleAuditConfig) -> list[Any]:
    """A deterministic, bounded sample of reachable states.

    Reuses the certifier's attack alphabet, so the audit probes the states the
    searches actually reach -- not an artificial distribution. A target with no
    declared operations still yields its initial state, so the audit is never
    silently empty.
    """
    from .certify import build_alphabet

    states: list[Any] = []
    alphabet = build_alphabet(target)
    seen_seq = 0
    for depth in range(1, config.max_depth + 1):
        for combo in itertools.product(alphabet, repeat=depth):
            if seen_seq >= config.max_sequences or len(states) >= config.max_states:
                break
            state = target.reset()
            ok = True
            for entry in combo:
                try:
                    target.step(state, entry.op, entry.actor, dict(entry.params))
                except Exception:  # noqa: BLE001 -- an invalid step is a dead branch
                    ok = False
                    break
            seen_seq += 1
            if ok:
                states.append(state)
        if seen_seq >= config.max_sequences or len(states) >= config.max_states:
            break
    if not states:
        states.append(target.reset())
    return states


# --------------------------------------------------------------------------- #
# The audit
# --------------------------------------------------------------------------- #

def audit_oracles(target: Any,
                  config: Optional[OracleAuditConfig] = None) -> OracleAudit:
    """Audit every declared invariant: can it catch anything?

    Sound and target-agnostic. For each invariant it runs two experiments --
    an evaluation census over reachable states, and a mutation-sensitivity probe
    over each state's numeric leaves -- and reports whether the oracle is
    discriminating, inert, vacuous, or unevaluable. It never asserts a
    vulnerability; it reports whether the *oracle* is capable of one.
    """
    cfg = config or OracleAuditConfig()
    name = getattr(target, "name", "target")
    audit = OracleAudit(target=name, config=cfg)

    invs = list(target.invariants())
    if not invs:
        return audit

    states = _sample_states(target, cfg)
    audit.states_sampled = len(states)

    numeric_paths: set[tuple] = set()
    for st in states:
        for path in _iter_numeric_paths(st):
            numeric_paths.add(path)
    audit.numeric_paths = len(numeric_paths)

    for inv in invs:
        audit.findings.append(_audit_one(target, inv, states, cfg))
    return audit


def _audit_one(target: Any, inv: Any, states: list[Any],
               cfg: OracleAuditConfig) -> OracleFinding:
    finding = OracleFinding(inv_id=inv.inv_id, title=getattr(inv, "title", ""))

    # --- Experiment 1: evaluation census ---------------------------------- #
    for st in states:
        try:
            result = bool(inv.predicate(st))
        except Exception:  # noqa: BLE001 -- an un-evaluable predicate is the finding
            finding.raised += 1
            continue
        finding.evaluations += 1
        if result:
            finding.ever_true = True
        else:
            finding.ever_false = True
            finding.falses += 1

    # A predicate that raises on *every* state is not checked at all.
    if finding.evaluations == 0:
        finding.verdict = OracleVerdict.UNEVALUABLE.value
        finding.note = (f"raised on all {finding.raised} states probed; the engine "
                        f"treats it as holding, so it never fires")
        return finding

    # --- Experiment 2: mutation sensitivity ------------------------------- #
    ignored: set[tuple] = set()
    for st in states:
        if finding.mutation_flips:
            break
        if finding.mutation_probes >= cfg.max_mutations_per_invariant:
            break
        paths = list(_iter_numeric_paths(st))[:cfg.max_probes_per_state]
        for path in paths:
            if finding.mutation_probes >= cfg.max_mutations_per_invariant:
                break
            try:
                cur = _get_path(st, path)
            except Exception:  # noqa: BLE001
                continue
            if not isinstance(cur, int) or isinstance(cur, bool):
                continue
            flipped = False
            for how in _PERTURBATIONS:
                if finding.mutation_probes >= cfg.max_mutations_per_invariant:
                    break
                mutant = copy.deepcopy(st)
                try:
                    _set_path(mutant, path, _perturb(cur, how))
                except Exception:  # noqa: BLE001 -- an immutable leaf cannot be perturbed
                    continue
                finding.mutation_probes += 1
                try:
                    if not bool(inv.predicate(mutant)):
                        finding.mutation_flips += 1
                        flipped = True
                        if finding.first_flip is None:
                            finding.first_flip = f"{'.'.join(map(str, path))}={_perturb(cur, how)}"
                        break
                except Exception:  # noqa: BLE001 -- a raise is not a flip
                    continue
            if not flipped:
                ignored.add(path)

    # --- Experiment 2b: cross-leaf sensitivity ---------------------------- #
    # A comparison invariant (``withdrawn <= balance``, ``shares * price >=
    # underlying``) is immune to a *local* perturbation of either side but flips
    # when one side is set to the other's value. O(leaves^2) per state, so it is
    # tried on a bounded prefix of the sampled states.
    cross_budget = cfg.max_cross_mutations
    for st in states[:cfg.max_cross_states]:
        if finding.mutation_flips or cross_budget <= 0:
            break
        paths = [p for p in _iter_numeric_paths(st)
                 if isinstance(_get_path(st, p), int) and not isinstance(_get_path(st, p), bool)]
        paths = paths[:cfg.max_probes_per_state]
        values = {p: _get_path(st, p) for p in paths}
        for path in paths:
            if finding.mutation_flips or cross_budget <= 0:
                break
            for other in paths:
                if other == path or cross_budget <= 0:
                    continue
                for new in (values[other], values[other] + 1):
                    if cross_budget <= 0:
                        break
                    mutant = copy.deepcopy(st)
                    try:
                        _set_path(mutant, path, new)
                    except Exception:  # noqa: BLE001
                        continue
                    finding.mutation_probes += 1
                    cross_budget -= 1
                    try:
                        if not bool(inv.predicate(mutant)):
                            finding.mutation_flips += 1
                            if finding.first_flip is None:
                                finding.first_flip = (
                                    f"{'.'.join(map(str, path))}={new} "
                                    f"(cross-leaf from {'.'.join(map(str, other))})")
                            break
                    except Exception:  # noqa: BLE001 -- a raise is not a flip
                        continue
            if finding.mutation_flips:
                break

    if finding.mutation_flips:
        finding.verdict = OracleVerdict.DISCRIMINATING.value
        return finding

    # Nothing tried flips the predicate. This is a *sample-relative* statement: the
    # oracle was not shown to be live, under the sampled states and the tried
    # perturbations. Report it as such, never as proof the oracle is dead.
    finding.ignored_paths = [".".join(map(str, p)) for p in
                             sorted(ignored, key=lambda p: tuple(map(str, p)))[:cfg.ignored_paths_cap]]
    if not finding.ever_false:
        finding.verdict = OracleVerdict.VACUOUS.value
        finding.note = (f"evaluable on all {finding.evaluations} sampled states and "
                        f"false on none; no local or cross-leaf perturbation of any "
                        f"sampled state flips it. It was NOT shown to be able to "
                        f"report a violation, so a clean result on it is not evidence "
                        f"of safety. (Bounded: a shape outside the tried perturbations "
                        f"or a depth beyond the sample may still flip it.)")
    else:
        finding.verdict = OracleVerdict.INERT.value
        finding.note = (f"fired on {finding.falses} sampled state(s) but no local or "
                        f"cross-leaf perturbation flips it; treat as an oracle that "
                        f"reacts to a non-numeric flag or a path beyond the sample. "
                        f"(Bounded: not shown to be dead, only not shown to be live.)")
    return finding
