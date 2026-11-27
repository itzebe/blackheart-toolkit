"""Coverage-guided corpus fuzzer -- the mutation engine.

The engine already had two search strategies: the state-space explorer, which
*enumerates* sequences by depth, and the random stateful fuzzer, which *samples*
them blind. Both are honest and both work; neither *learns from the target*.
Enumeration is exponential in depth and is diluted by decoy operations; a blind
random walk throws away every sequence that made progress toward a state it had
not reached yet. The strongest hunters in the field -- AFL, Echidna, Medusa --
beat both with the same idea: keep the inputs that reached new behaviour, and
mutate those, spending more energy where the target is most responsive.

This module brings that idea to BLACKHEART, universally:

  * **Corpus.** A pool of sequences that each contributed new *behavioural*
    coverage (see :mod:`blackheart.fuzz.coverage`). Nothing else is kept, so the
    corpus is a curated set of "inputs that taught us something".
  * **Deterministic coverage-beam growth.** Before havoc runs, the deepest-
    reaching prefixes are extended *one operation at a time*, keeping only the
    children that gained the most new coverage. This is what crosses an *ordered*
    state gate (register -> verify -> ... -> withdraw): a mid-sequence change in
    havoc destroys the prefix that already reached the deep state, so only an
    append can make progress, and the beam performs exactly those appends. It
    reaches an N-step ordered bug in ~N rounds instead of a blind search over the
    operation alphabet.
  * **Power schedule.** Energy is allocated AFL-style: an entry that is the sole
    source of some coverage bucket is *favoured* and mutated more; energy decays
    with the entry's age so the search does not stall on one promising input.
  * **Mutation operators.** A step is inserted, deleted, swapped, duplicated, or
    has its operation, actor, or a numeric parameter changed; two corpus entries
    are spliced (crossover). Every operator is structure-preserving against the
    target's declared ``OpSpec`` (an actor is only ever substituted for one that
    can actually invoke the operation), so the budget is spent on *reachable*
    sequences rather than on ones the target rejects.
  * **Determinism.** The whole search is driven by a seeded RNG and never reads
    the wall clock for a decision, so a run is exactly reproducible from its seed
    -- the property the rest of the engine already guarantees.

It reuses the existing, tested machinery rather than re-deriving it: the
``Target`` protocol and ``OpSpec``/``InvariantSpec`` from the invariant engine,
the delta-debugging minimiser, and the universal value engine
(:mod:`blackheart.value`) to price every hit. A "finding" here is a minimal,
attacker-reachable sequence that breaks a stated invariant *and* carries its
economic account -- the same shape every other engine reports.

Nothing here touches a network or a real system: it drives a local ``Target``.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from typing import Any, Optional

from ..invariants.engine import (
    InvariantFailure,
    unevaluable,
    _Budget,
    _minimize_ops,
    _minimize_values,
    _reachable_by_attacker,
)
from ..models import AttackStep
from ..value import analyse
from .coverage import CoverageMap, behaviour_features


# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #

@dataclass
class CorpusConfig:
    """Budgets and knobs for the coverage-guided search. Deterministic."""

    seed: int = 0
    #: Total candidate sequences to execute before the budget ends. The fair unit
    #: of comparison against the random fuzzer and the enumerating explorer.
    max_sequences: int = 2000
    #: Cap on a single sequence's length. Mutation never exceeds it.
    max_steps: int = 12
    #: Length of the initial random seeds (before mutation takes over).
    seed_length: int = 4
    #: How many fresh random seeds to plant before mutating the corpus.
    initial_seeds: int = 64
    #: Maximum corpus entries retained (memory bound). The least-valuable entry is
    #: evicted when full.
    max_corpus: int = 512
    #: Width of the deterministic coverage beam: how many best-gaining prefixes
    #: survive each growth round. Wide enough to keep alternatives, narrow enough
    #: that the growth phase does not exhaust the budget before havoc runs.
    beam_width: int = 8
    #: Per-invariant failure cap, matching the rest of the engine.
    max_failures_per_invariant: int = 3
    #: Target re-runs allowed per minimisation.
    minimize_budget: int = 300
    #: Shrink numeric parameters after op-minimisation (matches the fuzzer).
    shrink_values: bool = True
    #: Price each hit with the universal value engine (attacker profit, victim
    #: loss, repeatability). On by default; the account is what turns a broken
    #: invariant into a financial finding.
    price_findings: bool = True
    #: Extra seed sequences (e.g. model-guided hypotheses) planted before fuzzing.
    extra_seeds: list[list[AttackStep]] = field(default_factory=list)


# --------------------------------------------------------------------------- #
# Corpus entry
# --------------------------------------------------------------------------- #

@dataclass
class CorpusEntry:
    """One retained input: a sequence that reached new behaviour."""

    sequence: list[AttackStep]
    #: Total coverage buckets this entry was the first to reach (its "finds").
    finds: int = 0
    #: How many times it has been chosen for mutation (energy decays with this).
    picks: int = 0
    #: Its own coverage buckets, kept so a splice partner can be chosen and so
    #: energy can be recomputed without re-running the target.
    buckets: list[int] = field(default_factory=list)
    depth: int = 0

    @property
    def energy(self) -> float:
        """AFL-style energy: favoured entries get more, stale entries get less.

        ``finds`` rewards an input that opened new behaviour; ``picks`` is a
        decay so the search keeps moving instead of re-mutating one early hit
        forever. The constant keeps an entry with zero finds (a pure splice
        donor) from being starved entirely.
        """
        return (1.0 + self.finds) / (1.0 + self.picks)


# --------------------------------------------------------------------------- #
# Mutation
# --------------------------------------------------------------------------- #

def _all_ops(target: Any) -> list[Any]:
    return list(target.ops())


def _ops_for_actor(target: Any, actor: str) -> list[Any]:
    return [o for o in _all_ops(target) if not o.actors or actor in o.actors]


def _actors_for_op(target: Any, op_name: str) -> list[str]:
    for o in _all_ops(target):
        if o.name == op_name:
            return list(o.actors) or ["attacker"]
    return ["attacker"]


def _boundary_values(domain: list[Any]) -> list[Any]:
    """The parameter values worth trying for one op parameter.

    Mirrors the explorer's boundary discipline: the smallest, the largest, and a
    mid value, so a mutation lands on an *interesting* amount rather than a
    random integer. Non-numeric domains are passed through unchanged.
    """
    nums = [v for v in domain if isinstance(v, int) and not isinstance(v, bool)]
    if not nums:
        return list(domain)
    out = sorted({min(nums), max(nums)})
    mid = sorted(nums)[len(nums) // 2]
    if mid not in out:
        out.append(mid)
    return out


def _random_step(target: Any, rng: random.Random, index: int) -> AttackStep:
    ops = _all_ops(target)
    op = rng.choice(ops)
    actors = list(op.actors) or ["attacker"]
    actor = rng.choice(actors)
    params: dict[str, Any] = {}
    for key, domain in (getattr(op, "param_domain", {}) or {}).items():
        choices = _boundary_values(domain) or [0]
        params[key] = rng.choice(choices)
    return AttackStep(index=index, actor=actor, action=op.name, params=params,
                      target_contract=getattr(target, "name", "target"),
                      expected_effect=op.description)


def _random_sequence(target: Any, rng: random.Random, length: int) -> list[AttackStep]:
    return [_random_step(target, rng, i) for i in range(length)]


def _reindex(seq: list[AttackStep]) -> list[AttackStep]:
    return [AttackStep(index=i, actor=s.actor, action=s.action, params=dict(s.params),
                       target_contract=s.target_contract,
                       expected_effect=s.expected_effect)
            for i, s in enumerate(seq)]


def _key(seq: list[AttackStep]) -> tuple:
    """Total, deterministic order key for a sequence (used to break ties)."""
    return tuple((s.actor, s.action, tuple(sorted(s.params.items()))) for s in seq)


def mutate(target: Any, seq: list[AttackStep], rng: random.Random,
           max_steps: int, corpus: list["CorpusEntry"]) -> list[AttackStep]:
    """Produce one mutated candidate from ``seq`` (AFL-style, structure-aware).

    Applies a single operator. :func:`havoc` stacks many of these, which is where
    the real search power comes from. Every result is reindexed and length-
    bounded, and an actor/operation substitution is restricted to combinations the
    target declares reachable.
    """
    out = list(seq)
    ops = _all_ops(target)
    if not ops:
        return out

    operator = rng.choice(
        ["insert", "delete", "swap", "duplicate", "change_op", "change_actor",
         "mutate_param", "splice", "append", "append", "append"]
    )

    if operator == "append" and len(out) < max_steps:
        # Grow at the *end*: the move that extends a prefix that already reached a
        # deep state toward the next one. Weighted heavily (see the operator list)
        # because an ordered state gate is only crossed by keeping the prefix
        # intact and adding the next operation -- a mid-sequence insert or delete
        # destroys it.
        out.append(_random_step(target, rng, len(out)))
    elif operator == "insert" and len(out) < max_steps:
        pos = rng.randrange(len(out) + 1)
        out.insert(pos, _random_step(target, rng, pos))
    elif operator == "delete" and len(out) > 1:
        out.pop(rng.randrange(len(out)))
    elif operator == "swap" and len(out) >= 2:
        i = rng.randrange(len(out) - 1)
        out[i], out[i + 1] = out[i + 1], out[i]
    elif operator == "duplicate" and len(out) < max_steps:
        i = rng.randrange(len(out))
        out.insert(i, AttackStep(index=i, actor=out[i].actor, action=out[i].action,
                                 params=dict(out[i].params),
                                 target_contract=out[i].target_contract,
                                 expected_effect=out[i].expected_effect))
    elif operator == "change_op":
        i = rng.randrange(len(out))
        new_op = rng.choice(ops)
        actors = list(new_op.actors) or ["attacker"]
        params = {}
        for key, domain in (getattr(new_op, "param_domain", {}) or {}).items():
            choices = _boundary_values(domain) or [0]
            params[key] = rng.choice(choices)
        out[i] = AttackStep(index=i, actor=rng.choice(actors), action=new_op.name,
                            params=params, target_contract=out[i].target_contract,
                            expected_effect=new_op.description)
    elif operator == "change_actor":
        i = rng.randrange(len(out))
        allowed = _actors_for_op(target, out[i].action)
        out[i] = AttackStep(index=i, actor=rng.choice(allowed), action=out[i].action,
                            params=dict(out[i].params),
                            target_contract=out[i].target_contract,
                            expected_effect=out[i].expected_effect)
    elif operator == "mutate_param":
        i = rng.randrange(len(out))
        step = out[i]
        keys = [k for k, v in step.params.items()
                if isinstance(v, int) and not isinstance(v, bool)]
        if keys:
            key = rng.choice(keys)
            domain = None
            for o in ops:
                if o.name == step.action:
                    domain = (getattr(o, "param_domain", {}) or {}).get(key)
            choices = _boundary_values(domain) if domain else [0, 1, 10, 1000]
            params = dict(step.params)
            params[key] = rng.choice(choices or [0])
            out[i] = AttackStep(index=i, actor=step.actor, action=step.action,
                                params=params, target_contract=step.target_contract,
                                expected_effect=step.expected_effect)
    elif operator == "splice" and corpus:
        other = rng.choice(corpus).sequence
        if other:
            cut = rng.randrange(len(out))
            cut2 = rng.randrange(len(other))
            merged = out[:cut] + other[cut2:]
            out = merged[:max_steps] or list(out)

    if not out:
        out = [_random_step(target, rng, 0)]
    return _reindex(out)


def havoc(target: Any, seq: list[AttackStep], rng: random.Random,
          max_steps: int, corpus: list["CorpusEntry"], *, max_stack: int = 16
          ) -> list[AttackStep]:
    """AFL's havoc stage: stack several mutations onto one input.

    A single mutation rarely crosses a multi-step state gate; stacking many is
    what lets the corpus *extend partial progress* -- take a sequence that reached
    stage N, and grow or rewire it toward stage N+1. The stack size is drawn from
    a small geometric-ish distribution so most candidates are lightly mutated and
    a few are heavily rewired.
    """
    out = list(seq)
    stack = 1 + rng.randrange(max_stack)
    for _ in range(stack):
        out = mutate(target, out, rng, max_steps, corpus)
    return out


def deterministic_extend(target: Any, seq: list[AttackStep], max_steps: int,
                        rng: random.Random) -> list[list[AttackStep]]:
    """AFL's deterministic stage, adapted to sequences: grow ``seq`` by one step.

    For an ordered state machine -- a chain, a compound loop, a streak -- the only
    mutation that makes progress is *appending the next correct operation*. Random
    havoc almost never does that, because a mid-sequence change breaks the prefix
    that already reached the deep state. This stage tries, in a fixed order, every
    operation the target declares, appended to the retained sequence; each result
    that reaches new coverage is itself retained and grown again, so a bug that
    needs N repetitions of an operation is reached in ~N deterministic steps
    instead of a blind search over the whole operation alphabet.

    The candidate is executed by the caller; this only *proposes* them, so the
    coverage/energy bookkeeping stays in one place.
    """
    if len(seq) >= max_steps:
        return []
    out: list[list[AttackStep]] = []
    ops = _all_ops(target)
    for op in ops:
        actors = list(op.actors) or ["attacker"]
        actor = actors[0]
        params: dict[str, Any] = {}
        for key, domain in (getattr(op, "param_domain", {}) or {}).items():
            choices = _boundary_values(domain) or [0]
            params[key] = choices[0]
        step = AttackStep(index=len(seq), actor=actor, action=op.name, params=params,
                          target_contract=getattr(target, "name", "target"),
                          expected_effect=op.description)
        out.append(_reindex(list(seq) + [step]))
    return out


# --------------------------------------------------------------------------- #
# Report
# --------------------------------------------------------------------------- #

@dataclass
class CorpusReport:
    target: str
    sequences_executed: int = 0
    coverage_buckets: int = 0
    corpus_size: int = 0
    initial_coverage: int = 0
    failures: list[InvariantFailure] = field(default_factory=list)
    #: Economic account per failure (keyed by index into ``failures``), when
    #: ``price_findings`` is on.
    economic: list[dict] = field(default_factory=list)
    #: The sequence number at which each failure's invariant was first hit -- the
    #: fair "sequences-to-detection" cost.
    detection_at: list[int] = field(default_factory=list)
    #: Invariants that could not be evaluated on a reached state. A run with no
    #: failure and a non-empty list here has not shown the invariants hold.
    unevaluable: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "sequences_executed": self.sequences_executed,
            "unevaluable": list(self.unevaluable),
            "coverage_buckets": self.coverage_buckets,
            "initial_coverage": self.initial_coverage,
            "corpus_size": self.corpus_size,
            "failures": [f.to_dict() for f in self.failures],
            "economic": self.economic,
            "detection_at": self.detection_at,
            "notes": self.notes,
        }


# --------------------------------------------------------------------------- #
# The fuzzer
# --------------------------------------------------------------------------- #

class CoverageGuidedFuzzer:
    """AFL-style coverage-guided search over the abstract ``Target`` protocol."""

    def __init__(self, target: Any, config: Optional[CorpusConfig] = None) -> None:
        self.target = target
        self.config = config or CorpusConfig()

    # -- energy-weighted corpus selection --------------------------------- #
    @staticmethod
    def _pick(corpus: list[CorpusEntry], rng: random.Random) -> CorpusEntry:
        """Choose a corpus entry with probability proportional to its energy.

        A favoured entry (many unique finds, few picks) is chosen often; a stale
        one is chosen rarely. This is the power schedule that keeps the search on
        the frontier without abandoning the seeds that got it there.
        """
        weights = [max(1e-6, e.energy) for e in corpus]
        total = sum(weights)
        r = rng.random() * total
        upto = 0.0
        for e, w in zip(corpus, weights):
            upto += w
            if upto >= r:
                return e
        return corpus[-1]

    def _record_failure(self, report: CorpusReport, seq: list[AttackStep],
                        inv_id: str, state: Any, executed: int) -> None:
        cfg = self.config
        budget = _Budget(cfg.minimize_budget)
        minimal = _minimize_ops(self.target, seq, inv_id, budget)
        if cfg.shrink_values:
            minimal = _minimize_values(self.target, minimal, inv_id, budget)
        # Re-derive the observed state on the *minimal* sequence so the reported
        # evidence matches what is reported as minimal.
        _, min_state, _ = behaviour_features(self.target, minimal)
        failure = InvariantFailure(
            inv_id=inv_id,
            seed=cfg.seed,
            sequence=seq,
            actor_roles=[s.actor for s in seq],
            observed=self.target.snapshot(min_state),
            minimized=True,
            minimal_sequence=minimal,
            reproduction_command=(
                f"python -m blackheart fuzz --target {getattr(self.target, 'name', '')} "
                f"--strategy corpus --seed {cfg.seed}"
            ),
            reproducible=inv_id in behaviour_features(self.target, minimal)[2],
            reachable_by_attacker=_reachable_by_attacker(minimal),
        )
        report.failures.append(failure)
        report.detection_at.append(executed)
        if cfg.price_findings:
            acct = analyse(self.target, minimal, inv_id)
            report.economic.append(acct.to_dict())

    def _execute(self, seq: list[AttackStep], report: CorpusReport, cover: CoverageMap,
                 corpus: list[CorpusEntry], seen_failures: set, per_invariant: dict) -> tuple[int, int]:
        """Run one candidate; fold coverage; record violations; return (gain, richness).

        The single execution path used by every phase, so coverage, corpus
        retention, and failure recording can never diverge between the seeding,
        growth, and havoc phases. ``gain`` is the number of *new* buckets the
        candidate contributed (zero for a candidate that taught the search
        nothing); ``richness`` is the candidate's total bucket count, the tie-break
        that keeps the beam on the richest-reaching prefixes.
        """
        buckets, state, violated = behaviour_features(self.target, seq)
        for inv_id in unevaluable(state, self.target.invariants()):
            if inv_id not in report.unevaluable:
                report.unevaluable.append(inv_id)
        new = cover.merge(buckets)
        report.sequences_executed += 1
        if new:
            corpus.append(CorpusEntry(sequence=seq, finds=new, buckets=buckets,
                                      depth=len(seq)))
            if len(corpus) > self.config.max_corpus:
                victim = min(range(len(corpus) - 1), key=lambda i: corpus[i].energy)
                corpus.pop(victim)
        for inv_id in violated:
            if per_invariant.get(inv_id, 0) >= self.config.max_failures_per_invariant:
                continue
            fkey = (inv_id, tuple((s.actor, s.action) for s in seq))
            if fkey in seen_failures:
                continue
            seen_failures.add(fkey)
            per_invariant[inv_id] = per_invariant.get(inv_id, 0) + 1
            self._record_failure(report, seq, inv_id, state, report.sequences_executed)
        return new, len(buckets)

    def _beam_grow(self, seeds: list[list[AttackStep]], report: CorpusReport,
                   cover: CoverageMap, corpus: list[CorpusEntry], seen_failures: set,
                   per_invariant: dict, rng: random.Random) -> None:
        """Deterministic coverage-beam: extend the most-covering prefixes one step
        at a time.

        This is the phase that crosses an *ordered* state gate. Havoc almost never
        does, because a mid-sequence change destroys the prefix that already
        reached the deep state; here every child is a retained prefix plus one
        appended operation, and only the children that gained the most new
        coverage survive to the next round. So the beam walks the state machine
        one transition at a time, guided purely by the behavioural signal -- no
        per-target knowledge of the state semantics.

        The beam width bounds the budget; each round costs at most
        ``width * |ops|`` executions, and the growth stops at ``max_steps`` or
        when the budget ends.
        """
        cfg = self.config
        frontier = [list(s) for s in seeds]
        # ``depth`` counts growth *rounds*, not the seeds' own length: a seed may
        # already be long, and the point of this phase is to append to it, not to
        # re-reach its length. The real length bound is enforced by
        # ``deterministic_extend`` (it returns nothing at ``max_steps``).
        rounds = 0
        while frontier and rounds < cfg.max_steps:
            if report.sequences_executed >= cfg.max_sequences:
                return
            rounds += 1
            scored: list[tuple[int, int, list[AttackStep]]] = []
            for seq in frontier:
                for cand in deterministic_extend(self.target, seq, cfg.max_steps, rng):
                    if report.sequences_executed >= cfg.max_sequences:
                        break
                    gain, richness = self._execute(cand, report, cover, corpus,
                                                   seen_failures, per_invariant)
                    if gain:
                        scored.append((gain, richness, cand))
            if not scored:
                return
            # Keep the children that gained the most new coverage, then the ones
            # that reach the richest state, then the deepest, deterministically.
            scored.sort(key=lambda t: (-t[0], -t[1], -len(t[2]), _key(t[2])))
            frontier = [c for _, _, c in scored[: cfg.beam_width]]

    def run(self) -> CorpusReport:
        cfg = self.config
        rng = random.Random(cfg.seed)
        report = CorpusReport(target=getattr(self.target, "name", "target"))
        cover = CoverageMap()
        corpus: list[CorpusEntry] = []
        seen_failures: set[tuple] = set()
        per_invariant: dict[str, int] = {}

        # 1a. Plant model-guided seeds (hypotheses): the same information the
        #     enumerating explorer uses, and the starting point of the deterministic
        #     growth below.
        seed_seqs: list[list[AttackStep]] = []
        for seed_seq in cfg.extra_seeds:
            if report.sequences_executed >= cfg.max_sequences:
                break
            seq = _reindex(list(seed_seq))[: cfg.max_steps]
            seed_seqs.append(seq)
            self._execute(seq, report, cover, corpus, seen_failures, per_invariant)

        # 1b. Deterministic coverage-beam growth: extend the deepest-reaching
        #     prefixes one operation at a time. Run *before* the random seeds so the
        #     beam's small incremental gains are not masked by coverage a random
        #     seed already claimed. Seeded with the empty sequence too, so a chain
        #     that must be built from scratch (register -> verify -> ...) is grown
        #     from nothing. This is what reaches an ordered multi-step bug by
        #     construction rather than by luck.
        self._beam_grow([[], *seed_seqs], report, cover, corpus, seen_failures,
                        per_invariant, rng)
        report.initial_coverage = cover.count

        # 1c. Fresh random seeds: broaden the starting corpus with shapes the beam
        #     did not construct (unusual actors, parameter values, decoy mixes).
        for _ in range(cfg.initial_seeds):
            if report.sequences_executed >= cfg.max_sequences:
                break
            length = rng.randint(1, max(1, cfg.max_steps))
            seq = _random_sequence(self.target, rng, length)
            self._execute(seq, report, cover, corpus, seen_failures, per_invariant)

        # 2. AFL-style havoc on the retained corpus: broaden the frontier with
        #    different shapes, actors, and parameter values, and splice entries.
        while report.sequences_executed < cfg.max_sequences:
            if not corpus:
                self._execute(_random_sequence(self.target, rng,
                                               rng.randint(1, max(1, cfg.max_steps))),
                              report, cover, corpus, seen_failures, per_invariant)
                continue
            entry = self._pick(corpus, rng)
            entry.picks += 1
            candidate = havoc(self.target, entry.sequence, rng, cfg.max_steps, corpus)
            self._execute(candidate, report, cover, corpus, seen_failures, per_invariant)

        report.coverage_buckets = cover.count
        report.corpus_size = len(corpus)
        if not report.failures:
            report.notes.append(
                "no invariant violation found within budget; increase "
                "max_sequences or check the target's declared invariants")
        return report
