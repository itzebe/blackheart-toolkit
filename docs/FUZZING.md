# Coverage-guided fuzzing

BLACKHEART searches a target's state in three ways, and they answer different
questions:

| strategy | how it searches | strong at | weak at |
|----------|-----------------|-----------|---------|
| **state-space explorer** (`blackheart/statespace/`) | *enumerates* sequences by depth | shallow bugs, minimal counterexamples, decoy immunity via hypotheses | deep bugs (exponential in depth) |
| **random stateful fuzzer** (`blackheart/invariants/engine.py`) | *samples* sequences blind | broad, cheap coverage of shallow space | deep, ordered, state-gated bugs |
| **coverage-guided corpus fuzzer** (`blackheart/fuzz/`) | keeps inputs that reach new *behaviour*, grows the frontier, mutates | deep, ordered, state-gated bugs | nothing a random walk does not already reach cheaply |

Neither enumeration nor a blind random walk *learns from the target*. A blind walk
throws away every sequence that made progress toward a state it had not reached
yet, so the probability of drawing the exact sequence for an N-step ordered exploit
collapses with N, and every decoy operation dilutes it further. The coverage-guided
fuzzer is the third strategy, and it closes exactly that gap: it **keeps what
teaches it something**, and builds on it.

It is the same idea AFL, Echidna and Medusa use — keep the inputs that reached new
behaviour, and mutate those, spending more energy where the target is most
responsive — brought to BLACKHEART's abstract `Target` protocol.

## The coverage signal (`blackheart/fuzz/coverage.py`)

A compiler-instrumented fuzzer gets edge coverage from the binary. BLACKHEART runs
against a Python reference model, a state-space model, or a real-runtime adapter,
so it cannot. Instead it derives a **behavioural** signal from what the target
itself exposes, target-agnostically:

- **operation coverage** — which operations executed;
- **edge coverage** — which `(prev_op → op)` transitions executed (a state
  machine's behaviour lives in its transitions);
- **actor/op coverage** — which `(actor, operation)` pairs executed;
- **state coverage** — a discretised read of the snapshot after each step (which
  fields moved, and into which magnitude band).

Each feature is hashed into a fixed bitmap (AFL's `trace_bits` shape), so "did this
execution teach us anything new?" is a bitmap comparison — cheap, deterministic,
and process-independent (an explicit FNV-1a, never Python's salted `hash()`).

The one heuristic is the magnitude band: a **small** numeric value (below 4096 — a
stage index, a streak, a retry count) is hashed *exactly*, so stage 2 and stage 3
are different buckets; a **large** value (a wei balance) is banded by order of
magnitude, so a one-unit jitter is not mistaken for new coverage. That is what lets
the search tell "I made progress" from "I made noise", without a per-target hint.

This is honest about what it is: it is *behaviour* coverage, not source-line
coverage. It cannot see a branch the target does not reflect in its operations or
its snapshot. What it guarantees is that a sequence which reaches a state no
earlier sequence reached is kept and mutated — which is precisely the signal a
multi-step, state-dependent exploit needs.

## The three mechanisms that make it reach deep gates

1. **Corpus.** Every input that contributed a new bucket is retained (evicting the
   least-energetic when full). AFL-style energy: an entry that is the sole source of
   some bucket is favoured and mutated more; energy decays with the entry's age so
   the search does not stall.
2. **Deterministic coverage-beam growth.** Before havoc runs, the deepest-reaching
   prefixes are extended *one operation at a time*, keeping only the children that
   gained the most new coverage (tie-broken by coverage richness, then depth). This
   is what crosses an **ordered** state gate — havoc almost never does, because a
   mid-sequence change destroys the prefix that already reached the deep state. An
   N-step ordered bug is reached in ~N rounds instead of a blind search over the
   operation alphabet. The beam is seeded with the empty sequence, so a chain that
   must be built from nothing (register → verify → … → withdraw) is grown from
   scratch.
3. **AFL-style havoc.** The retained corpus is mutated (insert, delete, swap,
   duplicate, splice, change operation, change actor, mutate parameter — stacked)
   to broaden the frontier. Every operator is structure-preserving against the
   target's declared `OpSpec`: an actor is only ever substituted for one that can
   actually invoke the operation, so the budget is spent on *reachable* sequences.

The whole search is driven by a seeded RNG and never reads the wall clock for a
decision, so a run is exactly reproducible from its seed — the property the rest of
the engine already guarantees.

## Value pricing

Every hit is priced with the universal value engine (`blackheart.value`), so a deep
sequence that moves no value is reported as a *state manipulation*, not a finding.
A hit carries the same shape every other engine reports: a minimal,
attacker-reachable sequence that breaks a stated invariant *and* its economic
account.

## The honest claim, and the benchmark that measures it

The claim is **not** that coverage guidance is faster on every target. On a shallow
bug a blind random walk finds it too, and the benchmark says so. The claim is
narrower and testable:

> On a bug whose only route is a **deep, ordered, state-gated** sequence, the
> coverage-guided fuzzer reaches it and the random one does not, within the same
> budget.

`blackheart fuzz-bench` measures exactly that, on the same fixtures, the same
invariants and the same budget, and reports **sequences-to-detection** for both —
never a rate both engines reach given unlimited budget.

```bash
blackheart fuzz-bench --budget 3000 --seed 0
```

```json
{
  "cases": 3,
  "budget": 3000,
  "corpus_detection_rate": 1.0,
  "random_detection_rate": 0.6667,
  "corpus_false_positive_rate": 0.0,
  "random_false_positive_rate": 0.0
}
```

The deep fixture (`deep-gated-escalation`, an eight-step ordered escalation among
ten decoy operations) is a genuine missing-cap bug with a guarded control that caps
the withdrawal, so neither engine may report it. The corpus strategy finds it at
sequence 638; the random walk never does within budget. On the two shallow hard
fixtures both engines succeed — and the report says so.

## Usage

```bash
# the blind random walk
blackheart fuzz --target wrapper --runs 500

# the coverage-guided corpus (stronger on deep, ordered, gated bugs)
blackheart fuzz --strategy corpus --target wrapper --runs 4000 --steps 20 --seed 0

# the honest ablation
blackheart fuzz-bench --budget 3000
```

Read `found_at_sequence` in the report — that is how many sequences the search ran
before the hit, the cost signal you report. When hypotheses exist (from the
objectives/attack-chain stage), pass them as seeds; the fuzzer starts from them and
improves on them.

The discipline is in the `coverage-guided-fuzzing` skill
(`skills/coverage-guided-fuzzing/SKILL.md`).

## Safety and authorization

The fuzzer drives a local `Target` only: a Python reference model, a state-space
model, or a controlled local harness adapter. It never touches a network or a live
system, and it runs only against the fixtures and harnesses the rest of the engine
already restricts to local/forks-only scope. A hit is an input to the finding and
verification pipeline — it is not a submitted report.
