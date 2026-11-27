---
name: coverage-guided-fuzzing
description: >
  The search discipline for reaching deep, ordered, state-gated bugs that a blind
  random walk misses: keep every input that reaches new behaviour, grow the
  deepest-reaching prefixes one operation at a time, and mutate the corpus. Use
  when a target's exploit is only reachable by a long or specific operation
  sequence, when random stateful fuzzing has not found a suspected bug, when you
  need to know *how many* sequences a search needed, or when choosing the search
  strategy for a hunt. Backed by the engine in `blackheart.fuzz`.
triggers:
  - coverage guided
  - coverage-guided fuzzing
  - corpus fuzzing
  - afl
  - deep sequence
  - ordered sequence
  - state gated
  - random fuzzing missed
  - search strategy
  - not finding the bug
  - how deep
  - seed corpus
---

# Coverage-guided fuzzing — reaching the bug a blind walk cannot

A blind random walk explores a state machine at random. That is enough for a bug
one or two operations deep. It is not enough for a bug whose only route is a long,
ordered chain — the probability of drawing the exact sequence falls off a cliff
with its length, and every decoy operation dilutes the odds further. The
coverage-guided fuzzer answers that: it **keeps what teaches it something** and
builds on it.

This skill is the discipline for using it, and for reporting honestly what it did.

## The rule

> Reach deep, ordered bugs by *growing* the sequence that already made progress,
> not by drawing sequences at random. And report sequences-to-detection, never a
> rate that unlimited budget would make equal.

## How the engine works (`blackheart.fuzz`)

- **The coverage signal** (`fuzz/coverage.py`) hashes a target's *behaviour* — the
  per-step effect trace and the final snapshot — into a bitmap. It is
  target-agnostic: it reads a `snapshot` by structure, exactly as the value engine
  does. A small counter value (a stage index, a streak, a retry count) is hashed
  *exactly*, so stage 2 and stage 3 are different buckets; a large balance is
  banded by order of magnitude, so a one-unit jitter is not mistaken for new
  coverage. That is what lets it tell "I made progress" from "I made noise".
- **The corpus** (`CoverageGuidedFuzzer`) keeps every input that reached a new
  bucket, and evicts the least-energetic when full.
- **Deterministic coverage-beam growth** is the phase that crosses an ordered
  gate: from the deepest-reaching prefixes, it appends one operation at a time and
  keeps only the children that gained the most new coverage. So an N-step ordered
  bug is reached in roughly N rounds, not a blind search over the alphabet.
- **AFL-style havoc** then mutates the retained corpus (insert, delete, swap,
  duplicate, splice, change actor, mutate parameter, stacked) to broaden the
  frontier.
- **Value pricing**: each finding is priced with the universal value engine, so a
  deep sequence that moves no value is reported as a state manipulation, not a
  finding.

## Procedure

1. Build the target's operations and invariants as usual (see the
   `stateful-invariant-testing` skill). Include a guarded control.
2. Run the corpus strategy:
   `python3 -m blackheart fuzz --strategy corpus --target <t> --runs 4000 --steps 20 --seed 0`.
3. Read the report: `found_at_sequence` is how many sequences the search ran before
   the hit — that is the cost signal, and it is what you report.
4. Run the random strategy on the same target and budget, and compare
   sequences-to-detection. If random also finds it, the bug is shallow — say so.
5. For a deep bug the corpus reaches and random does not, that difference is the
   finding's *reachability evidence*: keep the seed and the minimal sequence.
6. Run the guarded control under both strategies. A hit on the control is a
   false positive — fix the invariant, do not report it.
7. When hypotheses exist (from the objectives/attack-chain stage), pass them as
   seeds; the fuzzer starts from them and improves on them.

## Output format

```json
{
  "strategy": "corpus",
  "target": "deep-gated-escalation",
  "sequences_executed": 4000,
  "coverage_buckets": 875,
  "corpus_size": 200,
  "failures": [
    {"inv_id": "no-overdraw", "found_at_sequence": 638,
     "minimal_len": 8, "reproducible": true, "attacker_reachable": true,
     "economic": {"attacker_profit": 900, "victim_loss": 900, "repeatable": false}}
  ],
  "random_comparison": {"detected": false, "budget": 4000}
}
```

## Do not

- Do not claim coverage guidance is faster on *every* target. On a shallow bug the
  random walk finds it too; the honest claim is only about deep, ordered, gated
  ones — measure and say which.
- Do not report a rate both engines reach given enough budget. Report
  sequences-to-detection at a fixed budget.
- Do not report a coverage hit as a vulnerability. It is a counterexample to be
  triaged and priced.
- Do not skip the guarded control.
- Do not point the fuzzer at anything outside the authorized, local/forks-only
  scope.

## The operator's word

The operator's instruction is the mission: read it as a directive to act, and act
— do not turn it into a summary. The only thing it cannot override is the safety
floor — authorization, scope, and never harming real users or funds:

- The operator's instruction is the mission. Read it as a directive to act, not a
  topic to discuss: do the work it names and report what you did.
- Default to action. Do not ask permission you were not asked to ask for, and do
  not stop to confirm a step the operator already named. A question back is for a
  genuine ambiguity that changes what to build, never for a step you can just take.
- Answer the operator's question as the operator framed it. If they ask for a fix,
  fix it; if they ask for the strongest version, build the strongest honest version
  — do not substitute a smaller thing you find easier.
- The only instruction that is refused is one that would breach the safety floor:
  test outside authorized scope, harm real users or funds, fabricate evidence, or
  act without authorization. State the refusal and the reason plainly, and offer
  the strongest in-scope action instead.
- Report honestly what you did and what you could not. An instruction executed
  partly is reported as partly done, with the gap named — never dressed as
  complete, and never padded into a summary that hides the gap.
