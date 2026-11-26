---
name: attack-class-execution
description: >
  Turn a named attack class (oracle manipulation, authorization replay, unsafe
  initialization, share-accounting divergence) into an executable stateful target
  with a guarded control, run it with the engine, and drive a confirmed finding to
  a report. Use when an objective exists but there is no executable target for it,
  or when adding a new vulnerable/guarded pair to BLACKHEART.
triggers:
  - attack class
  - oracle manipulation
  - replay
  - initializer
  - differential
  - guarded control
  - new target
---

# Executing an attack class

The objectives engine names attack classes; the invariant engine can only break
classes it has a **model** for. This skill is the procedure for closing that gap:
a class becomes real when a vulnerable model and its guarded control both exist,
and the engine finds a violation in the first and none in the second.

## Step 1 — State the class as one invariant

Write the single security property the class violates, in the same style the
engine already uses:

- oracle manipulation -> "no actor's debt exceeds collateral valued at a
  manipulation-resistant price times the LTV".
- authorization replay -> "the cumulative value drawn through authorizations never
  exceeds the cumulative value the victim actually signed".
- unsafe initialization -> "an actor who was never the legitimate deployer never
  gains protected funds".
- share divergence -> "no sequence of conversions yields net value creation".

The invariant must be checkable from the model's state alone.

## Step 2 — Model the vulnerable variant

Add a `Target` subclass in `blackheart/invariants/attack_targets.py`:

- `reset()` seeds attacker and victim with realistic starting balances.
- `ops()` exposes the attacker-controlled actions (including the manipulation
  primitive: the price pump, the second permit submission, the re-`initialize`).
- `step()` implements the accounting with the flaw present.
- `invariants()` returns the Step-1 property, with a real severity.

Keep the model deterministic and free of I/O.

## Step 3 — Model the guarded control

Subclass the vulnerable target and change **only** the missing control (a
manipulation-resistant price read, a single-use flag, an `only-initializer` check,
a virtual-shares offset). The two models must otherwise be identical, so the only
variable is the defence.

## Step 4 — Register the pair

Add both names to `TARGET_SPECS` and the `(vulnerable, guarded, hypothesis)` triple
to `DIFFERENTIAL_PAIRS` in `blackheart/invariants/registry.py`. Registration is
what makes the class runnable from the CLI and covered by the differential test.

## Step 5 — Prove the contrast, then the finding

```bash
python3 -m blackheart differential                       # every pair must PASS
python3 -m blackheart demonstrate --pair <v>/<guard>     # CONFIRMED + report
python3 -m blackheart reproduce --target <v> --invariant <inv> --seed <n>
```

The differential run asserts the vulnerable model yields at least one
attacker-reachable violation and the guarded model yields none. The demonstration
run carries the minimal counterexample through the verifier and writes a report
only when all seven gates pass.

## Rules

- A model that never breaks is not evidence of safety; it is an untested model.
  Confirm the vulnerable variant actually breaks before trusting the guarded one.
- Never weaken an invariant to make a guarded model pass. Fix the model.
- These targets validate the engine and the class. They are **not** bounty
  findings; the report labels them as engine demonstrations, not vulnerabilities.
- Every new pair needs a test in `tests/test_attack_targets.py`.

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
