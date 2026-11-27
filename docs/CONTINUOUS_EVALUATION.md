# Continuous adversarial evaluation

Two subsystems answer one question: *is the engine actually finding real defects,
and can we prove it run after run without flattering ourselves?*

- **TestSparker** (`blackheart/testsparker/`, `blackheart testsparker`) generates
  executable tests and runs them.
- **Continuous evaluation** (`blackheart/evaluation/`, `blackheart continuous`) runs
  campaigns over those adapters and reports metrics with honest denominators.

The interpreter that executes the tests lives in `blackheart/evm.py`.

## The three things that make a result trustworthy

### 1. An oracle that is not frozen

An adapter generates a test and a *claim* about what the code under test should do.
The claim is re-derived **at execute time** from the ABI, not frozen at generation
time, because a frozen claim compares a result against an expectation that was
written before the code ran. That is how a real regression (an injected `_SUB` bug in
the via-IR equality path) was missed until the oracle was fixed: with the stale claim
the run reported 0 signals; with the execute-time claim it reported 7.

A run with **no ground-truth corpus** reports `precision` and `recall` as `None` with
a reason — never a fabricated `1.0`. A rate computed over a zero denominator is not a
perfect score, it is an evaluation that decided nothing.

### 2. A gate that fails closed

`AuthorizationGate` decides whether an adapter may run. It refuses in every case where
it cannot prove permission:

| Situation | Result |
|---|---|
| Offline adapter (local interpreter only) | allowed — no live target involved |
| Live adapter, no authorization record | refused (fail closed) |
| Live adapter, record but no named target | refused (fail closed) |
| Live adapter, malformed record | refused — the check raised, and a raise is not a pass |
| Live adapter, `allow_live` false | refused — opt-in is required even with a record |
| Live adapter, `allow_live` true, no record | refused — opt-in is not a substitute for authorization |

`allow_live` is an **additional** gate, not a replacement for the record.

### 3. Learning that cannot move an unproven baseline

`blackheart/evaluation/learning.py` decides whether a run may change what future runs
are measured against:

- A `PARTIAL` run may not update a baseline.
- A run with a regression may not update a baseline.
- A counterexample that does not **reproduce** may not update a baseline.
- A freshly detected defect is **proposed**, not applied — it waits for independent
  review.

## Reading a campaign

```
python3 -m blackheart continuous --name nightly --limit 200 --evidence .evidence
```

```
campaign=nightly status=COMPLETE
  generated=200 executed=200 inconclusive=0
  defects_reported=0 regressions=0
  execution_coverage=1.0 (200/200)
  precision=unavailable (no known-answer corpus was supplied; ...)
  recall=unavailable (no known-answer corpus was supplied; ...)
```

`inconclusive` is never counted as a pass. A run whose artefact cannot be stored
reports `PARTIAL` and `evaluation_complete: false`, because completeness is a claim
about an artefact that exists.

## The interpreter

`blackheart/evm.py` is a deterministic EVM subset, enough for dispatch analysis and
the fixtures. It is validated against a real `anvil` node on the discriminator that
matters: a real selector reaches its handler (`STOP` + `SSTORE(0)=170`) and a bogus
selector reverts, with exact agreement.

Memory growth is modelled the way the EVM models it: quadratic expansion gas and a
hard cap, so an attacker-chosen offset halts as `OUT_OF_GAS` rather than allocating
or escaping as an exception. A campaign executes bytecode it did not write, and one
hostile offset must not be able to abort the run.

## Reviewer-model independence

The independent-review architecture is preserved, and the reviewer model is
**optional**. `blackheart models reviewer` reports whether a *separately
authenticated* reviewer exists and probes it; when none does, it reports
`available: false` and `independence: SAME_MODEL`, and the release workflow runs a
same-model adversarial review in a fresh context, recorded as `SAME_MODEL` — never as
an independent-model review. `FindingRecord.missing_confirmation_fields` refuses to
let a `SAME_MODEL` review back a `CONFIRMED` finding.

Core research and release do **not** depend on a reviewer credential. When valid
credentials become available, `models reviewer` reports `available: true` and the
review can run under `INDEPENDENT_MODEL` with no other change.

## What this cannot do

- A same-model review cannot exclude shared blind spots. A genuinely independent
  review remains outstanding until a verified reviewer credential exists.
- The interpreter models a subset of the EVM. It is validated on dispatch
  discrimination, not on gas accuracy or every opcode.
- Coverage of attack classes is *representative*, not exhaustive: 27 of 30 objective
  categories have an executable vulnerable/guarded model; 3 are deliberately
  prose-only because they require a live system, and they are reported as gaps.
