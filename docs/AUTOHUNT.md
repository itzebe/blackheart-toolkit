# AUTOHUNT — the operator's only job is review

`blackheart autohunt` is the autonomous controller. It drives the existing engines
across a list of **in-scope targets**, moves on from a target that yields nothing,
and stops **only** when the operator has something real to do: review a payable
candidate, or review a reproduction.

The operator is the **independent reviewer**. The controller never confirms a
finding and never submits one. It surfaces, with the exact record and evidence to
look at, and stops.

## What it stops for

| Reason | Meaning |
|---|---|
| `PAYABLE_FOUND` | a candidate passes the official bounty gate (`A_SUBMISSION_READY`) — review and, if you agree, submit |
| `AWAITING_REVIEW` | a reproduction is `B_POTENTIALLY_PAYABLE` or could not be graded (`F_NOT_ASSESSED`) — review it |
| `SCOPE_EXHAUSTED` | every in-scope target was tried; none was payable. **Not a proof of safety** |
| `BUDGET_EXHAUSTED` | the runtime/target budget ran out before the scope did |
| `BLOCKED` | no target could run (missing compatibility record, policy, or tool) |

A `C_VALID_NOT_PAYABLE` (ineligible) reproduction does **not** stop the hunt — it
is not payable, so the controller keeps moving to the next target. That is the
difference between "valid" and "payable", and the gate decides it, not a score.

## What it does not trust

The controller trusts nothing on its own. For each target it runs the external
chain, and a lead only reaches the operator through it:

```
scanner (compatibility-gated) -> lead -> grounded hypothesis -> certifiable Target
  -> model-level certification -> Foundry PoC (fail-closed) -> finding (evidence-gated)
  -> official bounty gate (A_SUBMISSION_READY is the only payable disposition)
```

A scanner lead is never a candidate. A model violation is never a finding. A
finding is never `CONFIRMED` without independent verification — which is the
operator's review. The controller is indifferent to how confident anything *looks*;
it only acts on what the gates produced.

## Usage

```bash
blackheart autohunt --targets scope.json --policy policy.json \
  --scanner slither --poc --json
```

`scope.json` is a list of in-scope targets:

```json
[
  {"component": "Pool", "path": "/src/pool", "repository": "org/repo",
   "commit": "abc123", "compatibility": "/path/to/pool.record.json"}
]
```

`--policy policy.json` is a normalized program policy (see
`blackheart program normalize`); without it every reproduction is graded
`F_NOT_ASSESSED` and surfaced for review, never called payable.

Budget and pacing: `--max-targets N`, `--max-runtime SECONDS`. By default the
controller stops at the first reviewable candidate; `--no-stop-on-review` collects
them all before stopping.

## Exit codes

`0` — a payable candidate or a reviewable reproduction was surfaced (there is
work for the reviewer). `1` — nothing to review this pass (scope/budget exhausted
or all targets blocked). `2` — bad invocation (no targets, unreadable files).

## Honest limits

The controller is only as strong as its pieces. It cannot make a scanner produce
a finding, cannot make a model reach an unmodelled function, and cannot run a
Foundry PoC where `forge` is absent (that target is `BLOCKED`). A
`SCOPE_EXHAUSTED` result says "nothing found within the targets and budget", not
"the scope is safe". The operator's review is the only path from a reproduction to
a submitted finding.
