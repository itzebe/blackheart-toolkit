---
name: stateful-invariant-testing
description: >
  Design, run, and triage stateful invariant tests that search for violations
  across arbitrary sequences of operations. Use when hunting for logic and
  accounting bugs that single-call tests miss, or when triaging invariant
  failures (is it a real vulnerability or dust?).
triggers:
  - invariant
  - stateful fuzz
  - property test
  - sequence
  - counterexample
---

# Stateful invariant testing

Do not test whether one function returns an expected value. Define **properties
that must hold for all reachable states**, then search for a sequence that breaks
them.

## Step 1 — Write invariants as security properties

Good invariants name the security property, not the implementation:

- Assets cannot be withdrawn without sufficient authorization.
- Outstanding credit cannot exceed properly backed collateral.
- Total accounting liabilities cannot exceed valid obligations.
- Unauthorized actors cannot change protected state.
- A signature cannot authorize an unintended operation.
- Replayed requests cannot create duplicate settlements.
- Failed operations cannot leave partially committed state.
- Liquidation cannot improperly seize healthy positions.
- State transitions cannot create assets from nothing.
- **The attacker's net value never materially exceeds what they supplied.**
- **No non-consenting actor suffers material loss.**

## Step 2 — Model actors and operations

Include at least one **adversarial** actor and one **victim**. Operations must be
bounded (sane amounts) and actor-scoped. Add the "unsolicited" primitives attackers
actually use: direct token transfer (donation), reentrancy callback, callback with
attacker-controlled data, ordering.

## Step 3 — Run the search

- Python engine (fast, model-based):
  `python3 -m blackheart fuzz --target vulnerable --runs 300 --steps 10`
- Foundry stateful invariants (real EVM):
  `forge test --match-contract InvariantsTest -vv`
- Echidna / Medusa (property fuzzers) for deeper campaigns.

## Step 4 — When an invariant fails

1. Save the seed. 2. Save the exact sequence. 3. **Minimise** it (delta-debug the
operations, then shrink values). 4. Reproduce deterministically. 5. Decide whether
it is attacker-reachable. 6. Establish real impact. 7. Independently reproduce.
8. Save a regression test.

A failed test alone is **not** a vulnerability.

## Step 5 — Triage honestly (the hard part)

Ask, in order:

- **Is it material?** Dust-level rounding (e.g. 1 wei of 1e18) is not a security
  bug. Quantify the extraction and compare to attacker cost.
- **Who is harmed and did they consent?** A "loss" the same actor caused by
  donating their own funds is not theft. Exclude voluntary actions from the
  invariant.
- **Is it reachable and controllable?** If the sequence needs a role or state an
  attacker cannot obtain, it is not a finding.
- **Does an existing protection block it?** Re-check with the real code.
- **Is it intentional?** Read the docs/comments.

Only after all of that does the finding go to the independent verifier.

## Gotchas

- **Your invariant can be wrong.** If it fails on a *known-safe* reference (a
  defended implementation), the invariant is too strict — fix the invariant, not
  the reference. Always run every invariant against a safe control.
- **Minimisation can loop forever** on 1e18-scale values. The engine caps it with
  `minimize_budget`; keep a budget.
- **`fail_on_revert = false`** in Foundry makes the fuzzer skip reverting calls —
  that is usually what you want, but understand it hides reverts that could be
  part of an exploit chain.
- **Foundry shrinks for you** and prints the shrunk sequence; capture it as
  evidence verbatim.

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
