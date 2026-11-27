---
name: attack-chain-design
description: >
  Generate attacker objectives and multi-operation attack chains that combine
  contracts, roles, and transactions. Use at the start of an engagement, before
  reviewing individual functions, to decide what to attack.
triggers:
  - attacker objective
  - attack chain
  - threat model
  - attack surface
  - entry point
  - trust boundary
---

# Attack-chain design

Attackers do not attack functions; they attack **systems**. Generate objectives
first, then compose operations into chains.

## Step 1 — Attacker objectives

Enumerate what an attacker wants, independent of any checklist. Standard set:

- Steal or withdraw assets without authorization.
- Create unbacked debt or credit.
- Bypass authentication or authorization.
- Escalate privileges.
- Manipulate accounting or settlement.
- Replay or forge authorization.
- Bypass signature verification.
- Cause inconsistent contract states.
- Manipulate collateral valuations.
- Exploit rounding or precision differences.
- Circumvent liquidation or risk controls.
- Exploit trust between external protocols.
- Obtain unauthorized access to protected information.
- Manipulate state through transaction ordering or timing.
- Exploit cross-contract interactions.

Use the engine: `python3 -m blackheart objectives --profile <profile.json>`.

For every objective record: attacker capabilities, required preconditions, assets
at risk, entry points, trust boundaries, the expected invariant, a candidate
sequence, and a safe place to test.

## Step 2 — Attack chains

Compose operations that are individually benign into a sequence that is not:

- deposit → borrow → transfer → withdraw
- approve → callback → external interaction → state update
- create authorization → change state → replay authorization
- modify collateral → trigger liquidation → exploit accounting
- bridge/teleport → settle → reverse/replay
- upgrade → initialize → exercise privileged functionality
- change oracle state → borrow → restore oracle state
- seed → donate → victim deposits → redeem (share inflation)

Use the engine: `python3 -m blackheart chains --profile <profile.json>`.

## Step 3 — Prioritise

Rank by **impact**, **attacker accessibility**, **novelty**, **testability**, and
**probability of violating an invariant**. Do the highest-expected-value chain
first; do not spray tests.

## Gotchas

- **Don't limit to known checklists.** The objective catalogue is deliberately
  broader than SWC/OWASP; use it, but add target-specific objectives from the
  product's actual invariants.
- **A chain is a hypothesis, not a claim.** Never write "this is exploitable"
  before executing it. Record it as a hypothesis in the ledger.
- **Chains must name their actors and their preconditions.** A chain that assumes
  the attacker is already the owner is not an attack.
- **Re-check the ledger.** If a chain's objective was already classified
  `FALSE_POSITIVE`, do not re-run it unchanged.

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
