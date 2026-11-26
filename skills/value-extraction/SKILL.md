---
name: value-extraction
description: >
  Universal value and profitability reasoning: turn any discovered violation into
  a priced economic account — what the attacker gains, what a counterparty or the
  protocol loses, whether the sequence repeats, and whether the extraction is worth
  the attacker's capital. Use whenever a candidate attack is found and you must
  decide whether it is a real extraction or a mere state manipulation, on any
  target (DeFi, lending, permits, prediction markets, payment systems, or plain
  state machines). Backed by the engine in `blackheart.value`.
triggers:
  - value extraction
  - economic impact
  - attacker profit
  - victim loss
  - is it profitable
  - value engine
  - quantify the extraction
  - repeatable drain
  - conservation residual
  - state manipulation
---

# Value extraction — deriving value is the point

A broken invariant is not yet a finding. The question BLACKHEART answers is about
**assets**, so every investigation ends in an economic account: who gained, who
lost, and whether it repeats. This skill is the discipline for producing that
account — and the engine in `blackheart.value` enforces it in code, so the prose
and the tooling say the same thing.

## The rule

> Price every candidate with the universal value engine, so the same accounting
> applies to every target — never a per-target guess.

A candidate that moves no value is a **state manipulation**, not a finding. Say
so plainly and move on.

## How the engine reads a target

`blackheart.value` classifies every field of a target's `snapshot` **by structure,
not by a hand-maintained name list** — that is what makes it universal:

- **asset** — per-actor value an actor owns or can redeem (a `balances` /
  `shares` / `cash` map). Both singular and plural spellings classify alike.
- **liability** — a per-actor obligation, subtracted from capital (`debt`,
  `borrowed`).
- **permission** — a per-actor grant that is neither owned nor owed
  (`allowance`). A permission is not capital.
- **protocol** — a protocol-held scalar (a `vault` total): classified, but not the
  attacker's capital.
- **other** — prices, counters, flags, and derived valuation views.

Honesty rules, enforced in code:

- never invent a balance — only what the target's own `snapshot` exposes;
- a step that reverts contributes no change and is never counted as profit;
- a wraparound (`2**256`) is an accounting artifact, not spendable value;
- a `redeemable` / valuation view is the same holding re-expressed, not a second
  asset — counting both would fabricate profit on an ordinary deposit;
- a snapshot that exposes no attacker-identifiable balance yields an explicitly
  **untracked** account — never an assumed zero and never an assumed impact.

## What to produce

For every candidate, produce a `ValueAccount` (`blackheart value analyse`, or
`analyse(target, sequence, invariant_id, case_id)`):

- `attacker_profit` — net change in the attacker's capital, in the target's own
  unit. Negative means the attacker paid to run the sequence.
- `victim_loss` — value absorbed from **non-attacker** participants. Non-zero even
  when the attacker's own net is flat, so it is a second, independent signal that
  value moved.
- `protocol_loss` — value taken from protocol-held scalars.
- `conservation_residual` / `value_created` — value created from nothing (unbacked
  mint). A **diagnostic**: a positive residual alone is not impact; only realised
  attacker gain or counterparty loss is.
- `repeatable` / `max_extraction` — can the sequence be run again, and how much
  does one run take.
- `financial_impact_established` — the honest yes/no: did money actually move.

## Procedure

1. **Model the value.** Run `blackheart value classify --target <t>` and read how
   each field is understood. If nothing is an asset or liability, the target
   exposes no trackable value — stop and say so.
2. **Run the sequence and price it.** `blackheart value analyse --target <t>`, or
   `analyse(...)` on a discovered violation. Read `attacker_profit` and
   `victim_loss`.
3. **Judge the account, not the invariant.**
   - gain beyond entitlement (positive `attacker_profit`), **or**
   - a loss pushed onto a non-consenting party (positive `victim_loss`), **or**
   - a bypassed restriction that moves value —
   → a finding. Otherwise it is a state manipulation.
4. **Quantify against real cost.** A permission is not capital; a borrow nets to
   zero; an obligation is subtracted. Compare the extraction to the attacker's
   capital and gas before calling anything a finding. Dust is not impact.
5. **Check repeatability.** A one-shot extraction and a repeatable drain are
   different severities; report which one this is.
6. **Never dress a guess as a finding.** State what you priced, with which
   sequence, and what the engine reported — including an honest "no value
   movement".

## Wire it into the search

The adaptive explorer prices every candidate when `profit_guided=True`: it
re-ranks its pending work toward value-moving `(actor, operation)` pairs and
minimises each violation while *keeping* the value movement, so the reported
minimal sequence is still the one that makes money. Prefer this mode when the
question is "how much can the attacker take", not merely "is an invariant broken".

```bash
blackheart value targets                     # which targets expose trackable value
blackheart value classify --target vault     # how each snapshot field is read
blackheart value analyse --target vault      # price a target's discovered violations
```

## Do not

- Do not report a broken invariant as a financial impact without a priced account.
- Do not count a permission, a valuation view, a wraparound, or a flow counter as
  spendable value.
- Do not inflate a residual into "value created" — only realised gain or loss is.
- Do not run anything against a live network; price against a local target or fork.

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
