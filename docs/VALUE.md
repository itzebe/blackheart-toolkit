# The universal value & profitability engine (`blackheart/value/`)

> Deriving value is the point. A broken invariant is not yet a finding: the
> question BLACKHEART answers is about **assets**, so every investigation ends in
> a priced economic account of who gained, who lost, and whether it repeats.

`blackheart/value/` is the single accounting layer the whole engine shares. The
discovery benchmark, the profit-guided state-space search, the demonstrations
pipeline, and the CLI all ask it the same question — *did the attacker profit, how
much, and from whom?* — so one engine can never report profit while another
silently reports zero. The priced account is carried on every `Finding`
(`Finding.economic`) and rendered into every report, so it travels with a finding
through the campaign, engine and report layers. `discovery/economic.py` is a thin
facade over it.

## Why it exists

The original accounting classified a target's fields against a **hand-maintained
name allow-list**. It missed the plural forms real targets use — the flagship
ERC4626 vault exposes `balances`, and the allow-list only had `balance`, so the
vault was read as holding no value at all — and it raised on snapshots it did not
recognise. A capability that is correct on the fixture and blind on the real
target is worse than useless, because it reports a clean bill of health.

The fix is **structural classification**: a field's meaning is decided by its
*shape* and *name tokens*, not by an enumerated list. Any target — DeFi, lending,
permits, prediction markets, payment systems, or a plain state machine — is read
by the same rules.

## Classification

`classify_field(name, value)` returns a `FieldKind`:

| Kind | Meaning | Shape |
|---|---|---|
| `asset` | per-actor value an actor owns or can redeem | `{actor: int}` map, or a value-bearing scalar |
| `liability` | per-actor obligation, subtracted from capital | `{actor: int}` map |
| `permission` | a per-actor grant; neither owned nor owed | `{actor: …}` map |
| `protocol` | a protocol-held scalar (a vault total) | scalar |
| `other` | prices, counters, flags, derived valuation views | — |

Name matching is a lower-cased **substring**, so `balance`/`balances` and
`share`/`shares` classify identically. Two correctness rules fall out of this:

- A permission needs **per-actor structure**. A scalar such as `total_authorized`
  contains the `authoriz` token but is a counter, not a grant — it is `other`.
- A **derived valuation view** (`redeemable`, `valuation`) is the same holding
  re-expressed in another unit. Counting it *and* the underlying share balance
  would double an actor's capital and fabricate profit on an ordinary deposit, so
  valuation tokens are `other`.

## The account

`analyse(target, sequence, invariant_id, case_id)` returns a `ValueAccount`:

- `attacker_profit` — net change in the attacker's capital, in the target's own
  unit.
- `victim_loss` — value absorbed from **non-attacker** participants. Non-zero even
  when the attacker's own net is flat, so it is a second, independent signal that
  value moved.
- `protocol_loss` — value taken from protocol-held scalars.
- `conservation_residual` / `value_created` — value created from nothing (unbacked
  mint). A **diagnostic only**: a positive residual is not impact; only realised
  gain or loss is.
- `repeatable` / `max_extraction` — can the sequence run again, and how much one
  run takes.
- `financial_impact_established` — the honest yes/no.
- `tracked` — `False` when the snapshot exposes no attacker-identifiable value.
  This is an explicit "I could not measure it", never an assumed zero and never an
  assumed impact.

## Honesty rules (enforced in code)

- Never invent a balance — only what the target's own `snapshot` exposes.
- A step that **reverts** contributes no change and is never counted as profit.
- A **wraparound** (`2**256`) is an accounting artifact, not spendable value, and
  is excluded from realised profit.
- A permission is not capital; an obligation is subtracted; a borrow that raises
  cash and debt equally nets to zero.
- A **state change with no value movement** is a state manipulation, not a
  financial impact.

## The profit-guided search

`blackheart/statespace/adaptive.py` prices every candidate when
`profit_guided=True` (the default). It then:

- re-ranks its pending work toward `(actor, operation)` pairs **observed to move
  value** (a distinct signal from structural coverage), and
- minimises each violation while **keeping** the value movement — and if shrinking
  drops the profit, it re-prices the original sequence rather than report an
  "extraction" whose minimal form is worthless.

The result: the search no longer merely finds a broken invariant, it finds the
smallest sequence that makes the attacker money.

## CLI

```bash
blackheart value targets                     # which targets expose trackable value
blackheart value classify --target vault     # how each snapshot field is read
blackheart value analyse --target vault      # price a target's discovered violations
```

## Tests

`tests/test_value.py` pins the structural classification, the honesty rules, and
the universality regression (the engine must classify every executable target
without raising, and must read the flagship vault's `balances` as the attacker's
capital). `tests/test_adaptive_discovery.py` pins the profit-guided search: every
priced violation carries a tracked account, the order changes, and minimisation
keeps the value movement.
