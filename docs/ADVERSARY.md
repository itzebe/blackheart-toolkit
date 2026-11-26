# Adversary emulation

A scanner answers *"does this pattern exist here?"*. It cannot answer *"who would
bother, what would it cost them, how long would they wait, and what do they take
first?"* — and those four questions decide which campaigns exist at all.

`blackheart adversary` answers them for a named capability set.

```bash
python3 -m blackheart adversary profiles
python3 -m blackheart adversary plan \
    --profile opportunist \
    --objective "receive more assets than entitled to" \
    --asset flex-market
```

## What changes a campaign

Not nationality. Four variables:

| Variable | Effect on the plan |
|---|---|
| **capability** | which stages exist at all (a role the actor does not hold is not a stage) |
| **capital** | whether a precondition can be bought atomically (flash) or must be held |
| **patience** | whether a `trigger` stage exists (wait for a price move, an epoch, a window) |
| **objective** | which outcome the extraction is measured against |

The three shipped profiles are points in that space:

| Profile | Dwell | Capital | Adds |
|---|---|---|---|
| `opportunist` | 0 days | flash only | the unprivileged attacker of `mindset.ATTACKER_QUESTION` |
| `organized` | 30 days | 10M, sustained | `trigger` (wait) and `persist` (repeat) |
| `state-grade` | 180 days | 1B, sustained | plus `MODEL_ONLY` reach outside the market |

## The plan is objective-first

Stages are `recon → position → accumulate → trigger → extract → persist`. Each
stage names the engine that runs it, the evidence it must produce, and — where it
matters — the condition the actor must wait for.

The stages that are **absent** carry as much information as the ones present:

* `opportunist` has no `trigger`: a one-transaction attacker must find the
  condition already present, which is exactly why flash-loan attacks are rare.
* `opportunist` has no `persist`: flash capital is repaid in the same transaction,
  so the extraction cannot be repeated without new capital.
* A profile without capital cannot plan `receive more assets` at all (`feasible:
  false`), but can still plan `bypass a restriction`, which needs no capital.

## Two hard rules

1. **Modelling a capability is not authorising it.** Validator control, supply
   chain, insider access and social engineering are `MODEL_ONLY`: they appear in
   the plan so the reasoning is complete, with `executable: false` and no engine,
   and nothing in the engine can run them.
2. **Thinking is free; execution is gated.** A plan is always produced. A stage is
   `executable` only when the asset passes the authorization gate
   (`blackheart.scope.check_asset`, the same gate every engine uses). Without a
   record the plan prints `NOT authorized` and every stage is held.

## What a stateless scanner cannot see

`scanner_contrast()` returns, per stage, what a scanner does and what it
structurally cannot:

| Stage | Scanner cannot |
|---|---|
| recon | say which entrypoint moves value or what a position is worth |
| position | fund, hold or unwind a position across blocks |
| accumulate | build entitlement from several calls that are each valid alone |
| trigger | wait for a price move, an epoch boundary or a governance window |
| extract | price the violation, so it cannot separate theft from noise |
| persist | tell whether the exploited state can be restored and re-exploited |

## Why this is not a persona

No profile models a person, an organisation or a nation. The only inputs are
capability, capital, patience and objective, because those are the things that
change what is reachable. Anything else would be decoration: it would make a
report sound dangerous without making it true.

## Acceptance bar

`tests/test_adversary.py`: the objective must be one of the three mindset
outcomes; a plan without authorization executes nothing; an authorized asset makes
the unprivileged stages executable; an out-of-scope asset is refused by the gate;
a capital-less profile cannot plan theft but can plan a restriction bypass;
`state-grade` gains `trigger`, `persist` and exactly the four `MODEL_ONLY` stages,
none executable; every executable stage names a registered engine; the plan is
deterministic.
