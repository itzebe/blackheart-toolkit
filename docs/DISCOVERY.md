# Historical-rediscovery discovery engine

BLACKHEART's state-space engine (`docs/STATESPACE.md`) searches for
invariant-violating sequences, but "it found something on a fixture" is not
evidence that it can find a *known* bug, and a benchmark that only reports its
hits teaches nothing. The discovery engine closes both gaps: it measures the
engine against a corpus of **real, publicly-disclosed vulnerabilities**, and it
turns every miss into a classified, testable regression.

The package is `blackheart/discovery/`; the CLI is `blackheart discovery`.

```
corpus (real root causes) --(harness)--> three-engine benchmark
                          --(search)-->   parameter-aware rediscovery
                          --(economic)--> attacker profit/capital account
                          --(missed)-->   per-stage miss classification
                          --(foundry_corpus)--> real EVM PoC + patched control
```

Nothing in this package asserts a *bounty* vulnerability. A "detection" is the
engine finding a sequence that breaks a case's stated invariant on a model of
known vulnerable logic — a **rediscovery**. That is an internal capability result.

## 1. The corpus (`discovery/corpus.py`)

`HistoricalCase` is one real, publicly-disclosed vulnerability with a **faithful
model**: a `vulnerable` factory and a `patched` factory that implement the *same*
invariants and differ only by the defence. The differential is the whole
benchmark — a "detection" that also fires on the patched control is a false
positive, and the harness counts it as such.

Each case records its `root_cause`, `protocol`, `reference`, `advisory`, and a
`pin` **only when it was independently verified** (never invented). The corpus
spans 20 cases over 15 distinct root causes and 9 distinct repositories
(reentrancy, access control, oracle manipulation, permit replay, initialisation,
rounding, fee accounting, share inflation, callback trust, insolvency,
liquidation, arithmetic, price manipulation, stale state, IDOR/object access).
`summary()` reports the shape and the minimum-bar checks.

## 2. The engine benchmark (`discovery/harness.py`, `discovery/blind_benchmark.py`)

Configurations run over the same targets, so the comparison is fair. The corpus
benchmark (`discovery/harness.py`) compares three engines; the blind-corpus
benchmark (`discovery/blind_benchmark.py`) compares all four:

| Engine | What it is |
|---|---|
| **baseline** | the existing random stateful fuzzer (`invariants.engine.StatefulFuzzer`) |
| **guided** | the state-space explorer (PR #47), driven by a **derived** model |
| **enhanced** | the parameter-aware search (`discovery/search.py`) |
| **adaptive** | the feedback-driven controller (`statespace/adaptive.py`, mission 06) |

`model_from_target` is **Capability B**: it reconstructs a `SystemModel` from a
target's own `ops()`/`invariants()`/actors, with explicit provenance
(`source="derived:Target.ops()"`). The guided engine therefore reads a model built
from what the system *exposes*, not a hand-written answer key.

Measured on the corpus (deterministic, seed 0):

| Metric | baseline | guided | enhanced | adaptive |
|---|---|---|---|---|
| recall (17 modelled cases) | 0.94 | 0.88 | **1.00** | **1.00** |
| false positives (patched controls) | 0 | 0 | **0** | **0** |
| sequences tried | 5100 | 567 | 479 | 10538 |

The guided engine's misses are exactly the parameter-boundary cases (§3).

### The adaptive engine (mission 06)

The guided engine's parameter blind spot is not the only gap: its frontier is
ordered **once** by a static rank and never revised, so what it learns from an
execution cannot change what it tries next. The adaptive controller
(`statespace/adaptive.py`) closes both gaps:

- **Iterative deepening, complete per depth** — every candidate sequence of
  length 1, then 2, ... over the target's operations × actors × boundary
  parameters, so a shallow exploit is never starved by a longer, higher-ranked one.
- **Execution feedback re-ranks the pending work** — after every execution the
  controller folds the observed coverage (operation/parameter pairs and
  adjacencies) into its priority and re-sorts, so a productive region is mined
  next. `priority_divergences` counts the times this changed the pick away from
  the static order — a non-zero count is evidence the feedback is real, not a
  static ordering wearing an "adaptive" label.

### The blind hold-out corpus (`discovery/blind.py`)

The development corpus and the original hold-out set were both used while the
engine was built, so neither can measure novelty. `discovery/blind.py` is a
**third**, independent corpus authored after the engine and its parameters were
frozen, with **new** root causes (approval double-spend, fee-on-transfer
accounting, unenforced expiry, liquidation boundary) plus two **clean negative
controls** whose invariant genuinely holds. The engines never import this module;
they see only a target's surface. `discovery/blind_benchmark.py` runs all four
engines over it and independently verifies every adaptive candidate (fresh
re-run + attacker reachability + patched-control differential). On the blind
corpus the guided engine recalls 0.75 while the adaptive engine recalls 1.00 and
every candidate is independently verified with no false positive on the clean
controls.


## 3. Parameter-aware search (`discovery/search.py`) — Capability D

The state-space explorer fixes each step's parameters to a single default value.
That blind spot is real: the classic first-depositor inflation attack needs a
*small* first deposit followed by a *large* donation, and a fixed "largest value"
default never tries the small deposit. The enhanced search enumerates operation
sequences over the model's relevant operations, across actors, **and across
parameter boundaries** (min/max and a small canonical set per value-like
parameter). Prioritisation is explicit: cross-actor sequences, ending on a
sensitive operation, with a small value present, are tried first. The search is
deterministic and deduplicates by canonical state key.

This is the only capability the enhanced engine adds; it reuses the existing
sequence runner, delta-debugging minimiser and `Violation` type unchanged.

## 4. Economic accounting (`blackheart/value/`, facade in `discovery/economic.py`) — Capability E

A violated invariant is not yet an *economic* finding. `analyse` turns a violating
sequence into an attacker P&L account: starting capital, per-step profit, final
profit, victim loss, protocol loss, repeatability and maximum extraction, all read
from the target's own `snapshot` — never invented. A gain matched by an equal loss
to another participant is labelled a transfer; only unbacked value is a solvency
event. `discovery/economic.py` is now a thin facade: the accounting itself lives in
the universal engine `blackheart/value/` (see `docs/VALUE.md`), so the discovery
benchmark, the state-space search, the campaign loop, and the CLI all share one
definition of "what counts as value". The facade also catalogues the economic
invariants (`ECONOMIC_INVARIANTS`) and maps each root cause to the invariants it can
violate.

The account is deliberately conservative, so a permission or an accounting
artifact is never reported as spendable value:

- **Profit is net capital** — owned asset fields minus obligation fields. A
  doubled `allowance` is a permission, not a balance; a borrow that raises cash
  and debt equally nets to zero.
- A step that **reverts** (raises) contributes no change and is counted in
  `reverted_steps`, never as profit.
- A **wraparound/overflow** value (2\*\*256 arithmetic) is flagged
  (`bounded_values`) and excluded from realized profit.
- `state_changed` and `financial_impact_established` separate a sequence that only
  flips a flag from one that actually moves value.
- Victim loss counts asset decreases only (a debt drop is a benefit, not a loss).

## 5. Missed-vulnerability analysis (`discovery/missed.py`) — Capability I

For every case the guided engine fails, `analyse_miss` walks the pipeline and
assigns the miss to the **first failing stage**: `model` → `invariant` →
`hypothesis` → `exploration` → `execution` → `minimisation` → `verification` →
`scope`. Each confirmed failure mode becomes a regression test, not an anecdote.

## 6. Real EVM reproduction (`harnesses/historical-corpus/`, `discovery/foundry_corpus.py`) — Capability G

A Python model of a bug is a hypothesis. The Foundry harness makes it executable:
`src/Historical.sol` holds vulnerable/patched pairs for three classes, and
`test/HistoricalCorpusPoC.t.sol` proves, for each, that the exploit succeeds on the
vulnerable contract **and** the patched control rejects it. A stateful invariant
suite (`test/BankInvariant.t.sol`) fuzzes the bank and **fails** on the vulnerable
contract while **holding** on the patched one — the differential is the evidence.

Everything runs in `forge`'s in-process EVM: no fork, no broadcast, no network.
`run_poc_suite` and `run_invariant_differential` capture the exact command and
output; if `forge` is absent they report `available=False` rather than pretending
the PoCs ran.

## Running it

```bash
python3 -m blackheart discovery corpus              # corpus shape
python3 -m blackheart discovery benchmark           # four-engine comparison
python3 -m blackheart discovery blind-benchmark     # four engines over the blind corpus
python3 -m blackheart discovery misses              # classify guided misses
python3 -m blackheart discovery campaign --fixture BL03-expiry-not-enforced  # adaptive campaign
python3 -m blackheart discovery economic            # attacker P&L per case
python3 -m blackheart discovery foundry             # real Foundry PoC suite
python3 -m blackheart discovery foundry-invariant   # invariant differential
```

The executable acceptance bar is `tests/test_discovery.py` (14 tests; the two
full-benchmark tests are marked `slow`).
