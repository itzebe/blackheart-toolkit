# Completeness assurance: certifying absence and running every search

A hunter that misses a bug and reports the target clean is worse than useless. The
hard part of offensive research is not finding *a* bug -- it is being honest about
the bugs you did **not** find. BLACKHEART's other searches sample the space, and a
sample can only ever say "found" or "not found within budget". This layer adds the
three things that make the hunt as complete and as honest as it can be:

| tool | what it does | what its negative result means |
|------|--------------|-------------------------------|
| **oracle audit** (`blackheart.assurance.oracles`) | for every declared invariant, decides whether it can catch anything at all | **no clean result on a weak oracle may be trusted** -- the oracle, not the search, is the gap |
| **bounded-exhaustive certifier** (`blackheart.assurance.certify`) | enumerates *every* sequence up to a depth over the declared alphabet and runs all of them | **no declared invariant is broken by any sequence of length <= D over the declared alphabet** (bounded) |
| **search portfolio** (`blackheart.assurance.portfolio`) | runs every strategy, unions the counterexamples, prices them once | **not found within budget by any strategy** -- never "secure" |

The certifier is the only search in the whole engine allowed to say "no
counterexample exists", and only up to its declared bound. Every stochastic search
-- the random fuzzer, the coverage-guided corpus fuzzer, the adaptive explorer, the
model-guided explorer -- reports "not found within budget" and nothing stronger.

But *every* search, including the certifier, checks the target's **declared
invariants** -- so the whole engine is only as strong as those oracles. The oracle
audit runs first and asks whether each declared invariant is *able* to catch
anything at all.

## Why "can't miss" means "union", not "one magic search"

No single strategy dominates. Each is strong where the others are weak:

| strategy | strong at | weak at |
|----------|-----------|---------|
| **oracle audit** | deciding whether the declared invariants can catch anything at all | not a search -- it finds no bugs itself |
| **bounded-exhaustive** | shallow bugs; the only *complete* search, to a depth; length-optimal counterexamples | exponential in depth |
| **adaptive** | iterative deepening + parameter-boundary variation + profit-guided feedback | deep ordered gates |
| **model-guided** | hypothesis-shaped multi-step sequences | bugs outside the hypothesis shapes |
| **coverage-guided corpus** | deep, ordered, state-gated bugs | cheap shallow space (a random walk already covers it) |
| **random** | cheap, broad, shallow coverage | deep or specific sequences |

Running one and trusting it is exactly how a bug is missed. The portfolio runs
**all** of them and unions the counterexamples, so its detection set is a **strict
superset** of any single strategy: it can only ever find *more*. That is the honest
sense of "can't miss" -- it does not, and cannot, promise to find everything, and
it says so on every result.

## The oracle audit: a clean search is only as good as the oracle it checks

Every strategy above -- including the bounded-exhaustive certifier -- checks the
target's **declared invariants**. A search can be perfect and still find nothing,
because the oracle it checks can never fire. So before any clean result is trusted,
`audit_oracles(target)` asks, for every declared invariant, whether it is *able* to
catch anything:

1. **Evaluation census** -- evaluate the predicate on every sampled reachable state;
   record how often it was evaluable and how often it was false.
2. **Mutation sensitivity** -- deep-copy each reachable state, perturb its numeric
   leaves, and ask whether the predicate ever flips. Two families are tried: *local*
   (`+1, -1, +2, *2` -- a rounding / off-by-one / fee bug) and *cross-leaf* (set one
   leaf to a sibling's value, or to that value plus one -- the shape of a
   `withdrawn <= balance` or `shares * price >= underlying` comparison).

The verdicts, and what each entitles you to claim:

| verdict | meaning | what a clean search on it proves |
|---------|---------|----------------------------------|
| **DISCRIMINATING** | a perturbation of a reachable state flips it | a bounded negative on a live oracle |
| **VACUOUS** | evaluable everywhere in the sample, never false, nothing flips it | *nothing* -- the oracle was not shown to be able to fire |
| **INERT** | it fired on a sample but no perturbation flips it | *nothing* -- it reacts to a flag or an unreached path, not the numeric state |
| **UNEVALUABLE** | it raised on every state probed | *nothing* -- it was never checked |
| **NO_STATES** | no reachable state could be sampled | *nothing* |

Every weak verdict is a **bounded, sample-relative** statement and is reported as
one: "VACUOUS" means "vacuous within the sampled states under the tried
perturbations", never "this oracle is dead". The audit never asserts a
vulnerability (that is the verifier's job) and never claims an oracle is *good* --
only *demonstrably live* or *not demonstrably live*.

```bash
# Audit the declared invariants before trusting any clean result.
python3 -m blackheart assure oracles --target permit-replay --depth 3
```

```python
from blackheart.assurance import audit_oracles, OracleAuditConfig
audit = audit_oracles(make_target("lending-oracle"), OracleAuditConfig(max_depth=3))
print(audit.verdict_line())
for f in audit.weak:                     # not shown to be live -- trust nothing here
    print(f.inv_id, f.verdict, f.note)
```

## The certifier: exact, breadth-first, and honest about its bound

`certify(target, CertifyConfig(max_depth=D))`:

1. builds the **attack alphabet** -- every `(actor, operation, parameters)` symbol,
   where an operation is paired with the actors *allowed* to invoke it, and each
   parameter takes its declared boundary values (min, max) plus the canonical small
   values `0, 1, 2` that an off-by-one / rounding / fee bug lives on;
2. enumerates **every sequence** of length `1..D` over that alphabet,
   **breadth-first**;
3. runs each one from a fresh state and checks every declared invariant;
4. reports a :class:`CoverageCertificate` with the exact space size it covered.

**State-space dedup.** When a target declares a self-contained state
(`state_is_isolated`, via the `PureState` mixin), the certifier explores the *state
space* instead of the raw sequence space: a state already reached is never
re-expanded, because the target's future depends only on its state. This is sound
-- a violation is a function of state, so no violation is lost -- and it is what
makes a deeper bound affordable. It is a pure optimisation: a differential test
asserts the certificate is identical to the full sequence enumeration. If the
reachable state space **closes** before the depth bound, the certificate is then
complete for *every* sequence length, not merely the bound, and says so.

Two properties follow directly from "exhaustive" and "breadth-first":

- **A counterexample is length-optimal.** The first sequence that breaks an
  invariant is the shortest one that breaks it -- stronger than a sampled
  counterexample of unknown minimality, and the one to hand to a verifier.
- **A clean result is a proof of absence -- within the bound.** If nothing breaks,
  then no declared invariant is broken by any sequence up to depth `D` over the
  declared alphabet. The certificate prints the bound and its three limits:

  > a clean certificate says nothing about sequences *longer* than `D`, operations
  > or parameter values *outside* the declared alphabet, or properties *not
  > expressed* as an invariant.

A budget that stops the enumeration early is reported as **INCONCLUSIVE**, never as
clean: `exhaustive` is `True` only when the whole space to the requested depth was
actually covered.

A fourth limit is the evaluability of the properties themselves. If a declared
invariant's predicate raises on a reached state it is **unevaluable**, not
satisfied: the certificate records it in `unevaluable`, says `INCOMPLETE`, and
makes no completeness claim for it. The same rule holds in every other strategy
(`FuzzReport`, `CorpusReport`, `ExploreReport`, `PortfolioResult`, `HuntResult`
all carry the list), so a run that found nothing while an invariant could not be
evaluated reports "could not tell" rather than "clean".

```bash
# Prove absence (or find the shortest counterexample) to depth 5.
python3 -m blackheart assure certify --target permit-replay --depth 5

# Wider alphabet, deeper bound, JSON out.
python3 -m blackheart assure certify --target lending-oracle --depth 4 --out cert.json
```

```python
from blackheart.invariants.registry import make_target
from blackheart.assurance import certify, CertifyConfig

cert = certify(make_target("permit-replay"), CertifyConfig(max_depth=5))
print(cert.verdict_line())
for v in cert.violations:               # already length-optimal
    print(v["length"], v["invariant_id"], v["economic"]["attacker_profit"])
```

## The portfolio: the union, with a coverage ledger

`run_portfolio(target, PortfolioConfig(...))` runs every strategy (oracle audit,
bounded-exhaustive, adaptive, model-guided, coverage-guided, random), **unions** the
counterexamples (deduplicated by invariant, actor, operation and parameters),
prices each once with the universal value engine, and returns a
:class:`PortfolioResult` whose `stages` list is the **coverage ledger**: how many
sequences each strategy ran and which invariants it broke. The result also carries
`oracle_audit` and a `weak_oracles` list; when any declared invariant was not shown
to be live, the portfolio's verdict says so **before** it says anything about a
clean result.

```bash
# Run every strategy and show the ledger.
python3 -m blackheart assure portfolio --target lending-oracle --depth 3 --runs 4000

# Restrict to a subset (default: all six).
python3 -m blackheart assure portfolio --target wrapper --strategies exhaustive,corpus
```

Each stage is isolated: a strategy that raises is recorded as an error and does not
abort the others, so a search that crashes cannot hide the counterexamples the
others already found.

## The verdicts, verbatim

The one sentence each result is entitled to state:

- **BROKEN** -- a length-optimal counterexample was found within the enumerated
  space.
- **CERTIFIED CLEAN to depth D** -- no declared invariant is broken by any sequence
  of length `<= D` over the declared alphabet, *and* the certificate names its
  three limits.
- **INCONCLUSIVE** -- the space was not fully explored; this is "not found within
  budget", not a proof of absence.
- **FOUND / NOT FOUND (portfolio)** -- the union of every strategy; a negative is
  "not found within budget by any strategy", never "secure".

## Class coverage: the layer beneath the search

Everything above -- the oracle audit, the certifier, the portfolio -- assumes the
target *has* an executable model. The invariant engine can only find a bug in a
class it has a **vulnerable target and its guarded control** for. An objective
category with no model has no state, no operation, and no invariant, so it is
invisible to **every** strategy -- including the bounded-exhaustive certifier. That
is the deepest way a hunter misses a bug: not a weak search, but no target at all.

`blackheart.invariants.coverage` is the honest, machine-checkable map from an
objective category to the executable model that covers it:

```bash
# Which attack classes can the engine actually break?
python3 -m blackheart coverage
# 25/25 objective categories have an executable vulnerable/guarded model
# Every objective category has a representative model the engine can break.
```

It resolves the claim against the registry rather than asserting it by hand: a
category is `MODELLED` only when the registry actually holds its vulnerable/guarded
pair. A category with no model is `UNMODELLED` and reported as a **named gap**, and
the command exits non-zero so a caller fails closed. The same gate runs in
`blackheart doctor` (a **hard** failure, not a setup warning) and in CI
(`.github/workflows/ci.yml`), so an unmodelled category can never merge silently.
The ledger is explicit that a model is a **representative, not exhaustive** coverage
of the class: one pair proves the engine can break the class, not that every
instance of it is caught.

The classes that were previously prose-only now have executable pairs -- the first
three in `blackheart/invariants/logic_targets.py`, the next eight in
`blackheart/invariants/defi_targets.py`:

| category | vulnerable model | the one control the guarded model adds |
|----------|------------------|----------------------------------------|
| rounding-precision | deposit mints shares with a **ceiling** | floor the issued shares and refuse a zero-share deposit |
| ordering-timing | an offer is accepted **after its deadline** | refuse an acceptance once `clock > deadline` |
| info-disclosure | a read is gated on **authentication** | gate the read on **owning** the object (object-level authz) |
| cross-chain-replay | a bridge message has no executed-marker or domain binding | refuse a replayed or wrong-domain message |
| slippage-manipulation | swap output divides by the reserve, not reserve + input | use the correct constant-product formula |
| silent-transfer-failure | a deposit is credited though the token moved nothing | credit only what the transfer actually moved |
| governance-manipulation | voting power is the current (flash-loanable) balance | read voting power from the proposal snapshot |
| denial-of-service | one frozen position blocks the whole liquidation path | skip the frozen position instead of halting |
| reward-manipulation | a stake does not checkpoint the reward debt | checkpoint `stake * rewardIndex` on stake |
| storage-collision | implementation logic may write the admin slot | reserve the admin slot against logic writes |
| decimals-mismatch | every token is scaled as if it had 6 decimals | scale each token by its real decimals |

Each guarded variant differs from its vulnerable twin in exactly one method, so the
differential isolates the defect and the guarded model is a genuine non-vacuity
control.

## Directed certification

The exhaustive certifier enumerates the whole declared space, which is the only
way to prove absence within a bound but too expensive for a multi-contract
alphabet. `certify_directed` spends the same budget on the paths an unprivileged
attacker actually uses: operations that move value or address, the actor in
`to`/`from`, the protocol contracts in `spender`/`target`, and the maximum
numeric value. It keeps the states with the most movement in a bounded beam.

```bash
blackheart closure certify --source ./src --contract Vault --asset Token \
  --depth 4 --max-states 200000 --beam 500 --param-sets 32
blackheart assure directed --target vulnerable --depth 4
```

It records `exhaustive: false` and says a miss is **not a proof of safety**. On
the ERC4626 pair it finds the first-depositor path (mint, donate, approve,
deposit) in a fraction of the exhaustive budget, and it does not call the guarded
twin clean when the budget runs out. Acceptance bar:
`tests/test_directed_certification.py`.

## The doctrine

The rules are in `blackheart.mindset.COVERAGE_DOCTRINE`,
`blackheart.mindset.ORACLE_DOCTRINE`, and `blackheart.mindset.MODEL_DOCTRINE`, and
are carried by every role prompt, every agent (`## The coverage bar`,
`## The oracle bar`, and `## The model bar`) and the mindset skill:

1. Run every search, not one; the portfolio's result is a superset of any single
   search.
2. Only a bounded-exhaustive search may say "no counterexample exists", and only up
   to its declared depth over the declared alphabet.
3. A clean result is bounded, not final -- state the bound with the result.
4. Prefer the certified, length-optimal counterexample; never present a sampled
   sequence as minimal.
5. Coverage is proven, not assumed; "every strategy found nothing" is an honest
   bounded negative, never proof the target is secure.
6. An oracle you did not audit is an assumption, not a check. Audit every declared
   invariant before trusting a clean result, and treat a weak oracle as an
   unsearched property.
7. Strengthen the oracle before strengthening the search: when the invariants are
   thin, the strongest engine still finds nothing.
8. A class with no model is a class every search is blind to. Turn an objective
   that exists only as prose into a vulnerable/guarded pair before trusting a clean
   result against it, and audit class coverage with `blackheart coverage`.
9. A model proves the class is breakable, not that every instance is caught. One
   representative pair is not exhaustive coverage of the class.

## What this does *not* claim

- It does **not** guarantee a target has no bug. No tool can. It guarantees that
  everything up to the stated bound was covered, that the union of every strategy
  was run, and that the declared invariants were audited.
- The alphabet is the **declared** one. A bug that needs an operation or parameter
  the target does not declare is outside it -- which is why declaring a complete
  `OpSpec.param_domain` matters.
- A clean certificate is about **declared invariants**. A property nobody wrote
  down is a property nobody checked.
- The oracle audit's weak verdicts are **sample-relative**: "VACUOUS" means "not
  shown to be live under the sampled states and tried perturbations", never "this
  oracle is dead". A predicate that reacts to a shape outside the perturbation
  families, or a value reachable only beyond the sample, may be reported weak.
- Class coverage is **representative, not exhaustive**. A `MODELLED` category means
  the engine has a pair that breaks that class, not that every instance of the class
  is caught. The ledger names the pair and never claims more.
