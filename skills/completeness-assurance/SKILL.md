---
name: completeness-assurance
description: >
  The can't-miss discipline: audit the oracles, run every search strategy, union the
  results, and be exact about what was covered. Audit every declared invariant to
  decide whether it can catch anything at all (a clean result on a weak oracle proves
  nothing); use a bounded-exhaustive enumeration to prove a target clean up to a
  depth (and only a bounded-exhaustive search may say "no counterexample exists");
  use the portfolio to make the detection set a superset of any single strategy. Use
  when a negative result must be trustworthy, when a hunt must not miss what any one
  search would find, when you need a length-optimal counterexample, when the declared
  invariants may be too thin to catch a bug, or when reporting a clean target. Backed
  by the engine in `blackheart.assurance`.
triggers:
  - can't miss
  - cannot miss
  - exhaustive
  - completeness
  - coverage
  - prove absence
  - no bug found
  - clean target
  - certified
  - certificate
  - portfolio
  - union of strategies
  - length optimal
  - shortest sequence
  - bounded search
  - assurance
  - oracle
  - oracle audit
  - vacuous invariant
  - weak invariant
  - discriminating
  - false positive
  - invariants too thin
---

# Completeness assurance — never confuse "not found" with "not there"

A fuzzer that samples a space and reports "clean" is dangerous: it hides the bug
it did not reach behind a confident negative. BLACKHEART's answer is three engines,
all in `blackheart.assurance`:

- **the oracle audit** — for every declared invariant, decide whether it can catch
  anything at all. Every search is bounded by the target's oracles, so this runs
  first: a clean result on a weak oracle proves nothing.
- **bounded-exhaustive certification** — enumerate *every* sequence up to a depth
  over the declared alphabet and run all of them. It is the only search allowed
  to say "no counterexample exists", and only up to its declared bound.
- **the portfolio** — run every strategy (oracle audit, bounded-exhaustive,
  adaptive, model-guided, coverage-guided, random), union the counterexamples,
  price them once, and report which strategy covered what.

The detection set of the portfolio is the **union**, so it is a strict superset of
any single strategy: it can only ever find *more*. That is the honest sense of
"can't miss" — it does not, and cannot, promise to find everything, and it says so
on the certificate.

## The rule that governs every negative

| Search | What a negative result means |
| --- | --- |
| oracle audit | **The declared invariants were (or were not) shown to be able to fire.** A weak oracle makes every clean result below meaningless. |
| bounded-exhaustive (to depth D) | **No declared invariant is broken by any sequence of length <= D over the declared alphabet.** Bounded, stated with its limits. |
| adaptive / guided / corpus / random | **Not found within budget.** Never "clean", never "secure". |

A clean certificate is **not** a proof the target is secure. It says nothing about
sequences longer than D, operations or parameters outside the declared alphabet,
or properties not expressed as an invariant. Print the bound with the result.

## Audit the oracle before you trust the search

A perfect search against a dead oracle finds nothing. `audit_oracles` evaluates
each declared invariant on reachable states and mutates each state's numeric leaves
(both *local* perturbations `+1, -1, +2, *2` and *cross-leaf* ones that set one leaf
to a sibling's value) to see whether the predicate can ever flip:

- **DISCRIMINATING** — a perturbation flips it. A clean search on it is a bounded
  negative on a live oracle.
- **VACUOUS / INERT / UNEVALUABLE / NO_STATES** — the oracle was *not shown to be
  able to fire*. A clean result on it proves **nothing**.

Every weak verdict is **sample-relative**: "VACUOUS" means "not shown to be live
under the sampled states and tried perturbations", never "this oracle is dead".
Strengthen the oracle before you strengthen the search — when the invariants are
thin, the strongest engine still finds nothing.

## Audit class coverage before you trust the target

Beneath the oracle sits the model. The engine can only break a class it has an
executable **vulnerable/guarded pair** for; a class that exists only as prose has no
state, no operation, and no invariant, so it is invisible to *every* strategy —
including the certifier. Audit the class coverage first:

```bash
# Which attack classes can the engine actually break?
python3 -m blackheart coverage
# 25/25 objective categories have an executable vulnerable/guarded model
```

- **MODELLED** — a registered vulnerable/guarded pair exists. The engine can break
  the class.
- **UNMODELLED** — no pair; a **named gap** every search is blind to. The command
  exits non-zero so a caller fails closed. Turn the category into a pair.

The same gate runs in `blackheart doctor` (a hard failure) and in CI, so a new
objective category with no model cannot merge silently.

A model proves the class is *breakable*, not that every instance is caught: one
representative pair is never exhaustive coverage of the class. Say "the engine can
break this class", never "this class is covered".

## How to run it

```bash
# Audit the declared invariants before trusting any clean result.
python3 -m blackheart assure oracles --target permit-replay --depth 3

# Exhaustively enumerate every sequence up to depth 5 and certify the result.
python3 -m blackheart assure certify --target permit-replay --depth 5

# Run every strategy, union the counterexamples, and show the coverage ledger.
python3 -m blackheart assure portfolio --target lending-oracle --depth 3 --runs 4000

# Restrict to a subset of strategies (default: all six).
python3 -m blackheart assure portfolio --target wrapper --strategies exhaustive,corpus
```

From Python:

```python
from blackheart.invariants.registry import make_target
from blackheart.assurance import (
    audit_oracles, OracleAuditConfig, certify, CertifyConfig,
    run_portfolio, PortfolioConfig,
)

audit = audit_oracles(make_target("lending-oracle"), OracleAuditConfig(max_depth=3))
print(audit.verdict_line())         # are the oracles even able to fire?
for f in audit.weak:
    print(f.inv_id, f.verdict, f.note)

cert = certify(make_target("permit-replay"), CertifyConfig(max_depth=5))
print(cert.verdict_line())          # the one honest sentence

res = run_portfolio(make_target("lending-oracle"), PortfolioConfig(certify_depth=3))
print(res.verdict_line(), res.invariants_found, res.weak_oracles)
```

## Why it is stronger than any single strategy

- **The oracle is checked first**: a clean result is only reported alongside the
  audit that says whether the invariants could have caught anything.
- **No missed union**: if *any* strategy finds a counterexample, the portfolio
  reports it. Running one strategy and trusting it is how a bug is missed.
- **Length-optimal counterexamples**: breadth-first enumeration yields the
  *shortest* sequence that breaks the invariant — stronger than a sampled
  counterexample of unknown minimality, and the one to hand to a verifier.
- **Deeper bounds when sound**: for a target with isolated state, the certifier
  explores the state space with dedup (a pure optimisation, asserted equal to full
  enumeration), so it reaches deeper for the same proof — and reports completeness
  for *all* depths when the state space closes.
- **Honest coverage ledger**: every stage records how many sequences it ran and
  which invariants it broke, so a reader sees exactly what was and was not covered.
- **One accounting**: every unioned counterexample is priced once with
  `blackheart.value`, so a broken invariant and a demonstrated extraction are never
  confused.

## Do not

- Do not report a stochastic search's negative as "clean"; it is "not found within
  budget".
- Do not report a certificate without its bound and its three stated limits.
- Do not trust a clean result before auditing the oracle it checks; a vacuous,
  inert, or unevaluable invariant makes the clean result meaningless.
- Do not report a weak-oracle verdict as proof the oracle is dead — it is
  sample-relative, and it must be stated as such.
- Do not present a sampled sequence as length-minimal.
- Do not let one strategy's crash hide another's finding — the portfolio isolates
  each stage.
- Do not trust a clean result for a class the engine has no model for; an
  unmodelled category is a class every search is blind to. Audit coverage with
  `blackheart coverage` and close the gap first.

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
