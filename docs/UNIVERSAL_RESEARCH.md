# Universal research intake

Four engines make BLACKHEART's research workflow **independent of the environment a
target happens to live in**. Before them, the engine could only research a target
that fit the shape it was built for: an EVM contract, in a local fork. Everything
else — an HTTP service, a web application, an API, a repository that is not
Solidity — had to be re-implemented, class by class, before a single hypothesis
could be tested.

They add **no new search engine**. Each one plugs into the existing pipeline
(objectives → hypotheses → invariants → value → findings) and keeps that pipeline's
own verdicts. What changes is the *input*: where the target lives, how it is
executed, what classes apply, and where the opportunity was found.

```
                    ┌─────────────────────────────────────┐
  target profile →  │ program_intel  (what is in scope?)   │
                    └─────────────────────────────────────┘
                                    ↓
                    ┌─────────────────────────────────────┐
                    │ coverage_engine (what classes apply, │
                    │  what paths compose, what is left?)  │
                    └─────────────────────────────────────┘
                                    ↓
                    ┌─────────────────────────────────────┐
                    │ environments (where does it run?)    │
                    └─────────────────────────────────────┘
                                    ↓
                    existing invariants → value → findings
                                    ↑
                    ┌─────────────────────────────────────┐
                    │ mail_intel (where was it found?)     │
                    └─────────────────────────────────────┘
```

---

## `coverage_engine` — the universal coverage engine

`blackheart coverage-engine {taxonomy,assess}`

The engine can only break a class it can *name and model*. This module answers
three questions, in order, and records every answer.

1. **What classes exist?** A `Taxonomy` of 39 attack classes, each with the
   surface it needs (`requires`), a severity band, and — where one exists — the
   `objective_category` of the executable vulnerable/guarded pair that can break
   it. The taxonomy is **extensible**: `Taxonomy.extend()` adds a class discovered
   mid-engagement, marked `discovered=True`, so a new class is recorded as a gap
   rather than silently omitted.
2. **Which apply to *this* target?** `ApplicabilityEngine` classifies every class
   as `APPLICABLE`, `INAPPLICABLE` (with a reason) or `UNRESOLVED`. A thin profile
   produces `UNRESOLVED`, never a guessed `INAPPLICABLE`: "we could not decide" is
   honest, "it does not apply" is a claim.
3. **What can be composed?** `SurfaceEnumerator` turns applicable classes into
   hypotheses (each with an `assumption` and a `violation`) and — where two classes
   can chain — into multi-stage attack paths. Individually benign behaviours that
   compose into a break are the class single-step search cannot see.

`ResearchController` runs the loop: prioritise, probe, adapt, record. Its stop
reasons are honest — `BUDGET_EXHAUSTED`, `STRATEGY_SPACE_EXHAUSTED`,
`ENVIRONMENT_BLOCKED` — and each states that it is **not proof** of absence.

### The coverage ledger

`CoverageRecord` is the auditable output. It refuses dishonest states:

| State | Requires | Meaning |
|---|---|---|
| `REPRODUCED` | evidence | the defect was reproduced, with a tier |
| `INAPPLICABLE` | a reason | the class cannot apply here, and why |
| `BLOCKED` | a reason | it applies but could not be tested |
| `TESTED_NO_ISSUE_FOUND` | a reason | searched within budget; **not** clean |
| `NOT_ASSESSED` | — | not attempted (an open class) |

A run with any open class summarises as `INCOMPLETE`. A run where everything was
searched summarises as `NO_FINDINGS_WITHIN_BUDGET` — never "clean".

### The linkage invariant

A taxonomy link must resolve to a **modelled** objective category, and every
modelled category must be nameable by the taxonomy. Both directions are enforced by
tests (`test_every_taxonomy_model_link_resolves_to_a_modelled_category`,
`test_every_modelled_category_is_reachable_from_the_taxonomy`): a broken link is a
blind spot, and a modelled-but-unnamed class is dead coverage no plan can select.

---

## `environments` — the execution adapters

`blackheart environment {list,route}`

An `ExecutionAdapter` declares the capabilities it has **confirmed by probing this
host**, not the capabilities it wishes it had. `probe()` returns a `Readiness` with
a real state; an unready backend is reported, never assumed.

Three backends ship:

| Backend | Target types | Evidence tier |
|---|---|---|
| `LocalSourceAdapter` | `source-repository`, `local-file` | `real-execution` |
| `HttpServiceAdapter` | `http-service`, `web-application`, `remote-service` | `real-execution` |
| `SequenceModelAdapter` | `protocol-implementation`, `smart-contract` | `simulation` |

`EnvironmentRegistry` routes a `(target_type, operation)` pair to the backend that
declares it, or raises `Unroutable` with the reason — an explicit limitation rather
than a silent no-op.

### The central gate

Every `_execute` call passes through **one** authorization gate. An adapter may not
override it; `validate_declaration` refuses a declaration that tries. This is why
adding a backend cannot add an authorization bypass: the gate is not per-backend.

The evidence tier is carried on every observation and is **never upgraded**.
A simulation result stays `simulation`; only a backend that really executed can
produce `real-execution`.

---

## `program_intel` — universal program intelligence

`blackheart program {normalize,requirement}`

A program's published policy arrives as free prose, in a different format on every
platform. `PolicyNormalizer` parses it into a `PolicyRecord` that **preserves what
the text actually said** and records what it could not establish:

- scope assets (verbatim, with the original line kept for audit),
- class rules (stated inclusions and exclusions),
- the minimum eligible severity band, derived from *this* program's wording,
- testing restrictions and rate limits,
- payouts, provenance (`source_url`, `retrieved_at`, `source_sha256`).

Anything the parser cannot classify becomes an **uncertainty** — `"unparsed
in-scope line: …"` — never a guess. An empty policy records an uncertainty, not a
silent empty. `is_verified()` is false when provenance is missing.

`PolicyVersionLog` makes the policy version-aware: adding a new version yields the
changes (`asset-added`, `asset-removed`, `minimum-severity`, …) and reports which
research needs reassessment. A program that lowers its severity floor changes what
is worth reporting; that must be a recorded event, not a surprise.

`PolicyEligibility` bridges to the coverage engine and returns **three** values:
`True` (stated eligible), `False` (stated excluded), `None` (not mentioned).
`None` is not `False`: an unmentioned class is unknown, and the coverage engine
must not treat unknown as excluded.

---

## `mail_intel` — secure Gmail intelligence

`blackheart mail {status,import}`

Bounty programs and scope changes arrive by email. This module reads them —
**read-only, always** — and is inert by design where it cannot be safe.

### Scope policy

Only `https://www.googleapis.com/auth/gmail.readonly` is ever requested.
`validate_scopes` refuses every forbidden scope, and `GmailReadOnlyClient` refuses
to construct with a write scope. The client has **no** `send`, `modify`, `delete`,
`insert`, `trash` or `compose` method — asserted by test, not by convention.

### The honest blocker

`gmail.readonly` is a Google **restricted** scope. A live unattended integration
requires Google verification (a security assessment), annual re-verification, and —
in testing mode — a 7-day refresh token. `describe_requirement()` reports this with
sources. BLACKHEART **does not bypass verification**; the fallback is manual import.

### The trust boundary

An email is **data**, never authority. `classify_message` extracts claims and flags
prompt injection; every claim records that it "never grants authorization".
`fence_email` wraps content in an explicit untrusted block. Links are recorded and
**never followed**. A flagged message is deprioritised (`priority=0`).

An email that claims new scope creates an opportunity **candidate**. It cannot
create an authorization: delivery goes through the existing `TriggerReceiver`,
whose own gate resolves authorization from BLACKHEART's records. A message claiming
`0xabc…` is in scope is still refused if no authorization record says so — proven
by test.

### The zero-OAuth fallback

`ManualImporter` parses a pasted or exported message (`parse_text`, `parse_json`)
and feeds the same intake. It works with no OAuth at all. An import is
`UNVERIFIED_SENDER` unless the operator attests authentication — because the
operator pasting text is not proof the mail was authentic.

---

## Acceptance bars

| Module | Tests |
|---|---|
| `coverage_engine` | `tests/test_coverage_engine.py` |
| `environments` | `tests/test_environments.py`, `tests/test_environment_agnostic.py` |
| `program_intel` | `tests/test_program_intel.py` |
| `mail_intel` | `tests/test_mail_intel.py` |

`test_environment_agnostic.py` is the end-to-end claim: one controller, unchanged,
researching a local repository, an HTTP service and a simulation state machine.
