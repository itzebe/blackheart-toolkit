# The evolving research engine

BLACKHEART is not a scanner. This document describes the part of it that makes
it *get better over time*: a persistent research memory, an autonomous hypothesis
engine, a class-aware tool selector, an adversarial verifier, and a
self-improvement loop with a benchmark that can reject a bad idea.

The mission for this work was explicit: the objective is **not** more scanners.
It is to make BLACKHEART progressively better at discovering, reproducing,
understanding, validating, and reporting real vulnerabilities — and to prove the
improvement with measurements rather than claims.

The engine runs under a canonical operational doctrine — the identity, the
six-phase lifecycle, the verdicts, and the security invariants — in
`blackheart/doctrine.py` (see `docs/DOCTRINE.md`, `blackheart doctrine`). Every
meaningful investigation ends in a persistent, evidence-gated finding record in
`blackheart/findings/` (`blackheart findings`).

---

## 1. Persistent research memory (`blackheart/research/`)

Every investigation — confirmed, unconfirmed, disproven, or incomplete — writes
one `ResearchRecord`. The record is deliberately rich: target + exact revision,
scope reference, vulnerability class, hypothesis, strategy, tools + configs,
reproducible commands, expected vs actual outcome, evidence hashes, exploitability
verdict, impact, false-positive reason, reusable lessons, confidence, and whether
it was independently verified.

The memory is an **append-only JSONL log**, replayed into the current state of
each record, so a status change is a new event and history is never lost. It
keeps four buckets strictly separate and exposes only *confirmed* records through
`attack_knowledge()`:

```
CONFIRMED    reproduced and independently verified  -> attack knowledge
UNCONFIRMED  a live hypothesis, not yet proven       -> a lead
DISPROVEN    actively falsified                       -> do not re-run
INCOMPLETE   started but not finished                 -> unfinished work
```

Two safety properties are enforced in code, not by convention:

- `ResearchRecord.promote(CONFIRMED)` **refuses** unless the record is marked
  independently verified *and* carries an evidence reference. An unverified idea
  can never be read back as a vulnerability.
- `ResearchMemory.save()` stamps a content hash so `verify_integrity()` can detect
  a tampered record.

Retrieval is what the hypothesis engine depends on: `search()` matches on target,
class, and free text across hypothesis/strategy/lessons/impact/false-positive
reason; `lessons_for()` returns both confirmed lessons and the reasons a
hypothesis was disproven; `disproven_signatures()` lets the engine skip a
falsified idea unless new evidence arrives.

## 2. Protocol intelligence and threat modeling (`blackheart/threatmodel/`)

Before the hypothesis engine may hunt, a **protocol-specific threat model** must
exist (mission P1 / Phase 2). This is the step that keeps the AI from drifting
into generic pattern-matching: the researcher writes down *what the protocol is,
what it promises, and where it stops trusting*, and only then does automated
hunting begin.

A `ThreatModel` records the architecture, the critical assets, the trust
boundaries (each with the **assumption** the trusted side makes about the
untrusted side), the security assumptions (each with the invariant that breaks
`if_false`), the security-relevant state transitions and their guards, and the
invariants — at least one **per critical asset**. It also carries the selected
**impacts** (Part 3.B), drawn from a canonical catalogue of thirteen, so effort
flows to consequential bugs rather than coverage.

Two enforcement points, both in code:

- `ThreatModel.is_complete()` / `missing()` is a **gate**. It requires a summary,
  architecture, critical assets, trust boundaries, assumptions, invariants,
  selected impacts, and that *every* critical asset is covered by an invariant.
  A `TargetProfile` is deliberately *not* a threat model — bootstrapping one with
  `model_from_profile()` leaves the assumption and invariant fields empty, and the
  gate reports them.
- `HypothesisEngine(profile, threat_model=…)` **raises `ThreatModelIncomplete`**
  rather than hunting against an incomplete model, and re-ranks the objectives so
  the selected impacts are investigated first (`steer_objectives`). Objectives are
  never dropped — only reordered — so nothing is silently hidden.

## 3. Autonomous hypothesis engine (`blackheart/hypothesis/`)

Given a target and the memory, the engine enumerates candidate hypotheses from the
objective catalogue and the attack-chain templates, then scores each on:

| Component | Weight | Meaning |
|---|---|---|
| exploitability | 0.30 | how readily an external attacker reaches it |
| impact | 0.30 | potential security/economic consequence |
| novelty | 0.15 | how much prior work already covers this (target, class) |
| evidence | 0.15 | did prior attempts in this class reach reproduction? |
| feasibility | 0.10 | can the right tools actually run in this environment? |

It ranks them, selects the next one, and **explains** the selection in words. A
(target, class) the memory has already *disproven* is skipped — unless the caller
supplies `new_evidence=True`, the one legitimate reason to revisit a falsified
idea.

### Surface applicability — the measured improvement

The baseline strategy scored every class from static constants, so it ranked the
same class first for *every* target. It never asked whether the target exposes the
surface a class needs. `blackheart/hypothesis/surface.py` reads the target's real
surface (entry points, trust boundaries, roles, dependencies, notes) and derives a
multiplier per class: classes whose required surface is **absent** are damped;
those **present** are boosted.

The detector is negation-aware and CamelCase-aware: `VaultNoOracle` with notes
"no external price dependency" is correctly read as *not* having an oracle. This
mattered — naive substring matching inverted the ranking on the benchmark's
negative corpus.

### 3a. Hypothesis generation engine — P2 (`blackheart/hypothesis/generation.py`)

Section 3 ranks *candidate* hypotheses from the objective/chain catalogue. P2 is
the next step: turn a **validated threat model** (section 2) into *specific,
falsifiable* hypotheses, and refuse to do so from a model that has not stated what
it protects.

The distinction is the whole point. A generic idea ("there might be an
access-control bug") is untestable, unfalsifiable, and indistinguishable from a
thousand others. P2 emits a hypothesis only when all of these are present, or it
records the draft as a **rejection with the missing fields named**:

| Field | Meaning |
|---|---|
| component, entry_point | the exact target and call path attacked |
| attacker_capability | the capability the attacker must already have |
| trust_boundary | the boundary the attack crosses |
| critical_asset | the asset endangered |
| invariant | the property that must hold (from the model's stated invariants) |
| expected_impact | the consequence, mapped to a *selected* impact |
| strategy | how to attempt it (composed with the hypothesis's own specifics) |
| reproduction_criteria | what a reproduction looks like |
| falsification_criteria | what result would prove it **wrong** |
| authorization_requirement | the gate that must pass before active testing |
| novelty_requirement | the review that must pass before submission |

Properties enforced in code:

- **Incomplete model is refused.** `generate()` raises `ThreatModelIncomplete`
  rather than inventing hypotheses against an unvalidated model.
- **Explainable ranking.** Each hypothesis carries `score_parts` (impact,
  exploitability, evidence, feasibility, cost-efficiency) and a written
  `rationale`; the weights are a reviewable value, not a buried constant.
- **Duplicates collapse by root cause.** Two hypotheses sharing
  (component, class, invariant) are the same bug however exploited; the lower one
  is kept as a rejection that names its duplicate. Overlaps (same component/class,
  different invariant) are kept and linked.
- **Negative results are kept.** `HypothesisStore` persists every generation,
  hypothesis and rejection, so a later cycle can ask "was this already rejected?"
  and get the reason.
- **Alternatives on contradiction.** `alternatives()` produces replacement
  hypotheses that keep the endangered asset but change the attack class, so a
  falsified idea pivots instead of repeating.
- **It learns across cycles.** A (component, class) the memory already records as
  CONFIRMED is suppressed as "already known", so cycle 2 does not re-hunt a solved
  bug.

### 3b. Investigation workflow engine — P3 (`blackheart/investigation/`)

P3 takes one hypothesis and drives it to an evidence-backed verdict, refusing to
skip steps:

```
HYPOTHESIS -> TRIAGE -> SOURCE_ANALYSIS -> TEST_DESIGN
           -> REPRODUCTION -> INDEPENDENT_CHALLENGE -> VERDICT
```

Every transition has **entry criteria** and **evidence requirements**; a
transition whose criteria are unmet is refused, and a refused transition leaves
the investigation exactly as it was (so a corrected retry is possible). The
properties the mission requires are enforced in code:

- **Authorization before execution.** REPRODUCTION re-checks the authorization
  gate immediately before running; an UNKNOWN, OUT_OF_SCOPE or stale asset cannot
  enter it, and the gate is re-checked even if scope closed since TEST_DESIGN.
- **Independent challenge before confirmation.** A `GENUINE_VIOLATION` is only
  recorded as CONFIRMED when an independent challenge actually reproduced it (and,
  when supplied, the novelty gate and the independent verifier agree). Otherwise it
  is held UNCONFIRMED — a lead, never promoted.
- **Honest outcome classification.** Malformed-input rejection, self-DoS,
  environmental failure, false positive, out-of-scope and a genuine violation are
  distinct outcomes with distinct memory statuses. An environmental failure is
  INCOMPLETE (retryable) — never "disproven".
- **Persistent and resumable.** State is an append-only JSONL log rebuilt by
  replay, so an interrupted investigation resumes with nothing lost — including
  after the sandbox that started it is gone. A crash-truncated final line is
  skipped and *reported*, not hidden.
- **Tamper-evident.** Every persisted state is *hash-chained*: it carries its
  sequence number, the previous record's chain hash, its own content hash, and its
  chain hash — plus an HMAC-SHA256 signature when a signing key is configured.
  `InvestigationStore.verify_integrity()` re-walks the chain and reports a single
  honest status (`VERIFIED` / `FAILED` / `LEGACY` / `UNAVAILABLE`). A verdict
  fabricated by editing the log — or by deleting, reordering, inserting, or
  truncating records — no longer matches the chain and is reported
  (`blackheart investigate verify`, exit 1) instead of being trusted. Detection is
  additive: replay still returns the (now suspect) state, but the engine refuses
  to record a `CONFIRMED` verdict over a log that fails verification. The honest
  limits — a keyless log can be fully rewritten by a capable attacker, and a
  locally stored checkpoint does not stop an attacker who can rewrite both — are
  documented in [INTEGRITY.md](INTEGRITY.md), not hidden.
- **Every run is evidence.** A reproduction is captured in the content-addressed
  evidence store; a reproduction with no evidence reference is not evidence.

## 4. Class-aware tool selection (`blackheart/exploit/toolselect.py`)

Tools are selected **by vulnerability class**, not run indiscriminately. For each
of fifteen classes the selector returns the primary tools that can actually
demonstrate it, corroborating tools, the secure control the class needs, the
engine method to use (stateful fuzz, differential pair, malformed input, memory
safety, workflow reachability), and a rationale. Tools missing from the current
environment are named as missing, not pretended.

## 5. Adversarial verification (`blackheart/verify/`)

The seven original gates are unchanged. Four opt-in challenges were added, each
applied only when the verifier supplies the corresponding fact (so existing
verdicts are untouched, and supplying them can only tighten the verifier):

- **root-cause** — is the stated root cause the real mechanism, not a symptom?
- **reproduction-integrity** — does the *secure control* also "reproduce"? If so
  the PoC does not discriminate a vulnerability from benign behaviour.
- **authorization-boundary** — is the asset explicitly AUTHORIZED by the gate?
- **false-positive-explanation** — does a benign explanation account for the
  observation?

## 6. Self-improvement (`blackheart/learning/`)

The engine closes the loop the mission describes:

```
extract lesson -> identify the weakness -> propose an improvement
-> demonstrate the OLD weakness with a failing case
-> benchmark on the historical corpus AND the negative corpus
-> measure -> accept or reject -> freeze the lesson as a regression test
```

Two hard safety properties:

- **The engine may not weaken safety.** `PROTECTED_PATHS` names `blackheart/authz`
  and `blackheart/verify`; any improvement that targets them is **refused**.
- **No overfitting.** Adoption requires improvement on the historical corpus
  *and* no regression on the negative corpus. A change that only memorises the
  historical corpus is rejected.

An "improvement" is a *value* (a `Strategy`), measured directly — the engine does
not rewrite its own source, so a human can review an adoption.

### Measured result

`python3 -m blackheart learn demo`:

| Corpus | Metric | Baseline | Surface-aware |
|---|---|---|---|
| historical | top-1 accuracy | 0.00 | **0.75** |
| historical | MRR | 0.149 | **0.781** |
| historical | surface-suppression | 0.485 | **0.879** |
| negative | top-1 accuracy | 0.00 | **1.00** |
| negative | MRR | 0.279 | **1.000** |

The negative corpus is the anti-overfitting gate: the surface-aware strategy is
*better* there too, because the rule it learned ("consider whether the target
exposes the surface a class needs") is the correct generalisation, not a
memorisation of the historical cases.

## 7. Resumable research queue (`blackheart/research/queue.py`)

A persistent, crash-safe queue of research tasks. Each entry carries the
authorized (target, asset), the profile and authorization record, priority,
attempt budget, completion criteria, and progress. Three properties the mission
requires:

- **Authorization is re-checked on every dequeue.** A stale or revoked scope moves
  the entry to BLOCKED and it does not run — this is how a closed program stops
  affected testing immediately.
- **Bounded.** A target that exhausts its attempt budget is BLOCKED, so the queue
  cannot loop forever.
- **Recoverable.** State is an append-only log; a restart (or a new sandbox)
  loses nothing.

## 7a. Pre-submission novelty gate (`blackheart/novelty.py`)

A confirmed, in-scope, reproduced finding can still be a **duplicate**, and a
"novel technique" for an already-known bug is not a new vulnerability. The gate
adjudicates a `NoveltyReview` and fails **closed**: a finding cannot be promoted
to submission-ready unless the review classifies it `LIKELY_NEW` or
`POSSIBLE_VARIANT`. Every other classification blocks submission and states why.

**How a review is scored.** The candidate is compared field by field against each
recorded public disclosure — root cause, affected component, trust boundary,
exploit path, impact, and vulnerability class — using token-set similarity,
weighted toward *root cause* (0.35) and *affected component* (0.25). The score is
normalised by the weight actually applicable, so a disclosure with few populated
fields is not unfairly zeroed.

**Classifications** (`NoveltyClass`):

| Classification | Trigger | Submittable |
|---|---|---|
| `LIKELY_DUPLICATE` | best match ≥ 0.72, **or** same root cause + same component | no |
| `ALREADY_FIXED` | best match ≥ 0.72 and the disclosure records a remediation | no |
| `POSSIBLE_VARIANT` | best match ≥ 0.40 (but below duplicate) | yes |
| `INSUFFICIENT_EVIDENCE` | no strong match **and** the search was under-powered | no |
| `LIKELY_NEW` | no strong match after a documented, adequately powered search | yes |

The decisive rule is the *same root cause in the same component* — a shared
component plus a substantially-shared mechanism is the same defect, whatever the
exploit path is called. This is the OSS-001 lesson: a Gemini CLI duplicate whose
technique differed was still the same bug.

**Novelty is not proven by absence of a result.** A search below
`MIN_SOURCES_FOR_NOVELTY` sources or `MIN_QUERIES_FOR_NOVELTY` queries is
`INSUFFICIENT_EVIDENCE`, never `LIKELY_NEW`. `LIKELY_NEW` means "no matching public
disclosure identified", not a guarantee.

**Relationship to the other gates.** The gate consumes a novelty review; it does
not perform the search. Duplicate detection against *BLACKHEART's own* history
(confirmed findings, disproven hypotheses, rejected leads) lives in the persistent
research memory (§1) and the queue's duplicate suppression — those stop the engine
re-investigating what it already knows, while the novelty gate stops it
*submitting* what the world already knows. A confirmed finding must clear the
integrity gate (§3b), the independent-challenge gate, and this novelty gate before
it is submission-ready; **AI consensus or a clean static scan is never sufficient**
on its own.

`blackheart novelty --file review.json` prints the adjudicated review and exits
non-zero when submission is blocked.

## 8. Honest limits

- The benchmark corpora are small (four historical, four negative scenarios).
- The surface detector is keyword/surface-based. It is negation- and
  CamelCase-aware and validated against the negative corpus, but it is a model of
  the target, not a proof about it.
- The learning engine adopts improvements as reviewed *values*. It does not edit
  source, and it cannot modify the authorization or verification modules.
- Continuous operation is provided by the durable scheduler
  (`blackheart/scheduler/`, `blackheart schedule`): an append-only, hash-chained,
  lease-fenced job queue that dispatches the engines with bounded retry, misfire
  recovery and authorization re-checked at every boundary. It adds reliability,
  not research insight — see `docs/SCHEDULER.md`.

## 9. Commands

```bash
blackheart research summary                 # bucket counts
blackheart research search --target X --vclass oracle-manipulation
blackheart research export --out memory.md  # markdown dump by bucket
blackheart research integrity               # re-hash stored records
blackheart threatmodel catalog                       # the 13 canonical impacts
blackheart threatmodel scaffold --profile p.json --impact theft-or-freeze --out model.json
blackheart threatmodel check --model model.json      # gate: exits non-zero until complete
blackheart threatmodel steer --profile p.json --model model.json
blackheart hypothesis --profile p.json --surface      # ranked next investigation
blackheart hypothesis --profile p.json --threat-model model.json  # gated + impact-steered
blackheart hypothesize --profile p.json --threat-model model.json --store research/private/hypotheses
blackheart investigate --dir research/private/investigations list
blackheart investigate --dir research/private/investigations show INV-...
blackheart investigate --dir research/private/investigations run --hypothesis hyp.json --authz authz.json
blackheart investigate --dir research/private/investigations verify        # hash-chain tamper check (exit 1 if edited)
blackheart investigate --dir research/private/investigations keygen        # HMAC key OUTSIDE the log (0600)
blackheart investigate --dir research/private/investigations checkpoint --key-path <key>   # detect tail truncation
blackheart integrity <log.jsonl> --require-signatures  # verify any append-only log (see docs/INTEGRITY.md)
python3 -m blackheart.demo_p2p3             # P2->P3 cycle vs the DVDF fixture (--skip-forge to use the recorded result)
blackheart doctrine                         # the operational doctrine (identity, lifecycle, verdicts, invariants)
blackheart findings add --file finding.json # document a finding (A-J record, hash-chained)
blackheart findings list --target X --status UNCONFIRMED
blackheart findings confirm --finding BH-2026-001 --evidence research/private/evidence  # the ONLY path to CONFIRMED
blackheart findings report --out research-report.md
blackheart findings integrity               # verify the findings log hash chain (exit 1 on tamper)
blackheart learn bench                      # baseline vs surface-aware
blackheart learn demo --out research/private/learning # full loop + regression test
blackheart queue plan                       # what would run next, and why
blackheart novelty --file novelty-review.json   # pre-submission gate (duplicate / already-fixed / under-powered search)
```
