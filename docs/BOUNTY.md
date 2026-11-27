# Bounty intelligence: program-specific eligibility, severity, and payout

A technically valid finding is not a payable one. A program pays only for what its
*own* policy says it pays for: an in-scope asset, a vulnerability class it does not
exclude, at a severity it recognises, not already known. This module answers that
question from the program's official policy, with provenance attached, and refuses
to answer it from a guess.

Implementation: `blackheart/bounty/`. CLI: `blackheart bounty`. Tests:
`tests/test_bounty.py`, `tests/test_trigger_bounty_cli.py`.

## Four separate axes

Collapsing these is how real reports are wrongly rejected or wrongly promised. The
engine keeps them distinct, and no axis overwrites another:

- **Technical validity** — does the finding hold up (classification, evidence)?
- **Severity** — how bad under *this program's* definitions, not a global CVSS.
- **Scope eligibility** — is the asset in scope and not excluded?
- **Payout eligibility** — does the program pay for this class at this severity?

A finding can be valid and non-payable (a real bug in a class the program does not
pay for); invalid and in-scope; payable at Low or Medium. `evaluate()` takes **no
numeric confidence score** — eligibility is decided by the policy's own rules, so
a threshold can never suppress a genuinely eligible Low/Medium finding.

## The ten outcome states

| Outcome | Meaning |
|---|---|
| `VALID_AND_PAYABLE` | confirmed, in scope, not excluded, at a paid severity |
| `VALID_BUT_NOT_PAYABLE` | confirmed and real, but the program does not pay for it (below minimum, zero payout) |
| `VALID_WITH_UNVERIFIED_ELIGIBILITY` | confirmed, but scope/severity/payout could not be established — *unknown*, not "no" |
| `INVALID` | a false positive / informational, not a bug |
| `OUT_OF_SCOPE` | the asset is explicitly out of scope |
| `EXCLUDED_BY_POLICY` | the class is excluded (e.g. self-XSS, known issues) |
| `DUPLICATE_OR_KNOWN` | matches a documented known issue |
| `INSUFFICIENT_EVIDENCE` | not confirmed and no evidence attached |
| `REPRODUCTION_REQUIRED` | not confirmed, but evidence exists — independent reproduction needed |
| `POLICY_UNVERIFIED` | the policy snapshot itself is not verified; nothing downstream is asserted |

`VALID_BUT_NOT_PAYABLE` is deliberately distinct from `INVALID`: a real bug the
program does not pay for is **never** reported as not-a-bug.

## The seven mandatory gates

No candidate becomes submission-ready without passing every gate. The gates are
independent and **non-compensating**: a failure in one fixes the classification,
whatever the others say. The official, program-specific policy is the sole
authority; the internal research score is prioritisation metadata that the gate
**never reads**.

> No invented numeric threshold decides whether a candidate is submitted, critical
> or eligible. A generic 80/100 (or 90/100, or any composite) is not a program
> requirement, not a severity definition and not a measure of exploitability. If a
> program publishes its own scoring system, use that system exactly and cite its
> source; otherwise do not invent one. A technically valid but ineligible finding
> is archived honestly, and an eligible Low is never discarded for scoring low.

| Gate | Question | Recorded | If it fails |
|---|---|---|---|
| **1 Deployment** | Is this exact code live, at a known address, on the chain the program covers? | exact address, verified implementation (proxy → implementation slot), chain id, evidence of active deployment, source identity against a pinned commit, and a runtime-bound deployment-truth record (`EXACT`/`METADATA_ONLY`); a bare `deployment_verified: true` is not enough | not a candidate |
| **2 Eligibility** | Do the published rules include this asset and this class? | official scope, eligible asset, no applicable exclusion, the exact policy sections with retrieval date and text hash | class C |
| **3 Reachability** | Can the stated attacker get there without a privilege nobody granted them? | attacker capabilities, no undisclosed privileged assumption, reproducible path, preconditions and cost | not this attacker's path |
| **4 Security violation** | What invariant is broken, and can an independent researcher reproduce it? | explicit invariant, demonstrated violation, independent reproduction, exact sequence and observed state | D or F |
| **5 Impact** | Who loses what, and does the attacker come out ahead? | affected asset or user, quantified loss, attacker cost against gain, repeatability, liquidity | class C |
| **6 Novelty** | Is this already known, audited, fixed or acknowledged? | audit comparison, issue/PR comparison, known-fix comparison, closest prior disclosure and the difference | D |
| **7 Reportability** | Can a triager act on this without asking us anything? | clear explanation, reproducible PoC, sufficient evidence, exact commands and block numbers | F |

### Classifications (what the candidate is)

| Class | Meaning |
|---|---|
| **A** | PAYABLE CANDIDATE — all seven gates pass, with evidence for eligibility and the applicable impact category |
| **B** | POTENTIALLY PAYABLE — technically convincing, but an explicitly identified external eligibility or deployment question remains unresolved |
| **C** | VALID, NOT PAYABLE — the technical defect exists, but a mandatory bounty requirement fails |
| **D** | REJECTED — incorrect, non-reproducible or not exploitable |
| **F** | INCOMPLETE RESEARCH LEAD — a plausible hypothesis, insufficient evidence to establish a vulnerability |

There is no sixth class. An "informational" observation is class **C**, because it
fails Gate 5 (impact).

### Gate dispositions (the process state)

The six dispositions are what a gate run concluded; they are **not** the
classification, and `classification_for()` is the only bridge between them.

| Disposition | Meaning | Class |
|---|---|---|
| `A_SUBMISSION_READY` | meets verified technical and program eligibility requirements | A |
| `B_POTENTIALLY_PAYABLE` | plausible qualifying vulnerability with outstanding validation | B |
| `C_VALID_NOT_PAYABLE` | technically valid, but excluded or otherwise ineligible | C |
| `D_INVALID_OR_DISPROVEN` | invalid or disproven | D |
| `E_INFORMATIONAL` | demonstrable observation without an established qualifying impact | C |
| `F_NOT_ASSESSED` | insufficient evidence to reach a conclusion | F |

Dispositions are **not** severity classes: a valid Low stays a valid Low whatever
its disposition. If the official policy cannot be retrieved or verified the gate
returns `F_NOT_ASSESSED` with `BLOCKED — OFFICIAL BOUNTY POLICY NOT VERIFIED`; a
technical finding may stay documented while its bounty eligibility is blocked.

A reassessment reports one of four **payment determinations**, derived from the
disposition so the two cannot disagree (`payment_determination`):

| Determination | From | Meaning |
|---|---|---|
| `PAYABLE` | A | satisfies the program's documented requirements |
| `POTENTIALLY PAYABLE` | B | credible eligibility argument, needs evidence |
| `NOT PAYABLE` | C, D, E | excluded, disproven, or no qualifying impact |
| `UNRESOLVED` | F | the official rules are ambiguous or the evidence is absent |

`PAYABLE` has exactly one source, `A_SUBMISSION_READY`, so no candidate can be
called payable without having passed every documented requirement. A reassessment
that quotes a clause must quote it verbatim from the captured policy text; the
determination is recorded with the clause, the retrieval date and the SHA-256.

```bash
blackheart bounty gate --record candidate.json            # exit 2 when policy unverified
blackheart bounty gate --record candidate.json --require-submission-ready  # exit 1 unless A
```

Implementation: `blackheart/bounty/gate.py` (`CandidateRecord`, `gate`,
`assert_submission_ready`). Regression tests: `tests/test_bounty_gate.py`.

## Provenance is first class

A `PolicySnapshot` records the exact source URL, retrieval date, a SHA-256 of the
retrieved text, and a revision id. A snapshot is verified only when the hash of
its captured text matches; anything less is `POLICY_UNVERIFIED`, never assumed.

When the official policy changes, a **new** snapshot is captured and findings are
**re-evaluated against it without rewriting the old evaluation**: the prior
decision and the policy it was made under stay in the ledger
(`reevaluate` links the new evaluation to the old via `supersedes`). Both survive.

## Submission is prepared, never sent

`prepare_submission` assembles an evidence-backed package and returns a
`submission_allowed` flag that is False unless the outcome is `VALID_AND_PAYABLE`,
evidence is attached, and the finding is submission-ready by the existing report
gate. **BLACKHEART never submits a report**; the owner reviews and sends it.

## Before a bounty mission: the language gate

A bounty mission runs the same pre-execution gate as any other investigation. The
program's scope tells you *what* you may test; the target's stack tells you *with
what*. Identify the stack and verify the tool before a single engine runs:

```bash
blackheart compat detect --root <target-source>
blackheart compat registry --language <language>
blackheart compat check --file compatibility.json --smoke-test passed   # exit 2 on BLOCK
```

A tool that cannot parse the target's language or version is `BLOCKED`, not
`NO_FINDINGS` — and a bounty report built on a blocked tool has no evidence
behind it. The mandatory policy and the per-language registry live in
[`SECURITY_TOOL_COMPATIBILITY.md`](SECURITY_TOOL_COMPATIBILITY.md).

## Usage

```bash
# Capture a policy snapshot with provenance (hash computed from the text)
blackheart bounty capture --program Acme \
  --source-url https://acme.example/scope --retrieved-at 2026-01-01T00:00:00Z \
  --text scope.txt --out snapshot.json

blackheart bounty verify-policy --snapshot snapshot.json

# Evaluate a finding (a ProgramPolicy JSON is built from the snapshot + rules)
blackheart bounty evaluate --policy policy.json --finding finding.json
blackheart bounty evaluate --policy policy.json --finding finding.json --reevaluate

blackheart bounty show --finding F-1
blackheart bounty prepare-submission --policy policy.json --finding finding.json
blackheart bounty gate --record candidate.json
blackheart bounty verify
```

## Limits (honest)

- The engine evaluates against a `ProgramPolicy` an operator assembles from the
  captured snapshot; it does not parse arbitrary policy prose into rules. Reading
  a policy page into structured rules is the operator's (or a research agent's)
  job; the engine's guarantee is that once a policy is stated, the decision is
  deterministic, provenance-carrying, and auditable.
- It does not know a program's unpublished triage. A `VALID_AND_PAYABLE` outcome
  is "payable under the published policy", not a promise of payment.
- Duplicate detection is against the *program's documented known issues*, not a
  live duplicate search across other reporters.
