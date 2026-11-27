---
name: authorization-gate
description: >
  Verify bounty authorization, scope, exclusions, safe harbor, program status,
  PoC requirements, and researcher eligibility BEFORE any active testing. Use
  whenever a campaign is about to touch a target, or when deciding whether an
  asset may be actively exploited.
triggers:
  - authorization
  - scope
  - safe harbor
  - in scope
  - out of scope
  - bounty program
---

# Authorization gate

No active testing without verified authorization. This is the first and last
check of every campaign. The gate **fails closed**: anything not explicitly
`AUTHORIZED` stays out of active exploitation.

## Procedure (in order)

1. **Locate the official program.** Use the platform's own page (Immunefi,
   HackerOne, Bugcrowd, or the vendor's own program page). A third-party tracker,
   a GitHub repo, or a deployed app is **not** an authorization source.
2. **Verify it is currently active.** Programs pause, close, and expire. Record
   the status you observed and when.
3. **Retrieve the current official scope.** Copy the exact asset list, not a
   summary. Note the program URL and retrieval timestamp.
4. **Identify exact authorized assets.** Map each asset you intend to touch to the
   scope list. Anything not on the list is `OUT_OF_SCOPE` or `UNKNOWN`.
5. **Verify testing restrictions and safe harbor.** Read the rules: what is
   prohibited (DoS, automated scanning, social engineering), and whether safe
   harbor is granted.
6. **Verify whether PoCs are required.**
7. **Verify researcher eligibility** for the user's jurisdiction.
8. **Verify practical payout availability** for the user (e.g. a Nigerian
   individual): supported payout rails, KYC requirements, and whether a payout can
   actually reach them.
9. **Confirm zero cost.** Participation and testing must be completable without
   spending money.
10. **Save dated evidence** for every check: the URL, the exact quote, the
    timestamp. Store it via the evidence store; record the authorization record in
    the registry.

## Asset classification

| Status | Meaning | Active testing? |
|---|---|---|
| `AUTHORIZED` | testing permitted under verified rules | yes |
| `PASSIVE_ONLY` | passive analysis permitted, active not established | no |
| `UNKNOWN` | authorization unresolved | no |
| `OUT_OF_SCOPE` | prohibited or excluded | no |

## Using the gate from code

```python
from blackheart.authz import new_record, authorize_active_testing, AuthorizationError
from blackheart.authz.registry import AuthorizationRegistry

rec = new_record(
    program="<program>", platform="immunefi",
    target_url="https://...", scope_url="https://...",
    program_active=True, safe_harbor=True, poc_required=True,
    nigerian_eligible=True, payout_feasible=True, zero_cost=True,
)
rec.assets = {"<asset>": "AUTHORIZED"}
rec.evidence = ["<evidence-id>"]   # required
rec.verified = True
AuthorizationRegistry("research/private/authz.jsonl").add(rec)

decision = authorize_active_testing(rec, "<asset>")
assert decision.allowed, decision.blockers
```

`authorize_active_testing` raises/denies unless **all** program checks pass
(`program_active`, `safe_harbor`, `zero_cost`, `nigerian_eligible`,
`payout_feasible`, `verified`, evidence present, scope URL present).

## Ranking candidate programs (mission section 7)

When the mission is *"find the next viable target"* rather than *"test this
target"*, use the eligibility registry instead of ad-hoc judgement. It encodes
steps 1–9 above as tri-state facts and **fails closed**: a fact that could not be
established is `"unknown"` and blocks entry.

```bash
# Rank every candidate program best-first; exit 0 iff at least one is viable.
python3 -m blackheart eligibility evaluate --file programs.json

# Emit a ready AuthorizationRecord for the top (or named) viable program.
python3 -m blackheart eligibility to-scope --file programs.json --out rec.json
```

A program is viable only when `program_active`, `scope_verified`,
`safe_harbor`, `zero_cost`, `nigerian_eligible`, and `payout_feasible` are all
`True` **and** at least one asset is `AUTHORIZED`. Viable programs are ranked
above non-viable ones, then by advertised top reward.

Two facts are worth recording honestly rather than optimistically:

- `nigerian_eligible` — a Nigerian individual may participate.
- `payout_feasible` — a Nigerian individual can *practically be paid*. A program
  that documents no country exclusion is still `"unknown"` here until a payout
  rail (bank transfer / PayPal) is confirmed for that individual. Do not upgrade
  "not documented as excluded" to "confirmed possible".

`payout_feasible=True` is **evidence-backed**: the gate refuses it unless the
program record also carries at least one dated evidence item (`evidence=[...]`).
No bounty brief publishes a supported-countries list, so this fact can only ever
be established by a dated operator/support record — asserting it without one
fails the gate closed (see `EVIDENCE_BACKED_FACTS` in `blackheart/eligibility.py`).

## Gotchas

- **Ownership is not permission.** A company owning an in-scope asset does not
  authorize testing its other assets. `reject_inferred_authorization` blocks the
  common mistakes (`public-repository`, `deployed-application`,
  `third-party-tracker`, `company-ownership`, `assumption`).
- **Scope changes.** Re-verify scope before *every* campaign; a previous
  engagement's scope is not evidence of current scope.
- **Re-check before pivoting.** When moving to a new target, the gate runs again
  from scratch.
- If a check cannot be completed, the asset is `UNKNOWN` — and `UNKNOWN` blocks
  active testing. Say so; do not guess.

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
