# Agentic-Bug-Hunter integration

BLACKHEART selectively adapted two capabilities from
[Agentic-Bug-Hunter](https://github.com/awarexone/Agentic-Bug-Hunter) (MIT,
Copyright (c) 2026 Claude Bug Bounty Hunter Contributors). This document records
**what** was taken, **from where**, **why it improves BLACKHEART**, **how it was
modified**, and **how it is tested** — the evidence trail the integration
mission requires. The upstream repository is not vendored or imported at
runtime; the algorithms were reimplemented in BLACKHEART's own model.

## What was examined (and what was not adopted)

The upstream project was read in full: its agent architecture, recon workflows,
vulnerability modules, validation/false-positive rejection, persistent memory
(``lead_board``), reporting, and tool integrations. Two things were strong enough
and non-duplicative enough to adopt. Everything else was deliberately left out:

- **Its agents and skills were not copied.** BLACKHEART already has a
  model-router, a specialist-agent set, `mindset.py` as the single source of
  truth, and an attacker-question doctrine. Importing a parallel agent set would
  duplicate work and dilute the product identity. Adding agents to raise a count
  is explicitly rejected.
- **Its tool wrappers were not copied.** BLACKHEART's engine layer already
  covers external tools.
- **No secrets, personal data, or unrelated files** were taken.

## Capability 1 — deterministic scope matcher

- **Upstream source:** `bughunter/tools/scope_checker.py` (and the scope rules in
  `skills/web2-recon/SKILL.md`).
- **BLACKHEART implementation:** `blackheart/authz/scope_matcher.py`.
- **Why it improves BLACKHEART:** BLACKHEART's authorization gate
  (`authorize_active_testing`) previously decided scope from an exact asset map
  only. Real programs publish scope as **patterns** (`*.example.com`, a CIDR, a
  path prefix, an explicit exclusion). The matcher evaluates a single asset
  against those patterns deterministically, which (a) lets a program's real scope
  be recorded faithfully and (b) closes the classic bypasses — wildcard/apex
  confusion, `evil-target.com` vs `*.target.com`, backslash and userinfo tricks,
  public-suffix wildcards like `*.com`.
- **Modifications for compatibility:** returns BLACKHEART's `AssetStatus` and a
  decision object `{in_scope, status, host, kind, matched_rule, reason}`; refuses
  public-suffix and single-label wildcards at construction; fails closed on
  malformed input. It is **advisory** to the gate — an explicit per-asset
  out-of-scope entry still wins, and all program-level checks still apply.
- **Integration:** `AuthorizationRecord` gained `scope_patterns` and
  `excluded_classes`; `classify_asset_by_pattern()` is consulted by
  `authorize_active_testing()` when the asset is not in the exact map;
  `blackheart scope --allow ... --exclude ... --asset ...` prints a decision.
- **Tests:** `tests/test_abh_integration.py` — 12 matcher tests (positive,
  negative, fail-closed, construction guards) + 4 authorization-gate integration
  tests.

## Capability 2 — deterministic weak-finding triage gate

- **Upstream source:** `skills/triage-validation/SKILL.md` (the 7-question gate,
  the KILL SIGNALS table, the NEVER SUBMIT list, the CHAIN REQUIRED table) and
  `bughunter/tools/lead_board.py` (`adjudicate`).
- **BLACKHEART implementation:** `blackheart/verify/triage.py`.
- **Why it improves BLACKHEART:** BLACKHEART's `IndependentVerifier` adjudicates a
  finding through seven **evidence** gates, but it had no encoded knowledge of the
  **classes** bounty triagers routinely reject as N/A (reflected XSS with no
  session theft, SSRF with only a DNS callback, CORS wildcard with no credentialed
  exfiltration, version disclosure with no working exploit, and so on). The gate
  rejects those weak classes *before* they consume verification effort and marks
  the classes that are only valid with a demonstrated chain. It complements the
  verifier; it does not replace it.
- **Modifications for compatibility:** the upstream tables are encoded as data
  (`KILL_SIGNALS`, `NEVER_SUBMIT`, `CHAIN_REQUIRED`) plus a pure, deterministic
  `TriageGate.evaluate(category, evidence, chain_demonstrated=...)`. A finding is
  described by its class and the evidence tags it actually established
  (`Evidence`); a missing required tag is the kill signal. A chain-required class
  is **downgraded** (not rejected) until its chain is proven. Two small judgement
  calls differ from a literal reading of upstream and are noted in code: CORS and
  SSRF are treated as chain-conditional (a downgrade) rather than hard rejects,
  matching upstream's own "CHAIN REQUIRED" rows for them.
- **Integration:** `Finding` gained an `evidence_tags` field;
  `is_submission_ready()` consults the gate when tags are present and blocks a
  finding that is either **rejected** (a kill-signal class) or **downgraded** (a
  chain-required class whose chain is not demonstrated) — the downgrade path is
  included so a weak class cannot bypass triage through the report gate;
  `submission_blockers()` names the reason (rejection or downgrade);
  `blackheart triage --category ... --evidence ...` prints the disposition (exit 2
  on REJECT).
- **Tests:** `tests/test_abh_integration.py` — 19 triage/scope adversarial tests
  (positive, negative, downgrade, universal-evidence, chain bypass, host/URL
  ambiguity) + 6 report-gate integration tests.

## Backward compatibility

Both capabilities are **additive**. A project with no `scope_patterns` and a
finding with no `evidence_tags` behave exactly as before (see the regression
tests `test_finding_without_evidence_tags_is_unchanged` and
`test_classify_by_pattern_returns_none_without_patterns`). No existing agent,
skill, model route, or gate was removed or weakened.

## Licence

MIT. The full upstream notice is reproduced in `THIRD_PARTY_NOTICES.md` and kept
in the module docstring of each adapted file. No upstream code is copied
verbatim; the tables and decision logic were reimplemented.
