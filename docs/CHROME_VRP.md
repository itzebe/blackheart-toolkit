# Chrome VRP engagement

A distinct, exploit-first research engagement against the Google Chrome
Vulnerability Reward Program. It is deliberately separate from the earlier
GitHub Actions scan: different target, different evidence, different ledger.

## What this is (and is not)

This harness runs **falsifiable boundary probes against a real, released
Chromium build** we control locally, on loopback origins we control. Each probe
tests one security invariant and writes its observation as JSON.

* It does **not** contact any third-party system.
* It does **not** touch another user's data.
* It does **not** claim a vulnerability. A probe that finds no violation is
  recorded as `FALSE_POSITIVE` (the invariant held) -- a real, reproducible
  result that tells us where *not* to spend the next hour.
* A probe that finds a violation is recorded as `NEEDS_MORE_EVIDENCE`: a
  **candidate**, never a finding, until it survives independent verification on
  a released build with no non-standard flags.

## The positive control

Negative results are only meaningful if the harness *can* detect a breach. The
`chrome doctor` command (and `positive_control()`) loads the Same-Origin Policy
probe with a **same-origin** child. The probe's invariant says a cross-origin
frame must be unreadable, so with a same-origin child the read succeeds and a
working probe must report the exact violation strings it would report for a real
breach. If the control does not trip, the clean engagement run proves nothing.

## Commands

```bash
# Locate a Chromium build, run one probe, and trip the positive control.
blackheart chrome doctor

# Run every hypothesis; record evidence + ledger events under
# research/private/chrome-vrp/ (gitignored).
blackheart chrome run

# Run a subset.
blackheart chrome run --only H1,H4

# Use a specific browser.
blackheart chrome run --binary /usr/bin/chromium
```

`BLACKHEART_CHROME` sets the browser path if autodetection fails.

## Hypotheses

| id | category | invariant under test |
|----|----------|----------------------|
| H1 | site-isolation | A cross-origin iframe's `contentDocument` is `null`; reads of `location`/`document` throw `SecurityError`. |
| H2 | isolation | `crossOriginIsolated` is `true` and `SharedArrayBuffer` is available **only** when `COOP: same-origin` + `COEP: require-corp` are served. |
| H3 | origin-integrity | `MessageEvent.origin` equals the sender's true origin (not spoofable). |
| H4 | process-model | CDP `SystemInfo` reports distinct browser, renderer, and GPU processes -- the renderer-to-browser privilege boundary exists. |

H4 is checked because the renderer-to-browser boundary is the premise of the
whole engagement: if a build silently ran single-process, that boundary would not
exist and every renderer-based hypothesis would be moot.

## Evidence and ledger

Everything is written under `research/private/chrome-vrp/` (gitignored):

* `evidence/` -- content-addressed store; `verify_integrity()` re-hashes every
  object. Each probe result (including the browser version string) is one object.
* `ledger/chrome-vrp.jsonl` -- append-only hypothesis ledger. Statuses use
  BLACKHEART's `Classification`: `FALSE_POSITIVE` (invariant held, do not re-run
  as new) and `NEEDS_MORE_EVIDENCE` (candidate, awaiting verification).
* `probes/` -- the HTML served to the browser (also embedded in
  `blackheart/chrome/probes.py`).
* `scope/` -- the official VRP rules and FAQ snapshots with their SHA-256, plus
  the authorization record registered through `blackheart scope`.

## Authorization

The engagement's scope is registered through BLACKHEART's own gate:

```bash
blackheart scope --file research/private/chrome-vrp/scope/authorization-record.json
blackheart scope --check research/private/chrome-vrp/scope/authorization-record.json --asset mojo-ipc
```

In-scope assets (a released Chromium build, V8, Blink, Mojo, PDFium, the GPU
process, and our own test harness) are `AUTHORIZED`. V8 experimental flags,
SwiftShader, WebNN, and third-party production systems are `OUT_OF_SCOPE`. The
gate fails closed while payout eligibility is unresolved -- that is deliberate
and must not be weakened.

## Rules we follow

From the official [Chrome VRP rules](https://bughunters.google.com/about/rules/chrome-friends/chrome-vulnerability-reward-program-rules)
and [VRP FAQ](https://chromium.googlesource.com/chromium/src/+/HEAD/docs/security/vrp-faq.md):

* Test only systems and computers we control.
* Reproduce on a released Chrome Stable/Beta/Dev; never present a local/debug
  build as proof of a released-build issue.
* No non-standard or unsafe flags, no `--single-process`.
* No destructive testing; no unauthorized external testing.
* No public disclosure or bounty submission without explicit human approval.

## Disposition (2026-11-12)

Run against Chromium 156.0.8078.79 (Debian trixie), local, headless:

* H1-H4: `FALSE_POSITIVE` -- every invariant held. Evidence integrity `ok`.
* Positive control: **detected** the deliberately-induced same-origin read.

Honest summary: this establishes a working, falsifiable harness and a verified
baseline on a maintained release. It has **not** found a vulnerability. The
value is the baseline plus the discipline: the next experiment must target a
boundary this harness can actually exercise, not one it has already shown holds.
