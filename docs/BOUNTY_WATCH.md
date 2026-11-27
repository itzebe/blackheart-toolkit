# Bounty watchtower

`blackheart watch` is the hourly, read-only change-intelligence layer for a
bounty watchlist. It answers three questions per target:

1. Did an **official policy** change?
2. Did an **in-scope repository** move?
3. Did a **monitored deployment** change?

and one question about the result: is this a credible, **permitted** investigation
lead, or just a change?

It is not a dashboard. It is a detector, a classifier and an evidence store. A
change is a lead; a lead is not a vulnerability. A commit is not a deployment.

## Non-goals and safety floor

- No transaction is sent, ever. The engine has no signing path and no write RPC.
- No target is tested, scanned or exploited by the watch cycle.
- No bounty is submitted and no program is contacted.
- No paid API, subscription, RPC upgrade or infrastructure is used.
- No secret is stored in the registry, the state, the reports or the issues.
- Every participation gate defaults to **false**. Monitoring is always allowed;
  action is not.

## Architecture

```
blackheart/watch/targets.json     independent per-target records
        │
        ▼
registry.py  ──►  fetch.py  ──►  state.py  ──►  classify.py  ──►  report.py
 (validate)      (policy,        (durable       (7 statuses,      (cycle report,
                  GitHub, RPC)    hashes,        score /100,       investigation
                                  dedupe)        eligibility)      record)
                                                     │
                                                     ▼
                                       source.py (verified-source diff)
                                                     │
                                                     ▼
                                                notify.py (SMTP, opt-in)
```

| module | responsibility |
| --- | --- |
| `registry.py` | Load and validate `targets.json`; write one JSON record per target; refuse duplicate slugs and broken references. |
| `fetch.py` | Real `urllib` clients: `HttpFetcher` (ETag, retry, size cap), `GitHubClient` (REST, token, rate-limit aware), `RpcClient` (chain id, block, code, EIP-1967/1822/admin slots, `owner()`). |
| `state.py` | Atomic JSON state, `flock` against concurrent cycles, event dedupe, failure ledger, `seen_events` pruning. |
| `classify.py` | Event model, 7 statuses, 100-point score, fail-closed eligibility gates, known-issue matching. |
| `cycle.py` | One cycle: policy snapshots and diffs, repository heads/releases/tags, contract fingerprints, source-diff trigger, report assembly. |
| `source.py` | Sourcify verified-source client, per-file manifest, bounded unified diff, changed-function extraction. |
| `report.py` | Cycle markdown, the 17-field investigation record, Africa/Lagos timestamps, the GitHub-issue body. |
| `notify.py` | Optional SMTP delivery; refuses without explicit configuration and never logs the password. |

## Watchlist coverage

43 independent records, in four groups:

| group | records | meaning |
| --- | ---: | --- |
| A | 7 | active monitoring (Lido, Safe, Phala, Zircuit, Frax, Whitechain, Ticko) |
| B | 10 | DeFi and Web3 |
| C | 15 | additional programs |
| D | 11 | discovery platforms (policy monitoring only) |

Recorded sources: **52 policy URLs**, **30 repositories**, **32 contracts** across
5 targets (Lido 17, Safe 4, Uniswap 7, Across 3, Layer3 1). Six records have a
named known-issue exclusion. Six have **no public program** and say so rather
than inventing one.

Coverage is deliberately uneven and honest:

- 37 of 43 have an official policy URL; the 6 without one are named in the
  registry (`NO_PUBLIC_PROGRAM_FOUND`).
- 18 of 43 have a verified repository; 25 are named gaps.
- 5 of 43 have a verified contract inventory; 38 are named gaps. A target with no
  recorded address is not claimed to be covered.

Every record carries its own `eligibility`, `restrictions`, `known_issues`,
`focus` and `value_class`. Scope and eligibility are never shared between
programs.

## What a contract observation contains

For each `ContractRef`:

- chain id, verified address, proxy flag;
- implementation, admin and owner when the standard slots or `owner()` answer;
- runtime bytecode SHA-256 fingerprint (keccak-style fingerprint of the code);
- block number and observation timestamp;
- the provenance URL for the address.

A changed fingerprint at the **same** implementation address is `CONTRACT_CODE`;
a changed implementation address is `CONTRACT_IMPL`; admin/owner changes are
`CONTRACT_ADMIN` / `CONTRACT_OWNER`. All three are deployment evidence. A
repository commit is never labelled deployment evidence.

The Safe singleton v1.4.1 fingerprint observed on chain 1 is
`0x1fe2df852ba3299d6534ef416eefa406e56ced995bca886ab7a553e6d0c5e1c4`, which is
exactly the `codeHash` published by `safe-deployments` for that singleton. That
is the cross-check that the fingerprint reader is correct.

## Verified source diff (what changed, not just that it changed)

A moved fingerprint says a deployment changed; it does not say what changed.
When the fingerprint or the proxy implementation actually moves, `source.py`
fetches the verified source for the **old** and the **new** implementation
address from [Sourcify](https://sourcify.dev) — free, no API key, no account —
and attaches a real delta to the deployment event:

- per-file SHA-256 manifest and a bundle fingerprint;
- files added, removed and modified;
- changed function/constructor/modifier names, with a security-sensitive subset
  (`withdraw`, `upgrade`, `oracle`, `verify`, `nonce`, …) called out;
- added lines that call out of the contract (`transfer`, `call`, `delegatecall`,
  …) as a review pointer, never as a finding;
- a unified diff capped at 200 kB, archived to `research/bounty-monitor/source-diffs/`.

It is deliberately bounded and quiet:

- the baseline is fetched **once** per contract (31 of the 32 recorded contracts
  are verified on Sourcify today);
- an unchanged address is never re-fetched, because deployed code is immutable;
- a change costs two requests (old and new implementation);
- a contract Sourcify does not verify is recorded `not_verified` and retried
  weekly — a gap, never a claim that the source is unchanged;
- no source text is stored in `state.json`, only hashes.

This is change intelligence, not semantic audit: it names the delta and the
functions, and the 17-field record still requires a human/agent to trace callers
and prove impact.

## Noise controls (learned from real cycles)

Hourly monitoring is only useful if it is quiet. The engine implements:

- **ETag / `304 Not Modified`** for policy pages, repository metadata, heads,
  releases and tags. A `304` keeps the previous value; it never looks like an
  empty head or a new release.
- **No branch guessing.** If repository metadata has no `default_branch`, the
  check fails closed as a gap. It never falls back to `main`, which previously
  produced a false `HEAD moved` event on a `dev`-default repository.
- **Empty repositories are a gap, not a failure.** A `409` from the commits API
  is recorded as "empty (no commits)"; the first commit that later lands is a
  real `REPO_HEAD` event.
- **Canonical repository names.** Redirecting names are resolved once and stored
  canonically, so a rename cannot look like a branch flip.
- **Counter/timestamp stabilisation.** View counters, submission counts, epoch
  values, ISO timestamps and long hex build ids are replaced before hashing.
- **Numeric-only diff suppression.** If the only difference between two policy
  snapshots is a number, it is a metric change, not a policy change. This covers
  integer counters *and* decimals/currency amounts: a live program page ticked
  `Vault TVL $79,950.72` to `$79,952` and produced a false `POLICY_CHANGED`
  before the decimal case was neutralised (2026-11-21, Plether).
- **Unconditional snapshot archiving on a detected change.** The previous text is
  archived before the new text is written, so a real diff is never downgraded to
  "previous text unavailable".
- **Event-id dedupe.** The same `(target, kind, component, old, new)` is reported
  once. Repeats are counted as `deduped`, not re-notified.
- **Routine commits stay `WATCH`.** A version-bump commit in a web wallet is a
  change, not a security lead; it is not promoted and not notified.

## Classification

| status | meaning |
| --- | --- |
| `NEW ACTIONABLE CHANGE` | permitted, credible, score ≥ 80 |
| `INVESTIGATE` | security-relevant, score 50–79 |
| `WATCH` | relevant but no credible attack path yet |
| `NO CHANGE` | no event and no failure this cycle |
| `POLICY BLOCKED` | security-relevant, but a participation gate forbids action |
| `KNOWN / DUPLICATE` | matches a recorded known issue or a seen event |
| `SOURCE INACCESSIBLE` | the check could not be completed |

Score (out of 100): exploitability 25, impact 20, novelty 15, official bounty
eligibility 15, evidence quality 10, reproducibility 10, research-effort
efficiency 5. The threshold for active investigation is **80**. The score is
explained component by component in every lead; it is never inflated.

## Eligibility gates (fail closed)

A target is actionable only when **all** of these are recorded true:

1. `eligibility.ai_agent_allowed` — AI-agent participation is permitted.
2. `eligibility.participation_authorized` — the operator has authorized action.
3. `eligibility.platform_participation_allowed` — the operator participates on
   the platform (HackerOne, Immunefi, HackenProof, Bugcrowd, …).

Current state: **none of the 43 records is permitted**. HackerOne and Immunefi
platforms are excluded by the operator's standing preference; Safe is `CLOSED`
(prior research recorded it closed until 2026-12-01); Ticko is `TESTNET_ONLY`;
six records have no public program. A policy sentence that appears to allow AI
agents is surfaced as a **review signal** and never flips a gate automatically.

## Known-issue exclusions

| id | target | status |
| --- | --- | --- |
| `SAFE-APPROVED-HASH-REPLAY-187` | Safe | public/fixed |
| `PHALA-001-KMS-KEY-SUBSTITUTION` | Phala | previously reported (monitor remediation only) |
| `ZIRCUIT-DELAYED-NAV-STALE-PPS` | Zircuit | excluded |
| `FRAX-FRAXNET-HOPV2-FXB` | Frax | previously investigated, no live path |
| `GRAB-CDN-FALSE-POSITIVE` | Grab | false positive |
| `MELI-INSCRIPCION-FALSE-POSITIVE` | MercadoLibre | false positive |

A matching event is `KNOWN / DUPLICATE` and cannot be promoted.

## Scheduling

Primary: `.github/workflows/bounty-watch.yml`.

- Cron `7 * * * *` (hourly, UTC, off the hour).
- `concurrency: bounty-watch` with `cancel-in-progress: false` — no two cycles
  interleave.
- `actions/cache/restore` and `actions/cache/save` around
  `research/bounty-monitor/state`, so the baseline survives a fresh runner.
- Artifacts: reports, investigation records and state, 90-day retention.
- Issues: four rolling, deduplicated issues (`actionable`, `investigate`,
  `policy-blocked`, `source gaps`), updated only when their content hash changes.
- A partial source gap is a **warning and an issue**, not a red job; the job fails
  only on a total outage (zero successful observations).
- Optional email to `MAIL_TO` (default `jonathanebi05@gmail.com`) only when the
  `SMTP_*` secrets are configured.

Secondary: `automations/bounty-watch/` runs the same engine on OpenHands'
scheduler and persists the state in the automation KV store. It is committed but
**not activated**; activation needs the operator's approval.

### Cost

Zero. The engine is stdlib-only Python and the runner's preinstalled interpreter;
there is no `pip install`, no paid API and no paid RPC. On a private repository,
hourly runs are ~720 job-minutes/month against the 2,000 free minutes; a public
repository is free. GitHub Actions may delay a scheduled run under load; the
engine does not claim an exact minute.

## Running it

```bash
python3 -m blackheart watch targets                 # the watchlist, no network
python3 -m blackheart watch targets --write DIR     # one JSON record per target
python3 -m blackheart watch policy                  # policy pages only
python3 -m blackheart watch cycle                   # one full read-only cycle
python3 -m blackheart watch cycle --target lido --json
python3 -m blackheart watch cycle --skip-source      # no Sourcify fetch/diff
python3 -m blackheart watch status                  # durable state summary
python3 -m blackheart watch selftest                # real policy + GitHub + RPC smoke test
```

Exit codes: `0` no change, `1` change, `2` source failure or incomplete. `2` is
a gap, not a clean result.

## State layout

```
research/bounty-monitor/
  README.md
  latest.md                     # most recent cycle report
  reports/                      # one .md + .json per cycle, plus INDEX.md
  targets/                      # one record per target, grouped A–D
  investigation-leads/          # 17-field records for actionable/investigate/blocked
  known-issues/                 # post-hoc classification of a recorded non-issue
  source-diffs/                 # unified diffs for a deployment change
  evidence/                     # archived real-source captures and demos
  state/state.json              # hashes, heads, fingerprints, dedupe, failures
  state/state.lock              # process lock (not committed)
  state/snapshots/policy/       # latest + archived policy text per URL
```

The state is the baseline. Deleting it re-baselines; the next cycle will report
first observations, not changes.

## Honest limitations

- **38 targets have no verified contract address.** They are monitored at the
  policy/repository level only, and the gap is printed in every cycle.
- **25 targets have no verified repository.** Same treatment.
- **HackerOne and Immunefi pages are JavaScript-heavy.** The fetcher records the
  stable server-rendered text; a client-side-only policy change may be missed.
  The `selftest` proves the page is reachable, not that every dynamic field is
  captured.
- **Open Bug Bounty returns HTTP 403 to automated clients.** It is recorded as
  `SOURCE INACCESSIBLE` every cycle; the gap is visible, not hidden.
- **Source diffing is EVM-only and depends on Sourcify coverage.** 31 of the 32
  recorded contracts are verified there today; Across periphery is not and is
  recorded `not_verified`. Non-EVM targets (Babylon/Cosmos, Solana-style) are
  monitored at policy/repository level only.
- **The diff names the delta; it does not prove impact.** Changed files and
  function names are extracted mechanically; the extractor also matches words in
  comments and NatSpec (`call`, `like`, `of`), so the sensitive subset is the
  reliable signal. Tracing callers, invariants and a reproducible exploit
  remains the investigation step. A real two-version demo (Safe 1.3.0 -> 1.4.1)
  is archived under `research/bounty-monitor/evidence/`.
- **Eligibility is a recorded fact, not a legal determination.** The registry
  reflects the operator's prior research; a policy change is surfaced for review,
  never auto-applied.
- **The GitHub Actions `schedule` is configured but has not been observed to
  fire on time.** `bounty-watch` (cron `7 * * * *`) produced **zero scheduled
  runs** across the 09:07, 10:07 and 11:07 UTC slots on 2026-11-21, while the
  sibling daily `uma-drift-monitor` (cron `06:17`) ran at **15:32Z and 15:50Z**
  on the two previous days. GitHub does run schedules in this repository, but
  with delays of hours. Manual dispatch is verified; hourly cadence is **not**
  claimed. A reliable hourly trigger needs an external cron with a scoped token
  or the OpenHands automation, both pending operator approval.

## Acceptance evidence

| # | requirement | evidence |
| --- | --- | --- |
| 1 | every target has an independent record | 43 records; `blackheart watch targets --write research/bounty-monitor/targets`; `tests/test_watch.py::test_packaged_registry_is_complete_and_independent` |
| 2 | official policies and scope recorded | 52 policy URLs; snapshots under `state/snapshots/policy/`; `test_first_cycle_baselines_and_reports_failure` |
| 3 | a real repository change is detected and deduplicated | real Spotify Backstage `HEAD moved` event in cycle 8; local test `test_repo_change_is_not_deployment_evidence`; dedupe `test_second_cycle_deduplicates_and_survives_restart` |
| 4 | a deployed-contract observation is compared to a baseline | 32 contracts fingerprinted; 31 verified source bundles captured; Safe singleton matches the official `codeHash`; a real two-version source diff is archived (`research/bounty-monitor/evidence/2026-11-21-real-source-diff-demo.md`); `test_contract_bytecode_change_is_a_deployment_change` |
| 5 | source changes distinguished from deployments | `deployment_evidence: false` on every repo event; `test_repo_change_is_not_deployment_evidence`; a deployment change carries a real Sourcify delta (`test_deployment_change_carries_a_verified_source_diff`), and unchanged code never re-fetches (`test_source_is_not_refetched_when_nothing_moved`) |
| 6 | known-issue exclusions enforced | six known issues; `test_known_issue_is_suppressed` |
| 7 | restricted targets cannot be promoted | `test_permitted_target_can_reach_actionable_but_blocked_cannot`; all 43 default to monitor-only |
| 8 | hourly scheduler configured and execution verified | cron `7 * * * *`; YAML + embedded Python validated; **manual dispatch runs 1 and 2 succeeded**; `test_hourly_workflow_is_guarded_and_runs_the_real_cycle`. The scheduled trigger itself was **not** observed: 0 runs across three hourly slots, while the sibling daily workflow ran ~9 h late |
| 9 | state survives a restart | `test_second_cycle_deduplicates_and_survives_restart` reloads from disk; cache restore/save in the workflow |
| 10 | a failed source is reported honestly | Open Bug Bounty 403 recorded as `SOURCE INACCESSIBLE`; `test_failed_source_is_reported_honestly` |
| 11 | no paid services or unauthorized actions | stdlib only, public endpoints, read-only RPC; `test_hourly_workflow...` asserts no `pip install` and no `eth_sendRawTransaction` |

## What was actually observed (2026-11-21)

Nine real cycles were run against public sources. They established the baseline,
detected real changes, and exposed four noise bugs that were fixed:

- Safe web-wallet `HEAD` version bump — `WATCH`, not a lead.
- CoinGecko and Layer3 policy counters — first a false `POLICY_CHANGED`, then
  suppressed by counter stabilisation and numeric-only diffing.
- A transient GitHub metadata failure that guessed `main` — fixed to fail closed.
- A redirecting Safe repository and an empty Alchemix repository — fixed to
  canonical names and an explicit empty-repo gap.

The steady state (cycle 9) is **42 `NO CHANGE`, 1 `SOURCE INACCESSIBLE`** (Open
Bug Bounty 403), with the repeated 403 deduplicated. No actionable lead was found
in this window; none is fabricated.
