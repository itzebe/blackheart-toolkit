# Durable autonomous execution scheduler

`docs/RESEARCH_ENGINE.md` §8 recorded the honest gap: *"Continuous operation needs
a scheduled runner; BLACKHEART provides the resumable state and the CLI, not the
scheduler itself."* This document describes the scheduler that closes it, and --
just as importantly -- what it does **not** claim.

The scheduler is a **dispatcher**. It does not implement research; it runs the
engines that already exist (`hunt`, the P3 `investigate` lifecycle) on a durable,
restart-safe, fenced queue, and records their verdicts verbatim. It introduces no
new engine and no new verdict.

## What it guarantees

| Property | Mechanism | Test |
|---|---|---|
| **Durability / restart-safety** | append-only, hash-chained JSONL log rebuilt by replay (`JobStore`) | `test_state_survives_restart_by_replay`, `test_hash_chain_detects_tampering` |
| **Explicit lifecycle** | `TRANSITIONS` state machine; an illegal move raises `InvalidTransition` | `test_illegal_transition_is_refused`, `test_completing_a_succeeded_job_raises` |
| **Lease ownership with fencing** | a claim grants a time-bounded lease and a **monotonic epoch**; heartbeat/complete must present the current epoch | `test_stale_worker_cannot_complete_after_reclaim`, `test_heartbeat_after_reclaim_is_refused` |
| **Stale-worker recovery** | an expired lease is reclaimed and the job re-queued, attempt history preserved | `test_stale_worker_cannot_complete_after_reclaim` |
| **Bounded retry with backoff** | deterministic bounded-exponential `RetryPolicy`; budget exhaustion dead-letters | `test_retryable_failure_backs_off_then_succeeds`, `test_budget_exhaustion_dead_letters` |
| **Misfire recovery** | a scheduled moment missed during downtime is recorded and run exactly once | `test_misfire_recorded_once_and_cleared` |
| **Idempotency / dedupe** | submitting the same key returns the existing job | `test_duplicate_idempotency_key_creates_one_job` |
| **Authorization at every boundary** | re-checked at claim *and* inside the executor *and* on recovery; with a live `authz_provider` the *current* record is read, so a scope withdrawal after enqueue blocks the job. The provider *fails closed*: a deleted or unreadable record blocks the job rather than falling back to the enqueue-time snapshot. A refusal at any boundary moves the job to the recoverable `BLOCKED` state, never the terminal `FAILED` dead-letter, so a policy decision is never confused with a spent attempt budget | `test_unauthorized_job_is_blocked_not_run`, `test_authorization_withdrawn_after_enqueue_blocks_execution`, `test_recovery_blocks_when_scope_withdrawn_while_down`, `test_live_authz_provider_returning_none_blocks_the_job`, `test_live_authz_provider_that_raises_blocks_the_job`, `test_execution_time_authorization_refusal_blocks_not_fails`, `test_cli_schedule_run_with_authz_blocks_after_withdrawal`, `tests/test_ingress.py::test_scope_revoked_between_accept_and_execution_blocks_the_job` |

The fence is the subtle one. Recovery *clears* the lease, so if the epoch were
derived from the current lease it would reset and a stale worker's epoch could
collide with a fresh claim. The epoch is therefore a **monotonic counter on the
job**, incremented on every claim. A worker holding epoch *N* can never write the
outcome of the epoch *N+1* attempt.

## The lifecycle

```
PENDING ──claim──▶ LEASED ──ok──────────▶ SUCCEEDED
   │                 │  └──retryable────▶ RETRYING ──claim──▶ LEASED
   │                 ├──terminal────────▶ FAILED   (dead-letter)
   │                 ├──lease expired───▶ PENDING  (stale recovery)
   │                 └──authz withdrawn─▶ BLOCKED
   ├──authz fails──────────────────────▶ BLOCKED
   └──cancel───────────────────────────▶ CANCELLED
```

`BLOCKED` is not terminal: an operator who re-establishes authorization can move
it back to `PENDING`. `SUCCEEDED`, `FAILED`, and `CANCELLED` are terminal and are
never revisited.

## Commands

```bash
# enqueue (deduplicated by --key, so a repeated cron trigger is one job)
blackheart schedule add --kind hunt --target access-control --asset vault \
  --authz authz.json --key "daily-access-control" --priority 5

# run: reclaim stale leases first, then drain runnable jobs. Pass --authz so the
# worker re-reads the live record at claim and execution; a scope withdrawal (an
# edit or a deletion) then BLOCKS the job instead of running on the enqueue-time
# snapshot. Without --authz the snapshot is used, as before.
blackheart schedule --authz authz.json run --owner worker-1

# inspect
blackheart schedule list [--state PENDING]
blackheart schedule show JOB-...
blackheart schedule history JOB-...
blackheart schedule summary

# operator controls
blackheart schedule cancel JOB-... --reason "scope withdrawn"
blackheart schedule misfire JOB-...        # record+clear a missed moment
blackheart schedule recover                # reclaim every expired lease
blackheart schedule checkpoint [--out cp.json]  # pin the signed chain head
blackheart schedule verify [--require-signatures] [--checkpoint cp.json]
```

A checkpoint pins the chain head *outside* the log; it is the only thing that
detects a truncated tail (a shorter log still verifies internally), including a
log truncated to empty. Keep it somewhere the attacker cannot also rewrite.

## Honest limits

- **It dispatches, it does not think.** The research value is entirely the
  engines'. A scheduler that runs a weak engine quickly is still a weak engine;
  the scheduler adds *reliability*, not *insight*.
- **Single-process by construction, correct across processes by fencing.** The
  store is a file append; concurrent writers on the same file are serialised by
  an exclusive `fcntl` lock around the read-head-then-append step (see the
  concurrency note above), and the epoch fence makes a superseded worker's write
  a no-op rather than a corruption. It is not a distributed lock service -- for many
  workers across many hosts, point them at one store and rely on the fence; do not
  expect sub-millisecond throughput.
- **Backoff is deterministic, not jittered.** Two workers recovering the same job
  compute the same `not_before`; this is deliberate (reproducibility) and is fine
  for a research queue, but it is not a thundering-herd dampener.
- **Misfire runs the job once, now.** It does not attempt to reconstruct how many
  intervals were missed. A research job is not a billing job; running it once on
  recovery is the correct semantics, and it is recorded (`misfires`).
- **Multiple workers may share one store.** The lease/fencing design exists so
  that several workers can dispatch from the same log. The append is serialised
  with an advisory `fcntl` lock across the read-head-then-append step, so
  concurrent writers keep the hash chain valid (covered by
  `test_concurrent_writers_keep_the_hash_chain_valid`). On a platform without
  `fcntl` (Windows) the lock is skipped and a single worker is assumed.
- **Replay is O(n) per save.** Every `save` replays the whole log to find the
  chain head, so appending is O(n) and a run of N saves is O(N²). For a research
  queue (hundreds to low thousands of events) this is milliseconds; it is not a
  high-throughput queue, and a future change could cache the head under the lock.
- **A clock is injected, not trusted.** Tests drive a controllable clock; in
  production the wall clock is used. A large clock jump forward reclaims live
  leases -- the fence still protects correctness (the old worker cannot complete),
  but it can cause a redundant re-run.
- **A single job must fit inside its lease.** The scheduler does not heartbeat a
  running executor on its behalf; `run_once` claims, runs and completes in one
  call. A `hunt`/`investigate` run longer than `lease_seconds` will be reclaimed
  by another worker and executed again. The fence makes this safe (the first
  worker's completion is refused), but it is wasted work. Set `--lease-seconds`
  above the slowest expected job, or run such jobs with a long lease and a single
  worker. This is the honest limit of a file-backed dispatcher; it is not a
  per-task heartbeat daemon.

## Trigger integration

The scheduler is the dispatch target for authorized triggers
(`blackheart/triggers/`, `docs/TRIGGERS.md`). A trigger receiver authenticates,
deduplicates, rate-limits, and authorizes a delivery, and only then calls
`Scheduler.enqueue`. Two properties make this safe:

- **The same authorization gate runs twice.** The receiver checks it before the
  job exists; the scheduler re-checks it at claim, in the executor, and on
  recovery. Withdrawing scope after acceptance still blocks the job.
- **Dedupe is shared.** A trigger's idempotency key is derived from its payload
  digest, so a resent delivery cannot create a second job even across a restart.

The scheduler and the trigger ledger share one chaining primitive
(`blackheart/chainedlog.py`), so both logs verify with the same
`blackheart integrity` machinery and neither can silently diverge on integrity.
