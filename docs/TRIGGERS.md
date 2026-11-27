# Triggers: production, authorized research triggers

A **trigger** is an external request to start BLACKHEART research on an asset. It
is the one place where data BLACKHEART did not create decides that work should
run, so it is handled as hostile input end to end: authenticated, validated,
deduplicated, scope-checked, rate-limited, recorded — and only then turned into a
durable scheduler job.

Implementation: `blackheart/triggers/`; the HTTP transport is
`blackheart/ingress/`. CLI: `blackheart trigger`, `blackheart ingress`. Tests:
`tests/test_triggers.py`, `tests/test_ingress.py`, `tests/test_trigger_bounty_cli.py`.

## Why it is built this way

The scheduler (`blackheart/scheduler/`) already runs jobs durably, and
`blackheart/monitor.py` already watches deployed code for drift. Neither answers
the question "an external event says: research this asset *now* — should we, and
how do we prove we were allowed to?". This module is that missing, guarded edge.
It **does not** implement research: it enqueues jobs the scheduler dispatches into
the existing engines, so a trigger runs exactly what an operator would run by
hand.

## The gate order (fixed)

Every delivery passes through these checks in this order. Nothing creates a job
until all of them pass.

1. **Authentication** (`TriggerSource.authenticate`). A source turns a raw
   delivery into a `TriggerRequest`, or raises `TriggerError`.
2. **Replay / nonce.** A delivery id already seen is refused outright.
3. **Duplicate payload.** A resend with a new delivery id but identical content is
   the same work; it is deduped to the existing job.
4. **Source allow-list.** Only configured sources may create work.
5. **Rate limit.** A sliding-window cap on accepted deliveries; a flood is
   rejected without creating jobs.
6. **Authorization.** The asset must pass the *existing*
   `blackheart.authz.authorize_active_testing` gate against the record the
   receiver is configured with. **A payload can never supply or override
   authorization** — there is no `authz` or `scope` field in the schema, and an
   unknown field is rejected. With a live `authz_provider` (the CLI wires one) the
   *current* record is read here and at every later boundary; if it cannot be
   produced — the file was deleted or is unreadable — the delivery is **rejected**
   rather than judged against the enqueue-time snapshot.
7. **Job creation.** Only now is a `Job` enqueued through the scheduler.

The scheduler re-checks the same authorization gate again at claim, in the
executor, and on recovery, so withdrawing scope after acceptance still blocks the
job (see `tests/test_triggers.py::test_scope_withdrawn_after_acceptance_blocks_job`).

## Sources

| Source | Authentication | Use |
|---|---|---|
| `WebhookTriggerSource` | HMAC-SHA256 over `timestamp.body`, constant-time compare, timestamp inside a skew window (replay defence) | GitHub/Stripe/generic webhooks |
| `ManualTriggerSource` | operator-invoked (validates the payload; every other gate still applies) | local CLI |
| `RecurringTrigger` | fires the same validated payload every `interval` seconds through the same gates | scheduled re-checks |

A source is responsible for **authentication only**. It cannot skip dedupe, rate
limiting, authorization, or job creation, because the receiver owns them.

## Honest states

A trigger record tells the truth about what happened to the work. A delivery is
`RECEIVED` → `AUTHENTICATED` → `ACCEPTED` (job created) → `DISPATCHED` (claimed)
→ `EXECUTED` (the engine ran) → `COMPLETED` (terminal), or `REJECTED` /
`DUPLICATE`. A trigger that only reached the queue is **never** recorded as
executed; `trigger sync` advances a record from its job's real state.

## The ledger

Every delivery — accepted or rejected — is appended to a tamper-evident,
hash-chained log (`blackheart/chainedlog.py`, the same primitive the job store
uses). A rejected record carries a digest and a safe reason, never the secret or
the raw body. `blackheart trigger verify` re-checks the chain.

## Usage

```bash
# Ingest a signed webhook delivery (secret from $BLACKHEART_TRIGGER_SECRET)
BLACKHEART_TRIGGER_SECRET=... blackheart trigger \
  --dir research/private/scheduler --authz authz.json \
  webhook --body body.json --headers headers.json

# Operator-initiated trigger
blackheart trigger --dir research/private/scheduler --authz authz.json \
  manual --payload payload.json

# Register and tick recurring triggers
blackheart trigger --authz authz.json recurring --add payload.json --interval 3600
blackheart trigger --authz authz.json recurring

# Inspect
blackheart trigger --dir research/private/scheduler list --state REJECTED
blackheart trigger --dir research/private/scheduler show <delivery-id>
blackheart trigger --dir research/private/scheduler --authz authz.json sync
blackheart trigger --dir research/private/scheduler verify
```

The webhook source is transport-neutral: an HTTP server that reads the raw body
and the signature/timestamp headers can call `TriggerReceiver.handle` directly.
The CLI's `webhook` subcommand is that same path from files or stdin, so the
behaviour is identical whether a test, a script, or a server drives it.

## The bundled HTTP listener (`blackheart ingress`)

`blackheart/ingress/` is a real `ThreadingHTTPServer` in front of the receiver, so
an operator does not have to write the transport. It **adds no execution path**:
every request is parsed into `(raw body, headers)` and handed to the same
`TriggerReceiver.handle`, so the gate order above is unchanged and cannot be
skipped. Start it with:

```bash
BLACKHEART_TRIGGER_SECRET=... blackheart ingress \
  --dir research/private/scheduler --authz authz.json \
  --host 127.0.0.1 --port 8787 serve
# validate configuration without binding (CI / pre-deploy):
blackheart ingress check
```

The transport enforces what the receiver should never have to see:

- **Body cap before allocation** — `Content-Length` over the cap is refused 413
  and the socket is closed without reading the body; a missing/invalid length is
  411/400. The body read itself is bounded.
- **Content type** — `application/json` (optional `; charset=`) only, else 415.
- **Methods/paths** — only `POST /trigger`, `GET /health`, `GET /ready`; others
  404/405 with `Allow`.
- **No desync, by construction** — *every* response closes the connection
  (`Connection: close`), so pipelined or leftover bytes can never be parsed as the
  next request. A webhook ingress gains nothing from keep-alive, and refusing to
  pipeline removes the whole smuggling class rather than auditing each early
  return. Covered for an undrained rejection, a `GET` carrying a body, and a valid
  signed `POST` whose declared `Content-Length` is shorter than the bytes sent.
- **No framing ambiguity** — a request carrying `Transfer-Encoding` is refused
  400. The body is read with a fixed `Content-Length` only, so a CL.TE/TE.CL
  coding (the classic smuggling vector when two hops disagree about where the body
  ends) is rejected rather than reconciled.
- **Bounded concurrency** — a hard cap on simultaneous connections; beyond it a
  connection is refused 503 instead of spawning an unbounded thread (slow-loris).
- **Timeouts** — a per-connection socket timeout drops a stalled client.
- **Graceful stop** — SIGTERM/SIGINT drain in-flight deliveries and close, so an
  orchestrator restart never loses an accepted job (it stays `PENDING` on disk).

Honest status codes: `202` means *the delivery was accepted and a durable job
exists* — never that the research ran; a duplicate is `200` with
`state=DUPLICATE`; a gate failure is `400`/`403`. `/health` is liveness only and
`/ready` is `503` unless a scheduler is attached (a delivery would be dispatched).
Responses and structured logs carry the delivery id and state, never the body, the
signature, or the secret.

**The signature proves *who sent* the request, never *that the target may be
attacked*.** Authorization stays the receiver's and the scheduler's, re-checked at
claim and again in the executor, so a scope withdrawal between acceptance and
execution still blocks the job — **provided the executing worker can see the live
record**. `ingress serve` only enqueues; a separate `blackheart schedule run`
worker executes. Give that worker the same record with `--authz`:

```bash
blackheart schedule --dir research/private/scheduler --authz authz.json \
  run --owner worker-1
```

With `--authz` the worker re-reads the file at claim and execution time and
**fails closed** if it cannot be read, so deleting or editing the file blocks the
queued job (`BLOCKED`, no engine run). Without `--authz` the worker can only see
the snapshot stored at enqueue — the previous behaviour, kept for callers that
never mutate their record. Both halves share one `make_live_authz_provider`, so
they cannot disagree about what "current authorization" means. Covered by
`tests/test_scheduler.py::test_cli_schedule_run_with_authz_blocks_after_withdrawal`.

## Limits (honest)

- The listener binds loopback by default. A non-loopback `--host` requires
  `--allow-public-bind`, and TLS/authentication in front of it is the operator's
  to terminate — the module speaks plain HTTP.
- The rate limiter is per-ledger (per `--dir`), not per source IP. It bounds total
  accepted work, which is what protects cost; per-source quotas are a policy the
  operator adds at the HTTP layer.
- **Every rejection is recorded for audit, so a flood still grows the ledger, and
  replay is O(n).** Each delivery replays the log (to find a nonce, a duplicate
  payload, or the rate-limit window), the same O(n)-per-append trade-off the job
  store already accepts for hundreds-to-low-thousands of events. The rate limiter
  stops a flood creating *jobs*; it does not stop a flood creating *rejected
  records*. Network-level rate limiting belongs in front of the listener — an
  operational control, not something this module should fake by dropping the
  audit trail.
- Authentication is HMAC shared-secret. Asymmetric signatures (e.g. Ed25519) are
  not implemented; add a `TriggerSource` if a provider requires them.
