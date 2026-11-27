# Investigation-log integrity: threat model and design

The P3 investigation log (`research/private/investigations/investigations.jsonl`)
is the record of **what was actually reproduced**. A verdict fabricated by editing
that log must not be trusted — that would defeat the engine's "no fabricated
evidence" gate. This document states exactly what the integrity design detects,
what it does **not**, and why.

The earlier design stored a single SHA-256 hash of each record *beside* the
record. That is useful, but it is **not** tamper-evidence against a capable
attacker: whoever can rewrite the payload can rewrite its adjacent hash, and
nothing binds one record to the next. The design below replaces it with a
layered, honest scheme.

## Threat model

| # | Threat | Detected? | By which layer |
|---|--------|-----------|----------------|
| 1 | Accidental corruption (bit rot, bad edit) | **Yes** | content hash |
| 2 | A single record edited, hash left stale | **Yes** | content hash |
| 3 | A record edited **and** its adjacent hash recomputed | **Yes** | hash chain |
| 4 | A record deleted | **Yes** | hash chain (`seq`/`prev`) |
| 5 | Records reordered | **Yes** | hash chain (`seq`/`prev`) |
| 6 | A record inserted | **Yes** | hash chain (`seq`/`prev`) |
| 7 | The log truncated (tail records removed) | **Yes, with a checkpoint** | checkpoint |
| 8 | Wholesale rewrite of the log, chain recomputed | **Yes, with a key** | HMAC-SHA256 |
| 9 | Legacy records predating integrity protection | **Reported `LEGACY`** | stamp presence |
| 10 | Host compromise that also holds the signing key | **No** | — |
| 11 | An attacker who can rewrite the log *and* a locally stored checkpoint | **No** | — |

Rows 10 and 11 are stated honestly: a party who controls the machine **and** the
key, or who can rewrite both the log and a local checkpoint, cannot be stopped by
anything stored on that machine. Defeating that requires an **off-host anchor**
(a remote append-only log, a transparency service, a signed timestamp from a
third party). The mission forbids paid infrastructure, so the limitation is
recorded here rather than papered over. **A locally stored checkpoint does not
protect against an attacker who can rewrite both the log and the checkpoint.**

## Layers

1. **Content hash** — `content_sha256 = SHA-256(canonical_json(payload))`.
   Detects rows 1–2.
2. **Hash chain** — every state record carries `seq` (its position), `prev` (the
   previous record's chain hash, `GENESIS` for the first), and
   `chain_sha256 = SHA-256(seq ‖ prev ‖ content_sha256)`. Deleting, reordering, or
   inserting a record changes some later record's expected `prev` or `seq`.
   Detects rows 3–6.
3. **Keyed MAC** — when a signing key is configured, each record also carries
   `hmac = HMAC-SHA256(key, seq ‖ prev ‖ content_sha256)` and `key_id`. Without
   the key an attacker cannot forge a chain that verifies, so a wholesale rewrite
   that recomputes every hash is still caught. Detects row 8. The key lives
   **outside the log** (a file with `0600` permissions, or `BLACKHEART_INTEGRITY_KEY`).
4. **Checkpoint** — a signed record of the chain head, kept in a separate file.
   The in-band chain cannot see a *shorter, internally consistent* log, so
   truncation (row 7) needs an external anchor. `blackheart investigate checkpoint`
   writes one; `blackheart investigate verify --checkpoint FILE` consumes it.

Only standard-library primitives are used (`hashlib`, `hmac`, `secrets`); no
algorithm is invented and no third-party dependency is added.

## Verification outcomes

`verify_integrity()` / `blackheart integrity FILE` return exactly one status, and
a caller must not collapse them:

| Status | Meaning | `ok` |
|--------|---------|------|
| `VERIFIED` | Chain intact; signatures verified when a key was required. | true |
| `FAILED` | A concrete check failed (edit, deletion, reorder, bad HMAC, checkpoint mismatch). | false |
| `LEGACY` | Records predate integrity protection (unstamped). Verifiable forward, not verified. | false |
| `UNAVAILABLE` | Verification could not run (no key where one is required, missing log). | false |

**`UNAVAILABLE` and `LEGACY` are never treated as success.** A tampered log still
*replays* (resumption is not blocked), but the engine refuses to record a
`CONFIRMED` verdict unless the log verifies `VERIFIED`: the confirmation gate
(`InvestigationEngine.verdict`) calls `verify_integrity()` first and holds the
finding as `UNCONFIRMED` on **any** other status — `FAILED`, `UNAVAILABLE`, or
`LEGACY`. A deployment that requires signatures but holds no key therefore cannot
confirm a finding (it gets `UNAVAILABLE`), and a log with a legacy prefix cannot
confirm one either.

## Commands

```bash
# Verify the investigation log's chain (exit 1 on tamper)
blackheart investigate --dir research/private/investigations verify

# Generate a signing key OUTSIDE the log (0600), then sign records with it
blackheart investigate --dir research/private/investigations keygen --out /secure/key.json
BLACKHEART_INTEGRITY_KEY=/secure/key.json blackheart investigate ... verify --require-signatures

# Pin the head so a truncated tail is detectable
blackheart investigate --dir research/private/investigations checkpoint --key-path /secure/key.json
blackheart investigate --dir research/private/investigations verify --checkpoint <file>

# Verify any append-only JSONL log produced by a stamping writer
blackheart integrity <file.jsonl> [--key-path FILE] [--require-signatures] [--checkpoint FILE]
```

## Key management

- The key is generated by `keygen` and written to a file the operator chooses
  (`0600`). It is **never** stored inside the log and **must not** be committed.
- `key_id` is recorded per record, so a rotated-in key does not invalidate records
  signed by an older key: a verifier selects the key per record.
- Without a key the log is still hash-chained. That is a real, useful guarantee
  (rows 1–6) but **not** protection against a full rewrite (row 8) — the tool says
  so rather than implying otherwise.

## What this is not

This is **tamper-evidence**, not tamper-*proofness*. It makes alteration
*detectable* to a verifier who holds the key or an off-host checkpoint. It cannot
make alteration *impossible* on a machine the attacker fully controls.
