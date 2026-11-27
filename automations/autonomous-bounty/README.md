# autonomous-bounty — send a brief, it hunts; you only submit

A brief-driven, unattended runner around BLACKHEART. You drop a **brief** (the
programs you are authorised on, their official policy, their in-scope code, and
the environments you want), and it:

1. **verifies the official policy** for each program (`bounty capture` +
   `bounty verify-policy`) — **fail-closed**: an unverifiable policy never becomes
   an authorisation and nothing runs for that program;
2. **gates the environments** you asked for (`local_fork` / `devnet`) against the
   policy text — an environment the policy forbids is **BLOCKED**, never escalated;
3. **runs the research plan unattended**: `blackheart mission` for source trees,
   `blackheart hunt` for deployed targets (behind the compatibility gate), inside
   the authorised scope (`--in-scope --authorized --scope-reference`);
4. **gates each finding** with `bounty prepare-submission` (which returns the
   formal Gate-D disposition A–F) and **prepares (never sends)** a package — but
   only a finding whose disposition is **A_SUBMISSION_READY or B_POTENTIALLY_PAYABLE**
   is treated as submittable; C/D/E/F findings are listed in the digest as
   "gated, not submittable" so a valid-but-not-payable result never wakes you;
5. **notifies you** by writing `research/private/autonomous-bounty/NEEDS-SUBMISSION.md`
   (and firing the automation callback) and **stops**. **Submission is always human.**

## It never submits
There is no code path that signs, emails, posts to, or contacts a program. The only
external effects are (a) fetching the public policy page and (b) running the engines
locally. `bounty prepare-submission` writes a package; it does not send it.

## Run it
```bash
# one pass over ./brief.json
python3 automations/autonomous-bounty/main.py

# see the exact plan without running anything
python3 automations/autonomous-bounty/main.py --dry-run

# unattended drain (your cron/webhook does this in the cloud)
python3 automations/autonomous-bounty/main.py --loop --interval 300
```

Override the engine command / repo root if needed:
`BLACKHEART_CMD="python3 -m blackheart" BLACKHEART_ROOT=/path/to/blackheart python3 main.py`

## The brief (`brief.json`)
Copy `brief.example.json` to `brief.json` and edit. Per program:
- `name`, `report_to` (the official security email — used only in the notification),
- `policy_url` **or** `policy_text_file` (a local snapshot, good for `--dry-run`),
- `environments`: `["local_fork","devnet"]` (or a subset),
- `source_paths`: local Solidity trees to run `mission` on,
- `contracts`: deployed addresses (needs a `compatibility` record for `hunt`),
- `severity_floor`, `compatibility` (optional).

**The programs you list are the only programs it touches.** Add or remove entries;
that is the whole scope.

## Sandbox output (where you look)
Under `research/private/autonomous-bounty/` (git-ignored):
- `NEEDS-SUBMISSION.md` — a program reached a preparable finding; lists the package
  path and your `report_to`. This is your cue to review and submit.
- `RUN-DIGEST.md` — a run finished with no preparable finding (or with blockers).
- `run-<timestamp>.md` — per-run snapshot.
- `ledger.jsonl` — append-only SHA-256 hash-chained record of every run and decision.

## Safety model (enforced in code, not by a model)
- **Authorisation first.** No policy → no run. No authorisation flags on the engines
  → they refuse (exit 2).
- **Environment confinement.** `local_fork` / `devnet` only when the policy allows;
  never promoted to a heavier environment.
- **No spend/rate cap** imposed (per operator instruction); cadence is your cron.
- **Never submit, never disclose.** Findings stay in the sandbox until you move them.

## Test
```bash
python3 -m pytest tests/test_autonomous_bounty_automation.py
```
