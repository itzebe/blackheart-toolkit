# Twyne daily bounty-operations monitor

A deterministic, LLM-free, read-only automation that keeps the Twyne engagement
scope verified between manual sessions. It is packaged as an OpenHands
plugin-spec automation (`.plugin/plugin.json`, `entrypoint.runner: "script"`), so
it runs without an LLM conversation.

Each daily run:

1. fetches the current official Twyne Immunefi program page(s);
2. extracts the facts that matter — program status, in-scope repositories and
   contract addresses, Safe Harbor, PoC requirement, KYC requirement, reward cap;
3. diffs them against the last verified snapshot;
4. revalidates every known asset's authorization against the fresh scope and
   records fresh dated authorization evidence (KV store + private dir), so the
   authorization gate's evidence-freshness check never trips on stale evidence;
5. emits a concise daily result.

## Fail-closed and read-only

- If the official scope cannot be fetched, the run stops with exit code 2,
  records the reason, and refreshes nothing.
- An asset is only `AUTHORIZED` while it still appears in the freshly fetched
  official scope **and** the program checks pass. Unknown assets default to
  `UNKNOWN`; `PASSIVE_ONLY` is never promoted.
- It never broadcasts a transaction, never runs active testing, never submits a
  report, and never contacts the program. Local-fork research is a separate,
  independently authorized step.

## Portability

- Standard library only, no import of the BLACKHEART package, so it runs in a
  bare sandbox.
- Cross-run state lives in the automation KV store (`AUTOMATION_KV_TOKEN`), which
  survives the fresh pod each cloud run gets, with a local-file fallback
  (`research/private/twyne-monitor/`, git-ignored) for local runs.

## Local validation

```bash
python3 automations/twyne-bounty-ops/main.py --dry-run   # fetch + diff + report, no writes
python3 automations/twyne-bounty-ops/main.py             # full run (writes snapshot + authz)
python3 -m pytest tests/test_bounty_ops_automation.py
```

## Deployment

Registered as a daily OpenHands plugin-spec automation (cron `0 6 * * *`, UTC).
The script uses the standard automation-service `fire_callback` contract and is a
no-op when run outside the service, so it is safe to run locally.
