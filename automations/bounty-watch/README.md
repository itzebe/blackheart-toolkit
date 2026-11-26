# bounty-watch automation (OpenHands scheduled execution)

A thin, read-only wrapper around `blackheart watch cycle`. It is the mission's
preferred scheduler option 1: OpenHands' own hourly execution, with state in the
automation KV store so a fresh sandbox does not lose the baseline.

## What it does

1. Loads the durable state document from `AUTOMATION_KV_TOKEN` / `AUTOMATION_API_URL`
   (or `research/private/bounty-watch/state.json` for a local run).
2. Runs one real monitoring cycle: official policy pages, GitHub repositories,
   and on-chain runtime fingerprints.
3. Writes the state back to the KV store and stores the latest markdown report
   under `bounty-watch-latest-report`.
4. Prints a concise status and fires the automation completion callback.

It never sends a transaction, never tests a target, never submits a report and
never contacts a program. Every source is read-only.

## Activation (requires the operator's approval)

The plugin spec is committed but **not activated**. To enable it, register the
directory as an OpenHands automation with a cron trigger `7 * * * *` UTC. The
GitHub Actions workflow in `.github/workflows/bounty-watch.yml` is the primary
scheduler; use this wrapper when GitHub minutes or runner availability are the
constraint.

## Local validation

```bash
python3 automations/bounty-watch/main.py --dry-run
python3 automations/bounty-watch/main.py --target lido
python3 -m pytest tests/test_watch.py -q
```

A dry run observes and reports but writes no state.
