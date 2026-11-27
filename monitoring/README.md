# Deployed-code drift monitoring

`monitoring/uma-drift-baseline.json` pins the keccak-256 of the live mainnet
runtime bytecode of every in-scope UMA/Across contract (and, for proxies, of the
resolved implementation). The scheduled workflow
`.github/workflows/uma-drift-monitor.yml` re-reads those contracts daily and opens
an issue when a fingerprint moves.

## Why

On an audited protocol the payable bug is almost always in a change shipped
*after* the audit. The monitor is the tripwire for that: it detects that the live
code changed, which is the cue to fetch the deployed source, diff it against the
audited repo HEAD, and fork-test the delta. A drift alert is **not** a finding —
it is a prompt to investigate.

## What it watches

The registry lives in `blackheart/monitor.py` (`TARGETS`). It is deliberately
address-based: `blackheart monitor targets` prints the current list. To add a
contract, add a `TargetSpec` there and regenerate the baseline.

## Regenerate the baseline

Run this after adding or removing a target, or after a drift alert is triaged and
accepted (so the next alert is only about the *next* change):

```sh
BLACKHEART_ETH_RPC=https://gateway.tenderly.co/public/mainnet \
  python3 -m blackheart monitor baseline --out monitoring/uma-drift-baseline.json
```

The command exits non-zero if any target could not be read, so an incomplete
baseline is never silently committed.

## Exit codes (`blackheart monitor run`)

| code | meaning | workflow action |
| --- | --- | --- |
| 0 | every target read and unchanged | nothing |
| 1 | code drift (a fingerprint or proxy impl moved) | open/update the drift issue |
| 2 | one or more targets unreadable (RPC gap) | fail the job (never report clean) |

A gap is intentionally **not** exit 0: an RPC outage must never look like "all
clear".

## Run it locally

```sh
python3 -m blackheart monitor targets
python3 -m blackheart monitor run --baseline monitoring/uma-drift-baseline.json
```
