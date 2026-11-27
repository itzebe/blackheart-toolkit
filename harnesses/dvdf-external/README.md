# DVDF external-source EVM harness

Mission 03's external-source validation target: the engine is run, unchanged,
against **real, third-party, independently-maintained bytecode** deployed to a
local EVM. This is the difference between re-deriving a bug from a *Python model*
of the logic (the historical-rediscovery corpus) and discovering a bug in the
**actual compiled contracts** of a project BLACKHEART does not own.

## Target (external, pinned)

| | |
|---|---|
| Project | Damn Vulnerable DeFi (DVDF) — a standard educational vulnerable-contract suite |
| Repository | `https://github.com/tinchoabbate/damn-vulnerable-defi` |
| Version | tag `v4.1.0` |
| Commit | `64fddf9f96de2782f8868898d68673acb295119c` |
| Nature | deliberately vulnerable, third-party, not a production protocol |

DVDF is **not** a production protocol and this harness makes **no** bounty claim.
Its role is to answer a capability question honestly: can the discovery engine
find and independently verify a real bug in unfamiliar external source it was not
tuned against? A hit here is a capability result, not a disclosure.

## What is external and what is ours

- **External (deployed, unmodified):** the DVDF `src/...` contracts at the pinned
  commit. The engine neither owns nor edits them.
- **Ours (the case declaration):** `blackheart/statespace/runtime/evm_cases.py`
  declares, per case, the contracts to deploy, the setup calls that reach the
  documented initial state, the operations the engine may try, the invariants it
  must hold, and the read-only snapshot it reads. This is the same explicit,
  auditable adapter pattern the HTTP apps use.
- **Ours (controls only):** `controls/src/*.sol` — minimal, faithful fixes for the
  challenges, used only by the verifier's differential control. The vulnerable
  target is upstream bytecode; the control is our fix, which is what makes a hit
  meaningful.

## Setup

```bash
./fetch.sh          # clone DVDF @ v4.1.0, build it, build the controls
```

Everything vendored/built is git-ignored (`vendor/`, `out/`, `lib/`, `cache/`,
`remappings.txt`) and re-created by `fetch.sh`. Requires `git` and `forge` (foundry).

## Run

```bash
export PATH="$PATH:/home/openhands/.foundry/bin"
python3 -m blackheart statespace evm --case dvdf-unstoppable   # one case
python3 -m blackheart statespace evm --all                     # every case
python3 -m blackheart statespace evm --list-cases              # enumerate
```

The engine spawns an ephemeral `anvil` node, deploys the case's contracts, runs
the unchanged discovery pipeline (hypothesis generation → model-guided exploration
→ minimisation → independent verification) over **real transactions**, and prints a
machine-readable report.

## Cases

| Case | Suite | Documented flaw (public) | Differential control |
|---|---|---|---|
| `dvdf-unstoppable` | development | ERC4626 vault trusts its live token balance; a donation breaks accounting | `StoredAssetsVault` (assets tracked in storage) |
| `dvdf-truster` | blind | flash loan forwards a caller-chosen arbitrary call | `SafeCallbackPool` (typed borrower only) |
| `dvdf-naive-receiver` | blind | anyone can force the victim receiver to take a loan and pay its fee | `SenderBoundPool` (borrower must be the caller) |

"development" = used to build/tune the adapter (the adapter author knows the bug).
"blind" = the discovery run the mission is judged on; the engine is not told where
the bug is.

## Honesty

- A hit on a deliberately-vulnerable suite is a **capability** result. It is not a
  production vulnerability and must never be reported as one.
- A rediscovered public issue is not a novel finding. The value here is that the
  engine found and *independently verified* it in real external bytecode.
