# Euler V1 external-source EVM harness (Mission 08)

Mission 08's third, **independent** external target: the engine is run, unchanged,
against a *third* third-party project — this time a **real production protocol**
rather than an educational suite — to test whether the discovery capability
generalizes to an unfamiliar architecture.

## Why a third target

Mission 03 found and verified a bug in DVDF (a graph of small DeFi contracts);
Mission 04 did the same on Ethernaut (standalone CTF challenges). Both are
deliberately-vulnerable teaching material with simple architectures. Mission 08
adds a target that differs on the axes most likely to hide overfitting:

| axis | DVDF | Ethernaut | **Euler V1** |
|---|---|---|---|
| maintainer | tinchoabbate | OpenZeppelin | euler-legacy-xyz |
| nature | educational | educational CTF | **real production protocol** |
| architecture | DeFi protocol graph | standalone challenges | **diamond-proxy** (one core, many module proxies) |
| build | its own Foundry project | Foundry + 6 submodules | Hardhat/JS (built here with Foundry) |
| the bug | ERC4626 accounting desync | misnamed constructor / underflow | a state-mutating path that **skips the solvency check** |

## Target (external, pinned)

| | |
|---|---|
| Project | Euler V1 — the lending protocol exploited in March 2023 |
| Repository | `https://github.com/euler-legacy-xyz/euler-contracts` |
| Commit | `24da0f2de98d984b0007133b2c251e7fbbda4115` |
| Nature | real production protocol; the exercised flaw was **fixed on-chain by governance** |
| Licence | GPL-2.0-or-later (used here only as a locally-built, git-ignored test target; never redistributed or deployed) |

Euler V1 is **not** a live target and this harness makes **no** bounty or
disclosure claim. Its role is a capability question, answered honestly: does the
discovery engine find and independently verify a real bug in a *third*, unrelated,
production-grade codebase whose architecture it was never tuned against? A hit here
is a capability result.

## What is external and what is ours

- **External (deployed, unmodified):** the Euler V1 modules at the pinned commit
  (Installer, Markets, Liquidation, Governance, Exec, EToken, DToken, IRMDefault,
  Euler core). The engine neither owns nor edits them.
- **Ours (integration glue):** `src/Bootstrap.sol` deploys the diamond and
  configures one market (the ERC20 `MockERC20`), reproducing the upstream test
  harness's setup exactly. `src/MockERC20.sol` is a minimal ERC20 used as the
  market's underlying.
- **Ours (the case declaration):** `blackheart/statespace/runtime/evm_cases_euler.py`
  declares the contracts to deploy, the setup calls, the operations the engine may
  try, the invariant it must hold, and the read-only snapshot it reads.
- **Ours (controls only):** `controls/src/ETokenFixed.sol` — a minimal patched copy
  of the affected module that adds the missing solvency check. Used only by the
  verifier's differential control; it is what makes a hit meaningful.

## Setup

```bash
./fetch.sh    # clone Euler V1 @ the pin, build it, build the harness, build the controls
```

Everything vendored/built is git-ignored (`vendor/`, `out/`, `lib/`, `cache/`,
`remappings.txt`, `foundry.lock`) and re-created by `fetch.sh`. Requires `git`,
`forge` (foundry) and `npm` (the vendored contracts import `hardhat/console.sol`,
resolved through the vendored `node_modules`).

## Run

```bash
export PATH="$PATH:/home/openhands/.foundry/bin"
python3 -m blackheart statespace evm --case euler-v1-donate   # this case
python3 -m blackheart statespace evm --all                     # every registered case
python3 -m blackheart statespace evm --list-cases              # enumerate all targets
```

## The case

| Case | Suite | Documented flaw (public) | Differential control |
|---|---|---|---|
| `euler-v1-donate` | blind | `EToken.donateToReserves` reduces the caller's collateral without calling `checkLiquidity`, so a borrower can donate its deposit to the reserves and leave the account insolvent (the debt survives; the loss is socialised) | `ETokenFixed` (performs the missing check; the donation reverts) |

"blind" = declared without the engine being told where (or whether) a flaw exists;
the ground truth is recorded for the report only and is never read by the engine.

## The minimal exploit (engine output)

Three operations, no privilege:

```
deposit 100e18  ->  borrow 1e18  ->  donate 100e18
```

After the donation the account's collateral value is 0 while its liability value is
~3.57e18, and the protocol's own `requireLiquidity` would revert on that state. The
engine found this sequence blind, minimised it to three steps, the independent
verifier re-derived it on a fresh deployment (`INDEPENDENTLY_VERIFIED`), and the
differential control did **not** reproduce it (`control_reproduced = false`).

## Honesty

- A hit on a known, patched, historical vulnerability is a **capability** result,
  not a novel finding and not a disclosure.
- The value here is that the engine found and *independently verified* the bug in
  real, production-grade, diamond-proxy bytecode from a third, unrelated project —
  with a differential control proving the result discriminates.
