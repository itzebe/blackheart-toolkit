# Ethernaut external-source EVM harness (Mission 04)

Mission 04's second, **independent** external target: the engine is run, unchanged,
against a *different* third-party project than Mission 03's Damn Vulnerable DeFi,
to test whether the discovery capability **generalizes** beyond the single
application it was first validated on.

## Why a second target

Mission 03 proved the engine can find and independently verify a real bug in one
unfamiliar external codebase (DVDF). One application is a point, not a
generalization. This harness adds a second application chosen to differ on every
axis that could otherwise hide overfitting to DVDF:

| axis | DVDF (Mission 03) | Ethernaut (Mission 04) |
|---|---|---|
| maintainer | tinchoabbate | OpenZeppelin |
| architecture | DeFi protocol graph (token/pool/vault) | standalone challenge contracts + per-level factories |
| build | its own Foundry project | Foundry project with 6 submodules |
| vulnerability classes | ERC4626 accounting desync; arbitrary-call flash loan; forced-action receiver | misnamed constructor / access control; integer underflow |
| solution form | empty scaffold to be filled by a solver | level test shipped with the solution filled in |

## Target (external, pinned)

| | |
|---|---|
| Project | OpenZeppelin Ethernaut — a standard security-education CTF |
| Repository | `https://github.com/OpenZeppelin/ethernaut` |
| Commit | `d05643a40aa98c45d66247c69ffceab8f44dd8cb` |
| Nature | deliberately vulnerable, third-party, not a production protocol |
| Licence | AGPL-3.0 (used here only as a locally-built, git-ignored test target; never redistributed or deployed) |

Ethernaut is **not** a production protocol and this harness makes **no** bounty
claim. Its role is to answer a capability question honestly: does the discovery
engine find and independently verify real bugs in a *second*, unrelated external
codebase it was not tuned against? A hit here is a capability result, not a
disclosure.

## What is external and what is ours

- **External (deployed, unmodified):** the Ethernaut level contracts at the pinned
  commit. The engine neither owns nor edits them.
- **Ours (the case declaration):** `blackheart/statespace/runtime/evm_cases_ethernaut.py`
  declares, per case, the contracts to deploy, the setup calls that reach the
  documented initial state, the operations the engine may try, the invariants it
  must hold, and the read-only snapshot it reads.
- **Ours (controls only):** `controls/src/*.sol` — minimal, faithful fixes for the
  levels, used only by the verifier's differential control. The vulnerable target
  is upstream bytecode; the control is our fix, which is what makes a hit
  meaningful.

## Setup

```bash
./fetch.sh          # clone Ethernaut @ the pinned commit (with submodules), build it, build the controls
```

Everything vendored/built is git-ignored (`vendor/`, `out/`, `lib/`, `cache/`,
`remappings.txt`) and re-created by `fetch.sh`. Requires `git` and `forge` (foundry).
The script syncs submodules to the *pinned commit's* recorded revisions, so the
dependency versions cannot silently drift.

## Run

```bash
export PATH="$PATH:/home/openhands/.foundry/bin"
python3 -m blackheart statespace evm --case ethernaut-fallout    # one case
python3 -m blackheart statespace evm --all                        # every registered case (both targets)
python3 -m blackheart statespace evm --list-cases                 # enumerate all targets
```

## Cases

| Case | Suite | Documented flaw (public) | Differential control |
|---|---|---|---|
| `ethernaut-fallout` | validation | the function meant to be the constructor (`Fal1out`) is public, so anyone becomes `owner` and sweeps the balance | `FalloutFixed` (constructor sets ownership; `Fal1out` inert) |
| `ethernaut-token` | validation | unchecked subtraction in `transfer` underflows the sender's balance | `TokenFixed` (checked subtraction) |

"validation" = declared by an author who had read the public, documented solution;
used to confirm the adapter generalizes to a second application. The engine is never
told which level is vulnerable or where the bug is.

## Fair comparison

The harness also supports a fair comparison of approaches on the same deployed
bytecode and the same budget:

```bash
python3 -m blackheart statespace evm-bench --all
```

This runs **guided** (BLACKHEART's unchanged engine), **random** (a uniform random
stateful fuzzer over the identical space), and records the upstream project's own
Foundry test as a provenance column. On these deliberately-small educational cases
the search space is tiny (hundreds to a few thousand sequences), so uniform random
sampling is competitive — reported honestly rather than hidden. The honest claim is
that the engine finds and independently verifies the bug, not that it beats random
on toy-sized spaces.

## Honesty

- A hit on a deliberately-vulnerable CTF is a **capability** result. It is not a
  production vulnerability and must never be reported as one.
- A rediscovered public issue is not a novel finding. The value here is that the
  engine found and *independently verified* it in real external bytecode from a
  second, unrelated project.
- The upstream test result is provenance only: DVDF ships an unfilled solution
  scaffold (so its shipped test fails by design) while Ethernaut ships its solution
  filled in (so its test passes). Neither is a BLACKHEART detection result.
