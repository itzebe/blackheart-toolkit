# The Solidity engine toolchain

Five Solidity analysis engines — Slither, Wake, Halmos, Echidna and Medusa — run
locally against a target's own source. This document is the operator's guide to
installing them reproducibly in any sandbox and verifying what is actually there.

The single source of truth is the pinned manifest,
[`blackheart/engines/toolchain.json`](../blackheart/engines/toolchain.json).
Bootstrap installs what it declares; doctor verifies against it. Nothing here
needs a paid service, an API key, or network access after installation.

---

## Why a manifest and not "just pip install"

Three requirements force a manifest:

1. **Reproducibility.** A finding is only worth something if another sandbox can
   reach the same tool version. Every version is pinned exactly; a floating
   version would silently change the analysis between runs.
2. **Isolation.** `slither-analyzer` ships a top-level `tests` package that
   **shadows this repository's `tests/` directory** if installed into the system
   interpreter — `pytest` then collects slither's tests instead of ours. Each
   Python engine therefore lives in its own venv under `~/.blackheart/venvs/`,
   and the native binaries under `~/.blackheart/bin/`.
3. **Honesty.** "Installed" must be checkable, not assumed. Doctor reads the
   version each binary actually reports and compares it to the pin, so drift and
   absence are visible rather than discovered later as a silently failed scan.

---

## Quick start (a fresh sandbox)

```bash
git clone https://github.com/itzebe/blackheart
cd blackheart
python3 -m pip install -e .          # or just run from the repo root

# 1. Install the pinned toolchain (idempotent; skips what is already present)
python3 -m blackheart engines bootstrap

# 2. Verify it against the manifest
python3 -m blackheart engines doctor

# 3. Run a real analysis on a local target
python3 -m blackheart engines run \
    --target harnesses/adversarial --engines slither,wake,halmos,echidna,medusa \
    --allow-local --workdir /tmp/engrun
```

`bootstrap` exits 0 when every pinned tool is present and 1 otherwise, so it can
gate a CI step or a sandbox setup script. `doctor` exits the same way.

### Prerequisites

| Need | Why | How |
|---|---|---|
| Python ≥ 3.11 | builds the engine venvs | the interpreter running blackheart |
| `git`, `curl` | clone, download release binaries | system |
| **Foundry** (`forge`) | crytic-compile compiles a Foundry target through it; Slither, Echidna and Medusa all need it | `curl -L https://foundry.paradigm.xyz \| bash && foundryup` |
| **solc** | the compiler for non-Foundry targets | `solc-select install 0.8.26 && solc-select use 0.8.26` (solc-select ships in the slither venv) |

`doctor` reports `forge` and `solc` under **toolchain** and fails if either is
missing, because an engine whose compiler is absent would exit non-zero — and a
non-zero exit must never be mistaken for a clean scan.

Foundry is the one prerequisite bootstrap does not install (it is a shell
installer, not a pinned artefact). If `doctor` reports `forge` missing:

```bash
curl -L https://foundry.paradigm.xyz | bash
~/.foundry/bin/foundryup
```

---

## What each engine does, and its real limits

| Engine | Method | Target types | Bound to watch | Honest limitation |
|---|---|---|---|---|
| **Slither** | static analysis | Solidity project/file | CPU; seconds per project | Pattern detectors: it reports *candidate* issues, not exploits. High false-positive rate on unusual code. |
| **Wake** | static analysis + property fuzzing | Solidity project/file | CPU | Its own Solidity front end, so it can disagree with solc on edge syntax. |
| **Halmos** | symbolic execution | Foundry project | **solver time and memory** | Bounded symbolic exploration. Unsupported opcodes, loops and solver divergence mean it explores a *subset* of paths — never claim complete coverage. |
| **Echidna** | property fuzzing | Solidity file / Foundry project | CPU; `--test-limit` | Needs properties to be written. It falsifies the properties you gave it; it does not invent them. |
| **Medusa** | sequence fuzzing | Foundry project / Solidity file | **CPU + memory; the heaviest engine** | Coverage-guided; a negative result is "not found within budget", never "clean". |

**None of these confirm a vulnerability.** Every engine's output is a candidate
that enters the normal pipeline; only BLACKHEART's verification gate plus a named
reviewer can move a cluster to `CONFIRMED`. The orchestrator resets any
self-declared `CONFIRMED` at ingestion and keeps it only as provenance under
`raw`.

---

## Commands

```bash
blackheart engines bootstrap [--engine NAME] [--python PATH] [--json]
blackheart engines doctor    [--engine NAME] [--json]
blackheart engines list      [--json]
blackheart engines run --target PATH --engines a,b,c --allow-local [--workdir DIR]
blackheart engines findings  [--workdir DIR]
```

- `bootstrap` installs missing engines and skips present ones. `--engine` limits
  it to one; `--python` chooses the interpreter for the venvs.
- `doctor` verifies against the manifest and never claims an engine is
  *operational* — that word is reserved for a successful real execution.
- `run --allow-local` is the explicit opt-in that authorizes a local/disposable
  target. A remote target requires `--authz`/`--asset` from an authorization
  record; the gate fails closed.

---

## States, and what each one means

Doctor reports one state per tool. The vocabulary is deliberately narrow:

| State | Meaning |
|---|---|
| `INSTALLED` | present, and reports the pinned version, and its declared toolchain deps resolve |
| `VERSION_MISMATCH` | present, but reports a different version than the pin |
| `MISSING` | not found |
| `BLOCKED` | present but cannot even report its version |

Separately, the engine contract (`docs/ENGINES.md`) uses `EngineState` for a
*run*: `MISSING`, `UNSUPPORTED`, `CONFIGURATION_ERROR`, `INSTALLED`, `READY`,
`RUNNING`, `COMPLETED`, `PARTIAL`, `FAILED`, `CANCELLED`, `VERIFICATION_PENDING`.

The words **installed**, **configured**, **operational**, **tested**,
**disabled** and **blocked** are never used interchangeably:

- **installed** — doctor reports `INSTALLED` at the pinned version.
- **configured** — the toolchain it needs (forge, solc, crytic-compile) resolves.
- **operational** — a real run against a real target succeeded. Only
  `tests/test_engines_live.py` and a manual run can show this.
- **tested** — a test exercised the real binary (live tests) or the real output
  shape (unit tests).
- **disabled** — an engine is present in the registry but the operator has not
  installed it; it is reported `MISSING` and excluded from a run.
- **blocked** — installation is impossible in this environment; the exact reason
  is recorded.

---

## Duplicate handling

Two engines rarely word the same defect identically, and the exact fingerprint
includes the description text. A second, coarser index therefore merges on the
*structural* identity — target, component, source location (line kept) and defect
class:

- The same defect reported by Slither and Wake collapses to **one** corroborated
  cluster, with `duplicate_of` set on the absorbed member.
- Two different classes on one line (a reentrancy and an unchecked transfer) stay
  **two** clusters.
- One class on two different lines stays **two** clusters.
- A property falsified by both Echidna and Medusa is **one** cluster: the defect
  class aliases `sequence-violation`/`assertion-violation` to
  `property-violation`, and the property identifier (not the engine's call
  counter) is the identity.

Corroboration is preserved across a reload: `load_state` restores the recorded
sources and membership rather than rebuilding from representatives alone.

---

## Tests

```bash
# Deterministic, toolchain-free: manifest integrity, resolution, doctor honesty,
# dedup/corroboration. Run in ordinary CI.
python3 -m pytest tests/test_engine_toolchain.py tests/test_engine_dedup.py \
                 tests/test_solidity_engines.py

# Real binaries. Skips when a binary is absent; FAILS if BLACKHEART_LIVE_ENGINES=1
# and one is missing, so a CI job that intends to run them cannot pass by skipping.
python3 -m pytest tests/test_engines_live.py -m live
BLACKHEART_LIVE_ENGINES=1 python3 -m pytest tests/test_engines_live.py -m live
```

The live tests run against `harnesses/adversarial/`, which needs one thing that is
**not** committed: `lib/forge-std` is in `.gitignore`, so a fresh clone has no
`forge-std` and the Halmos test fails on a missing import. Fetch it once, as
`harnesses/adversarial/README.md` says:

```bash
cd harnesses/adversarial && forge install foundry-rs/forge-std
```

Without it, `forge`, Echidna and Medusa still work; only the symbolic test needs
it. A failure there is a missing harness dependency, not a defect in the engine.

`tests/test_solidity_engines.py` pins each adapter's exit-code contract, its
parser and its normalization against the engine's **real** output shape, with no
toolchain required — so the parsing logic is covered even in a bare CI runner.

---

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `doctor` says `forge` missing | Foundry not installed, or `~/.foundry/bin` not on PATH | `foundryup`; doctor also looks in `~/.foundry/bin` directly |
| `doctor` says `solc` missing | no compiler selected | `~/.blackheart/venvs/slither/bin/solc-select install 0.8.26` |
| `pytest` collects slither's tests | slither installed into the system interpreter | never do that; bootstrap always uses a venv |
| Engine exits non-zero with no findings | compile failure (usually a missing forge or solc) | check the engine's `detail` in `engines-run.json`; a non-zero exit is **not** a clean scan |
| Halmos takes minutes | symbolic execution is expensive | bound it with a solver timeout; treat a timeout as "not found within budget" |
| Medusa is very slow | sequence fuzzing is the heaviest engine | lower `testLimit`/`workers` in the adapter options |
| Slither reports `clean` on code that plainly has a finding | it was pointed at a directory crytic-compile could not resolve, so it analysed **0 contracts** and still exited 0 | fixed in the adapter: it resolves the framework root, else `contracts/`, else `src/`, else the file list, and treats a 0-contract run as unparseable. If you see it again, run `slither <dir>` by hand and read the contract count |
| Every Foundry engine fails to compile with `Invalid option for --evm-version: osaka` | Foundry's default EVM target is newer than the pinned solc 0.8.26 can emit | fixed in the adapter: `FOUNDRY_EVM_VERSION` is pinned to `cancun` unless the target's `foundry.toml` sets `evm_version`, or the operator sets the variable |
| Halmos live test fails with `File not found: forge-std/Test.sol` | `harnesses/adversarial/lib/forge-std` is gitignored and absent in a fresh clone | `cd harnesses/adversarial && forge install foundry-rs/forge-std` |

---

## Sandbox portability

The repository carries everything a fresh sandbox needs: the pinned manifest, the
bootstrap and doctor commands, and the adapters. What it deliberately does **not**
carry is runtime state — installed venvs, downloaded binaries, corpora, or
credentials. Each sandbox installs its own toolchain with `bootstrap` and verifies
it with `doctor`.

Isolation rules for concurrent sandboxes:

- Engine runs write to a per-run `--workdir`; give each sandbox a unique one
  (`/tmp/engrun-$(date +%s)-$$`).
- Medusa's config and corpus live in the adapter's scratch directory under the
  run workdir, never inside the analysed project, so one run cannot mutate its
  target or overwrite another sandbox's corpus.
- No secrets are committed. `.env.example` lists variable *names* and
  descriptions only.

---

## Verified: a clean, isolated sandbox

The claims above were checked from a fresh clone with an empty `BLACKHEART_HOME`,
so nothing from the development sandbox could be used. Reproduce it with:

```bash
git clone https://github.com/itzebe/blackheart && cd blackheart
export BLACKHEART_HOME=/tmp/bh-clean-$(date +%s)
python3 -m blackheart engines bootstrap      # installs all five engines + solc
python3 -m blackheart engines doctor         # exits 0 only if every pin matched
```

What that run actually produced:

| Step | Result |
|---|---|
| `engines bootstrap` | slither 0.11.3, wake 4.22.2, halmos 0.3.3, echidna 2.4.0, medusa 1.5.1 installed under `$BLACKHEART_HOME`; solc 0.8.26 via solc-select |
| `engines doctor` | all seven rows `INSTALLED` at their pin, exit **0** |
| `engines doctor` on the *empty* home | six `MISSING` rows, exit **1** — it never claims a tool it did not find |
| slither on a reentrancy vault | `COMPLETED`, 3 findings (before the target-resolution fix: `clean`, 0 findings) |
| wake on the same vault | `COMPLETED`, 1 finding |
| medusa on a failing Foundry property | `COMPLETED`, 1 finding (before the EVM pin: `FAILED`, exit 6) |
| halmos on a non-Foundry target | `CONFIGURATION_ERROR` naming the missing `foundry.toml` — not a clean scan |
| echidna with no harness | `CONFIGURATION_ERROR` naming the missing predicate — not a clean scan |

The two engine defects above were found by *running* the engines, not by reading
the adapters. Each has a regression test that fails when the fix is reverted
(checked by mutation).
