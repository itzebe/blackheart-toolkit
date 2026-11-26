# Quickstart

BLACKHEART is a stdlib-only Python research harness. This page gets a working
install, proves the pipeline offline, and shows the first real commands. Read
`docs/CAPABILITIES.md` before treating any output as coverage: the engine still
cannot find a payable bug unaided.

## 1. Install

Requirements: Python 3.11 or newer.

```bash
python3 -m pip install -e .
blackheart --version
```

For the external toolchain (Foundry, Slither, Echidna, Halmos, Rust, live-protocol
tools), run the installer. It is optional for the core engine:

```bash
./install.sh --core      # Python package + Foundry
./install.sh             # full toolchain
blackheart doctor
```

## 2. Find your way around

```bash
blackheart info           # version, counts, capability headline, paths
blackheart guide          # every command, grouped
blackheart capability     # what it can and cannot do, with evidence
blackheart doctrine       # the six-phase method and its gates
```

`blackheart <command> --help` is the reference for a single command.

## 3. Prove the pipeline offline

```bash
blackheart init ./engagement
blackheart demo --dir ./engagement
```

`init` writes a workspace whose `authorization.json` is a **template that fails
closed**: it is unverified, has no evidence and authorizes nothing. Fill it from
a program's official policy before any active testing.

`demo` runs the repository's own vulnerable/guarded pair through the stateful
fuzzer, the evidence gate, the findings repository, SARIF and the baseline. It
uses no network, no Foundry and no provider key. A passing demo prints the
counterexample, the guarded-twin result and the baseline diff.

## 4. First real engagement

```bash
# 1. Fill authorization.json from the official policy, then verify the install
blackheart doctor

# 2. Read a source tree into an attack surface and candidate leads
blackheart ingest /path/to/target --synthesize --symbolic

# 3. Run the universal hunt against an executable target (names: blackheart targets)
blackheart hunt --target <target-name> --compatibility <record>

# 3b. Close the loop on a verified deployment: source model -> price -> verify -> finding
blackheart pipeline --chain-id 1 --address 0x... \
    --control-address 0x... --compatibility <record> --in-scope --authorized

# 4. Document what you actually verified
blackheart findings --dir findings add --file finding.json
blackheart findings --dir findings summary
blackheart findings --dir findings sarif --out reports/findings.sarif

# 5. Review only what changed since the last run
blackheart baseline --findings findings create --out baseline.json
blackheart baseline --findings findings compare --baseline baseline.json --fail-on-new
```

A finding is `CONFIRMED` only when it carries evidence, an independent
verification result and a named reviewer. The CLI refuses the rest.

## 5. Exit codes

| code | meaning |
|---|---|
| `0` | the command completed and its own verdict was positive |
| `1` | the command completed and its verdict was negative (a finding, a failed check, a new baseline item with `--fail-on-new`) |
| `2` | the command was blocked, invalid or could not run (a missing compatibility record, a malformed file, an unauthorized asset) |

A blocked run is never a clean run. Read the message and fix the named field.

## 6. What is deliberately absent

- No compile-and-execute of arbitrary third-party Solidity inside the engine.
- No automatic proof that a class is absent; a stochastic negative is "not found
  within budget".
- No submission. `blackheart bounty gate` prepares a decision; a human sends it.
- No provider key is required for core research or release.

See `docs/CAPABILITIES.md` for the measured statement, `docs/PIPELINE.md` for
the close-the-loop statuses, and `docs/DOCTRINE.md` for the method.
