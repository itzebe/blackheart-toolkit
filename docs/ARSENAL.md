# The arsenal: external engines, verified live

BLACKHEART's own engines are in-process models. This document covers the *external*
engines — Slither, Wake, Halmos, Echidna, Medusa, plus the Foundry/solc toolchain
they need — and states exactly what was verified on this host, what each engine
buys, and what it cannot do.

Everything here runs behind the same gate as the internal engines: a pinned,
versioned toolchain (`blackheart/engines/toolchain.json`), a compatibility record
bound to the target, and a status that is never upgraded by hope.

## Install

```bash
blackheart engines bootstrap      # pip engines into ~/.blackheart/venvs/<tool>,
                                  # github-release binaries into ~/.blackheart/bin
blackheart engines doctor         # every pin checked; exit 1 on a gap
```

`bootstrap` covers Slither, Wake, Halmos (pip) and Echidna, Medusa (release
tarballs). Foundry and solc are declared in the manifest's `toolchain` section and
are not installed by `bootstrap`; install them from the official releases and
verify the published checksum:

```bash
curl -sSLO https://github.com/foundry-rs/foundry/releases/download/v1.10.0/foundry_v1.10.0_linux_amd64.tar.gz
curl -sSLO https://github.com/foundry-rs/foundry/releases/download/v1.10.0/foundry_v1.10.0_linux_amd64.sha256
sha256sum -c foundry_v1.10.0_linux_amd64.sha256
tar xzf foundry_v1.10.0_linux_amd64.tar.gz
install -m755 forge anvil cast chisel ~/.foundry/bin/
~/.blackheart/venvs/slither/bin/solc-select install 0.8.26
~/.blackheart/venvs/slither/bin/solc-select use 0.8.26
```

A prebuilt release tarball is used deliberately instead of `curl | bash`: the
checksum is verifiable, and the policy forbids piping an unreviewed script into a
shell.

## What each engine is for

| Engine | Method | Buys | Cannot do |
| --- | --- | --- | --- |
| Slither | static (AST/IR) | ~100 detectors, whole-program dataflow printers | no stateful sequences, no cross-transaction reasoning |
| Wake | static (AST) | a second static opinion; Solidity-to-IR detectors | same limits as Slither |
| Halmos | symbolic execution | proves a property for **all** inputs, or returns a concrete counterexample | needs a Foundry test harness; cheatcode coverage is partial |
| Echidna | property fuzzing | fast counterexample search over long call sequences | stochastic: a pass is "not found within budget", never "clean" |
| Medusa | coverage-guided fuzzing | stronger exploration of gated paths than plain Echidna | same stochastic limit |

## Beyond the EVM: Rust/Substrate and live-protocol layers

The engines above read EVM bytecode and Solidity. A target in another stack is
**not** analysable by them, and saying so is the point of the compatibility gate:
`blackheart compat check` returns `BLOCKED` when no verified tool for the
detected language is installed. Two additional layers exist so that gate can
actually be satisfied rather than worked around.

### Rust / Substrate (Polkadot SDK, runtimes, Solana programs)

Installed by `install.sh` (skip with `--no-rust`): `rustc`/`cargo` stable,
a **nightly** toolchain (cargo-fuzz and the sanitizer runtimes need it),
`clippy`, `cargo-fuzz`, `cargo-audit`, `cargo-deny`.

What each buys, and what it does not:

| Tool | Buys | Cannot do |
| --- | --- | --- |
| `cargo test` | executes the target's own FRAME unit tests | FRAME unit tests do not exercise the compiled WASM runtime |
| `cargo-fuzz` | libFuzzer coverage over a decoder or arithmetic entrypoint | needs a harness that calls the production path; a harness that restates the implementation proves nothing |
| `cargo-audit` / `cargo-deny` | known-advisory and policy scan of the crate graph | a clean advisory scan is not a secure protocol |
| `clippy` | the first compile gate | lints are not a vulnerability model |

Verified on this host: `rustc 1.100.0`, `cargo 1.100.0`, `cargo-fuzz 0.13.2`,
`cargo-audit 0.23.0`, `cargo-deny 0.22.0`, `clippy 0.1.100`, nightly
`1.102.0-nightly`.

### Live protocol: web, API, recon, secrets, infrastructure

`ffuf`, `gobuster`, `dalfox`, `sqlmap`, `wafw00f`, `arjun`, `dnsx`, `gau`,
`naabu`, `nmap`, `nuclei`, `httpx`, `subfinder`, `katana`, `gitleaks`, `trivy`.
Authorized live assets only; every one is free and needs no API key.

These are reachability and evidence tools, not oracles. A nuclei template that
does not fire proves the template did not match; it does not prove the endpoint
is safe.

## Verified on this host (2026-11-21)

`blackheart engines doctor` → `result: all pinned tools present`:

```
slither 0.11.3 · wake 4.22.2 · halmos 0.3.3 · echidna 2.4.0 · medusa 1.5.1
forge 1.10.0 · solc 0.8.26
```

Real runs, not probes:

- **Slither** on `harnesses/dvdf` (Foundry project, 4 contracts, 100 detectors):
  `COMPLETED`, **23 findings → 19 clusters**, exit 255 (findings reported),
  `report.{md,json,sarif}` written.
- **Echidna** on a two-function property harness: `COMPLETED`, **1 finding**, and the
  counterexample it reported by hand was `inc(10)` — the exact violating call.
- **Halmos** builds the target and starts the symbolic engine, then fails on an
  unsupported cheatcode (`deployCode(string)`) that forge-std v1.17 emits from
  `setUp()`. Recorded as a failed run, **not** as a clean scan. Use a harness
  without that cheatcode, or an older forge-std, when symbolic execution matters.

## The defect this exercise found

The first Slither run through `blackheart engines run` reported
`FAILED — exit 1 (no parseable artifact)` while the same command run by hand
produced 23 findings. Root cause: the run workspace defaulted to the **relative**
path `research/private/engines`, the engine is executed with `cwd` set to the
*target*, so `--json` resolved relative to the target while the adapter looked for
the report relative to the process. A scan that found 23 issues was recorded as a
failed scan.

Fixed in `EngineAdapter.__init__`: the workspace is resolved to an absolute path, so
every artifact path is absolute for every adapter, including ones written later.
Acceptance bar: `tests/test_engine_workspace.py`.

This is the failure mode the doctrine warns about — an engine's *output* is not the
same as its *verdict*, and a lost artifact must never read as "nothing found".

## Reading the output honestly

- A static hit is a **lead**. It becomes a finding only after the differential or
  stateful engines reproduce a value-moving sequence, and the value engine prices it.
- A fuzzer that finds nothing reports `NO_FINDINGS` — "not found within budget".
- A compile failure or a missing artifact is `INCOMPLETE`/`FAILED`, never
  `NO_FINDINGS`. `_classify_exit` enforces this, and a non-zero exit is only read as
  success when the tool's own artifact proves findings.
