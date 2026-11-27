# Toolchain

BLACKHEART keeps five states strictly distinct, because "a binary exists" is not
"the tool works":

| State | Meaning |
|---|---|
| `installed` | binary present, not yet executed |
| `version_verified` | `--version` ran and returned a version |
| `functional` | the tool actually produced a correct result on a real input |
| `missing` | not present and not installable here |
| `unsupported` | cannot run in this environment |

`python3 -m blackheart tools verify --out registry.json` runs both a version
probe and a functional probe for every tool and writes the registry. A tool is
only reported `functional` when its functional command succeeded **and** its
output contained the expected marker.

## Select the tool for this target, not the last one

`installed` is not `compatible`. Before an engine runs, the mandatory
[language-aware policy](SECURITY_TOOL_COMPATIBILITY.md) requires the target's
stack to be identified and the tool's compatibility to be verified against it:

```bash
python3 -m blackheart compat detect --root <target-source>     # languages, roles, manifests
python3 -m blackheart compat registry --language <language>     # verified native tools
python3 -m blackheart compat check --file compatibility.json --smoke-test passed
```

`compat check` fails closed (exit 2) when the record is incomplete, the language or
tool is not in the verified registry, the evidence is not official documentation,
or the smoke test has not passed. An incompatible tool is reported `BLOCKED`,
never swapped for one that happens to be installed. Per-language native tooling
(Rust/Substrate, Python, Go, C/C++, Move, Cairo, JavaScript/TypeScript) is
registered there; the tables below cover the tools this installer manages.

## Install

```bash
./install.sh --core    # python package + Foundry only
./install.sh --no-rust # everything except the Rust toolchain (~1.5 GB)
./install.sh           # everything below
./install.sh --verify  # verify only, no installs
```

The five Solidity analysis engines (Slither, Wake, Halmos, Echidna, Medusa) are
installed from a **pinned manifest** into isolated venvs, not from `install.sh`'s
system-wide pip list: `slither-analyzer` ships a top-level `tests` package that
would shadow this repository's `tests/`. `install.sh` delegates to
`blackheart engines bootstrap` for them. See
[`SOLIDITY_ENGINES.md`](SOLIDITY_ENGINES.md) for the pinned versions, the
per-engine limits, and the exact bootstrap and doctor commands.

The installer is idempotent and non-fatal per tool. Anything it cannot install is
reported, never silently substituted. It uses only free/open sources and never
requires a paid key.

## Tools

| Tool | Category | Install path |
|---|---|---|
| forge / cast / anvil | EVM build, test, chain | foundryup |
| slither | Solidity static analysis | pip |
| echidna | property-based contract fuzzer | prebuilt release |
| medusa | stateful contract fuzzer | prebuilt release |
| halmos | symbolic EVM execution | pip |
| ~~aderyn~~ | retired upstream — all downloads withdrawn; removed from the registry | — |
| wake | Python Solidity framework (detectors + LSP) | pip (`eth-wake==4.22.2`) |
| mythril | symbolic EVM (isolated venv — pins old `eth-*`) | pip in venv |
| heimdall | EVM bytecode decompiler, CFG + ABI recovery (pinned in `bytecode_tools`, not `engines`) | prebuilt release, SHA-256 verified |
| semgrep | multi-language SAST | pip |
| nmap | network/service discovery | apt |
| nuclei | template-based scanner | go install |
| httpx | HTTP probing | go install |
| subfinder | subdomain discovery | go install |
| katana | web crawler | go install |
| solc / solc-select | Solidity compiler + version manager | pip |

### Rust / Substrate tools

The EVM engines cannot read a Rust target, and a Polkadot-SDK or runtime audit
needs these before a single line can be executed. `install.sh` installs the
toolchain; `cargo-*` are compiled from source and take a few minutes.

| Tool | Category | Install path |
|---|---|---|
| rustc | Rust compiler (stable) | rustup |
| cargo | build / test driver | rustup |
| cargo-fuzz | libFuzzer harnesses (needs **nightly**) | `cargo install` |
| cargo-audit | RustSec advisory scan of `Cargo.lock` | `cargo install` |
| cargo-deny | licence, ban, advisory and source policy for a crate graph | `cargo install` |
| clippy | Rust lints; the first compile gate, not a security tool | rustup component |

### Live-protocol tools (web / API / recon / secrets / infra)

Used against **authorized** live assets only. All free, open-source, no API key.

| Tool | Category | Install path |
|---|---|---|
| ffuf | content discovery / fuzzing | go install |
| gobuster | directory/DNS/vhost brute forcing | go install |
| dalfox | XSS scanning | go install |
| sqlmap | SQL injection | pip |
| wafw00f | WAF fingerprinting | pip |
| arjun | HTTP parameter discovery (API surface) | pip |
| dnsx | DNS resolution / subdomains | go install |
| gau | historical URLs (Wayback/CommonCrawl) | go install |
| waybackurls | Wayback URL fetch | go install |
| naabu | port scanning (needs `libpcap`) | go install + apt |
| gitleaks | secret scanning | prebuilt release |
| trivy | dependency/config/container CVEs | prebuilt release |

## Notes

- **Every Python tool gets its own venv** under `~/.blackheart/venvs/<tool>`
  (semgrep, sqlmap, wafw00f, arjun, mythril). They pin incompatible dependency
  sets, and a system-wide `semgrep` install also shadows this repository's
  `tests` package. The registry resolves the venvs directly, so none of them has
  to be on `PATH`. `BLACKHEART_<TOOL>_VENV` overrides a venv path
  (`BLACKHEART_MYTHRIL_VENV` keeps working for mythril).
- **The resolver does not trust `PATH`.** `~/.foundry/bin`, `~/go/bin`,
  `~/.cargo/bin`, `~/.local/bin` and `/usr/local/go/bin` are searched explicitly,
  because a tool found only by luck of the shell environment disappears in the
  next process — which is exactly how every engine once reported "not found" on
  a host where all of them were installed.
- **Go tools** require a Go toolchain; `install.sh` installs Go if missing and
  reports the tools `missing` rather than faking them when Go is unavailable.
- **nmap** and **libpcap-dev** (for naabu) need `sudo apt`; without passwordless
  apt they are reported `missing`.
- Versions are pinned in `install.sh` and `blackheart/tools/__init__.py` where
  practical.
- Nothing here needs an API key or a paid tier. Nuclei templates and katana
  crawling are used only against authorized targets.
- **Active use of web/API/infra tools is gated by `blackheart/authz/`**: a target
  must be classified AUTHORIZED (with the program brief and testing rules
  recorded) before the campaign loop will run a scanner against it.
