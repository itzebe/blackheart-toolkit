# Language-aware security research: policy and tool compatibility registry

**Status: MANDATORY.** This policy applies to every protocol investigation, code
review, vulnerability reproduction, audit and bug-bounty mission run under this
repository. It overrides generic tool-selection defaults.

> **RESEARCH FIRST. IDENTIFY THE STACK. VERIFY COMPATIBILITY. TEST NATIVELY. REPRODUCE INDEPENDENTLY. REPORT HONESTLY.**

- **Canonical, machine-readable form:** `blackheart/doctrine.py`
  (`LANGUAGE_AWARE_POLICY`, `COMPATIBILITY_GATE_FIELDS`, `EXECUTION_STATUSES`).
  Render it with `python3 -m blackheart doctrine` (or `--json`).
- **Enforced by:** `blackheart/toolchain/` (registry, gate, stack detector) and
  `python3 -m blackheart compat {registry,detect,check,statuses,template}`.
- **Acceptance bar:** `tests/test_tool_compatibility.py`, which fails if this
  document, the policy constants, the registry and the gate disagree.

## Why this policy exists

A security tool aimed at the wrong target does not report an error; it reports
**nothing**. Three failures are common and silent:

1. **Wrong language.** A Solidity analyser pointed at a Rust runtime, or a
   JavaScript SAST ruleset pointed at TypeScript that compiles to a different
   runtime, produces a clean report that says nothing about the target.
2. **Wrong version or framework.** A tool that supports language version N does
   not necessarily parse version N+1 syntax, or a framework's macros; the parse
   failure is then mis-read as "no findings".
3. **Wrong harness.** A fuzz target that wraps a helper instead of the production
   entrypoint tests the helper. A "passing" run is then evidence about the
   harness, not the protocol.

Each failure produces the same dishonest outcome: activity that looks like
coverage. This policy makes the stack explicit, the tool's compatibility an
evidenced claim, and the result one of four exact statuses.

---

## A. Repository reconnaissance comes first

Before selecting or executing security tools:

- Verify repository, branch, commit and target scope.
- Identify every security-relevant implementation language.
- Inspect source files, manifests, compiler configurations, dependencies and
  build systems.
- Identify protocol architecture, framework, runtime and execution environment.
- Identify existing native test and exploit harnesses.
- Distinguish production code from tests, documentation, generated code and
  frontend code.
- Never infer the complete technology stack from README files or file extensions
  alone.

`python3 -m blackheart compat detect --root <path>` implements this scan. It
reports a language backed by a build manifest as **confirmed**, a language seen
only by file extension as **UNCONFIRMED** (a hypothesis about the stack, not a
fact), the role split (production / test / documentation / generated / frontend),
and whether the target is a mixed-language protocol. It never reads file
contents, so a README claiming a language cannot influence the result.

## B. Tool compatibility verification

For every proposed tool, verify against the actual target:

- Supported language.
- Supported language version.
- Supported framework and runtime.
- Required compiler and build configuration.
- Instrumentation and execution requirements.
- Relevant vulnerability classes.
- Known limitations.

Use official tool documentation and verify compatibility against the actual
target. **Never assume a tool is appropriate because it worked on a previous
protocol.** The registry below records, per language, the supported versions, the
frameworks and runtime, the verified tools with their official documentation, the
native approaches, and the known incompatibilities.

## C. Select technology-native testing methods

| Language | Native tooling (examples, not exhaustive) |
|---|---|
| Solidity | Foundry, Slither, Echidna, Medusa |
| Rust/Substrate | Cargo, FRAME tests, Rust integration harnesses, proptest, cargo-fuzz |
| Python | pytest, Hypothesis, Bandit |
| Go | go test, native fuzzing, govulncheck |
| C/C++ | compiler sanitizers, libFuzzer, AFL++ |
| Move | native Move testing, framework-specific Move tooling |
| Cairo | Cairo testing, Starknet-specific tooling |
| JavaScript/TypeScript | native test frameworks, property-based testing, compatible static analysis |

These examples are **not exhaustive**. Research additional languages and
specialised frameworks whenever encountered, and add them to the registry (with
official documentation and a verification date) before relying on them.

## D. Mixed-language protocols

- Treat every security-relevant component independently.
- Map cross-component interactions: serialisation, message validation, signature
  verification, authorization, bridge operations and asset accounting.
- Never claim complete protocol coverage after examining only one language or
  component.

`blackheart compat detect` reports `mixed_language: true` and lists the
security-relevant languages when more than one carries production code. That flag
is a scope warning: each language gets its own gate record.

## E. Mandatory pre-execution compatibility gate

Before executing a security engine, document:

- Target component.
- Identified language and version.
- Framework and runtime.
- Selected tool.
- Official compatibility evidence.
- Reason for tool selection.
- Expected test coverage.
- Known limitations.

Run a compatibility smoke test before full analysis. If compatibility cannot be
established, **BLOCK execution** and research an appropriate alternative.

Record it in `templates/tool-compatibility.json` (blank record:
`blackheart compat template`) and check it:

```bash
python3 -m blackheart compat check --file compatibility.json --smoke-test passed
```

The gate fails closed (exit 2 on BLOCK). It refuses a record that:

- is missing any field above (the field names are read from
  `doctrine.COMPATIBILITY_GATE_FIELDS`, so policy and code cannot drift);
- names a language with no verified toolchain in the registry;
- names a tool the registry does not verify for that language;
- cites evidence that is not official documentation -- accepted values are an
  `http(s)` URL or `registry:<language>/<tool>` for the record's own tool when the
  registry lists it for that language (a language key may itself contain a slash,
  e.g. `registry:Rust/Substrate/Cargo`); a README path or "it worked before" is
  not evidence;
- has not run its smoke test, or ran it and failed.

The gate decides **whether a tool may run**. It does not run the tool, and an
ADMIT is not a result.

### The record is bound to a target, not to a research session

A record that admits *something* is not a record that admits *this*. Two more
fields bind it, and `bind()` (`blackheart/toolchain/enforce.py`) refuses a record
whose identity does not match the execution:

- `target_component` -- the component the record describes. It must name the
  target about to run (equal, case-insensitively, or equal by basename, so a
  record for `Vault.sol` covers `contracts/Vault.sol`). A record for protocol A
  never authorises protocol B. `*` is accepted **only** for a repository-bound
  record, and only for an execution that declares that repository.
- `repository` and `commit` -- when the execution declares them, the record must
  declare them too and they must match (a commit may be given as a full-length
  prefix of 7+ characters). A record verified at one commit does not silently
  cover another.
- `control_component` -- optional, and the only other component the record
  authorises: the guarded twin a differential check compares the target against
  (`hunt --control`). It is a comparison, not a grant: a control cannot be
  promoted into authority for a third component, and a record that declares none
  leaves the differential check failing closed.
- A caller that resolves a registry alias (`vulnerable`) to a model's canonical
  name (`vulnerable-vault`) declares both on its `ExecutionTarget`, so a record
  naming either binds and the nested executions -- which re-authorise the
  canonical name -- stay covered by the same record.

The registry also proves one class of language error without judgement:
`cross_language_mismatch()` rejects a record whose framework or runtime names a
tool that belongs to a *different* registered language -- Solidity + `FRAME`,
Rust + `anvil`, Python + `Next.js` -- because such a record describes two stacks.

## E2. The gate is enforced at the engine boundary

Section E is a rule; a rule that only the command line applies is a rule a
library caller can walk around. Enforcement therefore lives where a target is
actually acted upon, in `blackheart/toolchain/enforce.py`:

| Boundary | What it protects |
|---|---|
| `statespace.run_sequence` | the in-process sequence executor -- every statespace run funnels through it |
| `invariants.run_sequence` | the invariant engine's executor (fuzzing, differential, corpus) |
| `StateSpaceExplorer.explore` | the statespace search entry point |
| `hunt()` | the universal hunt (recall -> search -> certify -> verify -> order -> remember) |
| `Campaign.run_active` | the authorization-gated attack loop |
| `EngineOrchestrator.run` | dispatch to external engines |
| every `EngineAdapter.execute_scan` | the subprocess boundary, wrapped for subclasses that do not exist yet |
| `run_evm_case`, `run_runtime_discovery` | the EVM and live-harness runtimes |

Each entry point takes `compatibility=` (a record object, a dict, a JSON path or
JSON text) and validates it against the target *before* anything runs. On the
command line that is `--compatibility RECORD` for `blackheart hunt`,
`blackheart campaign` and `blackheart engines run`. A blocked run exits 2 and
prints the failed field and the remedy.

**Nested runs inherit, they do not widen.** The validated record is installed for
the duration of the run (a `ContextVar`, so concurrent runs cannot share it), and
every internal primitive calls `require_execution_authorized()`, which re-checks
the target name. An engine cannot reach a *different* target by calling an
already-authorised engine, and an engine that forgot to ask its caller for a
record still cannot execute: the chokepoint has no default and no bypass flag.

**The repository's own fixtures run under a self-test record.** The vulnerable /
guarded pairs, the historical corpus, the benchmarks and the runtime harness apps
are engine executions too, so they declare their stack like any other target:
`self_test_record()` (`target_component="*"`, `repository="blackheart"`). It is a
record, not an exemption -- it passes `bind()` and can only authorise targets that
declare this repository. Commands that execute only those fixtures are marked
`@_fixture_command` in `blackheart/cli.py`; the test suite installs the same
record in `tests/conftest.py`, and the enforcement tests suspend it to prove
denial.

**What is not gated yet, and why it is named.** Four surfaces still run an
external binary on a real target without passing the compatibility gate, because
each one needs a record per *target* and its tests require `forge`, which is
absent here and in CI (so the change could not be verified):

| Surface | What it runs |
|---|---|
| `blackheart fork run` / `fork verify` | `FoundryRunner` against a vendored fork |
| `blackheart dvdf` | `forge test` invariant campaigns over a DVDF project |
| `blackheart evmbench` | the EVM benchmark harness |
| `blackheart investigate` | an operator-supplied command through `SubprocessRunner` |

`blackheart tools` runs web adapters (ffuf, nuclei, sqlmap, ...) behind the
target-authorization gate, not the language gate: they are HTTP tools, not a
language toolchain, and the registry does not model them. A named gap is
better than a silent one; closing these is tracked work, not a claim.

**A failed gate is not a research result.** BLOCKED means the tool did not run.
It never means "no findings", and it never closes an investigation: section G
applies -- select the correct language-native method and continue from the last
verified state.

## F. Honest execution reporting

Use these exact statuses, and only these:

| Status | Meaning |
|---|---|
| `PASS` | Analysis completed successfully. |
| `BLOCKED` | Tool incompatible or required prerequisites unavailable. |
| `INCOMPLETE` | Analysis started but did not complete or coverage is insufficient. |
| `NO_FINDINGS` | Analysis completed successfully without identifying an issue. |

- A parser failure is **not** a vulnerability reproduction failure.
- A successful build is **not** proof of security.
- A clean scanner result is **not** proof that the protocol is secure.
- Never fabricate tool output, exploit results, test coverage or vulnerability
  confirmation.

`blackheart compat statuses` prints the set. An unknown status is an error
(`toolchain.status_meaning` raises), because a fifth, vaguer status is how an
honest `INCOMPLETE` becomes a false `PASS`.

## G. Research continuity

- Preserve the original vulnerability hypothesis and approved target scope.
- Never abandon a valid investigation because an inappropriate tool failed.
- Select the correct language-native testing method and continue from the last
  verified research state.

A BLOCKED tool is a tool problem. Changing the hypothesis, the scope, or the
claimed result to fit the tool that happened to be installed is the failure this
rule forbids.

## H. Final acceptance criteria

No investigation can be marked complete until:

- Technology stack is documented.
- Tool compatibility is verified.
- Relevant security-critical components have been examined.
- Appropriate native tests have been performed.
- Vulnerability hypotheses have been independently assessed.
- Coverage gaps and untested components are disclosed.

`blackheart.toolchain.CompletionReport` encodes these six criteria as checkable
flags; `missing()` names every unmet one, so "complete" is a checked claim.

---

## The registry

Every entry below was checked on the date shown in its section: each official
documentation URL returned HTTP 200 on that date (`curl -s -o /dev/null -L -w
'%{http_code}'`); the Solidity to JavaScript/TypeScript entries were checked on
2026-11-20 and the Vyper entry on 2026-11-21.
The registry is a *starting point*: a language, framework or tool that is absent
here is BLOCKED until it is researched, documented and added. The date records
when the documentation was checked, not a runtime probe of an installed tool --
that is `python3 -m blackheart tools verify`.

### Solidity

- **Versions:** 0.4.x-0.8.x via solc-select; Foundry uses the solc pinned by the project
- **Frameworks:** Foundry (forge/cast/anvil), Hardhat, Truffle
- **Runtime:** EVM (local anvil or an authorized fork)
- **Verified:** 2026-11-20

| Native tool | Official documentation | Vulnerability classes |
|---|---|---|
| Foundry | https://book.getfoundry.sh/ | business logic, access control, invariant violation, reentrancy, arithmetic, oracle manipulation |
| Slither | https://github.com/crytic/slither | static analysis, reentrancy, access control, dangerous constructs |
| Echidna | https://github.com/crytic/echidna | property-based fuzzing, invariant violation, stateful sequences |
| Medusa | https://github.com/crytic/medusa | stateful fuzzing, invariant violation, coverage |
| Halmos | https://github.com/a16z/halmos | symbolic execution, assertion violation, bounded input space |

Native approaches:

- `forge test` / `forge script` (local only, never `--broadcast`)
- invariant and stateful fuzz campaigns on a dedicated harness
- symbolic execution of a single assertion
- static analysis before dynamic testing

Known incompatibilities:

- Slither needs a solc the toolchain can install and a compilable build; it
  cannot analyse a project whose compiler version is unavailable
- Halmos requires a Foundry project and a symbolic-friendly harness
- Echidna and Medusa need their own harness contract; pointing them at a
  production entrypoint is not a test
- a fork test is only as faithful as the block it pins; record the block

### Vyper

- **Versions:** 0.3.x-0.4.x via the compiler the project pins (Foundry builds `.vy` with it)
- **Frameworks:** Foundry (Vyper sources), Ape, Titanoboa, Brownie
- **Runtime:** EVM (local anvil or Titanoboa's in-process EVM; never a broadcast)
- **Verified:** 2026-11-21

| Native tool | Official documentation | Vulnerability classes |
|---|---|---|
| vyper | https://docs.vyperlang.org/ | compiler, arithmetic, access control, reentrancy, storage layout |
| Foundry | https://book.getfoundry.sh/ | build, local test harness, invariant violation, reentrancy, arithmetic |
| Slither | https://github.com/crytic/slither | static analysis, reentrancy, access control, dangerous constructs |
| Titanoboa | https://github.com/vyperlang/titanoboa | in-process EVM harness, unit tests, trace debugging, stateful sequences |
| Hypothesis | https://hypothesis.readthedocs.io/ | property-based fuzzing, invariant violation, stateful sequences |

Native approaches:

- `boa` + `pytest` harness against the local EVM (never a broadcast)
- Hypothesis property campaigns driven through Titanoboa
- `forge build` with the project's pinned vyper, then `forge test` locally
- static analysis before dynamic testing

Known incompatibilities:

- Echidna, Medusa and Halmos do not analyse Vyper; use Titanoboa and Hypothesis
  instead of substituting an EVM tool that ignores the source
- Foundry compiles Vyper only when the pinned compiler is installed and the build
  is configured for it; record the vyper version
- Vyper `flag` members are 1-based (the first member is 1), unlike a Solidity
  enum; an empty flag is 0 and is a distinct value
- a fork test is only as faithful as the block it pins; record the block

### Rust/Substrate

- **Versions:** stable Rust for host tests; the runtime's pinned nightly for WASM builds
- **Frameworks:** Substrate FRAME, ink!, Solana programs (cargo-build-sbf)
- **Runtime:** native host tests + wasm32-unknown-unknown runtime
- **Verified:** 2026-11-20

| Native tool | Official documentation | Vulnerability classes |
|---|---|---|
| Cargo | https://doc.rust-lang.org/cargo/commands/cargo-test.html | unit tests, integration tests, doc tests |
| proptest | https://docs.rs/proptest/latest/proptest/ | property-based testing, input-space exploration |
| cargo-fuzz | https://rust-fuzz.github.io/book/cargo-fuzz.html | coverage-guided fuzzing, parser and codec bugs, panic reachability |

Native approaches:

- `cargo test` on the pallet/runtime crate under test
- FRAME mock runtime integration tests for extrinsics and origins
- proptest strategies over the SCALE codec and arithmetic
- cargo-fuzz targets for decoding and dispatch

Known incompatibilities:

- cargo-fuzz needs nightly and a libFuzzer-compatible toolchain
- FRAME unit tests do not exercise the compiled WASM runtime; build and
  benchmark the runtime separately
- a property test that restates the implementation's own arithmetic proves
  nothing (use an independent oracle)

### Python

- **Versions:** 3.11+ (this repository's floor)
- **Frameworks:** pytest, Django, Flask, FastAPI
- **Runtime:** CPython
- **Verified:** 2026-11-20

| Native tool | Official documentation | Vulnerability classes |
|---|---|---|
| pytest | https://docs.pytest.org/en/stable/ | unit tests, integration tests, regression tests |
| Hypothesis | https://hypothesis.readthedocs.io/en/latest/ | property-based testing, boundary conditions, stateful testing |
| Bandit | https://bandit.readthedocs.io/en/latest/ | static analysis, injection, credential handling, unsafe deserialization |

Native approaches:

- pytest for deterministic reproductions
- Hypothesis state machines for ordered, stateful protocols
- Bandit as a first pass, never as proof of absence

Known incompatibilities:

- Bandit is pattern-based: it cannot see a flaw that spans functions or depends
  on runtime configuration
- a passing test suite says nothing about a code path no test reaches

### Go

- **Versions:** 1.18+ for native fuzzing; the target module's go directive otherwise
- **Frameworks:** net/http, gRPC, Cosmos SDK, go-ethereum
- **Runtime:** Go runtime
- **Verified:** 2026-11-20

| Native tool | Official documentation | Vulnerability classes |
|---|---|---|
| go test | https://pkg.go.dev/testing | unit tests, integration tests, race detection |
| native fuzzing | https://go.dev/doc/security/fuzz/ | coverage-guided fuzzing, parser bugs, panics |
| govulncheck | https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck | dependency vulnerabilities, reachable-vulnerability analysis |

Native approaches:

- `go test -race` for concurrency findings
- `go test -fuzz` with a seed corpus for decoders and validators
- govulncheck to separate a present module from a reachable call

Known incompatibilities:

- native fuzzing requires Go 1.18 or newer
- govulncheck reports reachability from its own call graph; a "not reachable"
  answer is bounded by that analysis, not proof

### C/C++

- **Versions:** any clang/gcc with sanitizer support; clang for libFuzzer
- **Frameworks:** CMake, Autotools, Make
- **Runtime:** native process
- **Verified:** 2026-11-20

| Native tool | Official documentation | Vulnerability classes |
|---|---|---|
| compiler sanitizers | https://clang.llvm.org/docs/AddressSanitizer.html | memory safety, undefined behaviour, use-after-free, buffer overflow |
| libFuzzer | https://llvm.org/docs/LibFuzzer.html | coverage-guided fuzzing, parser bugs, memory safety |
| AFL++ | https://github.com/AFLplusplus/AFLplusplus | coverage-guided fuzzing, binary-only targets, long-running campaigns |

Native approaches:

- an instrumented build (`-fsanitize=address,undefined`) of the component
- libFuzzer or AFL++ targets around the parser/decoder entrypoint
- differential testing against a reference implementation

Known incompatibilities:

- sanitizers require rebuilding the target with instrumentation; an
  uninstrumented binary proves nothing
- AddressSanitizer and MemorySanitizer are mutually exclusive
- fuzzing an entrypoint that is not the production one tests the harness

### Move

- **Versions:** Move 2024 (Aptos) and Sui Move -- the two frameworks differ
- **Frameworks:** Aptos Framework, Sui Framework
- **Runtime:** Move VM
- **Verified:** 2026-11-20

| Native tool | Official documentation | Vulnerability classes |
|---|---|---|
| native Move testing | https://aptos.dev/build/smart-contracts/ | unit tests, access control, resource safety |
| Sui Move testing | https://docs.sui.io/ | unit tests, object model, access control |
| Move Prover | https://github.com/move-language/move/tree/main/language/move-prover | formal verification, abort conditions, invariants |

Native approaches:

- `aptos move test` / `sui move test` on the module under test
- Move Prover specifications for value-conservation properties
- framework-specific test harnesses; Aptos and Sui code are not portable

Known incompatibilities:

- Aptos and Sui Move are separate dialects with separate toolchains; a test
  written for one does not compile for the other
- Move Prover covers specified properties only; an unspecified invariant is
  unproven, not safe

### Cairo

- **Versions:** Cairo 1/2 with the Scarb version the project pins
- **Frameworks:** Scarb, Starknet Foundry (snforge/sncast), Starknet contracts
- **Runtime:** Cairo VM / Starknet
- **Verified:** 2026-11-20

| Native tool | Official documentation | Vulnerability classes |
|---|---|---|
| Cairo testing | https://docs.swmansion.com/scarb/ | unit tests, integration tests, compilation |
| Starknet Foundry | https://foundry-rs.github.io/starknet-foundry/ | contract tests, cheatcodes, fork testing |

Native approaches:

- `scarb build`/`scarb test` for the package under test
- snforge tests with cheatcodes for caller and block context
- fork tests against an authorized network snapshot

Known incompatibilities:

- Scarb and snforge versions are coupled to the Cairo compiler version; a
  mismatch fails to compile rather than silently mis-analysing
- Cairo 0 and Cairo 1 syntax are incompatible

### JavaScript/TypeScript

- **Versions:** Node 18+ (native test runner); the project's pinned Node otherwise
- **Frameworks:** Node.js, React, Next.js, Express, Hardhat (JS)
- **Runtime:** Node.js / browser
- **Verified:** 2026-11-20

| Native tool | Official documentation | Vulnerability classes |
|---|---|---|
| native test frameworks | https://nodejs.org/api/test.html | unit tests, integration tests, API behaviour |
| Vitest | https://vitest.dev/ | unit tests, mocking, coverage |
| fast-check | https://fast-check.dev/ | property-based testing, boundary conditions, stateful model testing |
| Semgrep | https://semgrep.dev/docs/ | static analysis, injection, insecure defaults |

Native approaches:

- the project's own runner (node:test / vitest / jest) for reproductions
- fast-check model-based testing for state machines
- Semgrep with the TypeScript/JavaScript rulesets as a first pass

Known incompatibilities:

- a TypeScript analyser sees the types, not the runtime value a caller can
  actually send
- Node and browser runtimes differ; test the one the product ships

---

## How future missions inherit this policy

The policy is not pasted into each mission; it is carried by every layer the
mission already reads.

| Layer | What it carries | Reaches |
|---|---|---|
| `blackheart/doctrine.py` `LANGUAGE_AWARE_POLICY` | the full policy, A-H | `blackheart doctrine`, `--json`, `--prompt` |
| `doctrine_prompt_block()` | the gate, in one sentence | every model role prompt (`providers/roles.py`) |
| `blackheart/mindset.py` `TOOLING_DOCTRINE` | the compatibility bar | `prompt_block()`, `agent_lens_block()`, `skill_document()` |
| `agents/*.md` (`## The language bar`) | the executor's rule | all 16 specialist agents |
| `skills/blackheart/SKILL.md` | the mission procedure | the master security-research skill |
| `skills/operational-doctrine/SKILL.md` | phase 4's gate | the lifecycle skill |
| `skills/exploit-verification/SKILL.md` | reproduction must name the language and native harness | the verification skill |
| `docs/TOOLCHAIN.md` | tool selection and the five install states | the tooling registry |
| `docs/BOUNTY.md` | the bounty workflow's gate | bounty missions |
| `templates/tool-compatibility.json` | the record a mission fills in | every mission artefact |
| `blackheart/toolchain/` + `blackheart compat check` | the fail-closed gate | the command line |
| `blackheart/toolchain/enforce.py` | the gate at the engine boundary | every engine, Python API and CLI |
| `docs/HUNT.md`, `docs/STATESPACE.md`, `docs/ENGINES.md` | `--compatibility` at the entry points | the hunt, the explorer, engine dispatch |
| `tests/test_tool_compatibility.py` | the acceptance bar for the record | CI |
| `tests/test_engine_enforcement.py` | the acceptance bar for enforcement | CI |

Changing the policy means changing `blackheart/doctrine.py` and this document
together; the test fails otherwise.

## Limits (honest)

- **The registry is a starting point, not a ceiling.** Eight languages are
  registered. A target in another language is BLOCKED until its native tooling is
  researched, documented with official URLs, dated, and added.
- **A verification date is not a runtime probe.** It records that the official
  documentation page was reachable and was the basis for the entry. Whether a
  tool is *installed and functional on this host* is a different question, answered
  by `blackheart tools verify`.
- **The gate checks a record, not the truth of it.** It can prove the fields are
  present, the language and tool are registered, the evidence is a documentation
  reference (an `http(s)` URL or a `registry:<language>/<tool>` entry for a listed
  tool), and the smoke test passed. It cannot prove that an arbitrary URL is the
  vendor's own documentation, so the `registry:` form is the stronger citation;
  and it cannot prove the researcher wrote honestly -- fabricating a record is
  fabrication, and forbidden.
- **A passing gate is not coverage.** It permits a tool to run. Only the tool's
  own result, reported as PASS / BLOCKED / INCOMPLETE / NO_FINDINGS, and the
  independent verification of a finding, say anything about the target.
- **The detector sees structure, not semantics.** It classifies by path segment
  and manifest, so an unusual repository layout may need a manual correction --
  which is why the record is written by a researcher, not generated by the scan.
- **Enforcement covers the execution primitives, not every helper.** The
  chokepoints are the two sequence executors, the four engine entry points, the
  orchestrator, the adapter `execute_scan` and the two runtimes. A pure function
  that *builds* a model or generates hypotheses touches no target state and is not
  gated; it also cannot produce a result. A future engine must call one of these
  primitives -- if it grows its own executor, add it to the chokepoint list and to
  `tests/test_engine_enforcement.py`.
- **The self-test record is broad by construction.** It authorises any target
  that declares `repository="blackheart"`, because that is what the repository's
  fixtures are. It cannot authorise a target that declares another repository, or
  none. It is the one place where the record does not name a single component,
  and it is confined to repository fixtures.
- **`compatibility=` is a parameter, not a proof of honesty.** A caller can pass a
  fabricated record. The gate proves the record is complete, official, smoke
  tested and bound to the target; it cannot prove the researcher told the truth.
  Fabricating a record is fabrication (section F).
