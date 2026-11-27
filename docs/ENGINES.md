# Multi-engine integration

BLACKHEART is not a wrapper around other scanners. This layer lets BLACKHEART
*use* three external offensive-AI engines as **subordinate, untrusted evidence
sources**, then coordinate, deduplicate, and independently judge what they
produce. An engine can contribute a candidate; it can never confirm a finding,
widen scope, or change a disposition.

```
authorization gate  ->  adapters  ->  normalize  ->  orchestrate  ->  report
   (fails closed)       (argv /        (unified      (dedup, corroborate,  (md /
                        isolated)      schema)        contradict, chain)    json / sarif)
```

## Engines and their boundaries

Eight engines share one registry. Three are external agentic
offensive engines used as subordinate evidence sources; five are local Solidity
analysis engines that run on the target's own source.

### Agentic engines

| Engine | Upstream | License | Integration boundary |
|---|---|---|---|
| **Strix** | usestrix/strix | Apache-2.0 | In-process / subprocess CLI (`strix --target ... --non-interactive`) |
| **Shannon** | KeygraphHQ/shannon | **AGPL-3.0** | **Isolated external process only** (`npx @keygraph/shannon start -u ... -r ...`); BLACKHEART never links its code |
| **PentAGI** | vxcontrol/pentagi | MIT (core) + EULA | **Isolated upstream service** over REST/GraphQL; BLACKHEART talks to it, never hosts or modifies it |

### Solidity engines

These analyse a Solidity project locally. They are installed by
`blackheart engines bootstrap` at the versions pinned in
[`blackheart/engines/toolchain.json`](../blackheart/engines/toolchain.json) and
verified by `blackheart engines doctor`. See [`TOOLCHAIN.md`](TOOLCHAIN.md).

| Engine | Upstream | License | Method | Needs |
|---|---|---|---|---|
| **Slither** | crytic/slither | AGPL-3.0 | static analysis | solc (via solc-select) |
| **Wake** | Ackee-Blockchain/wake | ISC | static analysis + property fuzzing | — (own front end) |
| **Halmos** | a16z/halmos | AGPL-3.0 | symbolic execution | Foundry, a solver |
| **Echidna** | crytic/echidna | AGPL-3.0 | property fuzzing | crytic-compile, solc |
| **Medusa** | crytic/medusa | AGPL-3.0 | sequence fuzzing | crytic-compile, solc |

### Bytecode tools

These consume **EVM bytecode**, not a Solidity source tree, so they are pinned in
their own manifest section (`bytecode_tools`) and are deliberately *not* members
of `SOLIDITY_ENGINES`: handing one a project directory would be a configuration
error, not a scan. `blackheart engines bootstrap` and `engines doctor` treat them
exactly like the source engines.

| Tool | Upstream | License | Method | Input |
|---|---|---|---|---|
| **Heimdall** | Jon-Becker/heimdall-rs | MIT | decompilation, CFG and ABI recovery | runtime bytecode, hex blob, or deployed address |

Heimdall is the answer to a gap the capability statement names explicitly: it
cannot see a *closed* component. Given the deployed runtime — which
`blackheart/watch` already fetches from Sourcify, and which `eth_getCode` returns
for anything else — Heimdall recovers the ABI, the function selectors and a
decompiled CFG, so an unverified contract is no longer a blank wall. It is a
**lead generator**: decompiled output is a reconstruction, never the source, and
nothing it reports may be recorded as a finding without a reproduction.

Its installation is verified by digest: the manifest pins the asset's SHA-256 and
the installer refuses a mismatch, so a silently re-uploaded release cannot become
the binary that runs. The pin is a reproducibility record computed from the
official asset, not an upstream-signed attestation, and the manifest says so.

All five are AGPL/ISC tools that BLACKHEART **invokes as separate processes**
over a file/argv boundary — it never imports or vendors their code, so
BLACKHEART's own license is unaffected, exactly as with Shannon.

The license boundary is not cosmetic. Shannon is AGPL-3.0: BLACKHEART invokes it
as a **separate program over a process boundary** and communicates only through
files/stdout — it does not import, vendor, link, or embed Shannon source, so
BLACKHEART's own license is unaffected. PentAGI's core is MIT but the product
ships a EULA/NOTICE: BLACKHEART treats it as a **network service** the operator
runs separately. See [`THIRD_PARTY_NOTICES.md`](../THIRD_PARTY_NOTICES.md).

## The adapter contract

Every adapter (`blackheart/engines/contract.py`) implements the same surface:

- `detect_installation()`, `inspect_version()`, `verify_health()`, `validate_configuration()`
- `inspect_capabilities()` — what the engine can actually do, each with an availability flag
- `prepare_execution(target, **opts)` — builds the argv/request **without running it**
- `execute_scan(target, **opts)` — runs it, bounded by timeout, output cap, and cancellation
- `normalize_findings(execution)` — maps raw engine records into `NormalizedFinding`

The contract deliberately exposes **no** method that can authorize a target,
confirm a finding, submit a report, disclose anything, or move funds. A test
asserts those method names are absent.

## States

`EngineState`: `MISSING`, `UNSUPPORTED`, `CONFIGURATION_ERROR`, `INSTALLED`,
`READY`, `RUNNING`, `COMPLETED`, `PARTIAL`, `FAILED`, `CANCELLED`,
`VERIFICATION_PENDING`. `verify_health()` never claims `INSTALLED` for a binary
that is not present, and never claims `READY` without the required configuration
(for example, Shannon without Docker is `UNSUPPORTED`; PentAGI without a
base URL/token is `MISSING`/`CONFIGURATION_ERROR`).

## The unified finding schema

`NormalizedFinding` (`blackheart/engines/schema.py`) is the single shape every
engine maps into: title, description, severity (canonical five levels), CWE,
CVSS, category, component, source location, impact, exploit steps, confidence,
reproduction status, and — crucially — **provenance**: source engine, engine
version, the raw artifact path, and the artifact's SHA-256.

Identity is an **engine-independent fingerprint** over the target, component,
category, CWE, and a normalised description. The same root cause described
differently by two engines collapses to one fingerprint; line numbers and engine
names do not change identity.

## Coordination, not concatenation

`EngineOrchestrator` (`blackheart/engines/orchestrator.py`) turns many engine
records into one judgement:

1. **Dedup** — records sharing a fingerprint form one `FindingCluster`. A
   second, coarser index also merges on the *structural* identity — target,
   component, source location (line kept) and defect class — because two engines
   rarely word the same defect identically and the exact fingerprint includes the
   description text. Location alone is not enough (one line can carry a reentrancy
   and an unchecked transfer, which are different bugs) and class alone is not
   enough either (one class recurs across many lines). A merged duplicate has its
   `duplicate_of` set, so it is visible rather than silently absorbed.
2. **Corroboration** — a cluster reported by more than one engine is marked
   corroborated. This *raises confidence*; it does **not** confirm. Two AI
   engines agreeing is not proof.
3. **Contradiction** — when one engine reports a defect and another explicitly
   fails to reproduce it, the disagreement is preserved and the cluster is sent to
   independent verification. It is never resolved by majority vote.
4. **Attack-chain correlation** — clusters are linked only when an enabling
   category edge exists (e.g. authentication -> authorization) **and** they share
   a component. Proximity alone never creates a chain.
5. **Prior-art check** — a fingerprint already in the engagement ledger is marked
   `DUPLICATE_OR_KNOWN`.

Only BLACKHEART's own verification gate (`blackheart.verify`) plus a named
reviewer can move a cluster to `CONFIRMED` — exactly as for a native finding.

## Security properties (enforced, and tested)

- **Authorization is the single choke point.** A run is refused unless the target
  passed BLACKHEART's authorization gate or the operator passed the explicit
  `--allow-local` opt-in for a local/disposable target. The gate is checked
  *before* any adapter is invoked.
- **Compatibility is a second choke point.** Dispatch also requires a validated
  language-aware compatibility record bound to the target
  (`--compatibility`, or an enclosing authorised run). `EngineOrchestrator.run`
  checks it once for the whole dispatch, and `EngineAdapter.__init_subclass__`
  wraps every adapter's `execute_scan` -- including adapters written later -- so
  no engine process starts without it. See `docs/SECURITY_TOOL_COMPATIBILITY.md`.
- **Engine output is untrusted.** A self-declared `CONFIRMED` disposition is
  reset to the honest "not yet proven" value at ingestion (its claim is preserved
  under `raw` for provenance). An engine cannot confirm its own finding.
- **No shell injection.** Engines are executed with an argv list and
  `shell=False`; a metacharacter in a target string is passed as a literal.
- **Bounded execution.** A hard timeout, an output cap, and process-group
  termination (SIGTERM then SIGKILL) prevent a runaway engine from hanging or
  exhausting the host. Output is drained to avoid pipe deadlock.
- **Secret redaction.** Engine stdout is redacted before it is persisted; API
  keys and bearer tokens do not reach the run state or the report.
- **No fabricated data.** Engine state, version, and findings are always read
  from a real probe or a real artifact. A missing engine is reported as missing,
  and its capabilities are explicitly listed as *not covered*.

## CLI

```bash
blackheart engines list [--json]                     # engines, state, version, license
blackheart engines capabilities --engine strix [--json]
blackheart engines verify [--engine strix]           # health + configuration (exit 1 if requested engine missing)
blackheart engines run --target URL --engines strix,shannon \
        --authz authz.json --asset app-1 [--report DIR]
blackheart engines run --target ./local --allow-local --engines strix \
        --compatibility compatibility.json
blackheart engines status                            # run state + per-engine health
blackheart engines cancel                            # cooperative cancellation of a running run
blackheart engines findings                          # normalized clusters from the last run
blackheart engines document --findings-dir research/private/findings
blackheart engines report [--stdout] [--format md,json,sarif]

# Toolchain (Solidity engines)
blackheart engines bootstrap [--engine NAME] [--python PATH]   # install pinned versions
blackheart engines doctor [--engine NAME] [--json]             # verify installs vs the manifest
```

`engines run` persists the orchestration result to
`<workdir>/engines-run.json`, so `status`, `findings`, `document`, and `report`
can re-read it across processes.

## Reporting

`blackheart/engines/report.py` writes **Markdown**, **JSON**, and **SARIF 2.1.0**.
Confirmed clusters, unconfirmed candidates, duplicates, missing engines, and
execution limitations are separate sections. A candidate is never labelled a
confirmed vulnerability. SARIF results carry `security-severity` and a
`blackheart-disposition` property so a consumer never mistakes a lead for a proven
defect.

## What is verified, and what is not

- **Verified in this repository's test suite** (`tests/test_engines.py`,
  `tests/test_engines_cli.py`, `tests/test_engine_controls.py`): the contract,
  the schema, every adapter's health/argv/normalization logic, orchestration
  (dedup/corroboration/contradiction/chains/prior-art), the authorization gate
  through every entry point, secret redaction, and the report writers — with
  positive and negative controls against BLACKHEART's real vulnerable/guarded
  targets.
- **Verified live, on demand** (`tests/test_engines_live.py`, gated by
  `BLACKHEART_LIVE_ENGINES=1`): every installed Solidity engine is executed
  against a real target and its output asserted, so "installed" and "operational"
  are separate claims with separate evidence. Run it after any toolchain change:

  ```
  blackheart engines bootstrap && BLACKHEART_LIVE_ENGINES=1 pytest tests/test_engines_live.py
  ```

  `tests/test_adversarial_harness.py` does the same for the multi-engine harness
  and gates each engine on the **engine resolver**, not on `PATH` — a
  `shutil.which` gate silently skipped every engine test on a host where all of
  them were installed.
- **Not verified here**: a live run of the *agentic* engines (Shannon, Strix,
  PentAGI). They need a model-provider key or a separately running service, and
  an authorized target, so they are an operational step rather than a test-suite
  step. The adapters are written against the engines' documented CLIs and output
  formats. This limitation is stated plainly rather than hidden.
