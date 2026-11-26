# The close-the-loop pipeline

`blackheart pipeline` is the one operation that turns a **verified deployment**
into a **priced, independently re-run finding** — or says exactly which step
stopped it.

It introduces no engine. It composes modules that already exist and carries each
module's own verdict:

| Stage | Module | What it decides |
|---|---|---|
| `attest` | `blackheart.verified_source` | Is there verified source for this address? |
| `model` | `blackheart.ingest.verified` | Does the source scan and synthesise into an executable model? |
| `certify` | `blackheart.discovery.certify` | Is there a reproducible violating sequence within the bound? |
| `price` | `blackheart.value` | What did the attacker gain, and who lost? |
| `verify` | `blackheart.statespace.verify` | Does it reproduce in a fresh model, and does a guarded control hold? |
| `evidence` | `blackheart.evidence` | Store the reproduction, certificate, price and verdict as immutable evidence. |
| `finding` | `blackheart.findings` | Write the A–J record, with the honest verdict. |

## Usage

```bash
blackheart pipeline \
  --chain-id 1 \
  --address 0x... \
  --control-address 0x... \
  --repository sourcify:1:0x... \
  --compatibility record.json \
  --in-scope --authorized \
  --findings research/private/findings \
  --evidence research/private/evidence \
  --reports research/private/reports \
  --report
```

Without `--control-address` the result can reach `REPRODUCED` but **not**
`VERIFIED`, and the finding is `STRONGLY_SUPPORTED`, never `CONFIRMED`. Without
`--in-scope --authorized` the independent verifier records the scope as
unestablished and the same downgrade applies. That is deliberate: a reproduced
model violation is not an authorized, controlled vulnerability.


## Source-only mode: no deployment, no hand-written hypothesis

```bash
blackheart pipeline --source ./src --contract Vault --max-depth 4 \
  --control-source ./fixed --control-contract VaultGuarded \
  --compiler-ast --poc --no-finding
```

`--compiler-ast` compiles the target's import closure and builds the surface
from solc's AST; if no compiler is available it falls back to the lexer and names
the reason. Pin the binary with `--compiler PATH` (for example a versioned
`solc-0.8.16`), add import roots with `--include-path PATH`, and add remappings
with `--remapping PREFIX=TARGET`. Foundry `foundry.toml`/`remappings.txt` and
ancestor `node_modules` are discovered automatically. `--ast FILE` uses a
supplied source-unit AST, combined-json payload, Foundry build-info file, or
build-info directory without compiling.

`--source` scans a local `.sol` file or tree, synthesises the executable model,
lets the bounded-exhaustive certifier enumerate **every** declared invariant,
prices each witness, selects the strongest one, re-runs it in a fresh model, and
optionally runs a source-level Foundry PoC. There is no attestation and no
deployment claim: `source_bound` is false and the finding says the model is
local.

`--control-source/--control-contract` supplies a guarded twin from source; the
verifier then records control integrity without a second deployment. A local run
still cannot establish on-chain scope or authorization, so the strongest honest
status is `REPRODUCED` unless `--in-scope --authorized` are also supplied. That
is not a missing feature: an unauthorized local reproduction must not be upgraded
to an authorized vulnerability.

### Protocol mode

```bash
blackheart pipeline --source ./src --protocol --max-depth 4 \
  --control-source ./fixed --control-contract protocol-control \
  --in-scope --authorized --poc
```

`--protocol` composes **every** recovered contract into one `ProtocolTarget`.
Caller→callee links are inferred from source (`--no-infer-links` disables it).
A statement-level external call executes in source order in the callee's
sub-state; a reverting callee reverts the caller atomically. A call the
composition cannot resolve is `UNMODELLED` and aborts the path. The model
coverage ledger is aggregated across contracts, so an unresolved external call
is a named gap rather than a silent no-op.

The source trace names the **owning contract** of each step, not the composed
target. `--poc` renders a multi-contract Foundry test that deploys each called
contract and routes each step to its contract; only the four supported invariant
forms render, and an unsupported form is reported, never invented.

### Strict verification

```bash
blackheart pipeline ... --poc --require-independent-engine
```

The verifier records the **producer engine** and the **verifier engine**.
`--require-independent-engine` refuses `INDEPENDENTLY_VERIFIED` when both are
the same, or when provenance was not recorded. A passing Foundry PoC supplies
`foundry`; without it the honest disposition is `REPRODUCED`. The strict flag is
opt-in because a fresh instance of the same engine is still a useful re-run — it
is simply not an independent engine.

## Statuses and exit codes

| Status | Meaning | Exit |
|---|---|---|
| `VERIFIED` | Independently reproduced in a fresh model, a guarded control held, and scope/authorization were established. With `--require-independent-engine`, a distinct engine (a passing Foundry PoC) must also have re-run the witness. A finding is written `CONFIRMED`. | 0 |
| `REPRODUCED` | Reproduced in a fresh model, but no control or no scope. A finding is written `STRONGLY_SUPPORTED`. | 0 |
| `NO_VIOLATION` | No violation within the certifier bound. A bounded negative, not safety. No finding. | 0 |
| `CERTIFIED_LEAD` | A reproducible model witness exists, but the verifier rejected it or could not establish it. No finding. | 1 |
| `ERROR` | The model, certifier, pricer or verifier failed. No finding. | 1 |
| `BLOCKED` | The compatibility gate refused before the model ran. No finding. | 2 |
| `NOT_VERIFIED` | No verified source for the address. No model. | 3 |
| `UNMODELLED` | Verified source exists, but no executable surface could be recovered. | 3 |

## What it proves — and what it does not

A `VERIFIED` result proves:

- the verified source was fetched and bound to the address;
- the source synthesised into an executable model;
- a bounded-exhaustive search found a sequence that breaks a declared invariant;
- the sequence reproduced in a **fresh** model instance;
- when a control was supplied, the control did **not** break the same invariant;
- the value engine priced the consequence (or said it could not);
- the finding carries evidence and an independent verification result.

It does **not** prove:

- that the source is the deployed bytecode — `source_bound` is only true when a
  real compiler rebuilt the source and the runtime matched (use `--rpc`); a
  missing compiler is `RECOMPILE_FAILED`, not a match;
- that the model covers arbitrary Solidity — it covers a fixed statement subset,
  and unmodelled operations do not move state;
- that the violation is a Foundry PoC — the reproduction is model-level unless
  `--poc` rendered and ran one; a PoC is still a reproduction, not a priced finding;
- that the finding is payable or correctly classified — severity is `unrated` and the
  program's official policy decides eligibility and payout;
- that a clean result is safe — `NO_VIOLATION` is bounded by `--max-depth` and the
  modelled surface.

## Optional proof stages

- `--rpc URL [--block N]` fetches the deployed runtime and attempts a real
  solc/forge recompilation; `source_bound` is reported honestly.
- `--poc` renders and runs a source-level Foundry test for a conservation,
  authorization, solvency or bounded-field invariant. With `--protocol`, it
  renders a multi-contract test that deploys each called contract. With
  `--rpc`, the test targets the deployed address on a fork. It accepts
  `--constructor-args` and `--proxy` for single-contract runs. `INCOMPLETE` is
  not a failed reproduction.
- `--require-independent-engine` makes a distinct verifier engine mandatory for
  `INDEPENDENTLY_VERIFIED`; a same-engine re-run is `REPRODUCED`.
- `--mutation-audit` asks whether the invariant set would catch a mutation;
  `--mutation-class` selects class-specific families. A `SURVIVED` mutation is
  weak-oracle evidence, not a bug.

The full additive surface (protocol composition, pinned-commit controls,
concrete-EVM witness replay, market economics, policy planning, corpus and
reviewer use) is `blackheart closure`; see `docs/CLOSURE.md`.

## Identity and the compatibility gate

The pipeline builds the model under the same language-aware gate as every other
engine. The identity is:

- component: `ingest:<ContractName>`, or `ingest:<protocol-name>` in
  `--protocol` mode
- repository: `--repository`, or `sourcify:<chain>:<address>`, or
  `local:<absolute-source-path>` in `--source` mode
- commit: `--commit`, or the verified source fingerprint

The compatibility record must bind to that identity. A mismatched record is
`BLOCKED` before the model is built. The result prints the identity it used, so a
record can be written from it.

## Acceptance

`tests/test_pipeline.py` pins the honest paths:

- vulnerable source + clean control + scope -> `VERIFIED`, `CONFIRMED`, evidence;
- vulnerable source without a control -> `REPRODUCED`, `STRONGLY_SUPPORTED`;
- clean source -> `NO_VIOLATION`, no finding;
- a control that also violates -> `CERTIFIED_LEAD`, no finding;
- unverified address -> `NOT_VERIFIED`, no model;
- mismatched compatibility record -> `BLOCKED`, no model, no finding.

`tests/test_pipeline_source.py`, `tests/test_protocol_pipeline.py` and
`tests/test_verification_independence.py` pin the source and verification paths:

- a protocol witness is traced to its owning contract, never to the composed name;
- a protocol PoC that compiles and runs can be the distinct engine that confirms;
- a fresh model instance is not a distinct engine, and strict mode reports
  `REPRODUCED` with the reason instead of confirming.
