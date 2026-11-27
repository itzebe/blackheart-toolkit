# Changelog

All notable changes to BLACKHEART are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.1.0] - 2026-11-22

### Added
- Composed ERC4626 model: view-function returns are folded into a conditional
  expression, internal and external calls run in source order, and an
  ERC20-like callee is modelled by shape. The protocol target derives the
  `erc4626:nonzero-shares` invariant and reproduces first-depositor share
  inflation on the vulnerable reference vault while the guarded twin survives.
- Generated Foundry invariant tests (`closure foundry --generate-invariant`):
  a complete handler fuzzes mint/approve/deposit/donate/withdraw and records the
  last successful deposit, so a guarded vault is not failed by a high-price
  conversion. The vulnerable vault fails; `SafeVault` is `NO_FINDINGS`.
- Attack-relevant boundary ordering in the certifier: actor/contract addresses
  and the maximum numeric value are crossed before the flat product, so a
  multi-parameter attack is reached inside the state budget.

### Changed
- `ingest --synthesize` now reports the new model semantics and keeps the honest
  unmodelled set (arrays of structs, mapping-to-struct writes, virtual dispatch,
  inline assembly, unbounded loops, reentrancy).
- Capability statement and ingest/improvement docs updated to match the model.


### Added
- Broader source-model semantics: compound assignment (`*=`, `/=`, `%=`), unary
  increment/decrement, `delete`, `if/else` branches and conditional
  `require`/`revert`, with atomic rollback on revert.
- Inferred cross-contract call edges (`ingest/callgraph.py`, `closure protocol --infer`),
  resolved only when the receiver is unambiguous.
- Deployment planning (`ingest/deploy.py`, `closure deploy-plan`): constructor
  signatures, helper deployments and a minimal proxy; a missing argument blocks the
  plan instead of defaulting to zero.
- Semantic equivalence checks (`ingest/equivalence.py`, `closure equivalence`):
  ABI selectors are compared with the deployed dispatcher.
- Live Uniswap-V2 reserve fetching and cross-pair quoting (`value/live.py`,
  `closure market --model live`).
- File-backed distributed work leases with monotonic epochs, stale recovery and
  dead-lettering (`distributed.py`, `closure corpus --queue-*`).
- Optional local Ollama reviewer provider (`BLACKHEART_PROVIDERS=ollama`).
- Source PoC assertions for authorization, solvency and bounded-field invariants,
  and `closure foundry --auto` to generate and run the test from a witness.
- Deployment truth join (`ingest/truth.py`, `closure truth`).
- Foundry execution backend for an arbitrary source tree and a caller-supplied test,
  with a fork URL/block and the compatibility gate checked before the tool.
- Source PoC constructor arguments, helper deployments, a minimal delegatecall proxy,
  a deployed-address target and fork execution (`--constructor-args`, `--helper`,
  `--proxy`, `--deployed-address`, `--fork-url`, `--fork-block`).
- Automatic guarded-control discovery: a bounded descendant commit touching named
  source paths, never the vulnerable commit itself.
- Class-specific mutation families (accounting, arithmetic, access-control, oracle,
  governance, reentrancy) and `--mutation-class`.
- Static order-book sandwich, utilisation-driven lending curve, best-venue quote and
  builder-bundle auction models, exposed through `closure market --model`.
- Resumable corpus pending work, explicit invalidation, and portable shard
  export/merge, exposed through `closure corpus`.
- The closure surface: real solc/forge source-to-runtime binding, source-level
  Foundry PoC rendering/execution, explicit multi-contract protocol composition,
  pinned-commit guarded controls, concrete-EVM witness replay, invariant mutation
  auditing, net-of-gas/bribe market and ordering economics, policy-aware
  planning, a durable deduplicated corpus with bounded parallel execution, and
  direct use of a verified independent reviewer. Exposed as `blackheart closure`
  and, where relevant, through `blackheart pipeline --poc/--mutation-audit/--rpc`.
  See `docs/CLOSURE.md`; every capability carries its limitation in
  `blackheart capability`.
- `blackheart pipeline`: one command from a verified deployment to a priced,
  independently re-run finding. It composes attestation, source synthesis,
  bounded-exhaustive certification, the value engine, independent verification,
  the evidence store and the findings repository. A finding is `CONFIRMED` only
  when a guarded control holds and scope/authorization are established;
  otherwise it is `STRONGLY_SUPPORTED`, with the missing check named.
  `tests/test_pipeline.py` pins every path.

### Added

- Distribution surface: Apache-2.0 license, NOTICE, package metadata, a clean
  wheel/sdist build, a tagged release workflow with checksums, and a verified
  clean-venv install smoke test.

## [1.0.0] - 2026-11-22

### Added

- Product surface: `version`, `info`, `guide`, `init`, `demo`, `doctor --json`
  and the global `--version` flag.
- SARIF 2.1.0 export, SARIF import, and an incremental finding baseline with
  `--fail-on-new`.
- Universal hunt, durable scheduler, production triggers, program-specific
  bounty gate, bounty watchtower, and the adversarial state-space engine.
- Historical-rediscovery discovery corpus, universal value/profitability engine,
  completeness assurance (oracle audit, bounded-exhaustive certifier, portfolio),
  coverage-guided corpus fuzzer, and 25 modelled attack classes with guarded
  twins.
- Solidity and Rust/Substrate ingestion, the language-aware toolchain registry
  and fail-closed compatibility gate, external engine adapters, and universal
  RPC resolution.
- Findings repository with evidence-gated confirmation, independent-review
  provenance, and a hash-chained ledger.
- Offline quickstart, capability statement and the operational doctrine.

[Unreleased]: https://github.com/itzebe/blackheart/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/itzebe/blackheart/releases/tag/v1.0.0
