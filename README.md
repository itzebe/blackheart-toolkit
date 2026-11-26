# BLACKHEART

**A wise and dangerous hacker with a black heart — an attacker-driven
security-research and exploit-verification engine.**

BLACKHEART is not a scanner and not a summariser. It does not merely inspect
code, run scanners, or summarise possible weaknesses. It generates attacker
objectives, builds multi-operation attack chains, writes and executes adversarial
Foundry / stateful-invariant tests, minimises counterexamples, has an independent
agent try to *disprove* every finding, and prepares submission-ready bounty
reports — all gated behind a verified-authorization check.

Its identity is the core of the project: **wise** (patient, methodical, honest
with itself above all) and **dangerous** (precise, relentless toward a real
weakness, unhurried until the impact is proven). The black heart is a *method* —
no mercy for its own assumptions, no vanity, no wishful thinking — never a
licence to act outside authorized scope. See `AGENTS.md` and
`blackheart/mindset.py` (`blackheart mindset --persona`).

> Core principle: **Don't just identify what might be vulnerable. Attempt to
> prove how an attacker could break it.**

---

## Start here

```bash
python3 -m pip install -e .
blackheart version
blackheart info
blackheart guide
blackheart doctor
blackheart init ./engagement      # authorization template fails closed
blackheart demo --dir ./engagement
```

`demo` proves the pipeline offline: stateful fuzz -> evidence gate -> finding ->
SARIF -> baseline. No network, no Foundry, no provider key. The full first-run
walkthrough is `docs/QUICKSTART.md`; the honest capability statement is
`docs/CAPABILITIES.md`.

---

## What is actually implemented (and verified)

| Capability | Where | Verified by |
|---|---|---|
| **Go / Cosmos SDK ingestion** (lexer-grade scanner: packages, functions, receivers, `MsgServer` handlers, consensus entry points, cgo/FFI boundaries, build flavors, and public-build **stubs** such as `//go:build !full` + `ErrNotImplemented`; category-linked leads, never findings) | `blackheart/ingest/golang.py`, `blackheart/ingest/golang_flags.py`, `blackheart ingest --language go`, `blackheart cosmos from-go` | `tests/test_golang_ingest.py`, `docs/GO_COSMOS.md` |
| **Local devnet backend** (a real compose-based non-EVM/container target: docker/compose probe, fixed `up`/`down`/`ps`/`logs` verbs, opt-in service `exec` with an argv list, central authorization gate, no remote host and no snapshot claim) | `blackheart/environments/devnet.py`, `blackheart environment list --compose FILE` | `tests/test_devnet.py` |
| **Language-coverage gate** (detects every production language in a tree and refuses to present a partial scan as clean; `FULL` / `BLOCKED` / explicit `PARTIAL`; wired into ingest, interrogate and pipeline) | `blackheart/ingest/coverage.py`, `blackheart ingest`, `blackheart interrogate` | `tests/test_golang_ingest.py`, `tests/test_golang_calls.py` |
| **Cosmos reference model** (executable accounting target: send/delegate/undelegate/redelegate/governance/lock/slash; supply, non-negative-balance, self-bond and locked-coin invariants; deliberate double-credit vulnerable twin; declared unmodelled surface) | `blackheart/cosmos/`, `blackheart cosmos model|certify|from-go` | `tests/test_cosmos.py`, `docs/GO_COSMOS.md` |
| **Temporal and staged bounty scope** (preserves `In scope from ...`, components under active remediation and the PoC requirement; the gate refuses a staged component or an unverified effective date) | `blackheart/program_intel/`, `blackheart/bounty/gate.py`, `blackheart program normalize`, `blackheart bounty gate` | `tests/test_policy_temporal.py` |
| Product surface (`version`, `info`, `guide`, `init`, `demo`, `doctor --json`) | `blackheart/product.py`, `blackheart/cli.py` | `tests/test_product_cli.py` |
| Attacker objective engine (13 objective classes) | `blackheart/objectives/` | `tests/test_objectives_chains.py` |
| Attacker mindset (the one question every mission answers; outcome + levers on every objective/hypothesis; role prompts) | `blackheart/mindset.py`, `blackheart mindset` | `tests/test_mindset.py` |
| Operational doctrine (identity, 6-phase research lifecycle, attack surfaces, hypothesis shape, methods, validation, verdicts, review, prioritisation, responsibilities, security invariants) exposed to the orchestrator and carried by every role prompt | `blackheart/doctrine.py`, `blackheart doctrine` | `tests/test_doctrine.py` |
| Findings documentation engine + persistent findings repository (A–J record, evidence-gated confirmation, search, linking, duplicate-by-root-cause, export md/json/SARIF 2.1.0, consolidated report, hash-chained log) | `blackheart/findings/`, `blackheart findings` | `tests/test_findings.py`, `tests/test_sarif.py` |
| Incremental finding baseline (content-addressed identity; new / resolved / changed / unchanged against a committed baseline; `--fail-on-new` for CI) | `blackheart/baseline.py`, `blackheart baseline` | `tests/test_baseline.py` |
| BLACKHEART identity (a wise and dangerous hacker with a black heart; leads every role prompt and every mission) | `blackheart/mindset.py` (`BLACKHEART_PERSONA`), `AGENTS.md` | `tests/test_mindset.py` |
| Attack-chain generator (multi-op sequences) | `blackheart/chains/` | `tests/test_objectives_chains.py` |
| Stateful invariant-breaking engine (fuzz + shrink) | `blackheart/invariants/engine.py` | `tests/test_invariants.py` |
| Coverage-guided corpus fuzzer (AFL-style: keeps inputs that reach new *behaviour*, grows the deepest-reaching prefixes one operation at a time to cross ordered state gates, then havoc-mutates the corpus; prices each hit with the value engine; honestly benchmarked against the random fuzzer) | `blackheart/fuzz/`, `blackheart fuzz --strategy corpus`, `blackheart fuzz-bench` | `tests/test_fuzz.py` |
| Adversarial state-machine discovery (model -> falsifiable hypotheses -> minimal invariant-violating sequences -> independent verification; 10 strategies; decoy-immune, benchmarked against the random fuzzer) | `blackheart/statespace/`, `blackheart statespace` | `tests/test_statespace.py` |
| Historical-rediscovery discovery engine (20 real vulnerability cases -> three-engine benchmark -> parameter-aware search -> attacker P&L -> per-stage miss analysis -> real Foundry PoC; full recall, zero false positives on patched controls) | `blackheart/discovery/`, `blackheart discovery` | `tests/test_discovery.py` |
| Universal value & profitability engine (classifies any target's snapshot value by structure — asset/liability/permission/protocol — and prices every candidate as attacker profit, victim loss, protocol loss, conservation residual, repeatability and max extraction; honest untracked account when no value is exposed) | `blackheart/value/`, `blackheart value` | `tests/test_value.py`, `tests/test_discovery.py` |
| Profit-guided adaptive search (the state-space explorer prices each candidate and re-ranks its pending work toward value-moving `(actor, operation)` pairs, minimising a violation while *keeping* the value movement) | `blackheart/statespace/adaptive.py` | `tests/test_adaptive_discovery.py` |
| Completeness assurance (an **oracle audit** that decides whether each declared invariant can catch anything at all — a clean result on a weak oracle proves nothing — a **bounded-exhaustive certifier** that enumerates every sequence to a depth over the declared alphabet, the only search allowed to say "no counterexample exists" up to its bound, and a **search portfolio** that runs every strategy, unions the counterexamples into a strict superset of any single search, and reports a coverage ledger) | `blackheart/assurance/`, `blackheart assure oracles`, `blackheart assure certify`, `blackheart assure portfolio` | `tests/test_assurance.py` |
| Executable attack classes beyond share accounting (oracle, permit, proxy) | `blackheart/invariants/attack_targets.py` | `tests/test_attack_targets.py` |
| Logic attack classes the engine can break, not just describe (**rounding precision** — share issuance that rounds up, **ordering/timing** — an offer accepted after its deadline, **info disclosure** — a read gated on authentication not ownership) | `blackheart/invariants/logic_targets.py` | `tests/test_logic_classes.py` |
| DeFi attack classes the engine can break (**cross-chain replay**, **AMM slippage**, **silent transfer failure**, **flash-loan governance**, **griefing DoS**, **reward manipulation**, **storage collision**, **decimals mismatch**) | `blackheart/invariants/defi_targets.py` | `tests/test_defi_classes.py` |
| MCP-server attack classes the engine can break (**audience/tenant confusion** — a token accepted by a resource or site it was not minted for, **CORS credential leak** — a reflected Origin paired with allow-credentials); three further accepted classes are recorded as prose-only because they need a live tenant | `blackheart/invariants/mcp_targets.py` | `tests/test_mcp_classes.py` |
| Class-coverage ledger (every objective category → the executable vulnerable/guarded model that covers it, or a **named gap** — a category with no model is a class every search is blind to; honest "representative, not exhaustive" framing; enforced as a hard failure in `doctor` and CI) | `blackheart/invariants/coverage.py`, `blackheart coverage` | `tests/test_logic_classes.py`, `tests/test_defi_classes.py` |
| Generic class demonstration (any pair → verified finding + report) | `blackheart/demonstrations.py` | `tests/test_cli_tools.py` |
| Foundry adversarial harness (PoC + invariant tests) | `harnesses/erc4626/` | `forge test` (see below) |
| Damn Vulnerable DeFi training harness (local-only, deterministic) | `blackheart/dvdf/`, `harnesses/dvdf/` | `tests/test_dvdf_exploit.py`, `blackheart dvdf` |
| External-source EVM validation (unchanged engine discovers + independently verifies real bugs in three independently-maintained third-party codebases on a local anvil node; differential controls; fair guided-vs-random-vs-upstream benchmark) | `blackheart/statespace/runtime/evm*.py`, `harnesses/dvdf-external/`, `harnesses/ethernaut-external/`, `harnesses/euler-v1/` | `tests/test_statespace_evm*.py`, `blackheart statespace evm`, `blackheart statespace evm-bench` |
| Real-target fork harness (in-scope source on a local mainnet fork) | `blackheart/targets/`, `blackheart/fork.py`, `harnesses/twyne-aave-wrapper/` | `blackheart fork run`, `tests/test_fork_targets.py` |
| Deployed-code monitor (polls live UMA/Oval/Across mainnet bytecode, pins keccak fingerprints, flags code changes and proxy re-pointings — read-only, stdlib-only) | `blackheart/monitor.py`, `blackheart monitor` | `tests/test_monitor.py` |
| **Universal hunt** (one command runs every engine in doctrine order — cross-target recall → search portfolio → path certification → independent verification → ordering search → memory write-back — and returns one honest verdict; no new engine, no lead upgraded) | `blackheart/hunt/`, `blackheart hunt` | `tests/test_hunt.py` |
| **Close-the-loop pipeline** (verified deployment or local source → source model → bounded-exhaustive certificate → value pricing → independent re-run against a guarded control → evidence-backed finding; `--protocol` composes every contract and infers links; `--require-independent-engine` refuses a same-engine confirmation; `CONFIRMED` only with control, scope and the declared engine gate, otherwise `STRONGLY_SUPPORTED`) | `blackheart/pipeline.py`, `blackheart pipeline`, `blackheart mission` | `tests/test_pipeline.py`, `tests/test_pipeline_source.py`, `tests/test_protocol_pipeline.py`, `tests/test_verification_independence.py`, `tests/test_mission.py` |
| **Ranked capability upgrades** (`blackheart improve status`) | `blackheart/improve/`, `docs/IMPROVEMENTS.md` | `tests/test_improve.py` |
| **Unified coverage ledger** (joins attack-class models, the capability matrix and the wider taxonomy; names every unmodelled category and every partial/no capability instead of implying coverage) | `blackheart/coverage_ledger.py`, `blackheart coverage --unified` | `tests/test_coverage_ledger.py` |
| **Whole-program taint leads** (SSA-lite def-use over the scanner's source, branch merges with phi nodes, attacker parameters/`msg.sender`/external returns propagated through internal calls to a fixpoint, source line and guard recorded; a lead, never a finding) | `blackheart/dataflow/`, `blackheart dataflow`, `pipeline --source --dataflow` | `tests/test_dataflow.py` |
| **Real-EVM execution routing** (`anvil` via `eth_call` when Foundry is installed, local `evmworld` otherwise; engine and fallback reason carried with the result; `revm` detected but not claimed as an adapter) | `blackheart/execution/route.py`, `blackheart evm-exec` | `tests/test_execution_route.py` |
| **Optional SMT path conditions** (Z3 discharge of the symbolic constraints when installed; SAT re-checked against every constraint and finite domain, UNSAT only over that bound; absence is explicit `UNKNOWN`, never a dependency) | `blackheart/symbolic/smt.py`, `symbolic-evm --smt`, `ingest --symbolic --smt` | `tests/test_smt.py` |
| **Witness source traces and CI artifacts** (certified step → contract/function/line/statement with unmapped reasons; `pipeline --sarif`, `--write-baseline`, `--baseline`, `--fail-on-new`) | `blackheart/witness.py`, `blackheart pipeline` | `tests/test_witness.py`, `tests/test_sarif.py`, `tests/test_baseline.py` |
| **Closure surface** (real solc/forge source-to-runtime binding, source-level Foundry PoC with constructor args/proxy/helpers/fork and four invariant forms, a caller-test Foundry backend with `--auto`, declarative multi-call fork scenarios with funded callers and balance-delta assertions, explicit and inferred protocol composition, pinned or discovered controls, concrete-EVM witness replay, generic and class-specific mutation audit, constant-product/single- and multi-range-V3/order-book/lending/venue/bundle/order-flow/live economics, including a declared multi-competitor bid ladder with win probability and optimal threshold bid, read-only live V3 tick-bitmap/liquidity reconstruction with gas/bribe/inclusion/failure/capital/competition pricing and pinned-fork execution of the selected candidate, policy-aware planning, resumable sharded corpus with epoch-fenced worker leases, deployment planning/truth/equivalence checks, including runtime-bound deployment truth enforced at finding confirmation and bounty submission, and independent-reviewer use including a local Ollama provider) | `blackheart closure`, `blackheart/pipeline.py` | `tests/test_solc.py`, `tests/test_pocgen.py`, `tests/test_foundry_backend.py`, `tests/test_protocol.py`, `tests/test_callgraph.py`, `tests/test_control.py`, `tests/test_bytecode_witness.py`, `tests/test_fork_scenario.py`, `tests/test_mutation_audit.py`, `tests/test_market.py`, `tests/test_orderflow.py`, `tests/test_live_market.py`, `tests/test_live_v3.py`, `tests/test_planning.py`, `tests/test_parallel_corpus.py`, `tests/test_distributed_queue.py`, `tests/test_deploy_plan.py`, `tests/test_equivalence.py`, `tests/test_deployment_truth.py`, `tests/test_reviewer_use.py` |
| Universal RPC resolution (operator override → keyless registry → You.com discovery → probed fallback; only an endpoint that *answered* is returned; no hardcoded endpoint) | `blackheart/rpc.py` | `tests/test_rpc.py` |
| Durable autonomous scheduler (append-only hash-chained job log rebuilt by replay; explicit lifecycle; lease ownership fenced by a monotonic epoch; stale-lease recovery; bounded retry with dead-letter; misfire recovery; idempotent dedupe; authorization re-checked at claim, in the executor and on recovery — dispatches existing engines, adds reliability not insight) | `blackheart/scheduler/`, `blackheart schedule` | `tests/test_scheduler.py`, `docs/SCHEDULER.md` |
| **Production trigger monitoring** (authenticated, authorized research triggers: HMAC webhook / manual / recurring sources; replay+duplicate dedupe; closed-schema payload validation; scope enforced against the configured authorization record — a payload can never assert its own scope; sliding-window rate limit; honest delivery states; tamper-evident ledger) | `blackheart/triggers/`, `blackheart trigger` | `tests/test_triggers.py`, `docs/TRIGGERS.md` |
| **Program-specific bounty intelligence** (validity, severity, scope and payout kept as four separate axes; ten outcome states so a valid-but-non-payable finding is never called invalid; program severity definitions and payouts; provenance-carrying immutable policy snapshots; re-evaluation on policy change without rewriting history; submission prepared, never sent) | `blackheart/bounty/`, `blackheart bounty` | `tests/test_bounty.py`, `docs/BOUNTY.md` |
| **Hourly bounty watchtower** (43 independent target records; official policy, repository and deployed-contract change detection; ETag/304, counter-noise suppression, fail-closed participation gates, seven statuses, a 100-point score with an 80 threshold; read-only and zero-cost) | `blackheart/watch/`, `blackheart watch` | `tests/test_watch.py`, `docs/BOUNTY_WATCH.md` |
| **Language-aware tool compatibility** (mandatory policy: identify the stack from source/manifests/build config before choosing a tool, verify the tool's documented compatibility against *that* language and version, test natively, and report exactly one of PASS/BLOCKED/INCOMPLETE/NO_FINDINGS; a verified per-language registry with official documentation and known incompatibilities; a fail-closed pre-execution gate; a stack detector that never confirms a language from an extension or a README) | `blackheart/toolchain/`, `blackheart compat` | `tests/test_tool_compatibility.py`, `docs/SECURITY_TOOL_COMPATIBILITY.md` |
| Independent verification agent (7 gates) | `blackheart/verify/` | `tests/test_verify.py` |
| Authorization gate (fails closed) | `blackheart/authz/` | `tests/test_authz.py` |
| Content-addressed evidence store | `blackheart/evidence/` | `tests/test_evidence_report.py` |
| Engagement ledger + hypothesis DB | `blackheart/ledger/` | `tests/test_evidence_report.py` |
| Submission-ready report writer | `blackheart/report/` | `tests/test_evidence_report.py` |
| Verified, portable toolchain registry | `blackheart/tools/`, `install.sh` | `blackheart tools verify` |
| Live-protocol toolchain (web/API/recon/secrets/infra) | `blackheart/tools/__init__.py` (`LIVE_TOOLCHAIN`), `install.sh` | `blackheart tools verify` |
| GitHub Actions attack-chain analyzer (workflow_run artifact checkout, PR-target untrusted checkout, script injection) | `blackheart/gha.py` | `tests/test_gha.py` |
| GitHub Actions analyzer benchmark (precision/recall/safe-accuracy gates) | `blackheart/gha_bench.py` | `tests/test_gha_bench.py` |
| Protocol intelligence + threat modeling (trust boundaries, assumptions, per-asset invariants; impact selection) | `blackheart/threatmodel/` | `tests/test_threatmodel.py` |
| Pre-submission novelty gate (mandatory documented search; fails closed on duplicate / already-fixed / under-powered search) | `blackheart/novelty.py` | `tests/test_novelty.py` |
| Persistent research memory (confirmed/unconfirmed/disproven/incomplete; confirmed-only attack knowledge) | `blackheart/research/` | `tests/test_research_engine.py` |
| Autonomous hypothesis engine (score/rank/select/explain; skip-disproven) | `blackheart/hypothesis/` | `tests/test_research_engine.py` |
| Hypothesis generation engine (P2: falsifiable hypotheses from a threat model; explainable ranking; duplicates/rejections; alternatives) | `blackheart/hypothesis/generation.py` | `tests/test_hypothesis_generation.py` |
| Investigation workflow engine (P3: resumable lifecycle, entry criteria, authz-gated reproduction, independent-challenge gate, hash-chained tamper-evident log) | `blackheart/investigation/` | `tests/test_investigation.py`, `tests/test_investigation_integrity.py` |
| Log integrity (hash chain + optional HMAC-SHA256 + checkpoints; honest threat model) | `blackheart/integrity.py` | `tests/test_investigation_integrity.py` |
| End-to-end P2+P3 demonstration (threat model -> hypotheses -> reproduce -> verdict -> learn) | `blackheart/demo_p2p3.py` | `tests/test_demo_p2p3.py` |
| Target-surface applicability model (negation/CamelCase-aware) | `blackheart/hypothesis/surface.py` | `tests/test_research_engine.py` |
| Class-aware tool selection (which tool proves which class, with a control) | `blackheart/exploit/toolselect.py` | `tests/test_research_engine.py` |
| Self-improvement engine + ranking benchmark (historical + negative corpora) | `blackheart/learning/` | `tests/test_research_engine.py` |
| Resumable research queue (re-checks the authorization gate on every dequeue) | `blackheart/research/queue.py` | `tests/test_research_engine.py` |
| 15 specialist agents + 23 skills | `agents/`, `skills/` | `tests/test_acceptance.py` |
| Multi-engine integration (Strix / Shannon / PentAGI as untrusted evidence sources; authorization-gated, license-isolated) | `blackheart/engines/`, `blackheart engines` | `tests/test_engines.py`, `tests/test_engines_cli.py`, `tests/test_engine_controls.py` |
| Cross-engine coordination (dedup, corroboration, contradiction, attack-chain correlation, prior-art) + unified md/json/SARIF reporting | `blackheart/engines/orchestrator.py`, `blackheart/engines/report.py` | `tests/test_engines.py` |

A **reference engagement** exercises the whole pipeline end to end
(`blackheart engagement`) and produces a CONFIRMED finding against a local,
deliberately-vulnerable reference target, with all seven gates passing and the
Foundry fuzzer independently reproducing it. See
`research/private/reference-engagement/` (gitignored private evidence).

---

## Install

Free and open-source only. No paid tool, subscription, or API key is required.

```bash
./install.sh --core     # python package + Foundry (fast path)
./install.sh            # full toolchain (echidna, medusa, halmos, semgrep, ...)
./install.sh --verify   # re-verify an existing toolchain only
```

The installer is idempotent and non-fatal per tool: anything it cannot install is
reported `MISSING`/`UNSUPPORTED`, never silently substituted. See
[docs/TOOLCHAIN.md](docs/TOOLCHAIN.md).

The engine and the cloud client use only the Python standard library, so no
`install.sh` step is needed for either. Cloud execution additionally needs an
`INSTABOX_API_KEY` secret in the environment; see
[docs/CLOUD_EXECUTION.md](docs/CLOUD_EXECUTION.md).

## Quick start

```bash
# 1. List what this build can do
python3 -m blackheart agents

# 2. Verify the toolchain actually runs (not just "binary exists")
python3 -m blackheart tools verify --out /tmp/blackheart-tools.json

# 3. Generate attacker objectives for a target profile
python3 -m blackheart objectives --profile examples/profile.example.json

# 4. Build attack chains
python3 -m blackheart chains --profile examples/profile.example.json

# 5. Search for invariant breaks (stateful fuzzing) and minimise counterexamples
python3 -m blackheart fuzz --target wrapper --runs 500
# ...or reach a deep, ordered bug the random walk misses (coverage-guided corpus)
python3 -m blackheart fuzz --strategy corpus --target wrapper --runs 4000 --steps 20
python3 -m blackheart fuzz-bench                       # corpus vs random, honest ablation
python3 -m blackheart reproduce --target wrapper --invariant no-material-victim-loss --runs 200

# 5a. Completeness assurance: audit the oracles, certify absence to a bound, run every strategy
python3 -m blackheart assure oracles --target permit-replay --depth 3   # can the invariants fire?
python3 -m blackheart assure certify --target permit-replay --depth 5   # exhaustive to depth 5
python3 -m blackheart assure portfolio --target lending-oracle --depth 3 # union of all 6 strategies

# 5b. Adversarial state-machine discovery (model -> hypotheses -> minimal
#     invariant-violating sequences -> independent verification)
python3 -m blackheart statespace strategies                # the 10 hypothesis strategies
python3 -m blackheart statespace --fixture stale-authorization model
python3 -m blackheart statespace --fixture stale-authorization hypotheses
python3 -m blackheart statespace --fixture stale-authorization explore
python3 -m blackheart statespace --fixture stale-authorization discover   # + verdicts
python3 -m blackheart statespace benchmark                # guided vs random, honest ablation

# 5c. Historical-rediscovery discovery engine (real-vulnerability corpus ->
#     three-engine benchmark -> parameter-aware search -> attacker P&L -> Foundry)
python3 -m blackheart discovery corpus                    # corpus shape
python3 -m blackheart discovery benchmark                 # baseline vs guided vs enhanced
python3 -m blackheart discovery misses                    # classify guided misses by stage
python3 -m blackheart discovery economic                  # attacker P&L per case
python3 -m blackheart discovery foundry                   # real Foundry PoC suite (needs forge)
python3 -m blackheart discovery foundry-invariant         # invariant differential

# 5d. Universal value & profitability engine (classify value, price any candidate)
python3 -m blackheart value targets                       # which targets expose trackable value
python3 -m blackheart value classify --target wrapper     # how a snapshot is read as value
python3 -m blackheart value analyse --target wrapper      # price a target's violations

# 5e. The universal hunt: every engine, in order, one honest verdict
python3 -m blackheart hunt --target vulnerable --control safe --in-scope --authorized
python3 -m blackheart hunt --target vulnerable --memory          # recall + write back proven
python3 -m blackheart hunt --target vulnerable --scenario sandwich
python3 -m blackheart hunt --target safe                          # a clean bounded negative

# 6. Run the full reference engagement (objectives -> chains -> fuzz -> forge -> verify -> report)
python3 -m blackheart engagement --workdir research/private/reference-engagement

# 6b. Monitor live mainnet contracts for post-audit code drift (read-only).
#     On an audited protocol the payable bug is usually in a change shipped
#     after the audit; this pins each deployed contract's keccak fingerprint and
#     reports the moment it moves (or a proxy is re-pointed).
python3 -m blackheart monitor targets                        # the watched registry
python3 -m blackheart monitor baseline --out /tmp/mon.json    # pin current code
python3 -m blackheart monitor run --baseline /tmp/mon.json    # report drift (exit 1 if changed)
# RPC defaults to BLACKHEART_ETH_RPC or a free public archive endpoint.

# 7. Gate a real engagement on authorization (blocks if not AUTHORIZED)
python3 -m blackheart campaign --profile p.json --authz auth.json \
    --engagement eng --asset asset-a --workdir research/private/eng

# 8. Drive any attack class end to end (fuzz -> finding -> verify -> report)
python3 -m blackheart targets                       # list executable targets
python3 -m blackheart coverage                      # which attack classes the engine can break
python3 -m blackheart differential                  # assert every vuln/guarded pair
python3 -m blackheart statespace mempool sandwich   # ordering (MEV) search: sandwich a victim swap
python3 -m blackheart demonstrate --pair permit-replay/permit-guarded \
    --workdir research/private/demo-permit
python3 -m blackheart doctor                        # portability + health check

# 9. Real-target fork harness: real in-scope source on a LOCAL mainnet fork
python3 -m blackheart fork targets                  # list real-target harnesses
python3 -m blackheart fork fetch --target twyne-aave-wrapper
python3 -m blackheart fork run   --target twyne-aave-wrapper --runs 48 --depth 40
python3 -m blackheart fork ledger --target twyne-aave-wrapper --ledger-dir research/private/fork/ledger
python3 -m blackheart fork verify --target twyne-aave-wrapper   # independent verification

# 10. Damn Vulnerable DeFi training harness (local-only, deterministic)
python3 -m blackheart dvdf UnstoppablePoC          # exploit + control both pass
python3 -m blackheart dvdf UnstoppableInvariants --invariant  # the violated invariant
python3 -m blackheart dvdf UnstoppableRegression   # guarded remediation regression
```

The fork harness compiles the **real** in-scope source (pinned commit) against
real dependencies and runs adversarial + stateful-invariant tests against a
**local mainnet fork** (real Aave V3). Nothing is broadcast; no paid RPC key is
needed. See [harnesses/twyne-aave-wrapper/README.md](harnesses/twyne-aave-wrapper/README.md).

## The authorization gate (read this first)

Active testing against any real target is **blocked by default**. An asset may
only enter active exploitation when it is explicitly classified `AUTHORIZED`
*and* every program-level check passes (`program_active`, `safe_harbor`,
`zero_cost`, researcher eligibility, payout feasibility) *and* dated evidence and
an official scope URL are recorded. Ownership of one asset is never permission to
attack another. See [docs/AUTHORIZATION.md](docs/AUTHORIZATION.md).

```bash
python3 -m pytest tests/test_authz.py    # 15 gate regression tests
```

## Finding quality gates

Every candidate finding is challenged against seven gates (reachability,
control, defense-bypass, reproduction, impact, independent verification, scope)
and classified `CONFIRMED`, `NEEDS_MORE_EVIDENCE`, `INFORMATIONAL`,
`FALSE_POSITIVE`, `OUT_OF_SCOPE`, `DUPLICATE_OR_KNOWN`, or `BLOCKED`. A finding is
only `CONFIRMED` when all seven gates `PASS` and an independent agent reproduced
it. A failed test alone is **not** a vulnerability.

## Documentation

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — how the engine is put together
- [docs/RESEARCH_ENGINE.md](docs/RESEARCH_ENGINE.md) — the evolving research engine (memory, hypotheses, self-improvement)
- [docs/STATESPACE.md](docs/STATESPACE.md) — adversarial state-machine discovery: model, hypotheses, explorer, verifier, benchmark
- [docs/FUZZING.md](docs/FUZZING.md) — coverage-guided corpus fuzzing: the behavioural coverage signal, the beam growth, the honest corpus-vs-random ablation
- [docs/VALUE.md](docs/VALUE.md) — the universal value & profitability engine: structural classification, the priced account, the profit-guided search
- [docs/COVERAGE.md](docs/COVERAGE.md) — completeness assurance: the oracle audit (is each declared invariant able to fire?), the bounded-exhaustive certifier (proving absence to a bound), the search portfolio (the union of every strategy, with a coverage ledger) and the class-coverage ledger (which attack classes the engine can break)
- [docs/CONTINUOUS_EVALUATION.md](docs/CONTINUOUS_EVALUATION.md) — continuous adversarial evaluation: executable tests (TestSparker), honest metrics with explicit denominators, a fail-closed authorization gate, baselines, and controlled learning; the reviewer model is optional, so review is recorded as SAME_MODEL unless a verified reviewer exists
- [docs/HUNT.md](docs/HUNT.md) — the universal hunt: every engine in one operation, the honest verdict ladder, universal RPC resolution, and You.com as the enforced search provider
- [docs/PIPELINE.md](docs/PIPELINE.md) — close the loop: verified deployment → model → price → independent verification → finding, with every honest status
- [docs/CLOSURE.md](docs/CLOSURE.md) — the closure surface: source-to-runtime binding, source-level PoC, protocol composition, guarded controls, concrete-EVM witness replay, mutation audit, market economics, policy planning, durable corpus and reviewer use
- [docs/ENGINES.md](docs/ENGINES.md) — multi-engine integration (Strix / Shannon / PentAGI) and its license boundaries
- [docs/INTELLIGENCE.md](docs/INTELLIGENCE.md) — external intelligence (You.com search/contents/research) and MCP wiring
- [docs/PRIOR_ART.md](docs/PRIOR_ART.md) — the free prior-art source (GitHub Advisory database): what its API actually supports, why a sentence query is refused, and why quota exhaustion is an error rather than an empty result
- [docs/EVM_BENCH.md](docs/EVM_BENCH.md) — measuring against EVMbench without a paid key: fix-diff ground truth, the three separate recall numbers, and why a 100% line score from noise detectors is worse than a 0% one
- [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) — upstream projects, licenses, and why the boundaries are drawn where they are
- [docs/TOOLCHAIN.md](docs/TOOLCHAIN.md) — tools, versions, verification states
- [docs/SECURITY_TOOL_COMPATIBILITY.md](docs/SECURITY_TOOL_COMPATIBILITY.md) — the mandatory language-aware policy and the verified per-language tool registry
- [docs/CAPABILITIES.md](docs/CAPABILITIES.md) — deployed-contract intelligence (read-only on-chain verification)
- [docs/AUTHORIZATION.md](docs/AUTHORIZATION.md) — the authorization gate
- [docs/INTEGRITY.md](docs/INTEGRITY.md) — log integrity: threat model, hash chain, HMAC, checkpoints
- [docs/PORTABILITY.md](docs/PORTABILITY.md) — running across independent sandboxes
- [docs/CLOUD_EXECUTION.md](docs/CLOUD_EXECUTION.md) — portable cloud execution on the persistent InstaBox machine
- [docs/CHROME_VRP.md](docs/CHROME_VRP.md) — the Chrome VRP engagement: boundary probes against a real Chromium
- [docs/TRIGGERS.md](docs/TRIGGERS.md) — production authorized trigger monitoring: authentication, dedupe, scope enforcement, honest states
- [docs/BOUNTY.md](docs/BOUNTY.md) — program-specific bounty intelligence: four separate axes, ten outcomes, provenance, re-evaluation
- [docs/BOUNTY_WATCH.md](docs/BOUNTY_WATCH.md) — the hourly watchtower: policy/repository/deployment change detection, noise controls, eligibility gates and the zero-cost scheduler
- [docs/RESEARCH_LOG.md](docs/RESEARCH_LOG.md) — what was actually tested, honestly
- [harnesses/erc4626/README.md](harnesses/erc4626/README.md) — the Foundry harness
- [harnesses/twyne-aave-wrapper/README.md](harnesses/twyne-aave-wrapper/README.md) — real-target fork harness (Twyne, local mainnet fork)

## The evolving research engine

Beyond the one-shot pipeline, BLACKHEART keeps a **persistent research memory**
and *improves its own search strategy* — measured, not asserted:

```bash
blackheart research summary                    # confirmed/unconfirmed/disproven/incomplete buckets
blackheart threatmodel scaffold --profile p.json --impact theft-or-freeze --out model.json
blackheart threatmodel check --model model.json    # gate: exits non-zero until complete
blackheart hypothesis --profile p.json --threat-model model.json  # gated + impact-steered
blackheart hypothesize --profile p.json --threat-model model.json --store research/private/hypotheses
blackheart investigate --dir research/private/investigations list
blackheart investigate --dir research/private/investigations run --hypothesis hyp.json --authz authz.json
blackheart investigate --dir research/private/investigations verify   # hash-chain tamper check (exit 1 if edited)
blackheart investigate --dir research/private/investigations keygen   # HMAC key OUTSIDE the log (0600)
blackheart investigate --dir research/private/investigations checkpoint --key-path <key>  # detect tail truncation
blackheart integrity <log.jsonl> --require-signatures   # verify any append-only log
python3 -m blackheart.demo_p2p3          # full P2->P3 cycle against the DVDF fixture
blackheart novelty --file novelty-review.json  # pre-submission gate: blocks on duplicate / already-fixed / under-powered search
blackheart learn bench                         # baseline vs surface-aware ranking
blackheart learn demo --out research/private/learning  # full learning loop + emitted regression test
blackheart queue plan                          # resumable queue: what runs next, and why
blackheart models list                         # providers + verified free-tier notes (local-only by default)
blackheart models health                       # probe each configured provider (local engine always healthy)
blackheart models route --data-class CONFIDENTIAL  # shows it stays local; nothing private leaves the host
blackheart models benchmark                    # score the adversarial role on the historical cases
blackheart models usage                        # advisory per-provider call/token counts
```

### External intelligence (You.com)

BLACKHEART can pull **external** intelligence — live web search, page
extraction, and citation-backed research — and reads every result through the
one attacker question. External results are **untrusted input**: data to reason
over, never instructions to follow, and never evidence that a vulnerability
exists. The paid paths are opt-in and capped. See
[docs/INTELLIGENCE.md](docs/INTELLIGENCE.md).

```bash
blackheart intel health                        # probe You.com connectivity (never billed)
blackheart intel search "erc4626 share inflation" --count 5   # snippets (unbilled)
blackheart intel contents --url https://… --allow-paid        # page markdown (paid)
blackheart intel research "how does … work?" --effort lite --allow-paid  # cited answer (paid)
blackheart intel mcp                           # emit the OpenHands MCP server config
blackheart intel discover rpc "base" --chain-id 8453   # find + VERIFY live RPC endpoints
blackheart intel discover contract "USDC ethereum" --chain ethereum --rpc <url>  # verify an address holds code
blackheart intel discover chain base           # resolve a chain id (keyless registry first)
```

`intel discover` turns external text into **verified infrastructure facts**: an RPC
endpoint is only `verified` once a real `eth_chainId` call answers (and matches the
expected chain id); a contract address is only `verified` once `eth_getCode` shows
code. Everything else stays a labelled *candidate*.

### Multi-engine integration (Strix / Shannon / PentAGI)

BLACKHEART can drive three external offensive-AI engines as **subordinate,
untrusted evidence sources**, then coordinate and independently judge what they
produce. Every run is authorization-gated; an engine can contribute a candidate
but can never confirm a finding. See [docs/ENGINES.md](docs/ENGINES.md).

```bash
blackheart engines list                        # engines, state, version, license
blackheart engines verify --engine strix       # health + configuration (exit 1 if missing)
blackheart engines run --target https://app.example --engines strix,shannon \
        --authz authz.json --asset app-1 --report research/private/engines/report
blackheart engines run --target ./local --allow-local --engines strix   # local/disposable target
blackheart engines findings                    # normalized clusters from the last run
blackheart engines report --stdout --format json
```

Shannon (AGPL-3.0) and PentAGI (MIT + EULA) are used strictly across a process or
network boundary; none of their source is vendored or linked (see
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)).

The learning loop proposes a strategy improvement, demonstrates the *old*
weakness with a failing case, benchmarks it against a historical corpus **and** a
negative (anti-overfitting) corpus, and adopts it only if neither regresses. It
may never modify the authorization or verification modules. See
[docs/RESEARCH_ENGINE.md](docs/RESEARCH_ENGINE.md).

## Tests

BLACKHEART is stdlib-only Python (requires-python >= 3.11). The suite runs with
`pytest`; the external-source EVM tests additionally need **Foundry** (`forge`,
`anvil`, `cast`) and their vendored harnesses restored.

```bash
# 1. install the toolchain (Python package + Foundry)
./install.sh --core            # or: pip install -e . ; curl -sSL https://foundry.paradigm.xyz | bash && foundryup

# 2. restore the git-ignored external harnesses (each pins its upstream commit)
harnesses/dvdf-external/fetch.sh          # DVDF @ v4.1.0 (64fddf9f...)
harnesses/ethernaut-external/fetch.sh     # OpenZeppelin Ethernaut @ d05643a4...

# 3. run the suite
python3 -m pytest tests/ -m "not slow" -q # the full fast suite
python3 -m pytest tests/ -m slow -q       # benchmarks + live engine scans
```

A fresh checkout that skips step 2 runs the same suite but the node-backed
external-EVM tests **skip** (a skip is not a pass); the exact skip reasons are
printed with `-rs`. Everything vendored by `fetch.sh` is git-ignored
(`harnesses/*/vendor|lib|out|cache/`), so it is never committed.

Tests that need extra prerequisites (each skips, with its reason, when the
prerequisite is absent):

| Prerequisite | Tests |
|---|---|
| Foundry `forge` + restored DVDF harness | `tests/test_statespace_evm*.py` (DVDF cases) |
| Foundry + restored Ethernaut harness | `tests/test_statespace_evm_ethernaut.py`, Ethernaut cases |
| `forge-std` in `harnesses/adversarial/`, `echidna`/`medusa`/`halmos`/`slither`/`mythril` | `tests/test_adversarial_harness.py` |
| `harnesses/hyperliquid-bridge/fetch.sh`, `harnesses/aave-wrapper/fetch-deps.sh` | `tests/test_bridge_real_source.py`, `tests/test_wrapper_real_source.py` |
| `PyYAML` | `tests/test_gha.py`, `tests/test_gha_bench.py` |
| `BLACKHEART_LIVE_YOU=1` + `YDC_API_KEY` | the live You.com smoke tests |

The Foundry PoC/invariant harnesses are run separately:

```bash
cd harnesses/erc4626 && forge test               # Foundry PoC + stateful invariants
cd harnesses/twyne-aave-wrapper && forge test    # real-target fork tests (needs forge + RPC)
```

For the reproducible clean-checkout procedure and the exact current
passed/failed/skipped totals, see
[research/mission04/FINAL_HANDOFF.md](research/mission04/FINAL_HANDOFF.md).

## Project

- **License:** Apache-2.0 (`LICENSE`, `NOTICE`).
- **Contributing:** `CONTRIBUTING.md` — setup, tests, the non-negotiable rules,
  and how to add a capability.
- **Security:** `SECURITY.md` — how to report a vulnerability in BLACKHEART
  privately, and the safe-harbour boundaries.
- **Releases:** `docs/RELEASE.md` — versioning, the tagged workflow, and how to
  verify a wheel.
- **Changelog:** `CHANGELOG.md`.

## Safety

BLACKHEART never runs destructive production testing, never broadcasts exploit
transactions to a live network, and never submits a report or discloses a finding
without explicit user approval. It does not spend money by default: the only
billable capability (paid You.com research/contents) refuses to run unless the
caller explicitly opts in *and* sets a hard per-run call cap. Private engagement
evidence lives under `research/private/` and is gitignored — never commit target
data, secrets, or bounty-confidential material.
