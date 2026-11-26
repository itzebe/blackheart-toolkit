"""An honest, machine-readable statement of what BLACKHEART can and cannot do.

This module exists because a research engine that overstates its reach is worse
than one that does less and says so. The capability matrix below was written
after three missions (UMA VotingV2, UMA dispute economics, Polymarket NegRisk)
that each ended in a negative, and it names the exact gaps those missions hit.

The rule it encodes: a capability is ``yes`` only when a command exists *and* a
test exercises it. Everything a human had to do by hand is ``partial`` or
``no``, with the reason recorded.
"""

from __future__ import annotations

from dataclasses import dataclass

STATUSES = ("yes", "partial", "no")


@dataclass(frozen=True)
class Capability:
    name: str
    status: str
    what_it_does: str
    evidence: str
    limitation: str


CAPABILITIES: tuple[Capability, ...] = (
    Capability(
        "research-doctrine",
        "yes",
        "Six-phase lifecycle, objectives, hypotheses, validation gates and verdicts.",
        "`python3 -m blackheart doctrine`; tests/test_doctrine.py",
        "The doctrine structures the work; it does not perform it.",
    ),
    Capability(
        "invariant-modelling",
        "yes",
        "25 objective categories modelled by 22 vulnerable/guarded executable pairs.",
        "`python3 -m blackheart coverage`; tests/test_logic_classes.py, tests/test_defi_classes.py",
        "A model is a representative of a class, never proof the class is absent.",
    ),
    Capability(
        "state-machine-search",
        "yes",
        "Enumerating explorer, bounded-exhaustive certifier, portfolio and corpus fuzzer.",
        "`blackheart statespace`, `assure certify`, `fuzz --strategy corpus`",
        "All of it runs on a hand-authored Target model, not on third-party Solidity.",
    ),
    Capability(
        "source-ingestion",
        "yes",
        "Scans a real .sol repository into contracts, functions, modifiers, state vars and call sites. "
        "`pipeline --source` and `mission --source` compile first and use the solc AST by default "
        "(`--scanner` forces the lexer); a supplied `--ast` or combined-json payload also works. "
        "The AST path uses the compiler's resolved parameter/return types, struct fields, modifier "
        "names and bases, binds each AST to its own compiled source unit, expands a single file's "
        "relative imports, and discovers the nearest foundry.toml/Hardhat project root.",
        "`python3 -m blackheart ingest <path>`, `blackheart pipeline --source`; "
        "tests/test_ingest.py, tests/test_ast_surface.py, tests/test_pipeline_ast_binding.py",
        "The AST path needs a compiler; without one it falls back to the lexer and says why. A "
        "correct surface is still only the input to synthesis: the statement interpreter models a "
        "subset, and an unmodelled operation is reported rather than simulated.",
    ),
    Capability(
        "whole-program-taint",
        "partial",
        "Builds an SSA-lite def-use graph per function, merges branches with phi "
        "nodes, and propagates attacker-controlled parameters, msg.sender/value, "
        "external-call returns and state through internal calls to a fixpoint. "
        "Reports source -> sink flows with a source line and function path; a "
        "recognised authorization guard is recorded on the flow.",
        "`python3 -m blackheart dataflow <path>`; tests/test_dataflow.py",
        "It is a Solidity-only, source-level approximation over the scanner's "
        "statement subset, "
        "not a compiler IR: virtual dispatch, overloaded names, inline assembly and "
        "arbitrary data structures are unresolved. A flow is a lead, never a finding.",
    ),
    Capability(
        "real-evm-execution",
        "partial",
        "`blackheart evm-exec` runs one bytecode message on a real ephemeral anvil "
        "node through `eth_call` when Foundry is installed, and otherwise on the "
        "local `evmworld` interpreter. The engine, the request and the fallback "
        "reason travel with the result; a local run is never labelled as a chain run.",
        "`blackheart evm-exec`; tests/test_execution_route.py",
        "anvil must be installed; `revm` is detected but has no stable command-line "
        "contract here. The local fallback is a model, not a chain, and neither path "
        "proves a multi-transaction protocol exploit.",
    ),
    Capability(
        "local-devnet-execution",
        "partial",
        "A local compose devnet backend that probes docker, reads the configured "
        "compose file, and runs a fixed verb set (`up`/`down`/`ps`/`logs`, plus "
        "opt-in `exec`) behind the central authorization gate. It is real local "
        "execution, not a simulation, and it cannot reach a remote host.",
        "`blackheart environment list --compose <file>`; tests/test_devnet.py",
        "Requires docker and a compose file; there is no snapshot/rollback, no "
        "transaction client, and no remote/testnet target. A QoreChain devnet "
        "still needs its own compose definition and a chain-specific sequence.",
    ),
    Capability(
        "smt-path-conditions",
        "partial",
        "Optional Z3 discharge of the symbolic path conditions: a SAT model is "
        "re-evaluated against every constraint and declared domain, and UNSAT is "
        "accepted only over those finite domains. The built-in bounded solver remains "
        "the default; absence of Z3 is an explicit UNKNOWN, never a false clean.",
        "`symbolic-evm --smt`, `ingest --symbolic --smt`; tests/test_smt.py",
        "Z3 is optional and not a runtime dependency. Mapping indices, symbolic "
        "division/modulo and non-integer values stay outside the translated fragment; "
        "a bounded SMT proof is not a proof about unbounded EVM arithmetic.",
    ),
    Capability(
        "witness-source-trace",
        "yes",
        "Maps a certified witness step to its contract, function, source line and "
        "statement, and exposes the certifier's prefix-minimal witness through one "
        "object. An unmapped step is reported as unmapped with its reason.",
        "`blackheart.witness`, `pipeline --source`; tests/test_witness.py",
        "The line is the first matching statement in the function body; overloads, "
        "inherited implementations and generated source can make that ambiguous, and "
        "the trace does not prove the witness executes on-chain.",
    ),
    Capability(
        "pipeline-ci-artifacts",
        "yes",
        "`pipeline` can export the findings repository as SARIF 2.1.0, write a "
        "content-addressed baseline, compare against one, and fail on a new finding, "
        "so a CI job can gate on regressions instead of noise.",
        "`pipeline --sarif --write-baseline --baseline --fail-on-new`; "
        "tests/test_sarif.py, tests/test_baseline.py",
        "It exports findings, not raw ingest or dataflow leads; a baseline identity "
        "is the root-cause fingerprint, so a moved line is a new identity.",
    ),
    Capability(
        "candidate-weakness-flags",
        "yes",
        "Twelve rules map source shapes to objective categories with the exact line as evidence.",
        "`python3 -m blackheart ingest <path>`; tests/test_ingest.py",
        "Flags are leads. Precision over recall; a miss is not a proof of safety.",
    ),
    Capability(
        "value-accounting",
        "yes",
        "Prices a sequence as attacker profit, victim loss, protocol loss and repeatability.",
        "`python3 -m blackheart value`; tests/test_value.py",
        "Requires a sequence the engine can already execute.",
    ),
    Capability(
        "findings-evidence-gate",
        "yes",
        "A finding cannot become CONFIRMED without evidence, verification and a named reviewer.",
        "`python3 -m blackheart findings`; tests/test_findings.py",
        "Gates honesty; does not create findings.",
    ),
    Capability(
        "solidity-execution",
        "partial",
        "`ingest/runner.py` runs `forge test --json` behind the compatibility gate and "
        "maps the result to PASS / BLOCKED / INCOMPLETE / NO_FINDINGS.",
        "`blackheart.ingest.runner`; tests/test_runner.py",
        "Execution needs the tool installed on the host; the generated harness is a "
        "skeleton a human completes. Nothing in-engine compiles Solidity itself.",
    ),
    Capability(
        "model-synthesis-from-source",
        "partial",
        "`ingest --synthesize` builds a Target from a contract's own external functions, "
        "derives conservation and owner-authorization invariants, and runs the "
        "certifier on it.",
        "`blackheart ingest <path> --synthesize`; tests/test_synthesize.py",
        "The subset includes compound assignment (`*=`, `/=`, `%=`), unary "
        "increment/decrement, `delete`, nested `if/else if/else`, struct-field "
        "flattening, arrays with `push`/`length`, array-of-struct member writes "
        "(`pools[i].amount += a`), function-local scalar declarations (initialised "
        "or zero-initialised, never leaked into contract state), inherited "
        "functions and state, source-ordered `require`/`revert` (including a "
        "direct `revert()` and an early `return` that halts later writes) with "
        "atomic rollback, statement-level external calls, internal calls, and a view "
        "function's return paths folded into one conditional expression (locals "
        "substituted, ternaries composed). A protocol composition resolves "
        "external reads, an interface/base-typed receiver with exactly one "
        "concrete implementation, and an ERC20-like callee by shape. It is still a "
        "subset: arrays of structs, mapping-to-struct writes, single-contract "
        "virtual dispatch, inline assembly, unbounded loops and arbitrary callback "
        "reentrancy are unmodelled; an unmodelled operation does not move state.",
    ),
    Capability(
        "generated-invariant-tests",
        "partial",
        "`ingest/generated_invariant.py` reads the recovered surface and emits a "
        "complete Foundry invariant test whose handler fuzzes every state-changing "
        "function it can model. It selects `erc4626:nonzero-shares`, an explicit-"
        "owner `authorization:owner-unchanged` property, or a caller-supplied "
        "Solidity body; the handler is generated, not a skeleton.",
        "`blackheart closure foundry --generate-invariant`; "
        "tests/test_generated_invariant.py, tests/test_generated_invariant_general.py, "
        "tests/test_protocol_erc4626.py",
        "There are only three shapes. The ERC4626 shape needs a constructor-"
        "supplied asset with a mint function; a generic body is supplied by the "
        "operator, and a function whose parameters cannot be modelled is reported "
        "in `skipped`. A holding invariant is NO_FINDINGS, never a proof of safety.",
    ),
    Capability(
        "source-symbolic-reachability",
        "partial",
        "`ingest --synthesize --symbolic` converts the same OpModel into symbolic "
        "operations -- including mapping reads and writes -- and asks, breadth-first, "
        "which operations an unprivileged actor can reach and with what input. "
        "Conditional effects are split into true/false paths at the point they occur, "
        "and struct fields, array pushes and `.length` are carried into the symbolic "
        "state when the length is concrete, so a branch-gated write is explored "
        "rather than refused.",
        "`blackheart ingest <path> --synthesize --symbolic`; tests/test_symbolic.py, "
        "tests/test_synthesize.py",
        "The solver decides a bounded integer fragment; an address-like parameter is "
        "enumerated from its declared finite domain, a symbolic mapping key or a "
        "symbolic array length is reported unsupported, nested member/index bases are "
        "not modelled, and conditional effects are capped at 256 branches per "
        "operation. A path budget that runs out is not a clean result.",
    ),
    Capability(
        "sarif-interchange",
        "yes",
        "Exports the findings repository as SARIF 2.1.0 with the evidence-gated "
        "verdict, a stable content fingerprint, a record digest and the full A-J "
        "record embedded for a lossless round-trip.",
        "`blackheart findings sarif`; tests/test_sarif.py",
        "SARIF's `level` is a presentation hint. The verdict and the evidence "
        "gate travel in `properties`; a consumer that ignores them can over-read "
        "a result.",
    ),
    Capability(
        "incremental-baseline",
        "yes",
        "Creates a content-addressed finding baseline and compares a fresh "
        "repository against it: new, resolved, changed (verdict/severity) and "
        "unchanged, with `--fail-on-new` for CI.",
        "`blackheart baseline create|compare`; tests/test_baseline.py",
        "Identity is the root-cause fingerprint, so a moved root-cause line is a "
        "new identity and a new title is not. It covers findings, not raw ingest "
        "flags.",
    ),
    Capability(
        "go-cosmos-ingestion",
        "yes",
        "Scans a Go / Cosmos SDK module into packages, types, message handlers, "
        "consensus entry points, cgo/FFI boundaries and build flavors. It follows a "
        "handler's calls to the keeper that writes state (receiver fields, "
        "same-package functions, package-qualified functions through the scanned "
        "import table, and a single concrete interface implementation), reports "
        "public-build stubs (`//go:build !full`) as stubs, never as the implementation "
        "the full build runs, and maps message handlers to a Cosmos surface.",
        "`blackheart ingest <path> --language go`, `blackheart cosmos from-go <path>`; "
        "tests/test_golang_ingest.py, tests/test_golang_calls.py, tests/test_cosmos.py",
        "It is a scanner, not a compiler: an import that cannot be matched to a scanned "
        "package, an ambiguous cross-package method, embedded interfaces, generics, "
        "method values and build expressions beyond `full`/`!full` are unresolved. A "
        "delegated write into a `!full` stub is a coverage gap, never a clean result, "
        "and a message surface is not a model of the handler's accounting.",
    ),
    Capability(
        "language-coverage-gate",
        "yes",
        "Compares the stack detected from manifests and production source against the "
        "scanner that actually ran, and refuses to present a partial scan as complete. "
        "An explicit `--allow-unscanned LANG` is recorded as a partial exception, never "
        "as coverage.",
        "`blackheart ingest`, `interrogate`, `pipeline --source`; "
        "tests/test_golang_ingest.py",
        "It answers only whether a language carrying production code was opened at all. "
        "It does not prove the opened language was modelled completely.",
    ),
    Capability(
        "cosmos-reference-model",
        "partial",
        "An executable Cosmos SDK accounting target (send, delegate, undelegate, "
        "redelegate, governance deposit/withdraw, lock/unlock, slash) with supply "
        "conservation, non-negative balance, self-bond and locked-coin invariants, plus "
        "a deliberate double-credit vulnerable twin for the differential check.",
        "`blackheart cosmos model|certify`; tests/test_cosmos.py",
        "It is a reference model of the accounting shape, not a chain simulator. IBC, "
        "BeginBlock/EndBlock, governance execution, the EVM lane, cgo/FFI and slashing "
        "rounding are declared unmodelled.",
    ),
    Capability(
        "policy-temporal-scope",
        "yes",
        "Preserves a second scope window (`In scope from ...`), staged/under-remediation "
        "components and the PoC requirement through normalization, and the bounty gate "
        "refuses a staged component or an unverified effective date.",
        "`blackheart program normalize`, `blackheart bounty gate`; "
        "tests/test_policy_temporal.py, tests/test_bounty_gate.py",
        "Dates are preserved verbatim, not converted or compared to a clock; the "
        "operator must verify the effective date for the report date.",
    ),
    Capability(
        "deployment-truth",
        "partial",
        "Read-only deployed facts (chain id, block, runtime code, proxy slots, "
        "EIP-7702 designators, selectors) plus the verified source Sourcify publishes "
        "for the address, bound by its fingerprint and recompiled against the runtime.",
        "`python3 -m blackheart deployed <address>`, `blackheart closure truth`; "
        "tests/test_deployed.py, tests/test_deployed_selectors.py, "
        "tests/test_verified_pipeline.py, tests/test_deployment_truth.py",
        "The verified source is the explorer's claim until a local recompilation "
        "matches the runtime; a missing compiler or a closed implementation leaves "
        "`source_bound` false.",
    ),
    Capability(
        "verified-source-to-model",
        "partial",
        "Attests a deployment, scans its verified Solidity, synthesises the executable "
        "model, and certifies it -- status NOT_VERIFIED / UNMODELLED / BLOCKED / ERROR "
        "/ CERTIFIED / NO_VIOLATION, with the source fingerprint attached.",
        "`blackheart.ingest.verified.build_verified_model`; tests/test_verified_pipeline.py",
        "It models the source surface, not the compiled bytecode; the statement subset "
        "is the same one `ingest --synthesize` interprets, and a negative names its bound. "
        "When runtime code is supplied, a real solc/forge recompilation is attempted by "
        "default; without a compiler the binding is RECOMPILE_FAILED and source_bound stays "
        "false, never assumed. An EIP-1967/EIP-1167 proxy is resolved to its implementation.",
    ),
    Capability(
        "model-coverage-contract",
        "partial",
        "Classifies every function, statement, call edge and function-level path as "
        "MODELLED / UNMODELLED / UNREACHABLE / EXTERNAL with `file:line` evidence, "
        "carries the ledger on every certificate, hunt, portfolio and pipeline result, "
        "and refuses a clean verdict when a reachable item is outside the model. "
        "`blackheart closure coverage --source` prints it; `ingest --coverage` attaches it.",
        "`blackheart.ingest.model_coverage`; tests/test_model_coverage.py",
        "Path coverage is function-level: branch enumeration is the certifier's bounded "
        "job, not this ledger's. A hand-written registry target has no source statement "
        "ledger, so its coverage is declared complete by construction. An unresolved "
        "external call remains EXTERNAL until a protocol link resolves it.",
    ),
    Capability(
        "autonomous-source-pipeline",
        "partial",
        "Runs source -> model -> certify -> price -> independent re-run -> optional "
        "Foundry PoC -> evidence-backed finding from a local .sol tree, with no "
        "human-authored hypothesis and no deployment address. The certifier enumerates "
        "every declared invariant, the value engine ranks the witnesses, a fresh model "
        "re-runs the selected one, and an optional guarded source contract supplies the "
        "control. With --protocol every recovered contract is composed into one target "
        "and caller->callee links are inferred from source. A local run never claims a "
        "deployment binding.",
        "`blackheart.pipeline.run_source_pipeline`, `blackheart pipeline --source "
        "[--protocol]`; tests/test_pipeline_source.py, tests/test_protocol_pipeline.py",
        "The hypothesis is only as good as the declared invariants and the modelled "
        "statement subset; a source-only run cannot establish on-chain scope or "
        "authorization, so its strongest honest status is REPRODUCED unless the operator "
        "declares both. Protocol inference is source-regex unless a compiler call graph "
        "is supplied, and a model-level reproduction is not a Foundry PoC unless --poc "
        "runs and passes. Severity/payout still come from the official policy.",
    ),
    Capability(
        "verified-source-to-finding",
        "partial",
        "Runs the whole loop in one command: attest, synthesise, certify, price, "
        "independently re-run in a fresh model against an optional guarded control, "
        "and write an evidence-backed finding. CONFIRMED only when the verifier's "
        "disposition is INDEPENDENTLY_VERIFIED and scope/authorization are established; "
        "otherwise STRONGLY_SUPPORTED with the missing check named.",
        "`blackheart.pipeline`, `blackheart pipeline`; tests/test_pipeline.py",
        "The reproduction is model-level by default, not a Foundry PoC; the statement subset "
        "and certifier depth bound what can be found. A guarded control, explicit scope and "
        "a runtime-bound deployment truth record are required for CONFIRMED on an address "
        "target; severity is unrated because the program policy decides it. Source-level PoC "
        "and mutation audit are opt-in, and a PoC that cannot be rendered is reported rather "
        "than invented.",
    ),
    Capability(
        "source-to-runtime-binding",
        "partial",
        "Writes verified Sourcify files into a temporary Foundry/solc project, compiles "
        "the selected contract's import closure, and compares the runtime bytecode with "
        "the deployed runtime after stripping solc metadata. It discovers Foundry "
        "`foundry.toml`/`remappings.txt` and ancestor `node_modules`, selects an exact "
        "`solc-<version>` when the pragma requires one, and names the compiler's "
        "unresolved import. `build_verified_model` attempts this by default whenever "
        "runtime code is supplied.",
        "`blackheart.ingest.solc`, `build_verified_model`; tests/test_solc.py, "
        "tests/test_verified_pipeline.py",
        "It still requires a compiler on the host and a resolvable dependency tree; a missing compiler is "
        "RECOMPILE_FAILED, never source_bound. The source is still the explorer's verified "
        "bundle, and a metadata-only match is not a proof of semantic equivalence.",
    ),
    Capability(
        "source-level-foundry-poc",
        "partial",
        "Renders the certifier's witness as a Foundry test that imports the verified source, "
        "calls the contract through its ABI and asserts a conservation, authorization, "
        "solvency or bounded-field invariant through public getters; supports supplied "
        "constructor arguments, helper deployments, a minimal delegatecall proxy, a "
        "deployed-address target and fork flags; runs it behind the compatibility gate and "
        "reports PASS/FAIL/BLOCKED/INCOMPLETE.",
        "`blackheart.pocgen`, `blackheart pipeline --poc`, `blackheart closure poc`; "
        "tests/test_pocgen.py, tests/test_foundry_backend.py",
        "Only four invariant forms have a generated assertion; constructor arguments and "
        "helpers must be supplied, never inferred; the proxy has no admin/upgrade semantics; "
        "the conservation assertion still names two accounts rather than every holder; and a "
        "PASS is a reproduction, not a priced finding. A compile failure is INCOMPLETE, never "
        "a proof.",
    ),
    Capability(
        "multi-contract-composition",
        "partial",
        "Namespaces several synthesized contracts into one ProtocolTarget and applies "
        "explicit caller->callee links, or source-inferred links with `--infer`, using the "
        "same actor and shared parameters. Statement-level external calls run in source "
        "order with the caller's context, a reverting callee reverts the caller, and a "
        "single unconditional callee return value can be assigned in the caller. An "
        "interface- or base-typed receiver resolves to the one concrete contract that "
        "implements it; two candidates are reported as ambiguous, never guessed. A "
        "link with a missing callee parameter is refused rather than fabricated as zero.",
        "`blackheart.ingest.protocol`, `blackheart closure protocol`, "
        "`blackheart pipeline --source --protocol`; tests/test_protocol.py, "
        "tests/test_protocol_semantics.py, tests/test_protocol_pipeline.py",
        "Inference is source-regex unless `--compiler-callgraph` is supplied: an "
        "interface with no supplied implementation, single-contract virtual dispatch and "
        "inline assembly are unresolved, and ambiguous receivers are reported rather than "
        "guessed. A call with no known "
        "outcome is `UNMODELLED` and aborts the path. Reentrancy is modelled only as a "
        "`nonReentrant` guard and a bounded call stack; arbitrary callback ordering is "
        "not explored. Each contract keeps its own unmodelled surface, and protocol "
        "source PoCs render only the four supported invariant forms.",
    ),
    Capability(
        "distinct-engine-verification",
        "partial",
        "Records the producer and verifier engine on every independent re-run. With "
        "`--require-independent-engine`, a same-engine or unrecorded replay is "
        "REPRODUCED, not INDEPENDENTLY_VERIFIED; a passing Foundry PoC supplies the "
        "distinct `foundry` engine. A finding can only be CONFIRMED after the strict "
        "gate passes.",
        "`blackheart.statespace.verify.VerificationIndependence`, "
        "`blackheart pipeline --require-independent-engine`; "
        "tests/test_verification_independence.py",
        "Strict mode is opt-in; the legacy default still treats a fresh instance as an "
        "independent re-run. A PoC that cannot be rendered or a host without forge "
        "leaves the result REPRODUCED, never confirmed.",
    ),
    Capability(
        "guarded-control-automation",
        "partial",
        "Builds a control model from a verified address, a shallow-fetched pinned commit, or "
        "an automatically discovered descendant commit touching named paths; replays the exact "
        "witness on both models and distinguishes CONTROL_CLEAN, CONTROL_ALSO_VULNERABLE and "
        "NO_VIOLATION.",
        "`blackheart.control`, `blackheart closure control`; tests/test_control.py",
        "Discovery is bounded to a commit depth and only finds a later commit touching the "
        "named paths; it does not prove the commit is the security fix. The comparison is "
        "model-level unless the same witness is also run as a PoC.",
    ),
    Capability(
        "invariant-mutation-audit",
        "partial",
        "Mutates the target's state after each operation and re-certifies the mutant, "
        "reporting CAUGHT (the invariant noticed) or SURVIVED (the clean result is weak "
        "evidence); class-specific families cover accounting, arithmetic, access-control, "
        "oracle, governance and reentrancy fields.",
        "`blackheart.assurance.mutation`, `blackheart pipeline --mutation-audit`, "
        "`blackheart closure mutate --class`; tests/test_mutation_audit.py",
        "Operators are still state mutations, not guard removal or source edits. A survivor "
        "is a warning about the invariant, not a vulnerability; the audit does not prove the "
        "original target safe.",
    ),
    Capability(
        "market-ordering-economics",
        "partial",
        "Prices a constant-product swap and sandwich, single- and multi-range "
        "Uniswap-V3 exact-input swaps and sandwiches with tick crossing, a static "
        "order-book sandwich, a utilisation-driven "
        "lending curve, a best-venue quote, a builder-bundle auction with gas, "
        "priority fee, bribe, inclusion probability, failed-transaction and capital "
        "costs, and a competitive order-flow bid ladder that prices the fraction of "
        "declared competitors outbid, the expected value and the optimal threshold "
        "bid; the live V2 path reads real reserves "
        "and the live V3 path reconstructs initialized tick ranges from slot0, "
        "liquidity and the tick bitmap, read-only, searches attacker sizes for the "
        "best measured sandwich, prices operator-supplied gas, bribe, inclusion, "
        "failed-transaction, capital and competitor costs, and can execute the "
        "selected candidate on a pinned Foundry fork, so a gross gain is not "
        "mistaken for a net profit.",
        "`blackheart.value.market`, `blackheart.value.orderflow`, "
        "`blackheart closure market`; tests/test_market.py, tests/test_orderflow.py",
        "Order-book depth is static and does not model queue position or latency; the "
        "order-flow ladder is declared by the operator, not observed from a mempool, "
        "and a competitor's response, private order flow and builder policy are not "
        "modelled; the "
        "lending curve is not a live oracle. V3 ranges are operator-supplied for the "
        "deterministic model and reconstructed from a bounded live bitmap window for "
        "live-v3; gas and inclusion are operator inputs, not measurements, and an "
        "unconvertible gas cost is left unpriced. The model does not route through a "
        "V3 router; the fork validator does, for one candidate at one pinned block. "
        "Competition is a static competitor bid/outbid, not a live searcher game. "
        "Queue position, latency, competing-searcher strategy, cross-venue routing "
        "and live bundle inclusion are not modelled. A profitable model is not a "
        "live opportunity.",
    ),
    Capability(
        "policy-aware-planning",
        "partial",
        "Filters the objective catalog through a normalized program policy, keeping "
        "allowed, explicitly excluded and unknown classes separate; an unverified policy "
        "is advisory only.",
        "`blackheart.planning`, `blackheart closure plan`; tests/test_planning.py",
        "The policy must be normalized and its provenance supplied; the planner does not "
        "fetch or verify the policy itself, and an unknown class is never silently allowed.",
    ),
    Capability(
        "bounded-parallel-corpus",
        "yes",
        "Runs independent tasks in a bounded thread pool with per-task error capture and "
        "input-order results; keeps a deduplicated, hash-chained corpus with resumable "
        "pending work, explicit invalidation, portable shard export/merge and an epoch-fenced "
        "lease queue for shared-filesystem workers.",
        "`blackheart.parallel`, `blackheart.corpus`, `blackheart closure corpus`; "
        "tests/test_parallel_corpus.py",
        "The lease queue is a shared-filesystem protocol, not a network service: workers on "
        "different volumes do not share a queue, and shards are offline files. The corpus is "
        "a store of results, not a search strategy, and a stale result must be invalidated "
        "explicitly.",
    ),
    Capability(
        "independent-reviewer-use",
        "partial",
        "Asks the resolved distinct, verified reviewer provider directly and records "
        "INDEPENDENT / UNAVAILABLE / ERROR; an absent reviewer is never replaced by the "
        "primary model.",
        "`blackheart.reviewer`, `blackheart closure review`; tests/test_reviewer_use.py",
        "Requires a separately authenticated, probed provider serving different weights. "
        "With none configured the answer is UNAVAILABLE, and same-model review must be "
        "requested and recorded as SAME_MODEL.",
    ),
    Capability(
        "bytecode-witness-replay",
        "yes",
        "Replays a symbolic witness on the concrete EVM and compares the halt status and "
        "declared storage slots, returning VERIFIED / DIVERGED / INCOMPLETE.",
        "`blackheart.bytecode`, `blackheart closure bytecode`; tests/test_bytecode_witness.py",
        "It proves reachability of the recorded terminal outcome on one message call, not "
        "the source-level cause or a multi-call stateful sequence.",
    ),
    Capability(
        "bytecode-symbolic-execution",
        "partial",
        "Bounded symbolic execution over runtime bytecode: forks on a symbolic JUMPI, "
        "asks the solver for a witness, and reproduces it on the concrete EVM; constant "
        "arithmetic wraps at 256 bits, shifts/SIGNEXTEND/BYTE/ADDMOD/MULMOD/EXP fold, "
        "SHA3 of concrete memory is computed, and `evm_fuzz` diffs a vulnerable and a "
        "guarded revision with coverage-guided mutation.",
        "`blackheart.symbolic.evm`, `blackheart.evm_fuzz`; tests/test_symbolic_evm.py, "
        "tests/test_evm_fuzz.py",
        "Symbolic arithmetic is unbounded by default. `--wrap` forks ADD/SUB/MUL on their "
        "256-bit overflow/underflow case, so those paths become reachable; symbolic AND/OR/XOR "
        "are carried with sound interval bounds, while symbolic EXP and division stay "
        "unbounded. A path that hits a call, a symbolic memory offset or a symbolic SHA3 is "
        "reported as `unsupported`, never cleared.",
    ),
    Capability(
        "witness-to-poc",
        "partial",
        "Renders a runnable Foundry test from a symbolic witness or a differential "
        "divergence: it etches the runtime bytecode at a fixed address, calls it with the "
        "witness calldata, and asserts the recorded terminal outcome or the twin contrast.",
        "`blackheart.symbolic.poc`, `blackheart symbolic-evm --poc-out`, "
        "`blackheart evm-diff --poc-out`; tests/test_poc.py, tests/test_cli_evm.py",
        "It writes the test, it does not compile or run it; the caller still runs "
        "`forge test`, and a witness for a non-revert terminal state only proves "
        "reachability, not impact.",
    ),
    Capability(
        "witness-poc-execution",
        "partial",
        "Writes a rendered PoC into a minimal Foundry project and runs `forge test` only "
        "after the language-aware gate admits the target, reporting PASS / FAIL / "
        "BLOCKED / INCOMPLETE. A blocked run never invokes forge.",
        "`blackheart.symbolic.poc_runner`, `blackheart poc run`; "
        "tests/test_poc_runner.py",
        "It needs forge installed and a compatibility record bound to the target. A PASS "
        "means the witness reproduced; it does not price the impact or prove a finding.",
    ),
    Capability(
        "calldata-minimization",
        "yes",
        "Deterministic delta debugging over 32-byte calldata words: zero, halve, clear a "
        "bit or drop a word while the caller's predicate still holds, so a report carries "
        "the smallest reproducer the search found.",
        "`blackheart.symbolic.minimize`, `symbolic-evm --minimize`, "
        "`evm-diff --minimize`; tests/test_minimize.py, tests/test_cli_evm.py",
        "It is a bounded search over an arbitrary predicate, so it returns a smaller "
        "reproducer, not a proven minimal one.",
    ),
    Capability(
        "storage-layout-diff",
        "yes",
        "Parses solc `storageLayout` JSON, extracts it from a Foundry build-info or solc "
        "combined JSON, and reports added, removed, moved and type-changed variables with "
        "an explicit compatibility verdict: an append is safe, an insert or a type change "
        "is not.",
        "`blackheart.ingest.storage_layout`, `blackheart layout diff`, "
        "`blackheart layout extract`; tests/test_storage_layout.py",
        "It compares the layout JSON the caller supplies; it does not fetch the layout "
        "or prove that the deployed storage matches it.",
    ),
    Capability(
        "symbolic-256-bit-arithmetic",
        "partial",
        "With `--wrap`, a symbolic ADD, SUB or MUL forks into its non-overflow and "
        "overflow/underflow cases, each with the wrapped 256-bit result.",
        "`blackheart.symbolic.evm._wrap_add/_wrap_sub`; tests/test_symbolic_evm.py",
        "Only ADD/SUB/MUL are wrapped and only when the flag is on; symbolic EXP and "
        "division remain unbounded integers, while AND/OR/XOR are carried as bounded "
        "bitwise expressions.",
    ),
    Capability(
        "vyper-model-synthesis",
        "partial",
        "Translates a Vyper module into the same ContractSurface the Solidity "
        "interpreter consumes, so it reaches the same model and certifier.",
        "`blackheart.ingest.vyper_synth`; tests/test_vyper_synth.py",
        "Same fixed statement subset as Solidity synthesis; loops and raw calls are "
        "unmodelled, and the translation does not type-check Vyper.",
    ),
    Capability(
        "cross-target-transfer",
        "partial",
        "Records the assumptions a certificate relied on (required operations, actor "
        "count) and refuses a transfer the new target cannot satisfy; "
        "`transfer_decisions` explains each accept or refusal.",
        "`blackheart.learning.transfer`; tests/test_transfer_provenance.py",
        "Assumptions are structural, not semantic: a transfer is a seed a human still "
        "has to verify against the real contract.",
    ),
    Capability(
        "rust-substrate-ingestion",
        "yes",
        "Scans a Rust crate or pallet into dispatchables, weights, storage items and "
        "bodies, and rule-matches them into category-linked leads.",
        "`python3 -m blackheart ingest <crate> --language rust`; tests/test_ingest_rust.py",
        "Lexer-grade: it does not expand macros, resolve trait bounds or type-check. A "
        "dispatchable it fails to recognise is a blind spot, reported in `errors`.",
    ),
    Capability(
        "solana-anchor-ingestion",
        "partial",
        "Recovers a Solana/Anchor program's instruction handlers (the `#[program]` entry "
        "points and every `Context<T>` handler) and their `#[derive(Accounts)]` structs "
        "with per-field constraints, including multi-line attributes and cross-field "
        "`has_one` bindings, then emits category-linked leads for an unbound writable "
        "raw account and an unchecked CPI.",
        "`python3 -m blackheart ingest <program> --language rust`; tests/test_ingest_anchor.py",
        "It sees the account-validation surface, not the Solana runtime: the account "
        "data layout, CPI return values and the semantics of the invoked venue program "
        "are outside the model, and a `/// CHECK:` comment is a claim, not a check. A "
        "`has_one`/`constraint` in another field clears the account lead, so a lead is "
        "a place to read the handler, never a finding.",
    ),
    Capability(
        "assumption-interrogation",
        "yes",
        "Derives the claims the code makes and attempts to falsify each one, in "
        "Solidity, Rust/Substrate and Solana/Anchor. On Anchor the authorization "
        "claim is judged against the `#[derive(Accounts)]` struct, not the handler "
        "body, and FRAME weights are not claimed.",
        "`python3 -m blackheart interrogate <path>`; tests/test_interrogate.py, "
        "tests/test_ingest_anchor.py",
        "A SURVIVED verdict is a static check that found no counterexample, never a "
        "proof; each verdict prints what it could not see, and UNTESTABLE is kept "
        "distinct from clean.",
    ),
    Capability(
        "linear-arithmetic",
        "yes",
        "Proves a conjunction of linear inequalities UNSAT and tightens variable "
        "bounds; the symbolic solver uses it to prune infeasible branches.",
        "`blackheart.symbolic.linear`; tests/test_linear_solver.py",
        "Linear only: a product of two variables or a non-linear guard is not decided.",
    ),
    Capability(
        "runtime-binding",
        "partial",
        "Recompiles verified source and compares it to the deployed runtime, stripping "
        "the CBOR metadata tail; resolves EIP-1967 and EIP-1167 proxies.",
        "`blackheart.ingest.verified`; tests/test_verified_pipeline.py",
        "The recompiler is caller-supplied; a source that does not reproduce the "
        "runtime is reported, never silently treated as the deployed code.",
    ),
    Capability(
        "decompiled-surface",
        "partial",
        "Recovers a closed component's function names, selectors and parameters from "
        "decompiler text and records every body as unmodelled.",
        "`blackheart ingest.decompiled`, `blackheart verified-model --decompiled`; "
        "tests/test_decompiled_ingest.py",
        "A surface, not semantics: reachability can be asked, effects cannot.",
    ),
    Capability(
        "amm-venue-simulation",
        "partial",
        "Constant-product pricing with basis-point fees, multi-hop routing, an exact "
        "sandwich accounting of attacker profit and victim loss, and a gas charge "
        "against the gross profit.",
        "`blackheart.venues.amm`; tests/test_venues_amm.py",
        "Each hop is one constant-product pool; this AMM model has no order book or MEV "
        "bundle (a separate static order-book model exists but is not routed through the "
        "AMM), and it does not automatically convert the profit asset into the gas asset.",
    ),
    Capability(
        "closed-source-components",
        "partial",
        "The decompiler recovers a closed component's function surface; its effects "
        "stay unmodelled.",
        "`blackheart.ingest.decompiled`; tests/test_decompiled_ingest.py",
        "A bug whose semantics live in the closed body is still invisible.",
    ),
    Capability(
        "foundry-execution-backend",
        "yes",
        "Writes an arbitrary source tree and a caller-supplied Foundry test, compiles and "
        "runs it with the real toolchain behind the compatibility gate, and reports "
        "PASS/FAIL/BLOCKED/INCOMPLETE with optional fork URL and block.",
        "`blackheart.ingest.foundry`, `blackheart.symbolic.poc_runner`; "
        "tests/test_foundry_backend.py, tests/test_poc_runner.py",
        "It is a test runner, not a semantics engine: the caller must supply the test and "
        "the project setup, or use `--auto` to generate one from a renderable witness. A "
        "PASS proves that test, not the protocol's safety.",
    ),
    Capability(
        "fork-stateful-poc",
        "partial",
        "A generated source PoC can target a deployed address and run with `--fork-url` and "
        "`--fork-block`, so the sequence executes against real chain state instead of a "
        "locally deployed copy. `closure scenario` additionally renders a declarative "
        "multi-call fork test with funded callers, value, expected reverts and balance-delta "
        "assertions.",
        "`blackheart.pocgen`, `blackheart.symbolic.poc_runner`, `blackheart.fork_scenario`, "
        "`blackheart pipeline --rpc --poc`, `closure scenario`; tests/test_pocgen.py, "
        "tests/test_fork_scenario.py",
        "The fork is read-only unless Foundry impersonates accounts; the generated test covers "
        "conservation, authorization, solvency or a bounded field on one contract surface. A "
        "scenario is low-level calldata (no ABI encoder), asserts call success/revert and "
        "balance deltas, and runs at one pinned block. A fork RPC is an external dependency.",
    ),
    Capability(
        "economic-simulation-of-external-venues",
        "partial",
        "A constant-product AMM venue prices a trade, a multi-hop path and a sandwich, "
        "with a gas charge; the closure market model adds a single-range Uniswap-V3 pool, "
        "a static order book, a lending curve, a best-venue quote and a builder-bundle "
        "auction.",
        "`blackheart.venues.amm`, `blackheart.value.market`; tests/test_venues_amm.py, "
        "tests/test_market.py",
        "Order-book depth is static, so queue position and latency are not tested. "
        "Uniswap-V2 reserves can now be fetched read-only and compared across pairs; V3 is "
        "a single-range model, and cross-tick routing and live bundle inclusion are not "
        "modelled.",
    ),

    Capability(
        "cross-contract-callgraph-inference",
        "partial",
        "Infers caller -> callee edges from explicit receiver types, a state "
        "variable's interface/base type with exactly one concrete implementation, "
        "and a receiver function name that only one known concrete contract exposes; "
        "ambiguous receivers are reported unresolved. `--compiler-callgraph` replaces "
        "the regex pass with Slither's compiler call graph when Slither is installed.",
        "`blackheart.ingest.callgraph`, `closure protocol --infer --compiler-callgraph`; "
        "tests/test_callgraph.py",
        "The default is source-regex inference. The compiler path needs Slither and "
        "still does not resolve an interface with no supplied implementation, a "
        "base type with more than one concrete implementation, or inline assembly; "
        "an unavailable dot file is a named gap, never a guessed edge.",
    ),
    Capability(
        "deployment-planning",
        "partial",
        "Reads constructor signatures, plans a target, helpers and a minimal proxy, "
        "and blocks with the missing argument names instead of defaulting them.",
        "`blackheart.ingest.deploy`, `closure deploy-plan`; tests/test_deploy_plan.py",
        "Constructor arguments and helper wiring are still supplied by the operator; "
        "no automatic dependency graph or proxy-admin setup is inferred.",
    ),
    Capability(
        "semantic-equivalence-checks",
        "partial",
        "Adds ABI-selector evidence to a metadata-stripped runtime match, and can "
        "compare the compiled storage layout and a canonical AST fingerprint against "
        "a supplied expected layout/AST: source selectors missing from the deployed "
        "dispatcher, moved storage slots and a changed semantic AST are reported.",
        "`blackheart.ingest.equivalence`, `closure equivalence --storage-layout --ast`; "
        "tests/test_equivalence.py",
        "PUSH4 scanning is a heuristic. Layout and AST checks compare against an "
        "expected artifact, not the deployed bytecode, so they do not prove that the "
        "deployment's semantics equal the source; extra deployed selectors are "
        "reported, not failed.",
    ),
    Capability(
        "live-market-data",
        "partial",
        "Fetches Uniswap-V2 reserves and reconstructs a Uniswap-V3 pool's initialized "
        "tick ranges from slot0, liquidity, fee, spacing and the tick bitmap over "
        "read-only eth_call, then prices a sandwich, searches attacker sizes, "
        "prices gas/bribe/inclusion/failure/capital/competition, and can execute the "
        "selected candidate on a pinned Foundry fork.",
        "`blackheart.value.live`, `blackheart.value.live_v3`, `closure market --model "
        "live|live-v3`; tests/test_live_market.py, tests/test_live_v3.py",
        "The V3 snapshot is bounded by the scanned bitmap window (marked INCOMPLETE "
        "when truncated); gas, inclusion, failure/capital costs and a competitor "
        "bid are operator-supplied and a fork validation is one candidate at one "
        "pinned block. Queue position, latency, competing-searcher strategy, router "
        "routing and live bundle inclusion are not modelled.",
    ),
    Capability(
        "distributed-lease-queue",
        "yes",
        "A hash-chained work queue with worker leases, monotonic epochs, stale-lease "
        "recovery and dead-lettering, usable across processes on one shared volume.",
        "`blackheart.distributed`, `closure corpus --queue-claim`; tests/test_distributed_queue.py",
        "It is a shared-filesystem protocol, not a network service: workers on different "
        "volumes do not share a queue.",
    ),
    Capability(
        "local-reviewer-model",
        "yes",
        "An optional local Ollama OpenAI-compatible provider can serve as a reviewer "
        "without a cloud account; it still passes the distinct-model and liveness gates.",
        "`blackheart.providers.registry`, `blackheart.providers.router`; "
        "tests/test_reviewer_optional.py",
        "It requires a local Ollama install and a model distinct from the primary; a "
        "missing or unverified local model is never reported as independent.",
    ),
    Capability(
        "multi-invariant-source-poc",
        "partial",
        "Renders and runs source-level PoCs for conservation, authorization, solvency "
        "and bounded-field invariants, with constructor args, helpers, proxy and fork.",
        "`blackheart.pocgen`, `closure foundry --auto`; tests/test_pocgen.py, "
        "tests/test_foundry_backend.py",
        "Only four invariant forms are rendered, on a single contract surface; a "
        "non-renderable invariant is UNSUPPORTED, never guessed.",
    ),
    Capability(
        "deployment-binding",
        "partial",
        "One command resolves a live RPC, fetches the verified source, proves it is "
        "bound to the deployed runtime, recovers the component surface, compiles the "
        "source as a fail-closed smoke test and emits a complete compatibility record "
        "plus a loadable record sidecar. A missing repository, commit, verified source, "
        "component or passing smoke test blocks the record.",
        "`blackheart deployment bind`; tests/test_deployment_binding.py",
        "The binding proves the verified source reproduces this runtime and compiles; "
        "it does not prove semantic equivalence, does not see inside a closed "
        "implementation, and needs a native compiler on the host.",
    ),
    Capability(
        "deployment-truth-join",
        "partial",
        "Joins chain facts, proxy implementation and verified source into one record "
        "with SOURCE_VERIFIED / IMPLEMENTATION_VERIFIED / BYTECODE_ONLY / UNVERIFIED, "
        "carries the recompiled runtime binding and exposes a fail-closed gate that "
        "requires EXACT or METADATA_ONLY. A finding whose target names a deployed "
        "address cannot be CONFIRMED without that gate, and the bounty gate refuses a "
        "`deployment_verified` claim without it.",
        "`blackheart.ingest.truth`, `blackheart closure truth`, "
        "`blackheart findings confirm --deployment-truth`, `blackheart bounty gate`; "
        "tests/test_deployment_truth.py, tests/test_bounty_gate.py",
        "The gate proves the verified source reproduces this runtime, not that the "
        "runtime is safe; a closed implementation remains opaque.",
    ),
)


@dataclass(frozen=True)
class Diagnosis:
    gap: str
    impact: str
    status: str
    fix: str


DIAGNOSIS: tuple[Diagnosis, ...] = (
    Diagnosis(
        "No repo-to-surface path",
        "Every mission began with hand-transcription, which is slow and skips code.",
        "fixed",
        "`blackheart ingest` now extracts contracts, functions, guards and call sites.",
    ),
    Diagnosis(
        "No rule engine over real source",
        "Weakness shapes were noticed by eye, inconsistently.",
        "fixed",
        "Twelve category-linked rules with line-level evidence.",
    ),
    Diagnosis(
        "No capability statement",
        "The engine could imply coverage it did not have.",
        "fixed",
        "`blackheart capability` prints this matrix; the mission reads it first.",
    ),
    Diagnosis(
        "No Solidity execution in-engine",
        "Reproduction was manual Foundry work, so throughput was one hypothesis at a time.",
        "partial",
        "Gated `forge test` runner added; the tool and a completed harness are still required.",
    ),
    Diagnosis(
        "A source-only investigation still needed a human to state the hypothesis",
        "The certifier could find a witness, but an operator had to choose the target, "
        "build the model, pick the invariant and decide whether the result was worth a "
        "finding.",
        "fixed",
        "`run_source_pipeline` scans a local tree, synthesises the model, enumerates every "
        "declared invariant, prices each witness, selects the strongest, re-runs it in a "
        "fresh model against an optional guarded source control, optionally runs a Foundry "
        "PoC, and writes the evidence-backed record. It never upgrades a local model to a "
        "deployment claim.",
    ),
    Diagnosis(
        "Source surfaces were recovered only by a lexer",
        "Inheritance, struct fields, parameter types and return types were re-derived from text, "
        "so a construct the lexer missed became an unmodelled function with no trace of why.",
        "fixed",
        "`ingest/ast_surface.py` maps a solc source-unit AST into the same ContractSurface model; "
        "`pipeline --source --ast FILE` uses it directly and `--compiler-ast` compiles first. "
        "A missing compiler or AST falls back to the lexer with a named reason.",
    ),
    Diagnosis(
        "No model synthesis",
        "The executable model was authored by hand for every target.",
        "partial",
        "OpSpecs are derived from function surfaces and a statement subset is interpreted; "
        "arbitrary Solidity is still not modelled.",
    ),
    Diagnosis(
        "No deployment-to-model path",
        "A verified deployment still had to be transcribed into a Target by hand.",
        "fixed",
        "`ingest/verified.py` attests, scans, synthesises and certifies one address, "
        "bound by the source fingerprint.",
    ),
    Diagnosis(
        "No verified-source diff",
        "Deployed code, proxies and selectors are verified read-only; verified source "
        "is fetched, but it was not recompiled and compared to the runtime bytecode.",
        "fixed",
        "`ingest/verified.py` rebuilds the source through a caller-supplied recompiler, "
        "strips the CBOR metadata tail, reports EXACT / METADATA_ONLY / MISMATCH, and "
        "resolves EIP-1967/EIP-1167 proxies.",
    ),
    Diagnosis(
        "No linear arithmetic in the solver",
        "A contradiction between two linear guards could survive as UNKNOWN, wasting "
        "the exploration budget on an infeasible branch.",
        "fixed",
        "`symbolic/linear.py` proves a linear conjunction UNSAT and tightens bounds; "
        "the solver consults it before enumerating.",
    ),
    Diagnosis(
        "Closed components are a blank wall",
        "A bug in a closed layer was invisible to every engine.",
        "partial",
        "A decompiler's function surface is now parsed into the same model, but its "
        "bodies stay unmodelled; only reachability can be asked.",
    ),
    Diagnosis(
        "No venue or ordering economics",
        "A transaction-ordering bug had no way to be priced.",
        "partial",
        "`venues/amm.py` prices a constant-product swap and a sandwich exactly; an "
        "order book and multi-venue routing are still absent.",
    ),
    Diagnosis(
        "A witness stopped at a printed assignment",
        "A solver witness proved reachability but left the reproduction to hand-written "
        "Foundry work, so the loop from witness to PoC stayed manual.",
        "fixed",
        "`symbolic/poc.py` renders a Foundry test that etches the runtime bytecode and "
        "calls it with the witness calldata; `symbolic-evm --poc-out` writes it.",
    ),
    Diagnosis(
        "A rendered PoC still needed a human to run it",
        "The test existed but nothing compiled or executed it, so a witness could sit "
        "between a lead and a reproduction indefinitely.",
        "fixed",
        "`blackheart poc run` writes the test into a minimal Foundry project and runs "
        "`forge test` behind the compatibility gate; a blocked run never invokes forge, "
        "and a PASS is recorded as a reproduced witness, not a finding.",
    ),
    Diagnosis(
        "A reproducer carried noise that buried the signal",
        "A 4 KB fuzz input or a 200-word calldata made the report harder to read and the "
        "cause harder to see.",
        "fixed",
        "`--minimize` delta-debugs the calldata while the divergence or the terminal "
        "outcome still holds; the PoC is rendered from the minimized input.",
    ),
    Diagnosis(
        "Equal runtime bytecode hid a storage-layout break",
        "A proxy upgrade can keep the bytecode identical and still move every variable "
        "below an inserted slot, which a bytecode comparison cannot see.",
        "fixed",
        "`ingest/storage_layout.py` and `blackheart layout diff` report added, removed, "
        "moved and type-changed variables, and refuse compatibility on a move; "
        "`layout extract` pulls the layout straight out of a build-info.",
    ),
    Diagnosis(
        "Symbolic arithmetic could not overflow",
        "An overflow-dependent path was invisible because symbolic ADD/SUB were modelled "
        "over unbounded integers.",
        "partial",
        "`symbolic-evm --wrap` forks ADD/SUB/MUL on the 256-bit overflow/underflow case, "
        "and symbolic AND/OR/XOR are carried with sound bounds; symbolic EXP and division "
        "are still unbounded.",
    ),
    Diagnosis(
        "Ordering economics stopped at one pool",
        "A multi-hop route or a gas bill could turn a nominal sandwich into a loss, and "
        "the venue could not express either.",
        "partial",
        "`venues/amm.py` now chains hops and charges gas against the gross profit; an "
        "order book and an MEV bundle remain absent.",
    ),
    Diagnosis(
        "Go handlers stopped at the handler body",
        "A Cosmos message handler usually delegates its state write to a keeper, so a "
        "body-only scan reported no write for the exact path an unprivileged account "
        "reaches.",
        "partial",
        "`ingest/golang_calls.py` follows receiver fields, same-package functions, "
        "package-qualified calls through the scanned import table and a single concrete "
        "interface implementation to a bounded depth. An unmatched import, an ambiguous "
        "cross-package method, embedded interfaces, generics and method values remain "
        "unresolved, and the report says so.",
    ),
    Diagnosis(
        "Only three environments are scannable",
        "Solidity, Rust/Substrate and Go/Cosmos are ingested. Vyper reaches the model "
        "but has no rule engine; Move, Cairo and JavaScript services are detected by "
        "`compat detect` but have no scanner here.",
        "open",
        "Add a scanner and a rule set per environment, reusing the flag and "
        "interrogation contracts so a new language cannot invent a new verdict.",
    ),
)


def as_dict() -> dict:
    return {
        "can_find_payable_bug_unaided": False,
        "verdict": (
            "Partially capable. BLACKHEART drives the methodology, models 27 of 30 objective categories, "
            "searches state machines, ingests real source, synthesises an executable model "
            "for a common statement subset (branches, struct fields, arrays, inheritance, "
            "source-ordered requires, bounded loop unrolling, statement-level external "
            "calls), certifies a model built from a verified deployment, binds a "
            "recompilation to the deployed runtime, recovers a closed component's surface, "
            "reasons symbolically over source and runtime bytecode within a bound "
            "(path-sensitive conditional effects, constant wrapping, opt-in 256-bit ADD/SUB "
            "overflow, SHA3 of concrete memory, linear pruning), renders and runs a Foundry "
            "PoC, diffs a storage layout, prices a multi-hop constant-product sandwich net "
            "of gas, prices single- and multi-range V3 swaps with tick crossing, reads live "
            "V2 reserves, plans a deployment, infers unambiguous call "
            "links (optionally from Slither's compiler graph) and leases work across "
            "workers, traces whole-program taint, routes bytecode to anvil with a "
            "labelled local fallback, and discharges symbolic paths with optional Z3. "
            "It still cannot compile or execute arbitrary Solidity itself, "
            "cannot model arbitrary statements, conditional external-call returns "
            "across mixed tuple declarations, single-contract virtual dispatch, symbolic EXP "
            "or a symbolic array length, and "
            "cannot read the semantics of a closed body. A payable bug therefore still "
            "needs a human hypothesis and a real reproduction."
        ),
        "capabilities": [
            {
                "name": c.name,
                "status": c.status,
                "what_it_does": c.what_it_does,
                "evidence": c.evidence,
                "limitation": c.limitation,
            }
            for c in CAPABILITIES
        ],
        "diagnosis": [
            {"gap": d.gap, "impact": d.impact, "status": d.status, "fix": d.fix}
            for d in DIAGNOSIS
        ],
    }


def render_markdown() -> str:
    lines = ["# What BLACKHEART can and cannot do", ""]
    lines.append(
        "> Can it find a payable bug unaided? **No.** It can drive the method, model the "
        "classes, search state machines, read real source, synthesise a model for a common "
        "statement subset (branches, struct fields, arrays, inheritance, source-ordered "
        "requires, bounded loops, statement-level external calls), bind a recompilation "
        "to deployed runtime, recover a closed component's surface, reason symbolically "
        "over bytecode within a bound, render and run a Foundry PoC, diff a storage "
        "layout, compare an AST fingerprint, price a sandwich net of gas, fetch live V2 "
        "reserves and reconstruct live V3 tick ranges, plan a deployment, infer "
        "unambiguous call links and lease work across "
        "workers, traces whole-program taint, routes bytecode to anvil with a labelled "
        "local fallback and uses optional Z3 for symbolic paths. It cannot model arbitrary "
        "statements, external-call "
        "return values, single-contract virtual dispatch or symbolic EXP, prove deployed semantic "
        "equivalence, or read the semantics of a closed body, so a human still owns the "
        "final judgement."
    )
    lines.append("")
    lines.append("## Capabilities")
    lines.append("")
    lines.append("| status | capability | evidence | limitation |")
    lines.append("|---|---|---|---|")
    for c in CAPABILITIES:
        lines.append(f"| {c.status} | {c.name} | {c.evidence} | {c.limitation} |")
    lines.append("")
    lines.append("## Self-diagnosis")
    lines.append("")
    lines.append("| gap | impact | status | fix |")
    lines.append("|---|---|---|---|")
    for d in DIAGNOSIS:
        lines.append(f"| {d.gap} | {d.impact} | {d.status} | {d.fix} |")
    lines.append("")
    return "\n".join(lines)
