# Closing the loop: source, control, proof, price

`blackheart pipeline` is the one command from a verified deployment to a
finding. This page records the additive pieces around it, what each one proves,
and what it still cannot do. Every claim here is exercised by a test.

## The shape

```
verified source ──compile──> runtime binding
      │                         │
      ├── synthesis ──> model ──certify──> witness
      │                                   │
      │                          ┌────────┼─────────┐
      │                          │        │         │
      │                     source PoC  control   mutation
      │                          │        │       audit
      └────────────── price ─────┴────────┴─────────┘
                                      │
                              independent review
                                      │
                                 finding
```

None of these stages is a new search engine. Each calls an existing tested
module and carries that module's verdict.

## Commands

```bash
# One command joins chain, verified source, component and a compatibility record
blackheart deployment bind 0x... --chain 1 --repository owner/repo --commit <sha> \
  --rpc https://... --out deployment.json

# Compile verified source and bind it to the deployed runtime (needs solc/forge)
blackheart pipeline --chain-id 1 --address 0x... --rpc https://... --block 19000000

# Or run the same loop on a local tree, with no address and no hand-written hypothesis
blackheart pipeline --source ./src --contract Vault --max-depth 4 \
  --control-source ./fixed --control-contract VaultGuarded --poc --no-finding

# The operator-facing wrapper: same pipeline, plus mission.json and MISSION.md
blackheart mission --source ./src --contract Vault --depth 4 --poc --dataflow \
  --control-source ./fixed --control-contract VaultGuarded --no-finding

# Read the model-coverage contract before trusting any clean result
blackheart closure coverage --source ./src --contract Vault
blackheart ingest ./src --coverage --json

# Compose several contracts with explicit links, or infer unambiguous ones
blackheart closure protocol --source ./src --link Vault.deposit=Token.mint --certify
blackheart closure protocol --source ./src \
  --link Caller.go=Callee.bump \
  --link-param Caller.go=Callee.bump:b=a \
  --link-return Caller.go=Callee.bump:seen=answer \
  --certify
blackheart closure protocol --source ./src --infer --certify

# Directed certification: spend the budget on value-moving paths first
blackheart closure certify --source ./src --contract Vault --asset Token \
  --depth 4 --max-states 200000 --beam 500 --param-sets 32

# Plan a deployment and check source/runtime equivalence
blackheart closure deploy-plan --source ./src --contract Vault \
  --constructor-args '["0x...",7]' --helper Token='[1000]' --proxy
blackheart closure equivalence --source ./src --runtime runtime.hex --abi abi.json
blackheart closure truth --address 0x... --rpc https://...
# By default this recompiles the verified source and compares it with the
# deployed runtime; only EXACT/METADATA_ONLY sets source_bound. Pass
# --no-bind-runtime only when the compiler is unavailable and say so.

# Fetch live V2 reserves and price a sandwich on the snapshot
blackheart closure market --model live --rpc https://... --pair 0x...:30:Uniswap \
  --victim 100000000000000000 --attacker 10000000000000000

# Replay a witness against a fixed/patched control
blackheart closure control --target-source ./vulnerable --control-source ./fixed \
  --contract Vault --steps witness.json --compatibility record.json --repository owner/repo

# Prove a symbolic witness on the concrete EVM
blackheart closure bytecode --runtime runtime.hex --witness witness.json

# Audit invariant strength
blackheart closure mutate --source ./src --contract Vault

# Plan from the program's own policy (allowed / excluded / unknown)
blackheart closure plan --policy policy.md --program example --profile profile.json

# Run a caller-supplied Foundry test against an arbitrary source tree
blackheart closure foundry --source ./src --test ./test/Exploit.t.sol \
  --test-name test_exploit --compatibility record.json --repository owner/repo \
  --fork-url https://... --fork-block 19000000

# Run a declarative multi-call scenario on a pinned fork
blackheart closure scenario --scenario scenario.json --rpc https://... \
  --block 19000000 --compatibility record.json --repository owner/repo

# scenario.json:
# {"name": "sandwich",
#  "calls": [{"target": "0x...", "data": "0x...", "caller": "0x...",
#             "value": 0, "expect_revert": false}],
#  "fund": {"0x...": 1000000000000000000},
#  "balance_deltas": [{"address": "0x...", "delta": -1}]}

# Render and run a source-level Foundry PoC
blackheart closure poc --source ./src --contract Vault --steps witness.json \
  --invariant conservation:balance-totalSupply --compatibility record.json \
  --repository owner/repo
# ... with constructor args, a helper deployment and a fork target
blackheart closure poc --source ./src --contract Vault --steps witness.json \
  --invariant conservation:balance-totalSupply --constructor-args '[7]' \
  --deployed-address 0x... --fork-url https://... --fork-block 19000000

# Price an ordering attack
blackheart closure market --pool-in 1000000000000000000 \
  --pool-out 1000000000000000000 --victim 100000000000000000 \
  --attacker 10000000000000000

# Price a Uniswap-V3 swap/sandwich inside one declared tick range
blackheart closure market --model v3 \
  --sqrt-price 79228162514264337593543950336 --liquidity 1000000000000000000000000 \
  --fee-pips 3000 --sqrt-lower 79228162514264337593543950336 \
  --victim 10000000000000000000000 --attacker 100000000000000000000

# Cross initialized ranges; repeat --range LOWER:UPPER:LIQUIDITY
blackheart closure market --model v3-multi \
  --sqrt-price 79228162514264337593543950336 --fee-pips 3000 \
  --range 39614081257132168796771975168:79228162514264337593543950336:1000000000000000000 \
  --range 79228162514264337593543950336:158456325028528675187087900672:2000000000000000000 \
  --victim 100000000000000000000 --attacker 10000000000000000000

# Read the live pool's slot0, liquidity and tick bitmap, reconstruct the ranges,
# then price a sandwich against that snapshot (read-only; no transaction sent)
blackheart closure market --model live-v3 --rpc https://... \
  --pair 0x88e6A0c2dDD26FEEb64F039a2c41296FcB3f5640:USDC-WETH \
  --direction token1->token0 --victim 1000000000000000000 \
  --max-words 24 --optimize

# --optimize searches attacker sizes geometrically from victim/1000 to
# victim*10 and reports the best measured profit; a negative best is an
# honest no-profit result, not a missing measurement.

# Charge gas, a builder bribe and an inclusion probability, then execute the
# selected candidate on a pinned Foundry fork. Gas is converted only when the
# profit token is WETH or --native-price/--gas-cost supplies the conversion.
blackheart closure market --model live-v3 --rpc https://... \
  --pair 0x88e6A0c2dDD26FEEb64F039a2c41296FcB3f5640:USDC-WETH \
  --block 26476300 --direction token1->token0 \
  --victim 1000000000000000000 --max-words 24 --optimize \
  --gas-units 250000 --gas-price-wei 1000000000 --bribe-bps 500 \
  --inclusion-bps 9000 --failed-tx-cost 100000 --capital-cost 50000 \
  --competitor-bid 200000 --fork-validate

# Price a competitive builder auction against a declared bid ladder.
blackheart closure market --model orderflow --gross 1000000 --bribe 200000 \
  --competitor-bids '[150000, 190000, 250000]' \
  --failed-tx-cost 5000 --capital-cost 1000
# Reports the fraction of competitors outbid, expected value, and the optimal
# threshold bid. A tie loses; the bid is paid only when included.

# --fork-validate renders a standalone Foundry test, funds the input token at
# its balance mapping slot, runs the front-run/victim/back-run on the fork and
# reports PASS (matched within --fork-tolerance-bps), DIVERGED, FAIL, BLOCKED
# or INCOMPLETE. It never signs or broadcasts a transaction.

# Durable, deduplicated corpus
blackheart closure corpus --path corpus.jsonl --add '{"target":"A"}' --verdict PASS
blackheart closure corpus --path corpus.jsonl --verify
blackheart closure corpus --path corpus.jsonl --invalidate '{"target":"A"}' --reason stale
blackheart closure corpus --path corpus.jsonl --pending '[{"target":"A"}]'
blackheart closure corpus --path corpus.jsonl --export-shard shard.json
blackheart closure corpus --path corpus.jsonl --merge-shard shard.json

# Claim/complete work with an epoch-fenced lease
blackheart closure corpus --path corpus.jsonl --queue-claim --worker w1 \
  --keys '["a","b"]' --limit 1
blackheart closure corpus --path corpus.jsonl --queue-complete a --worker w1 \
  --epoch 1 --verdict DONE
blackheart closure corpus --path corpus.jsonl --queue-recover --keys '["a"]'

# Discover a control commit touching a path
blackheart closure control --target-source ./src --repo https://github.com/owner/repo \
  --vulnerable-commit abc123 --path src/Vault.sol --steps witness.json \
  --compatibility record.json --repository owner/repo

# Use a verified independent reviewer when one is configured
blackheart closure review --prompt review.md
```

## The model-coverage contract

A clean search used to mean "the alphabet the engine chose had no
counterexample". That is not the same as "the target has no counterexample": a
reachable function the statement parser rejected, an internal helper outside the
operation alphabet, or an external call no protocol link resolved was invisible
to every strategy. `blackheart/ingest/model_coverage.py` turns that into an
explicit, serialized contract.

Every item is classified as one of:

- `MODELLED` -- the model represents it and a search can exercise it;
- `UNMODELLED` -- reachable, but outside the model, with a reason and `file:line`;
- `UNREACHABLE` -- not reachable from an external entry point, so its absence
  does not weaken a clean result;
- `EXTERNAL` -- an external call a single-contract model cannot apply; a
  protocol link may resolve it to `MODELLED`.

The ledger is attached to `SynthesisReport.model_coverage`,
`ProtocolReport.model_coverage`, `CoverageCertificate.model_coverage`,
`PortfolioResult.model_coverage`, `HuntResult.model_coverage`,
`VerifiedModel.model_coverage` and `PipelineResult.model_coverage`. Its
fingerprint is stable for the same surface.

The gate is deliberately blunt: if any reachable item is `UNMODELLED` or
`EXTERNAL`, a no-violation result is `INCOMPLETE MODEL COVERAGE`, never
`CERTIFIED CLEAN`, `NO_VIOLATION` or `NOT FOUND`. A violation that was actually
found is still reported; the ledger only limits what a *negative* may claim.
`UNREACHABLE` items do not block, because an unprivileged attacker cannot call
them.

## Honest limits

| Area | What it does | What it still lacks |
|---|---|---|
| Solidity semantics | Compound assignment, unary inc/dec, `delete`, function-local scalar declarations (never leaked into contract state), nested `if`/`else if`/`else`, source-ordered `require`/direct `revert`, an early `return` that halts later writes, mapping and struct-field writes, arrays with `push`/`length`, array-of-struct member writes, inherited functions/state, literal-bound loops, statement-level external calls in source order, and unconditional callee return values, including tuple returns assigned with `(x, y) = callee()` into locals or state, with atomic rollback; symbolic execution splits conditional effects into true/false paths | A general Solidity interpreter: array-of-struct member writes are modelled by the source certifier but deliberately refused by the symbolic executor; mapping-to-struct field writes, conditional return arity outside the declared tuple, cross-contract reads, single-contract virtual dispatch, inline assembly and unbounded loops stay unmodelled, conditional paths are capped at 256 branches per operation, and unmodelled statements do not move state |
| Compilation | Real `solc`/`forge` compile of verified source; runtime compared after metadata stripping | Compiler and imports must be available; a metadata match is not semantic equivalence |
| Source PoC | Foundry test importing the real source and asserting conservation, authorization, solvency or a bounded field; supplied constructor args, helper deployments, a minimal delegatecall proxy, a deployed-address target and fork flags; with `--protocol`, a multi-contract test that deploys each called contract and routes each step to its owner | Four invariant forms only; single-contract constructor args/helpers must be supplied; the proxy has no admin semantics; a protocol PoC deploys no-arg contracts and cannot supply per-contract constructor wiring |
| Protocol composition | Multiple contracts, namespaced state, explicit links with `param_map`/`return_map`, unambiguous inferred links, and nested statement-level external calls executed in source order against the receiver's synthesized model; a reverting callee rolls back the caller, a return value (including a named tuple component) can be assigned in the caller, an interface/base-typed receiver resolves to the one concrete implementation, a `nonReentrant` guard refuses recursive entry, and an unguarded recursion stops at a named depth limit. `pipeline --source --protocol` runs the whole certify/price/verify/finding loop over the composition. | Every call has an explicit `RETURNED`/`REVERTED`/`UNMODELLED` outcome; `UNMODELLED` aborts the path and names the gap. The default inference is source-regex; `--compiler-callgraph` uses Slither when installed, but an interface with no supplied implementation, single-contract virtual dispatch and inline assembly still stay unresolved; two concrete candidates are ambiguous. Cross-contract reads beyond the modelled return expression, mixed tuple-declaration forms and arbitrary callback ordering are not modelled. |
| Foundry backend | Arbitrary source tree + caller-supplied test or `--auto` generated test, real compile/run, fork URL/block, gate first; declarative multi-call fork scenarios with funded callers, value, expected reverts and balance-delta assertions | A test runner, not a semantics engine: the generated test is only as good as the renderable witness; a scenario is low-level calldata, asserts call success/revert and balance deltas, and runs at one pinned block |
| Control | Verified address, pinned shallow-fetched commit, or a discovered descendant commit touching named paths; model replay | Discovery is bounded by depth and does not prove the commit is the security fix; model-level unless also run as a PoC |
| Mutation audit | Generic and class-specific families (accounting, arithmetic, access-control, oracle, governance, reentrancy), CAUGHT/SURVIVED | Operators are state mutations, not guard removal or source edits; a survivor warns about the oracle, not a bug |
| Market | Constant-product sandwich, static order-book sandwich, utilisation-driven lending curve, best-venue quote, builder-bundle auction with failure/capital costs and competitor outbid, competitive order-flow bid ladder with win probability and optimal threshold bid, live V2 reserves with cross-pair quoting, exact single- or multi-range Uniswap-V3 swaps with tick crossing, read-only live V3 `slot0`/`liquidity`/tick-bitmap reconstruction with a geometric attacker-size search, operator-supplied gas/bribe/inclusion/failure/capital/competition economics, and a generated Foundry fork test that executes the candidate and compares measured attacker profit and victim loss | A V3 snapshot is bounded by the scanned bitmap window (`--max-words`, marked `INCOMPLETE` when the boundary word has initialized bits); gas, inclusion, failure cost, capital cost and competitor bids are inputs, not measurements, and an unconvertible gas cost is left `unpriced`; the order-flow ladder is declared, not observed, and a competitor's response, private order flow and builder policy are not modelled; fork validation is one candidate at one pinned block. Live mempool dynamics, queue position, latency, competing-searcher strategy, cross-venue routing and live bundle inclusion remain unmodelled |
| Policy planning | Three-valued class eligibility from a normalized policy | Does not fetch or verify the policy; unverified policy is advisory |
| Reviewer | Direct use of a resolved distinct, probed model, including a local Ollama provider | Requires a distinct local/remote model and a successful liveness probe; absent means `UNAVAILABLE`, never a fabricated review |
| Verifier independence | Records producer and verifier engine; `--require-independent-engine` refuses `INDEPENDENTLY_VERIFIED` for a same-engine or unrecorded replay; a passing Foundry PoC supplies `foundry` | Strict mode is opt-in; a host without forge or an unrenderable witness stays `REPRODUCED`, never confirmed. |
| Corpus / parallel | Bounded thread pool, chained deduplicated store, resumable pending work, explicit invalidation, portable shard export/merge, and epoch-fenced worker leases | Leases are a shared-filesystem protocol, not a network service; the corpus stores results, it does not search |
| Bytecode witness | Concrete EVM replay of halt and declared storage | One message call; not the source cause or a stateful multi-call sequence |

## Still missing after this round

- A general Solidity semantics engine. The coverage ledger now makes every
  reachable gap visible and blocks a clean negative, but it does not model the
  gap: a contract with an unmodelled function returns `INCOMPLETE`, not a finding.
  The subset is wider (nested `else if`,
  path-sensitive conditional symbolic effects, struct fields, arrays with a
  concrete length, inheritance, source-ordered external calls and single or
  tuple unconditional call returns), but arrays of structs, conditional returns
  across tuple declarations, cross-contract reads, single-contract virtual
  dispatch, inline assembly and general unbounded control flow are still
  unmodelled.
- Fully automatic protocol setup: constructor args and helper wiring are still
  supplied; the plan blocks rather than inventing them.
- A semantic equivalence proof: ABI-selector evidence is stronger than a bytecode
  hash, but it is not an AST or storage-layout proof.
- A compiler-grade cross-contract call graph; inference is source-regex and only
  resolves unambiguous receivers. Go now uses the exact `go.mod` import path, but
  embedded interfaces, generics and method values remain unresolved.
- Live MEV realism: V2 reserves are real and V3 ranges can now be reconstructed
  from the live pool's tick bitmap (bounded, read-only, and explicitly
  `INCOMPLETE` when truncated). Queue position, latency, competing searchers,
  cross-venue routing and live bundle inclusion are still not modelled.
- A network work queue: leases are shared-filesystem only.
- A reviewer with no provider at all: zero-provider mode still cannot be
  independent, though a local Ollama model can be.

## Statuses that must not be upgraded

- `RECOMPILE_FAILED` is not `source_bound`.
- A `SOURCE_VERIFIED` truth record without a runtime binding is not
  `source_bound`; the findings and bounty gates refuse it.
- `INCOMPLETE` is not a failed reproduction.
- `CONTROL_ALSO_VULNERABLE` is not specificity.
- `SURVIVED` is not a bug; it is weak evidence about an invariant.
- `UNAVAILABLE` is not an independent review.
- `PASS` on a PoC is a reproduction, not a priced finding.
- A clean bounded search is "not found within budget", never "clean" -- and a
  clean search over an incomplete model is `INCOMPLETE MODEL COVERAGE`, never a
  clean target.
