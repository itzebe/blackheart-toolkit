# Ranked capability upgrades

`blackheart improve` is the executable form of the ranked improvement list. Each
entry is a real module with an acceptance test; nothing is a status page pretending
to be a capability.

```bash
python3 -m blackheart improve status
python3 -m blackheart improve status --json
```

| Key | What it does | Honest limit |
|---|---|---|
| `compiler-execution` | `improve execution` compiles a project behind the compatibility gate and returns the chosen contract's ABI-backed model. | A witness still needs a renderable invariant and a Foundry-compatible tree. |
| `model-coverage` | `improve model-coverage` reports every modelled operation, every unmodelled operation and every unmodelled statement. | It measures the gap; it does not invent the missing semantics. |
| `closed-source` | `improve closed` recovers a decompiled surface and optionally replays a concrete witness on the runtime. | A closed body's source semantics remain unavailable. |
| `invariant-discovery` | `improve invariants` proposes conservation, authorization, reentrancy and timing candidates with `file:line` provenance. | Candidates are leads with confidence, never claims. |
| `market-simulation` | `improve market` races declared searchers with latency and prices our expected value against the eligible ladder. | Builder policy, private order flow and bundle merging are unmodelled. |
| `crosschain-oracle` | `improve crosschain` models bridge replay/authentication and oracle staleness/deviation. | It does not read live bridge or oracle state. |
| `policy-payout` | `improve bounty` evaluates a finding, runs the official-policy gate and packages the payout and policy citations. | It prepares; it never submits. |
| `independent-review` | `improve review` fails closed for a configured-but-unverified key or a same-model fallback. | A same-model review remains a recorded fallback, not independent verification. |
| `scale-triage` | `improve scale` ingests independent paths in parallel and ranks results with a stable score. | Large repositories still need memory and a depth budget. |
| `continuous-operation` | `improve continuous` runs one watch cycle and offers only recommended, non-blocked, above-threshold leads to an explicit enqueue callback. | The callback owns authorization; a lead is a candidate, not a verdict. |

## Why these are separate from the engines

Each module composes an existing engine rather than adding a parallel one:

* compilation uses `blackheart.ingest.compile` and the same compatibility gate;
* model coverage reads `blackheart.ingest.synthesize`'s own report;
* closed-source analysis reads the decompiler surface and `blackheart.bytecode`;
* invariant discovery reads `blackheart.solidity.extract` and adds source patterns;
* market simulation reads `blackheart.value.orderflow`;
* bounty packaging reads `blackheart.bounty` and `blackheart.program_intel`;
* review gating reads `blackheart.providers.router`;
* scaling reads `blackheart.parallel`;
* continuous operation reads `blackheart.watch`.

The acceptance bar is `tests/test_improve.py`. A change that weakens a limit
statement or promotes a candidate to a finding fails the repository's capability
and doctrine tests.

## Compiler input is now the default, and it is bound correctly

`blackheart pipeline --source` and `blackheart mission --source` attempt a
compiler AST first and fall back to the lexer with the compiler's own reason;
`--scanner` forces the lexer. Three defects were fixed on that path:

* a single file now expands its relative imports, so `Vault.sol` that imports
  `./Token.sol` no longer compiles alone in a temporary tree;
* the project root is discovered from the nearest `foundry.toml` or Hardhat
  config, so remappings and `lib/` dependencies are visible (`--project-root`
  overrides it);
* each AST is sliced against the source list it was compiled in, not whichever
  file sorted first. The old binding could put one contract's body into another
  contract's surface, which made model coverage look better or worse than it was.

The acceptance bar is `tests/test_pipeline_ast_binding.py`. This improves the
input to synthesis; it does not make the statement interpreter model arbitrary
Solidity.

## The composed model now reaches ERC4626 share inflation

The single-contract interpreter reported the four operations that matter —
`convertToShares`, `convertToAssets`, `deposit`, `withdraw` — as unmodelled,
so the certifier could not see the first-depositor inflation. Three fixes close
that gap without pretending the EVM is modelled:

* view functions are read as one conditional expression (locals substituted,
  return paths folded into ternaries), so `convertToShares`/`convertToAssets`
  have a value;
* internal calls and external calls through a declared state variable execute in
  source order; a single-contract step still does not pretend a cross-contract
  effect happened;
* an ERC20-like callee is modelled by shape (`balanceOf` mapping), including
  `transferFrom` and the nested `allowance` write the statement subset cannot
  read. `address(this)` is the caller contract.

The protocol target derives `erc4626:nonzero-shares` when a contract exposes
`convertToShares`: while supply is non-zero, one unit must not convert to zero
shares. On the reference pair the vulnerable vault violates it and `SafeVault`
survives. `blackheart closure foundry --generate-invariant` then emits a real
Foundry invariant test with a fuzzed handler and runs it; the vulnerable vault
fails, the guarded twin survives.

Acceptance bars: `tests/test_protocol_erc4626.py`,
`tests/test_generated_invariant.py`. The model is still a bounded subset: a
successful model violation is a lead, and a generated invariant that holds is
`NO_FINDINGS`, never "secure".
