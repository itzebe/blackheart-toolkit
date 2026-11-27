# Hyperliquid Arbitrum bridge harness

Adversarial and property tests for the **real, in-scope** Hyperliquid Arbitrum USDC
bridge (`Bridge2.sol`), compiled verbatim from the fetched source.

- Target repo: `https://github.com/hyperliquid-dex/contracts`
- Pinned revision: `d7e66aa751ffbd19bfd2b90fd5d9a3d8f32d99ee`
- Deployed (legacy Arbitrum bridge): `0x2df1c51e09aecf9cacb7bc98cb1742757f163df7`

## Scope / safety

All tests run in a **local** EVM (chain_id 1337, so the contract's own `block.number`
hook is used). Nothing is broadcast. The optional `fork` profile builds a **local**
read-only Arbitrum fork to confirm the deployed bytecode matches the audited source —
it never sends a transaction.

## Run

```bash
./fetch.sh            # vendors the bridge source + pinned deps (git-ignored, idempotent)
forge test            # adversarial + invariant suites against the real source
forge test --match-contract Bridge2Test        # 15 adversarial tests
forge test --match-contract Bridge2Invariants  # stateful invariants (4, independent)
# deeper fuzz:
FOUNDRY_INVARIANT_RUNS=1000 FOUNDRY_INVARIANT_DEPTH=200 forge test --match-contract Bridge2Invariants
```

### Independent engines (same harness, different fuzzers)

```bash
# Medusa (coverage-guided, multi-worker). Needs --foundry-compile-all so the
# test/ harness is compiled; see medusa.json.
medusa fuzz --config medusa.json

# Echidna. The harness etches a minimal ArbSys stub so it runs off-chain-id-1337
# too; see test/echidna.yaml (do NOT set balanceContract to a 2**128 value).
echidna . --contract Bridge2Echidna --config test/echidna.yaml
```

All three engines run the **same** real source and the same handler; each has been shown
to catch a deliberately injected quorum bug (see the evidence file), so a pass is
meaningful rather than vacuous.

`fetch.sh` pins: Hyperliquid contracts `d7e66aa…`, OpenZeppelin `v4.9.6`,
nitro-contracts `v1.2.1`, forge-std `v1.9.6`.

## Layout

```
fetch.sh                 vendor the target source + pinned deps
foundry.toml             src = vendor/src (the real Bridge2.sol), chain_id 1337
remappings.txt           @openzeppelin/…, @arbitrum/nitro-contracts/…
medusa.json              Medusa config (property testing, target = Bridge2Medusa)
test/MockUSDC.sol        minimal EIP-2612 USDC (only mock in the harness)
test/Bridge2.t.sol       15 adversarial tests (forgery, replay, authz, dispute, permit)
test/Bridge2Invariants.t.sol  Foundry stateful handler + 4 independent invariants
test/Bridge2LifecycleInvariants.t.sol  validator-set lifecycle handler + 4 invariants + 5 targeted tests
test/Bridge2Medusa.t.sol      Medusa harness (self-contained; same actions/properties)
test/Bridge2Echidna.t.sol     Echidna harness (inherits the Medusa harness)
test/echidna.yaml             Echidna config
```

## Result

See `../../research/private/hyperliquid/RESEARCH_LEDGER.md` and
`../../research/private/hyperliquid/evidence/BRIDGE_INVARIANTS_2026-11-10.md`. Current
outcome: **FALSIFIED** — 22/22 tests pass and 8/8 stateful invariants hold across Foundry
(180,000 calls over the withdrawal and lifecycle harnesses), Medusa and Echidna, and each
invariant is mutation-validated (proven to fail on a deliberately injected bug). The
privileged validator-set lifecycle (epoch monotonicity, authorization, dispute period) is
also covered. No exploitable weakness was demonstrated in the audited revision.
