# twyne-aave-wrapper — real-target fork harness

Adversarial, evidence-producing tests against the **real, in-scope** Twyne
`AaveV3 aToken wrapper` source, run on a **local mainnet fork** against **real
Aave V3**.

- Upstream: `https://github.com/0xTwyne/aave-v3-aToken-wrapper`
- Pinned commit: `797be33e22cce033f6d9c66650d9604ee48fc60d`
- Program: Twyne (Immunefi) — `https://immunefi.com/bug-bounty/twyne/information/`

Nothing here is broadcast. `forge test` runs entirely in-process on a fork; no
production state is written, and no paid RPC key is required (the harness uses a
keyless public endpoint, overridable with `BLACKHEART_ETH_RPC`).

## Layout

| Path | Purpose |
| --- | --- |
| `fetch.sh` | Vendors the real source into `vendor/` at the pinned commit and derives `remappings.txt`. Idempotent. |
| `foundry.toml` | Compiles `vendor/src` (real source) against real dependencies; `[profile.fork]` holds the keyless RPC. |
| `test/TwyneWrapperForkBase.sol` | Deploys the real wrapper behind a UUPS proxy against real Aave; funds actors with real WETH. |
| `test/TwyneWrapperSmoke.t.sol` | Non-vacuity: the harness is really wired to Aave; the zero-share guard is real. |
| `test/TwyneWrapperAdversarial.t.sol` | The hypotheses H1–H7 (see below). |
| `test/WrapperHandler.sol` | Stateful handler for the invariant fuzzer (honest actors). |
| `test/TwyneWrapperInvariants.t.sol` | Stateful invariants over arbitrary sequences. |

## Usage

```bash
# from the repo root, with forge on PATH
python3 -m blackheart fork fetch --target twyne-aave-wrapper
python3 -m blackheart fork run   --target twyne-aave-wrapper --runs 48 --depth 40
python3 -m blackheart fork ledger --target twyne-aave-wrapper --ledger-dir research/private/fork/ledger
```

Or drive `forge` directly:

```bash
cd harnesses/twyne-aave-wrapper
forge test --match-contract TwyneWrapperAdversarialTest -vv
```

## Hypotheses and their evidence-backed status

| Id | Hypothesis | Result |
| --- | --- | --- |
| H1 | Donating aTokens moves the wrapper share price (inflation attack) | FALSE_POSITIVE — price comes from Aave's supply index, not the wrapper balance |
| H2 | Rounding drift makes `totalSupply` exceed the backed aTokens | FALSE_POSITIVE — backed balance is exactly `>= totalSupply` after 200 small deposits |
| H3 | A CV accrues aTokens beyond its shares via rebalance rounding | FALSE_POSITIVE — 50 rebalances stay exact |
| H4/H5 | A registered collateral vault can pull aTokens while holding zero shares | NEEDS_MORE_EVIDENCE — mechanism real and reproduced, but no CV-side path that over-states collateral has been shown |
| H6 | Six-decimal assets (USDC) round-trip losslessly | FALSE_POSITIVE — 1m USDC in → 999,999.999999 USDC out |
| H7 | Wrapper shares rebase as Aave yield accrues | FALSE_POSITIVE — share count constant; same shares redeem more (intended design) |

The wrapper's `rebalanceATokens_CV` is **unbounded by the wrapper itself** — it
moves exactly `convertToAssets(|shares - scaledBalanceOf(caller)|)` with no cap
tied to the caller's wrapper-share balance. The bound that keeps this safe is
enforced by the *caller* (the Twyne collateral vault, which passes its own
tracked collateral). This is a real trust boundary and is recorded as
`NEEDS_MORE_EVIDENCE`, **not** as a vulnerability: reaching a loss requires a
registered CV to pass an over-stated value, and no such path has been shown.
