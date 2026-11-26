# Aave aToken wrapper adversarial harness (real source)

This harness runs BLACKHEART's priority Twyne hypothesis against the **actual**
Aave V3 aToken wrapper source, not a model of it:

> Can Aave aToken / wrapper-share accounting be converted into unauthorized
> value extraction (first-depositor inflation / donation dilution)?

It is the concrete follow-up to the open question recorded in
`docs/RESEARCH_LOG.md` ("Twyne wrapper vs real source — obtain the actual wrapper
source and re-run the harness against it").

## What is here

```
foundry.toml                 solc 0.8.28, cancun, invariant config
remappings.txt               dependency remappings
fetch-deps.sh                fetches the target source + pinned deps (git-ignored)
test/AaveWrapperInvariants.t.sol         stateful invariant harness (handler + 2 invariants)
test/AaveWrapperAccountingAttack.t.sol   focused inflation / conversion attack tests
```

The wrapper source (`src/`) and the dependencies (`lib/`) are **not committed**:
the wrapper is BUSL-1.1 (source-available, not open source) and is treated as
target-confidential; the dependencies are large third-party trees. All of it is
git-ignored and re-fetched at pinned revisions.

## Fetch and run

```bash
./fetch-deps.sh          # fetches wrapper source + pinned deps, copies src/ into place
forge test -vv           # runs both test contracts
```

Pinned revisions (see `fetch-deps.sh`):

| Dependency | Revision |
|---|---|
| `0xTwyne/aave-v3-aToken-wrapper` | `797be33` (tag 1.0.1) |
| `aave-dao/aave-v3-origin` | `d7919c0` |
| `euler-xyz/ethereum-vault-connector` | `a7d3c29` |
| `foundry-rs/forge-std` | `v1.9.0` |

## What the tests assert

`AaveWrapperAccountingAttack` (all must pass):

- `test_inflationAttack_is_blocked_by_zero_share_revert` — the documented attack
  ratio (2 wei seed, 10e18 donation, 1e18 victim deposit). If the victim's deposit
  were accepted for zero shares the attacker would profit; the test asserts either
  the deposit reverts (blocked) or the victim is made whole and the attacker gains
  nothing.
- `testFuzz_inflationAttack_no_profitable_path` — 256 runs across seed / donation /
  victim-deposit space; asserts no profitable path exists.
- `testFuzz_repeatedConversions_never_create_value` — 256 runs across a rate
  (yield) change; asserts no value is created and the wrapper never over-reports.

`AaveWrapperInvariants` (stateful fuzzing, ~6000 handler calls):

- `invariant_reported_equals_redeemable` — the wrapper never reports more assets
  than it holds.
- `invariant_shares_backed` — total supply is fully backed by aTokens.

## Result (honest)

**No confirmed finding. The hypothesis is falsified against the real source.**
The wrapper reverts with `StaticATokenInvalidZeroShares()` when a deposit or skim
would mint zero shares, which blocks first-depositor inflation; the victim's
deposit cannot be diluted. See `docs/RESEARCH_LOG.md` for the full record,
including the two harness artefacts found and discarded during development.

## Safety

Local, in-process EVM only. No fork, no broadcast, no network, no real funds. The
wrapper is compiled from source; no deployed contract is touched.
