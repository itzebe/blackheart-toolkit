# Damn Vulnerable DeFi — local training harness

A self-contained, **local-only** Damn Vulnerable DeFi-style challenge used for
exploit training and as the executable acceptance fixture for the researcher-led
workflow. It never touches a network: `forge` runs everything in its in-process EVM.

This is a re-implementation of the *Unstoppable* challenge (vault trusts its live
token balance; a donation breaks the share/asset accounting invariant and the
liveness monitor permanently pauses the vault), plus a guarded remediation and a
regression test.

## Layout

```
src/DamnValuableToken.sol     minimal ERC20
src/UnstoppableVault.sol      ERC4626-style vault; totalAssets() reads live balanceOf
src/UnstoppableMonitor.sol    on-chain liveness monitor that pauses the vault on failure
test/UnstoppablePoC.t.sol     the exploit + a control that proves causation
test/UnstoppableInvariants.t.sol  stateful invariant fuzz (FAILS on purpose = the finding)
test/UnstoppableRegression.t.sol  guarded-vault remediation + regression test
```

## Dependencies

`lib/forge-std` is not committed (see the repository `.gitignore`). Fetch it once:

```bash
forge install foundry-rs/forge-std
```

## Run

```bash
forge build
forge test --match-contract UnstoppablePoC -vv          # exploit: 2 pass (exploit + control)
forge test --match-contract UnstoppableInvariants -vv   # FAILS on purpose: invariant violated
forge test --match-contract UnstoppableRegression       # guarded vault: regression passes
```

The invariant run **failing is the finding**: Foundry shrinks the counterexample
to a single `donate(...)` call and prints the reproducible fuzz seed
(`0x424c41434b4845415254`, pinned in `foundry.toml`).

## Determinism

`foundry.toml` pins the fuzz/invariant seed and the actors, so the exploit and the
counterexample reproduce exactly on every run.
