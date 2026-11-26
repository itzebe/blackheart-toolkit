# ERC4626 adversarial harness

A self-contained Foundry project that demonstrates BLACKHEART's exploit workflow
at the EVM level: a deliberately vulnerable vault, a safe control, a PoC, and
stateful invariant tests.

## Layout

```
src/IVault.sol            minimal vault interface
src/MockERC20.sol         real ERC20 (no mocks of the code under test)
src/VulnerableVault.sol   share inflation: first-depositor donates to steal
src/SafeVault.sol         same vault with virtual shares/offset
test/ExploitPoC.t.sol     deterministic PoC (vulnerable exploitable, safe blocks)
test/VaultHandler.sol     stateful handler for the invariant fuzzer
test/Invariants.t.sol     invariant_* (vulnerable) and SafeInvariantsTest (control)
```

## Dependencies

`lib/forge-std` is not committed (see the repository `.gitignore`). Fetch it once:

```bash
forge install foundry-rs/forge-std
```

## Run

```bash
forge build
forge test -vv --match-contract ExploitPoC        # PoC: 2 pass
forge test -vv --match-contract InvariantsTest    # vulnerable: invariants break (expected)
forge test -vv --match-contract SafeInvariantsTest# safe control: invariants hold
```

The vulnerable invariant run **fails on purpose** — the failure *is* the
counterexample, and Foundry shrinks it automatically. The safe control run
passing is what makes the invariants meaningful (non-vacuity).
