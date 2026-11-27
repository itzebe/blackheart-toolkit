# Adversarial harness — multi-engine exploit development

A self-contained Foundry project that demonstrates BLACKHEART's full
exploit-development workflow across **six engines** at the EVM level. Every
engine runs locally: in-process EVM, no broadcast, no live network. Each attack
class ships a *vulnerable* target and a *defended* control, so every result is a
differential — the exploit works on one and is blocked on the other.

The harness is driven from Python by `blackheart/adversarial.py`
(`python -m blackheart.cli adversarial`), which captures the exact command and
output of each engine as evidence and builds a `Finding` from the real output.

## Attack classes (vulnerable / control)

| Class | Vulnerable | Control | Property proven |
|-------|-----------|---------|-----------------|
| Reentrancy | `VulnerableVault` | `SafeVault` | attacker cannot withdraw more than deposited |
| Oracle manipulation | `LendingMarket` + spot `Oracles` | TWAP `Oracles` | borrow stays within the fair LTV bound |
| `tx.origin` auth | `Access` (tx.origin) | `Access` (msg.sender) | only the owner may call privileged setters |
| Unprotected initializer | `VulnerableInit` | `SafeInit` | ownership cannot be seized after deploy |

## Layout

```
src/token/AdversarialERC20.sol      hostile ERC20: reentry hook, fee-on-transfer, rebasing
src/vault/VulnerableVault.sol       state updated after the external call
src/vault/SafeVault.sol             checks-effects-interactions + reentrancy lock
src/vault/LendingMarket.sol         spot-oracle lending (intentional bugs)
src/oracle/Oracles.sol              manipulable spot price + TWAP
src/access/Access.sol               tx.origin vs msg.sender authorization
src/attack/ReentrancyAttacker.sol   generic reentrancy attacker
src/attack/OracleManipulationAttacker.sol
src/attack/PhishingProxy.sol        tx.origin phishing proxy

test/ExploitPoC.t.sol               8 deterministic PoC tests (4 exploits + 4 controls)
test/VaultHandler.sol               stateful handler (differential actor model)
test/Invariants.t.sol               VulnerableVaultInvariants (breaks) / SafeVaultInvariants (holds)
test/Echidna.sol + test/echidna.yaml
test/Medusa.sol + medusa.json
test/Symbolic.t.sol                 Halmos proofs + counterexamples
test/Fork.t.sol                     isolated local mainnet fork (read-only)
```

## Engines and how to run them

```bash
# Fast (always): PoC + stateful invariants
forge test --match-contract ExploitPoC -vv            # 8 passed
forge test --match-contract VulnerableVaultInvariants # FAILS on purpose (the counterexample)
forge test --match-contract SafeVaultInvariants       # passes (non-vacuity control)

# Property fuzzers
echidna test/Echidna.sol --contract EchidnaVulnerableVault --config test/echidna.yaml
medusa fuzz --config medusa.json --compilation-target test/Medusa.sol \
    --target-contracts MedusaVulnerableVault

# Symbolic execution (proofs + counterexamples)
halmos --contract Symbolic

# Static analysis
slither src --filter-paths lib
aderyn

# Mythril (fed forge-built bytecode; solc download is blocked in this sandbox)
myth analyze -f out/VulnerableVault.sol/VulnerableVault.bin --execution-timeout 90 -t 3

# Isolated local mainnet fork (read-only, in-process, no broadcast)
forge test --match-contract ForkIsolation -vv
```

## Deterministic reproduction

* **Foundry** prints `Fuzz seed: 0x…`; replay with
  `forge test --match-contract VulnerableVaultInvariants --fuzz-seed 0x…`.
* **Echidna** prints `Seed: …`; replay with `--seed <n>`.
* **Medusa** shrinks the failing sequence automatically and prints it.
* **Halmos** prints the concrete witness (e.g. the attacker address) it found.
* `blackheart adversarial` writes `seeds.json` collecting all of the above.

## Isolated forks

`foundry.toml` defines keyless, free public RPC endpoints under
`[rpc_endpoints]`. A fork runs in-process (`forge test --fork-url mainnet`) or
as a local node (`anvil --fork-url mainnet`); state changes live in the local
EVM and **nothing is broadcast**. `test/Fork.t.sol` pins a fixed block, reads
real mainnet state, runs the exploit locally, and asserts the mainnet state is
unchanged.

## Dependencies

`lib/forge-std` is not committed (see the repository `.gitignore`). Fetch it once:

```bash
forge install foundry-rs/forge-std
```

## Tool constraint (recorded so it is not re-discovered)

Halmos 0.3.3 cannot symbolically deploy a contract defined in a **different
source file** — it emits an unsupported `deployCode(string)` cheatcode. Every
contract a `check_*` function deploys must live in the same file as the test.
This is why `test/Symbolic.t.sol` defines its mocks inline.
