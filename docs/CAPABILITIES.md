# Deployed-contract intelligence

`blackheart.deployed` reads a contract's real on-chain facts and reports them
honestly. It is stdlib-only (`urllib`), read-only, and never sends a transaction.

```bash
python3 -m blackheart deployed 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48 \
    --rpc https://eth.drpc.org
```

It records:

- the runtime bytecode and its SHA-256 (so the exact deployed artifact is pinned),
- the chain id and block number the reads were taken at,
- standard proxy patterns detected by reading their storage slots
  (EIP-1967 implementation/beacon/admin, EIP-1822, OpenZeppelin legacy), and the
  resolved implementation/beacon/admin addresses,
- a raw evidence record for every RPC read (method, params, result, block, source).

Honesty rules, enforced in code and covered by tests:

- **No code, not verified.** An address with no runtime code is reported
  `verified: false` with a limitation, never as a deployed contract.
- **EIP-7702 is an EOA.** A `0xef0100 || address` delegation designator is detected
  explicitly and reported as an account that *delegates*, not a contract.
- **An unreachable RPC is a recorded limitation**, not a success and not a crash.

The command exits non-zero when the contract could not be verified, so a caller
fails closed.

### Function-selector fingerprinting

`--selectors` fingerprints specific functions in the runtime bytecode. Selectors are
keccak-256 of the canonical signature; since a stdlib-only environment has no keccak
library, `blackheart.deployed` ships a correct pure-Python Keccak-f[1600]
(`keccak256`, `function_selector`), checked against known vectors in the tests.

```bash
python3 -m blackheart deployed 0x63AF37417932581722c7cEeD80Cc803F018949bb \
    --rpc https://eth.drpc.org \
    --selectors "setLiquidateIncentiveShareBps(uint256);setLiquidationIncentive(uint256)"
# selector     0xd189cdbe  present  setLiquidateIncentiveShareBps(uint256)
# selector     0xa8431081  absent   setLiquidationIncentive(uint256)
```

This distinguishes *which build* of a contract is deployed without trusting a block
explorer: a present selector is evidence a function exists, not proof of behaviour, so
it is treated as a fingerprint. Signatures are separated with `;` (a comma is part of a
signature such as `transfer(address,uint256)`).
