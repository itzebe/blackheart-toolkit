# managed-oracle-m2 — Mission 02 gate verification

Fork tests that assert, against live Polygon state, that an unprivileged caller cannot move
value through the deployed `PolymarketOOReporter` or `ManagedOptimisticOracleV2`, and that the
live oracle implementation is the V2 code the sources describe.

The contracts under test are the **deployed** ones; nothing is vendored and nothing is deployed.

```bash
./fetch.sh                 # clones forge-std at a pinned tag
export PATH="$PATH:$HOME/.foundry/bin"
forge test                 # forks block 97702628 by default
FORK_BLOCK=98000000 forge test
```

Full evidence and the mission report: `findings/informational-recovery/mission-02/`.
