# Historical-corpus Foundry harness

Real, executable reproductions of three publicly-disclosed vulnerability classes,
used as the Foundry half of the discovery engine's Capability G. Everything runs
in `forge`'s in-process EVM: no fork, no broadcast, no network, no real funds.

## Layout

```
src/Historical.sol              vulnerable + patched pairs (reentrancy, access
                                control, signature replay) and their attackers
test/HistoricalCorpusPoC.t.sol  one exploit + one patched control per class
test/BankInvariant.t.sol        stateful invariant fuzz; FAILS on the vulnerable
                                bank, HOLDS on the patched bank (the differential)
```

## What each test proves

- `test_reentrancy_drains_vulnerable` — the reentrant attacker ends with more than
  it deposited and the bank is drained.
- `test_reentrancy_patched_control_holds` — the *same* attacker reverts against the
  checks-effects-interactions bank; the bank stays solvent.
- `test_access_control_vulnerable` / `..._patched_control_reverts` — an
  unprivileged caller changes protected state, then is rejected by `onlyOwner`.
- `test_permit_replay_vulnerable` / `..._patched_control_reverts` — a signature
  doubles the allowance, then a single-use flag rejects the replay.
- `invariant_vulnerable_solvent` — the stateful fuzzer finds a 2-call sequence that
  makes the bank unable to honour its deposits (expected failure = the bug).
- `invariant_patched_solvent` — the same invariant holds on the patched bank.

## Running

```bash
./fetch.sh                     # vendor forge-std once (git-ignored)
forge test -vv                 # all tests; the vulnerable invariant is expected to fail
forge test --match-contract HistoricalCorpusPoC   # the exploit PoC suite (all pass)
```

The Python entry points are `blackheart discovery foundry` and
`blackheart discovery foundry-invariant`.
