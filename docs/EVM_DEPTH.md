# Bytecode, deployment and venue depth

This page records what the EVM-facing engines actually do, so a later session does
not re-derive it or over-claim it.

## Symbolic bytecode execution

`blackheart/symbolic/evm.py` walks real runtime bytecode, forks on a symbolic
`JUMPI`, and asks the three-valued solver for a witness. It is bounded and it
stops rather than guesses.

- **Constant arithmetic follows the EVM**: `ADD`/`SUB`/`MUL` wrap at 256 bits;
  `SIGNEXTEND`, `BYTE`, `SHL`, `SHR`, `SAR`, `ADDMOD`, `MULMOD` and `EXP` fold.
- **`SHA3` is computed** when the offset, size and memory words are concrete --
  which is what a mapping slot needs. Symbolic memory or a symbolic offset is
  reported as `unsupported`.
- **Symbolic ADD/SUB/MUL can wrap, on request.** `--wrap` forks a symbolic ADD
  into the non-overflow case (`a+b < 2**256`, result `a+b`) and the overflow case
  (`a+b >= 2**256`, result `a+b-2**256`); SUB and MUL fork the same way. Each
  fork doubles the paths at that operation, so it is opt-in. Symbolic AND/OR/XOR
  are carried as expressions with sound interval bounds; symbolic EXP and
  division remain unbounded, and that limit is printed, not hidden.
- **Linear pruning**: `blackheart/symbolic/linear.py` proves a conjunction of
  linear inequalities UNSAT and tightens variable bounds. The solver consults it
  before enumerating, so an infeasible branch does not consume the path budget.
- **Coverage-guided fuzzing**: `blackheart/evm_fuzz.coverage_fuzz` keeps calldata
  that reaches a new program counter, grows the corpus from those inputs, and
  records the inputs that revert. `run_bytecode(..., collect_pcs=True)` is the
  trace it reads; the trace is off by default.

CLI: `blackheart symbolic-evm CODE --input cd0=0..1000 [--wrap] [--minimize]
[--poc-out PoC.t.sol]`, `blackheart evm-diff VULN GUARDED --words 751
[--minimize]`, `blackheart evm-fuzz CODE --iterations 500`.

## Witness to PoC

`blackheart/symbolic/poc.py` turns a solver witness into a Foundry test. The test
etches the supplied runtime bytecode at a fixed address with `vm.etch`, calls it
with the witness calldata, and asserts the recorded terminal outcome
(`assertFalse(ok)` for a revert, `assertTrue(ok)` otherwise). A differential
divergence becomes a two-twin test that asserts the revert status or return value
differs. It is a reproduction harness, not a finding: a non-revert witness proves
reachability, not impact.

`blackheart/symbolic/poc_runner.py` runs it. `blackheart poc run` writes the test
into a minimal Foundry project and invokes `forge test --json` **only** after the
language-aware gate admits the target. A blocked run never starts forge. The
statuses are `PASS` (the assertion held: the witness reproduced), `FAIL` (the test
ran and the assertion did not hold), `BLOCKED` (the gate refused or forge is
absent) and `INCOMPLETE` (the build or output could not be interpreted). A `PASS`
is a reproduced witness, not a priced finding.

```
blackheart symbolic-evm CODE.hex --input cd0=0..1000 --poc-out Witness.t.sol
blackheart evm-diff VULN.hex GUARDED.hex --words 751 --poc-out Divergence.t.sol
blackheart poc run Witness.t.sol --compatibility record.json \
    --target-component C --repository org/repo --commit abc1234
```

## Minimizing a reproducer

`blackheart/symbolic/minimize.py` delta-debugs 32-byte calldata words: it zeros a
word, halves a value, clears a bit or drops a word, and keeps every change that
still satisfies the caller's predicate. `symbolic-evm --minimize` preserves the
terminal outcome on the concrete EVM; `evm-diff --minimize` preserves the
divergence. The PoC is rendered from the minimized input. The search is bounded
and returns a smaller reproducer, not a proven minimal one.

```
blackheart evm-diff VULN.hex GUARDED.hex --words 751,0,0 --minimize --poc-out Divergence.t.sol
```

## Storage-layout diff

`blackheart/ingest/storage_layout.py` reads a solc `storageLayout` JSON and
compares two of them. An **appended** variable is compatible; a **moved**,
**removed** or **type-changed** variable is not, because every slot below the
change now means something else. Equal runtime bytecode cannot show this.
`layout extract` pulls the layout out of a Foundry build-info or a solc combined
JSON, so the comparison does not start with hand transcription.

```
blackheart layout extract out/build-info/abc.json --contract Vault -o old.json
blackheart layout extract out/build-info/def.json --contract Vault -o new.json
blackheart layout diff old.json new.json   # exit 1 on a break
```

## Deployment to model

`blackheart/ingest/verified.py` attests a Sourcify deployment, scans the verified
Solidity, synthesises the model and certifies it. Three additions make the binding
honest:

- `strip_metadata` removes the CBOR metadata tail, so two builds can be compared
  without a false mismatch.
- `bind_runtime` reports `EXACT`, `METADATA_ONLY`, `MISMATCH`, `NO_DEPLOYED_CODE`,
  `NO_RECOMPILE` or `RECOMPILE_FAILED`. Only a bound result sets
  `source_bound=True`; a mismatch keeps the model and says the source is not the
  deployed code.
- `resolve_proxy` reads an EIP-1967 implementation slot and an EIP-1167 minimal
  proxy. The address is recorded, not silently followed.

CLI: `blackheart verified-model CHAIN ADDRESS --runtime CODE.hex`.

## Closed components

`blackheart/ingest/decompiled.py` parses a decompiler's function surface (names,
selectors, parameters, visibility) into the same `ContractSurface`. Every body is
`assembly { }`, so the interpreter marks it unmodelled and the result is
`UNMODELLED` with the recovered names. A surface answers *reachability*; it never
answers *effect*.

CLI: `blackheart verified-model 1 0x0 --decompiled decompiled.txt`.

## Venue economics

`blackheart/venues/amm.py` prices a constant-product swap with basis-point fees,
chains a multi-hop path, and accounts a sandwich exactly: attacker profit in the
input asset and victim loss in the output asset. `sandwich(..., gas_units=,
gas_price_wei=)` reports `net_profit` beside the gross `attacker_profit`, so a
gas bill that exceeds the extraction is visible instead of assumed away.
`profitable` is the gross ordering effect; `net_profitable` is the one after gas.
Each hop is one pool: there is no order book, no MEV bundle, and no automatic
conversion between the profit asset and the gas asset.

## What is still absent

- Symbolic EXP wrapping and symbolic `SHA3`.
- External calls, symbolic memory offsets and symbolic storage keys.
- A recompiler shipped in-engine (the caller supplies one).
- The semantics of a closed body.
- Order-book, multi-venue and MEV-bundle simulation.
- A bundled compiler: `poc run` invokes the host's `forge`, it does not ship one.
