# Go, Cosmos SDK and language coverage

BLACKHEART was built around one environment (Solidity/EVM) and one Rust/Substrate
scanner. A chain written mostly in Go — a Polkadot-SDK + Cosmos SDK + EVM chain
such as QoreChain — therefore produced a **false clean**: the ingest reported
hundreds of files and zero functions, and only the Solidity interface stubs were
read. This document records what was added, what it proves, and what it still
does not.

## What the Go scanner recovers

`blackheart ingest <path> --language go` (or automatic detection from `go.mod`)
uses `blackheart/ingest/golang.py` to recover, from source:

- packages and their files;
- functions and methods, with receiver, signature, body, line and **path**;
- message handlers (`MsgServer` / `msgServer` receivers, or a `*types.Msg…`
  parameter);
- consensus entry points (`BeginBlock`, `EndBlock`, `PrepareProposal`,
  `ProcessProposal`, `VerifyVoteExtension`, `AnteHandle`);
- build flavors from `//go:build` constraints: `community`, `full`,
  `unconditional` and the raw constraint text;
- **stubs**: a function whose body only returns `ErrNotImplemented`,
  `ErrNotSupported`, `errors.New("not implemented")` or `panic("not
  implemented")`, or a file gated to a non-`full` build;
- boundaries that the model cannot cross: cgo/FFI, unsafe, reflection, dynamic
  dispatch, non-Go assets.

The public/community build is the default read. A stub in that build is a
*missing implementation*, not the full build's behaviour. The scanner reports it
as a stub and the rules do not judge it as implementation.

## Rules and their limits

`blackheart/ingest/golang_flags.py` emits leads, each mapped to a modelled
objective category and carrying `file:line`:

- panic reachable from an unprivileged message;
- unchecked error/value result (`_ = …`, `SendCoins`, `MintCoins`, `BurnCoins`,
  `Delegate`, `Undelegate`, `Set`);
- unchecked integer cast (`int64(amount)`, `uint64(...)`, `math.MaxInt64`);
- wall-clock time in consensus or a handler (`time.Now`, `time.Since`);
- unbounded state iteration (`GetAll…`, `Iterate…`, `range k.GetAll…`);
- missing authority check on a reachable message that writes state.

A flag is a lead, never a finding. The guarded twin must not fire; that is
pinned by `tests/test_golang_ingest.py`.

## Language coverage is fail-closed

`blackheart/ingest/coverage.py` detects every production language in a tree from
manifests and source extensions, then compares it with the scanner that actually
ran:

- `FULL` — every production language has a scanner and was scanned;
- `BLOCKED` — at least one language with production code was not scanned;
- `PARTIAL` — the operator explicitly allowed a language to be skipped, and the
  exception is recorded.

The gate is wired into `ingest`, `interrogate` and `pipeline --source`. An
unscanned language is never presented as clean. `--allow-unscanned LANG` is the
only way to proceed, and it is recorded as a partial exception.

## The Cosmos reference model

`blackheart/cosmos/` supplies an executable Cosmos SDK accounting target:
`send`, `delegate`, `undelegate`, `redelegate`, `unjail`, governance
`deposit`/`withdraw_deposit`, `lock`/`unlock` and `slash`. It declares four
invariants (supply conservation, non-negative balances, self-bond floor and
locked-coin backing) and a `vulnerable=True` twin that double-credits
`undelegate`, `unlock` and `withdraw_deposit`.

```bash
blackheart cosmos model
blackheart cosmos certify --expect guarded
blackheart cosmos certify --vulnerable --expect vulnerable
blackheart cosmos from-go /path/to/chain
```

`from-go` recovers the message surface from Go source: message name, receiver,
file/line, whether the handler writes state, and whether a signer/authority check
is present. It deliberately does not invent the handler's accounting semantics.

## What is still not covered

- **Devnet execution.** There is no backend that boots a Cosmos devnet, submits
  messages, and captures the resulting state. The reference model is a model, not
  a chain. `tests` and the capability statement say so.
- **IBC, BeginBlock/EndBlock, governance execution, EVM-lane calls, cgo/FFI and
  slashing rounding** are declared unmodelled by the Cosmos target.
- **Build expressions** beyond `full` / `!full` are preserved as text, not
  evaluated. A module gated on an arbitrary tag may be misclassified.
- **Generated code** (`*.pb.go`) is skipped by the rules; it is a surface, not a
  target.
- **Upstream patch differential.** The scanner can read a vendored or replaced
  module, but it does not yet diff a dependency's upstream fix against the
  pinned fork to generate a regression witness.

## Commands

```bash
python3 -m blackheart ingest /path/to/chain --language go
python3 -m blackheart interrogate /path/to/chain --language go
python3 -m blackheart cosmos from-go /path/to/chain --json
python3 -m blackheart cosmos certify --expect guarded
python3 -m pytest tests/test_golang_ingest.py tests/test_cosmos.py
```
