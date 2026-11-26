# Repository ingestion (`blackheart ingest`)

Every earlier mission began the same way: clone the target, open the source, and
hand-transcribe its interface into the engine's `Target`/`OpSpec` model. That
step is where a research engine stops researching and starts typing. `ingest`
removes it for the first stage.

```bash
python3 -m blackheart ingest path/to/repo            # markdown triage sheet
python3 -m blackheart ingest path/to/repo --json     # machine-readable
python3 -m blackheart ingest path/to/repo --out out  # write surface.md
python3 -m blackheart capability                     # what the engine can/cannot do
```

## What it does

1. **Scans** every `.sol` file (test, snapshot, script and mock trees excluded by
   default; `include_tests=True` to include them).
2. **Extracts** contracts, libraries and interfaces; for each, its functions with
   visibility, mutability, modifiers, parameters, source line, and body; its
   state variables; and its declared modifiers.
3. **Matches** twelve rules against every function and emits a `CandidateFlag`
   per hit, each carrying the exact source line as evidence.
4. **Renders** a triage sheet and a JSON payload.

The scanner is lexer-grade: it strips comments and string literals while
preserving byte offsets, so `file:line` is always the real line. It is not a
compiler and can be fooled by exotic syntax, which is why the output is framed as
leads.

## Compiler AST surfaces

The lexer is the default because it needs no compiler and tolerates partial
source. When a compiler AST is available, `blackheart.ingest.ast_surface`
maps it into the **same** `ContractSurface`/`FunctionSurface` objects, so
synthesis, certification, pricing and verification do not change:

```bash
# Use a solc source-unit AST or combined-json payload
blackheart pipeline --source ./src --contract Vault --ast build/ast.json

# Compile locally first; fall back to the lexer with the compiler's reason
blackheart pipeline --source ./src --contract Vault --compiler-ast
# Pin the compiler used by --compiler-ast
blackheart pipeline --source ./src --contract Vault --compiler-ast \
  --compiler ~/.local/bin/solc-0.8.16
# Add an import root or remapping when the project does not declare it
blackheart pipeline --source ./src --contract Vault --compiler-ast \
  --include-path ./node_modules --remapping '@oz/=./node_modules/@oz/'
```

`--compiler-ast` narrows the build to the selected contract's internal import
closure, so an unrelated broken contract cannot fail the target's build. It
reads `foundry.toml` (`libs`, `allow_paths`, `remappings`), `remappings.txt`,
and ancestor `node_modules`/`lib` directories automatically, selects the exact
`solc-<version>` a `pragma solidity 0.8.16;` requires when it is installed, and
names the compiler's own unresolved-import diagnostic on failure.

`--ast` accepts a raw source-unit AST, a solc `--combined-json` payload, a
Foundry build-info file (`output.sources[*].ast`), or a build-info directory. The AST path uses the
compiler's resolved parameter and return types, struct fields, modifier names,
bases and source offsets. It does not silently repair a
node whose `src` cannot be resolved: that body stays empty and is reported as
unmodelled. A missing compiler or an empty AST falls back to the lexer and the
model stage names why.

## The rules and the categories they map to

| rule | objective category | fires on |
|---|---|---|
| `unchecked-low-level-call` | `silent-transfer-failure` | `.call` whose success flag is not observed |
| `delegatecall-present` | `storage-collision` | `.delegatecall` outside a library |
| `tx-origin-used` | `auth-bypass` | `tx.origin` |
| `unguarded-state-changer` | `access-control` | external state changer in a contract that has guards, without one |
| `unguarded-initializer` | `privilege-escalation` | public `initialize*` with no `initializer` modifier |
| `selfdestruct-present` | `denial-of-service` | `selfdestruct` / `suicide` |
| `unbounded-loop-over-param` | `denial-of-service` | loop over a caller-supplied array |
| `ecrecover-unchecked` | `signature-bypass` | `ecrecover` with no `address(0)` check |
| `timestamp-comparison` | `ordering-timing` | `block.timestamp` in a comparison |
| `oracle-staleness-unchecked` | `oracle-manipulation` | `latestRoundData` with no `updatedAt` |
| `self-balance-pricing` | `accounting-manipulation` | pricing off `balanceOf(address(this))` |
| `mint-without-transfer` | `unbacked-debt` | a mint with no visible collateral intake |

The mapping is validated at import: a rule pointing at a category that does not
exist in `blackheart.objectives._OBJECTIVE_CATALOG` raises, so the taxonomy and
the rules cannot drift. `tests/test_ingest.py` asserts the same thing.

## What it is not

A flag is **a lead, not a finding**. Each rule is precision-first: it fires on a
shape, and the sheet tells you the line, the reason and the attacker question it
would have to answer. `tests/test_ingest.py` pins that a guarded twin
(`onlyOwner`, `initializer`, a checked `.call`) does **not** fire, because a
triage sheet full of false positives is not read.

## Honest scope

`ingest` reads source. It does not deploy or execute the target, and a bug in a
closed component (an unverified contract, a closed order book) is invisible to
it. The executable model is a **bounded statement subset**, not the EVM: a clean
result over an unmodelled operation is meaningless, and the report says so. That
is stated in the engine itself: `python3 -m blackheart capability`.

## Executable model (`--synthesize`)

```bash
python3 -m blackheart ingest path/to/repo --synthesize --depth 3
```

For each contract it builds a `Target` whose operations are the contract's own
externally callable functions, derives conservation invariants, and runs the
bounded-exhaustive certifier on it.

Two rules keep it honest:

- **Only what it can read.** A tiny interpreter handles assignment, compound
  assignment, unary inc/dec, `delete`, nested `if`/`else if`/`else`, mapping
  writes, `require` / `if ... revert` guards and literal-bound loops. An
  operation with anything else is marked *unmodelled* and its effects are
  **not** simulated. `--symbolic` splits conditional effects into true/false
  paths rather than refusing the operation.
- **Only the unprivileged attacker.** Actors are `attacker` and `victim`; the
  owner slot is a sentinel. A guarded function is unreachable until an
  *unguarded* function lets an actor take the slot — the bug the search exists
  to find.

`tests/test_synthesize.py` pins the discrimination: a contract with an unguarded
`setOwner` is broken within depth 3, and the same contract with `onlyOwner` is
certified clean to the same depth.

A violation is a **lead about the source** under the modelled subset. A clean
result over an unmodelled contract is meaningless, and the report says so.

`--coverage` prints the model-coverage ledger without certifying:

```bash
python3 -m blackheart ingest path/to/repo --coverage --json
```

Every reachable function, statement, internal/external call edge and
function-level path is classified `MODELLED`, `UNMODELLED`, `UNREACHABLE` or
`EXTERNAL`, with `file:line` evidence. Any reachable gap makes the result
`INCOMPLETE MODEL COVERAGE`; a clean search is never reported as a clean target.
See `docs/CLOSURE.md` for the full contract.

The modelled subset now includes struct fields (flattened to `obj.field`),
arrays with `push` and `.length`, function-local scalar declarations
(initialised or zero-initialised; they live in the call frame, never in contract
state), inherited functions/state from contracts in the same scan, nested
`if/else if/else`, and source-ordered `require`/`revert` (a `require` after a
write reads the written state and rolls the whole call back on failure; a direct
`revert()` fails the path, and an early `return` stops the writes after it). Statement-level external calls are recorded on the operation and
executed by `closure protocol`, which resolves the receiver through its declared
type; a single-contract step does not pretend a cross-contract effect happened.
Calls execute in source order, so an argument reads the caller state at the call
site. A view function is now interpreted as one conditional expression per
declared return value: locals are substituted, each `return` becomes a condition,
and the paths fold into nested ternaries. A tuple return such as
`returns (uint256, uint256)` is therefore preserved, and `(x, y) = callee()`
binds both values. That is what lets `convertToShares`/`convertToAssets` be
modelled instead of reported unmodelled. A call to another function in the same
contract is an internal call; a call through a declared state variable is an
external call resolved by `closure protocol`; a receiver typed as an interface
or base contract resolves to the one concrete implementation supplied to the
protocol, while two candidates are reported as ambiguous.

The protocol target also models the external ERC20-like call by shape: a callee
with a `balanceOf` mapping gets `transfer`/`transferFrom`/`approve`/`mint`/`burn`
semantics even when its nested `allowance` write is outside the statement
subset. The fallback is selected by structure, never by a token name. It models
`address(this)` as the caller contract, so `transferFrom(msg.sender,
address(this), assets)` and `asset.balanceOf(address(this))` read the right
account.

Every external call now has an explicit outcome: `RETURNED`, `REVERTED` or
`UNMODELLED`. A `REVERTED` call restores the whole protocol snapshot. An
`UNMODELLED` call aborts the path and records the reason in
`ProtocolTarget.unmodelled_calls`; it is never treated as success. A `Link` can
map differently named parameters (`param_map`) and assign a modelled callee
return back into the caller (`return_map`). A link with a missing parameter or
an unresolved receiver is `UNMODELLED`, not a fabricated zero. Nested external
calls execute in the callee's sub-state, and a `nonReentrant` modifier refuses a
recursive entry. An unguarded recursive call stops at a named depth limit rather
than looping or reporting a clean result. Acceptance bar:
`tests/test_protocol_semantics.py`.

Still unmodelled: arrays of structs, mapping-to-struct field writes,
single-contract virtual dispatch, inline assembly, unbounded loops and arbitrary
callback reentrancy. The synthesized target also
derives an `authorization:<owner>` invariant, so an unguarded write to the owner
slot is a violation even when no conservation pair exists. A protocol whose
contract has `convertToShares` also derives
`erc4626:nonzero-shares`: while supply is non-zero, one unit must not convert to
zero shares. That is the share-inflation condition, derived from the surface,
not from a contract name.

## Symbolic reachability (`--symbolic`)

```bash
python3 -m blackheart ingest path/to/repo --synthesize --symbolic --json
```

With `--synthesize`, `--symbolic` asks a second question of the same model: not
"can this sequence break an invariant?" but "which operations can an
unprivileged actor reach, and with what input?". It converts the `OpModel`s into
`blackheart.symbolic` operations and walks them breadth-first.

- **Mapping reads and writes are modelled** when the key is concrete under the
  current actor and state (`balances[msg.sender]` becomes `balances[attacker]`).
  A symbolic key is reported `unsupported`; the operation is never half-applied.
- **Numeric parameters stay symbolic** over their declared domain; an
  address-like parameter is enumerated from its finite domain, because the
  integer solver cannot reason about identities.
- **A witness is a verified assignment** for the whole path. An `UNKNOWN` guard
  is counted, never claimed; a path budget that runs out sets `exhausted: false`,
  which is not a clean result.

On the `Bank` fixture the pass reports `rescue` reachable only after
`setOwner(attacker)` -- the same unguarded-owner-take the certifier finds. It is
a **lead**, over the same subset the certifier uses: assignment, `+=`/`-=`,
mapping writes and `require` / `if ... revert`.

The output is additive: without `--symbolic`, the payload is unchanged.
Acceptance bar: `tests/test_symbolic.py`, `tests/test_synthesize.py`.

## Gated execution (`blackheart.ingest.runner`)

`run_foundry(project_dir, compatibility=..., target_component=..., repository=...)`
runs `forge test --json` **only** when the compatibility gate admits a record
bound to that exact component/repository/commit. A blocked run returns `BLOCKED`
and never invokes the tool (`tests/test_runner.py` proves the invocation count is
zero). Statuses are the doctrine's: `PASS` / `NO_FINDINGS` / `INCOMPLETE` /
`BLOCKED`.

`write_harness(...)` emits a Foundry invariant-test **skeleton** with the derived
invariants as TODO assertions. It is deliberately incomplete: it will not compile
until a human binds it to the real constructor and getters, and the runner reports
`INCOMPLETE` until then rather than a false `NO_FINDINGS`.

### Generated invariant tests (`closure foundry --generate-invariant`)

The skeleton is no longer the only option. `blackheart/ingest/generated_invariant.py`
reads the recovered surface, deploys the vault and its asset, and emits a
**complete** Foundry invariant test with a handler that fuzzes
`mint`/`approve`/`deposit`/`donate`/`withdraw`:

```bash
python3 -m blackheart closure foundry \
  --source harnesses/erc4626/src --contract VulnerableVault \
  --generate-invariant --asset MockERC20 \
  --compatibility <record> --repository blackheart
```

The invariant is the one the model derives: a successful positive deposit must
not mint zero shares. The handler records the last successful deposit, so a
guarded vault whose `deposit` rejects zero shares is not failed by a mere
`convertToShares(1) == 0` at a high price. On the reference pair the vulnerable
vault **fails** the invariant and `SafeVault` survives it. A failing invariant is
mapped to `PASS` (a reproduced bug); a holding invariant is `NO_FINDINGS`, never
"secure".

The generator is no longer ERC4626-only. `render_surface_invariant` selects from
the recovered surface:

| Template | Selected when | Property |
|---|---|---|
| `erc4626:nonzero-shares` | `convertToShares` and `deposit` exist | a positive deposit must not mint zero shares |
| `authorization:owner-unchanged` | an explicit `owner`/`admin` getter exists | an unprivileged handler call must not change the owner |
| `generic` | the operator passes `--invariant-body` | the caller states the property; the generator supplies the fuzzed calls |

```bash
python3 -m blackheart closure foundry \
  --source ./src --contract Vault --generate-invariant \
  --invariant-template authorization:owner-unchanged \
  --compatibility <record> --repository owner/repo

python3 -m blackheart closure foundry \
  --source ./src --contract Vault --generate-invariant \
  --invariant-body 'require(vault.totalSupply() <= 1e30, "supply cap");' \
  --compatibility <record> --repository owner/repo
```

`applicable_invariants` refuses an ambiguous surface; the operator must choose a
template rather than let the generator guess. A function whose parameters cannot
be modelled is listed in `GeneratedInvariant.skipped`, never silently dropped.
Acceptance bars: `tests/test_protocol_erc4626.py`,
`tests/test_generated_invariant.py`, `tests/test_generated_invariant_general.py`.

## Rust / Substrate: the second environment

The EVM engines cannot read a runtime, and a Polkadot-SDK target is a different
environment with the same attacker question. `blackheart ingest <crate>` detects
the stack from the tree (`Cargo.toml`, `.rs` vs `.sol`) and dispatches to
`blackheart/ingest/rust.py`; `--language rust` forces it.

```bash
python3 -m blackheart ingest substrate/frame/assets --language rust
python3 -m blackheart ingest substrate/frame/assets --language rust --json
```

What the scanner recovers, per module:

| Field | Meaning |
|---|---|
| dispatchable | a function inside `#[pallet::call]`, i.e. the attacker-reachable surface |
| weight | the `#[pallet::weight(...)]` annotation, including an impl-level default |
| body | the function body, with comments, strings, raw strings and char literals blanked |
| storage items | `#[pallet::storage] pub type ...` |

It handles both the bare `#[pallet::call]` form and the modern
`#[pallet::call(weight(<T as Config>::WeightInfo))]`. That second form matters:
matching only the bare attribute reported `pallet-assets` — 34 dispatchables — as
having **none**, and every rule then stayed silent. `tests/test_ingest_rust.py`
pins both forms.

The rules (`blackheart/ingest/rust_flags.py`) judge only dispatchables, because a
`pub fn` on `Pallet<T>` that no dispatchable calls is not reachable by an
unprivileged account:

| Rule | Category | Question |
|---|---|---|
| `panic-in-dispatchable` | denial-of-service | can I make it panic with an input any signed account can supply? |
| `unbounded-storage-iteration` | denial-of-service | can I grow state until it exceeds the block weight? |
| `saturating-arithmetic-in-value-path` | accounting-manipulation | if this clamps, who gets the difference? |
| `unchecked-cast` | accounting-manipulation | can I pick an amount whose cast wraps? |
| `multiplication-without-checked` | accounting-manipulation | can I overflow before it is bounded? |
| `no-origin-check` | access-control | what stops any signed account from calling this? |
| `missing-weight-annotation` | denial-of-service | can it cost more than it declares? |
| `event-before-state-change` | state-inconsistency | what does an indexer believe that is not true? |
| `time-window-comparison` | ordering-timing | can I choose the block the window opens on? |
| `unchecked-transfer-result` | silent-transfer-failure | does state record success for a failed transfer? |

A flag is a lead. The scan on `pallet-assets` (34 dispatchables) produces **zero**
flags, which is the correct answer for a hardened pallet and the reason the rule
set is judged on precision first: `tests/test_ingest_rust.py` fires every rule on
its vulnerable shape and requires the guarded twin to be silent.

Anything the scanner could not read is returned in `errors`, never dropped. A
dispatchable it failed to recognise is a blind spot the caller must know about.

## Taint leads (`blackheart dataflow`)

The scanner produces a surface; `blackheart dataflow <path>` adds an SSA-lite
def-use pass over the same source. It propagates parameters, `msg.sender`,
`msg.value`, external-call returns and state through internal calls to a
fixpoint, merges `if` branches with phi nodes, and reports a flow with its
contract, function, source line, source-to-sink path and whether a recognised
owner/admin guard protects it.

A flow is a **lead**. It is not a finding, it does not execute the contract, and
virtual dispatch, overloaded names, inline assembly and arbitrary data structures
remain unresolved. `pipeline --source --dataflow` adds the same pass as a named
lead stage before the certifier.
