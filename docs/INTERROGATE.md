# Interrogation: question the code, then try to break what it claims

Every other engine here starts from a suspicion — a rule matched, a class is
modelled — and looks for a witness. `blackheart interrogate` runs the other way:
it reads the claims the code makes and tries to falsify each one.

```bash
python3 -m blackheart interrogate <path>                 # auto-detect the stack
python3 -m blackheart interrogate <path> --json
python3 -m blackheart interrogate <path> --language rust
```

## The claims

A claim is something the source asserts, explicitly or by structure. The set is
deliberately small, and every claim is derived from the surface — never invented:

| Claim | Derived from | Falsified when |
|---|---|---|
| `only an authorized caller can change state through F` | an externally callable, state-changing function | there is no modifier and no identity check in the body |
| `loops in F terminate within the block limit` | a `while`/`for` in the body | `while (true)`, or a bound that grows inside the loop |
| `state is written before any external call in F` | an external call in the body | the call precedes the first state write |
| `external calls conserve total supply` | `_mint`/`_burn`/`totalSupply` writes | an unguarded mint or burn is externally reachable |
| `initialize can only succeed once` | a function named `initialize*` | no `initialized` flag or `initializer` modifier |
| `dispatchable F cannot be made to panic` (Rust) | a dispatchable body | `unwrap`/`expect`/`panic!`/`todo!` |
| `the work in F is bounded` (Rust) | a dispatchable body | storage iteration |
| `F declares the weight it consumes` (Rust) | a dispatchable | no `#[pallet::weight]` and no impl-level weight |
| `only an authorized origin can call F` (Rust) | a dispatchable | no `ensure_signed`/`ensure_root`/`ensure_origin`/identity `ensure!` |

## The three verdicts, and why there are three

* **`FALSIFIED`** — a concrete reason the claim does not hold, with evidence at a
  real `file:line` and a counterexample sketch. This is a *lead*: the next step
  is a reproduction under scope, not a report.
* **`SURVIVED`** — this specific check found no counterexample. It always carries
  a `blind_spot` naming what the check could not see, because a static "survived"
  is not a proof.
* **`UNTESTABLE`** — the claim cannot be decided from the source that was read.
  This state exists so that "I could not tell" is never rendered as "clean".

That third state is the whole point. The same discipline `blackheart assure`
applies to searches — a stochastic negative is "not found within budget", never
"clean" — is applied here to assumptions.

## Two precision bugs it caught in its own first run

The engine was first run against `pallet-assets` and `SafeVault`, and both runs
found a false positive that had to be fixed before the output could be trusted:

1. **`ensure!` is not an origin check.** Counting the bare macro as authorization
   would hide exactly the missing-guard bug the claim looks for. Only
   `ensure_signed`/`ensure_root`/`ensure_origin`/`ensure_none`, a `ForceOrigin`
   style check, or an `ensure!` that compares an identity now count.
2. **`msg.sender` is not a guard.** `balanceOf[msg.sender]` is the *subject* of an
   operation, not a check on the caller. Only a comparison (`require(msg.sender
   == owner)`, `if (msg.sender != ...)`), a `only*` modifier, or a role check
   counts. Treating it as a guard reported a public, unguarded `withdraw()` as
   safe.

Both are pinned by `tests/test_interrogate.py`.

## What it is not

It does not execute anything. It cannot see a reentrancy path through a second
contract, a guard that checks the wrong dimension (a self-grantable role, a
signature without a nonce), or a bug in a closed component. Every verdict names
its method and its blind spot, and the ledger is a triage sheet, not a finding
report.
