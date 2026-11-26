# TON reference model

`blackheart ton` gives TON (The Open Network) an executable reference target, the
same way `blackheart cosmos` does for Cosmos. It adds **no new search engine**: it
is a `Target` the existing bounded-exhaustive certifier and differential run.

## Why it exists

TON is an asynchronous actor chain with cell storage and message-based entry
points, so the EVM models cannot express it. Before this model, a TON tree was
reported `BLIND` by `blackheart agent` (seen, not modelled). This closes that at
the **model level**: the three bug classes a TON jetton/wallet most often gets
wrong now have an executable shape and a guarded/vulnerable twin.

## The three classes

| Invariant | Class | Bug it catches |
|---|---|---|
| `ton:supply-conservation` | conservation | a jetton `transfer` that credits the destination without a matching debit |
| `ton:admin-only-mint` | authorization | a `mint` that does not check the admin, so any wallet mints itself tokens |
| `ton:wallet-seqno-advanced` | replay | a wallet message handler that does not advance `seqno`, so a signed transfer replays |
| `ton:no-negative-balance` | sanity | a negative jetton or wallet balance |

## Use

```
blackheart ton model                       # operations + invariants + what is not modelled
blackheart ton certify                     # guarded twin: no invariant broken (exit 0)
blackheart ton certify --vulnerable --expect vulnerable   # proves the model finds all three
```

The guarded twin is clean; the vulnerable twin breaks conservation (double-credit
transfer), admin-only-mint (unguarded mint) and wallet-seqno (replay), which is the
differential that proves the model can tell them apart.

## Honest limits

This is a **reference model**, not a TVM simulator. It models the subset an
unprivileged account can reach through ordinary messages. It does **not** model:
TVM gas and cell/boc layout, asynchronous delivery order and bounce handling, the
masterchain/workchain split, TEP-74 forward payloads and excess returns, or
get-methods. A violation here is a **lead about the message/accounting shape**,
never a finding against a deployed contract.

## Next

A FunC source scanner — `blackheart ton from-func` — mirroring `from-tact`, to
recover `recv_internal`/`recv_external` handlers and their sender checks from
FunC source. Until then, a FunC-only tree stays `BLIND` in `blackheart agent`.

## Reading FunC

`blackheart ton from-func <path>` recovers the `recv_internal`/`recv_external`
entry points and the op-dispatch sites inside them (`if (op == op::mint())`),
with a guard/write heuristic per block, and `blackheart ton model-from-func`
derives and certifies a model from that surface. FunC is a stack language, so this
is coarser than the Tact scanner: guard and write attribution is a source
heuristic, dispatch reached through a helper is not seen, and a surface is a lead,
never a finding.

## Hunting a TON target

`blackheart ton hunt <path>` runs the full hunt on a model derived from the tree:
scan (Tact, then FunC) → derive → search → certify → verify, under the
repository-bound self-test record (a derived model is BLACKHEART's own, not a
third-party component). The verify stage re-derives a fresh instance via
`HuntConfig.target_factory`.

By default there is no control and no declared scope, so the witness is
**REPRODUCED, NOT YET CONTROLLED** — a lead, never an independent confirmation.
Supply a **guarded twin** and declare scope to lift it:

```
blackheart ton hunt <vulnerable> --control <guarded-twin> --in-scope --authorized --scope-ref <program>
```

With a discriminating control (the guarded twin holds the invariant) and declared
scope/authorization, the verdict becomes **VERIFIED** and the verify stage reports
`INDEPENDENTLY_VERIFIED`. This is a **model-level** verification — a fresh re-run
plus a discriminating control, not a deployed-contract confirmation — and the
command says so. A control that *also* breaks the invariant is rejected, so the
check discriminates rather than rubber-stamps.

## Reading a real contract

`blackheart ton from-tact <path>` recovers the `receive` surface of every `.tact`
file — handler name, contract, line, whether it checks `sender()` against an
owner/admin, and whether it writes state. It is a **surface, a lead**: it names
reachability and authorization, and never invents accounting semantics. A FunC
tree is not yet read.

## Deriving a contract model

`blackheart ton model-from-tact <path> --certify` maps the recovered handlers onto
the reference operations and certifies the **specific** contract: it enables only
the ops the contract exposes, takes **authorization** from the source (an unguarded
`mint`/`change_admin` is reachable by anyone, so `ton:admin-only-mint` can break as
a lead), and lists every handler it cannot map as unmodelled. It does **not** apply
the reference model's deliberate bugs — those are not derivable from a surface. A
broken invariant here is a lead about the contract's authorization shape, never a
finding.
