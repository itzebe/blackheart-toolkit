# The universal hunt

The hunt is the single entry point that runs **every engine BLACKHEART has, in
the order the doctrine requires, and returns one honest verdict**. It introduces
no new search and no new verifier: it *composes* the engines that already exist
and are already tested, passes each stage's real output to the next, and never
upgrades a lead it did not prove.

```bash
blackheart hunt --target vulnerable --control safe --in-scope --authorized \
  --compatibility record.json
blackheart hunt --target vulnerable --memory            # recall + write back proven attacks
blackheart hunt --target vulnerable --scenario sandwich # search the ordering space too
blackheart hunt --target safe                            # a clean bounded negative
```

## Compatibility: the record must cover the comparison

The hunt is a compatibility-gated execution, and so is every engine it calls. One
record authorises exactly two components: the target under test
(`target_component`) and, when the hunt is given `--control`, the guarded twin it
is compared against (`control_component`). A record that declares no control
leaves the differential check failing closed at the gate -- the run reports the
error, it does not fall back to the target's authority.

A registry alias and the model's canonical name are the *same* component
(`vulnerable` resolves to `vulnerable-vault`). The hunt declares both at its
boundary and resolves `--control` the same way, so a record naming either form
binds at the hunt boundary *and* at the nested engine boundary. Without that, the
two boundaries would compare the record against different strings and no record
could satisfy both.

An **unevaluable invariant** is reported, never folded into the result: if a
declared predicate raises on a reached state, the hunt's `unevaluable` list and
its verdict note say so, because a negative that could not be evaluated is
"could not tell", not "clean".

## The stages

The order is fixed (`blackheart/hunt/HUNT_STAGES`). A caller may run a prefix with
`--stages search,certify`; a stage that is not requested is recorded as *skipped*,
not silently omitted.

| # | Stage | What it calls | What it produces |
|---|-------|---------------|------------------|
| 1 | `recall` | `blackheart.learning.transfer.AttackMemory` | proven attacks from earlier targets that structurally resemble this one, as candidate seeds |
| 2 | `search` | `blackheart.assurance.portfolio.run_portfolio` | the union of every strategy's counterexamples, the oracle audit, and the value-priced hits |
| 3 | `certify` | `blackheart.discovery.certify.certify_path` / `certify_concolic` | each candidate turned into a reproducible, prefix-minimal **witness**, or dropped |
| 4 | `verify` | `blackheart.statespace.verify.IndependentSequenceVerifier` | the independent disposition per certified candidate |
| 5 | `order` | `blackheart.statespace.mempool.search_ordering` | the interleavings that profit an attacker, when a scenario is named |
| 6 | `remember` | `blackheart.learning.transfer.AttackMemory` | **only** fully verified attacks written back as transferable shapes |

## The verdict ladder

`HuntResult.verdict_line()` is the one sentence a caller can trust. It reports the
**strongest** thing that is actually true, and nothing stronger:

1. **VERIFIED** — at least one candidate was independently reproduced, found
   attacker-reachable, and held under a discriminating control. This is the only
   disposition that is a finding.
2. **REPRODUCED, NOT YET CONTROLLED** — reproduced and attacker-reachable, but the
   guarded twin was not established. Supply `--control` to reach VERIFIED. This is
   *not* a finding.
3. **CERTIFIED LEAD** — proven to break an invariant with a reproducible witness,
   but not yet independently verified.
4. **CANDIDATE LEADS ONLY** — counterexamples found, none certified. Leads, not
   findings.
5. **NOT FOUND** — no counterexample by any strategy, to the stated bound. This is
   *"not found within budget"*, never a proof of absence. When the bounded-exhaustive
   certificate is present the line says exactly what the bound does and does not
   cover.

Every verdict carries a **weak-oracle note**: if the oracle audit could not show a
declared invariant can catch anything, a clean result on it proves nothing, and the
line says so.

## The honest claim

The hunt does **not** claim it "misses nothing" — that claim is not provable and
would be a lie. It makes the strictly stronger, honest claim it can support:

- **every strategy is run**, and the search result is the **union** (a strict
  superset of any single search);
- every candidate is **certified or dropped**, never asserted;
- verification is **independent** — a fresh instance, a discriminating control,
  scope and authorization facts — and the hunt reports the verifier's verdict
  rather than rubber-stamping it;
- the **coverage ledger** is attached, so a clean result is bounded, not final;
- only a fully verified attack is promoted to the cross-target memory.

## Universal RPC resolution

No fork test or `deployed` check depends on a hardcoded endpoint any more. Every
one resolves a *live* endpoint through `blackheart/rpc.py`, in a fixed order:

1. the operator's explicit `--rpc` / `$BLACKHEART_ETH_RPC` (always wins, verbatim);
2. the keyless `chainid.network` registry;
3. **You.com** discovery (`blackheart.intelligence.discover`), the enforced provider;
4. a last-resort list of well-known endpoints.

Every candidate is probed with a real `eth_chainId` call; only one that *answered*
(and matched the expected chain id, when given) is returned. When none answers, the
resolver returns `""` and says so — it never returns an endpoint it did not see
answer.

## You.com is the enforced provider

The intelligence router no longer silently falls through to a generic keyless
provider while the primary is up. When You.com is configured it is the **whole**
order: a technical query is never answered by a thin DuckDuckGo/Wikipedia result.
The keyless fallbacks are preserved as an explicit, opt-in capability
(`--allow-fallback` on `blackheart intel route` / `investigate`, or
`SearchRouter.search(..., allow_fallback=True)`), and are used automatically only
when the primary is *not configured* — honest degradation beats no context.

## The compatibility gate

The hunt is an engine execution, so it is compatibility-gated at its boundary
(`blackheart/toolchain/enforce.py`): it runs only under a validated
language-aware record bound to its target.

```bash
blackheart hunt --target Vault --compatibility compatibility.json
```

Without a record the hunt exits 2 and names the missing field and the remedy; it
never starts a stage. A record written for another target, another repository or
another commit is refused by the same gate. Inside an authorised run the stages
inherit the authority and cannot widen it -- a stage that reaches a different
target is blocked. See `docs/SECURITY_TOOL_COMPATIBILITY.md` sections E and E2.

## The operator's word

The operator's instruction is the mission: it is read as a directive to act, not a
topic to discuss, and the default posture is to do the work and report the result.
This rule lives in `blackheart/mindset.py` (`OPERATOR_AUTHORITY`) and reaches every
layer — the role prompts (`prompt_block`), every specialist agent
(`agent_lens_block`, and every file under `agents/`), and the mindset skill. The one
thing the operator's word never overrides is the safety floor: authorization, scope,
and never harming real users or funds.
