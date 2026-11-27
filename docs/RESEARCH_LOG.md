# Research log

Honest record of what was actually tested in this environment. Nothing here is
invented: every result below was produced by a command that was run and whose
output is quoted.

## Historical-rediscovery discovery engine (mission 3.A/3.B/3.D/3.E/3.G/3.H/3.I)

Branch `feat/blackheart-discovery-engine` (from PR #47 head `3ba5bcd`). New package
`blackheart/discovery/`, CLI `blackheart discovery`, harness
`harnesses/historical-corpus/`, tests `tests/test_discovery.py`.

**Corpus (Capability A).** `discovery/corpus.py` — 20 real, publicly-disclosed
vulnerability cases, each with a vulnerable/patched model pair that shares the same
invariants. `python3 -m blackheart discovery corpus` -> `total_cases 20`,
`modelled_cases 15`, `distinct_root_causes 15`, `distinct_repositories 9`. Pins are
recorded only when independently verified (none are pinned here; references are
public advisories/repos, never invented).

**Three-engine benchmark (Capabilities B/H).** `python3 -m blackheart discovery
benchmark` over 17 modelled cases (15 corpus + 2 blind holdout), deterministic seed
0, baseline 300 runs × 10 steps:

| metric | baseline | guided (PR #47) | enhanced |
|---|---|---|---|
| recall | 0.94 (16/17) | 0.88 (15/17) | **1.00 (17/17)** |
| false positives on patched controls | 0 | 0 | **0** |
| sequences tried | 5100 | 567 | 479 |
| root-cause recall | 0.93 | 0.87 | **1.00** |

Capability B is `harness.model_from_target`: the guided engine reads a `SystemModel`
reconstructed from the target's own `ops()`/`invariants()`/actors
(`source="derived:Target.ops()"`), not a hand-written model.

**Parameter-aware search (Capability D).** `discovery/search.py`. The PR #47
explorer fixes each step's parameters, so it misses the first-depositor inflation
case (needs a 1-wei deposit then a large donation) — measured: guided 15/17. The
enhanced search adds parameter-boundary enumeration and reaches 17/17, finding the
inflation sequence at minimal length 3 with a small value present (asserted in
`test_enhanced_search_finds_parameter_boundary_case`).

**Economic accounting (Capability E).** `python3 -m blackheart discovery economic`
-> 15 attacker P&L accounts read from each target's own snapshot, e.g.
H01-reentrancy `profit=200, protocol_loss=201, repeatable=True`; H10-insolvent-withdraw
`victim_loss=800, protocol_loss=1600`. The account is conservative: profit is net
capital (assets minus obligations), a reverted step counts as zero, an overflow is
flagged and excluded, and `financial_impact_established` separates a value movement
from a mere state flip (see the mission 2.5 validation below — the original
accounting over-counted a doubled `allowance` as profit and was hardened here).

**Missed-vulnerability analysis (Capability I).** `python3 -m blackheart discovery
misses` -> the two guided misses are classified `exploration` (budget/ordering), and
the analyser proves the case is otherwise reachable — the exact failures the
enhanced search fixes.

**Real EVM reproduction (Capability G).** `harnesses/historical-corpus/`.
`python3 -m blackheart discovery foundry` -> PoC suite passes: the reentrancy,
access-control and permit-replay exploits all run on the vulnerable contracts and
their patched controls reject the same sequence (`forge test --match-contract
HistoricalCorpusPoC` -> 6 passed). `python3 -m blackheart discovery
foundry-invariant` -> `differential_established: true` (the stateful invariant
FAILS on the vulnerable bank with a 2-call shrunk counterexample and HOLDS on the
patched bank). In-process EVM only; no fork, no broadcast.

**Regression bar.** `tests/test_discovery.py` -> 14 passed (2 full-benchmark tests
marked `slow`). Full suite on this branch `python3 -m pytest tests/` -> **920
passed, 16 skipped, 0 failed** (109.22s). This branch is built on PR #47's head, so
the count includes PR #47's `tests/test_statespace.py` as well as the 14 new
discovery tests; `main` measured **812 passed, 24 skipped** in the same
environment. No test regressed.

## Independent validation (mission 2.5) — integration and evidence check

Independently re-ran the PR #47 claims on its actual head and found the capability
claims reproduce; four economic-accounting defects were found and fixed, and one
harness provenance gap was closed. Evidence: `research/discovery/*.json`,
regenerated from the fixed engine.

**Reproduction.** `python3 -m pytest tests/` -> **930 passed, 16 skipped, 0 failed**
(+10 new adversarial economic/pin tests). Benchmark reproduced exactly
(development 15 cases -> enhanced recall 1.0, guided 0.8667, baseline 0.9333;
holdout 2 -> 1.0; all-modelled 17 -> enhanced 1.0, guided 0.8824, baseline 0.9412;
false positives 0 everywhere). `forge test` (pinned `forge-std v1.9.7`):
`HistoricalCorpusPoC` 6 passed, `BankInvariantTest` 1 failed as expected,
`SafeBankInvariantTest` 1 passed — verified from a **clean** `out/`+`cache/`.

**Interoperability.** A `discovery` violation is a `statespace.explore.Violation`
and runs through the shared `IndependentSequenceVerifier` unchanged: with the
patched model as the secure control the disposition is `REPRODUCED`, and when the
control is made non-discriminating the verifier correctly returns `REJECTED`
(`secure control reproduces the violation`).

**Defects found and fixed (economic accounting).** Each is now a regression test in
`tests/test_discovery.py`:

1. A step that **raised** (reverted) propagated out of `analyse` instead of
   counting as no-op.
2. `allowance` was summed into the attacker's "capital", so a replayed permit
   (H04) was reported as `profit=101` although no value moved.
3. A **wraparound** balance (H17, `2**256 - …`) was reported as astronomical
   profit; it is now flagged (`bounded_values`) and excluded.
4. A borrow that raised `cash` and `debt` equally was counted as profit; profit is
   now net of obligations. Victim loss now counts asset decreases only.

**Harness provenance.** `harnesses/historical-corpus/fetch.sh` installed
`forge-std` **unpinned** (and `forge install` created a submodule + `.gitmodules`
in a repo that keeps vendored deps git-ignored). It now clones and checks out the
immutable tag `v1.9.7` — the same pin `foundry_corpus.ensure_deps()` uses — and a
test asserts the two agree and that `forge install` is not invoked.

## Environment

- Sandbox: Linux x86_64, Python 3.13.15, Foundry `forge 1.9.0`.
- Engine test suite: `python3 -m pytest tests/` -> **115 passed** (was 60 before the
  attacker-engine extensions below).
- Foundry harness: `ExploitPoC` 2 pass; `GeneratedPoC` 2 pass; `SafeInvariantsTest`
  holds; `InvariantsTest` (vulnerable) breaks 2/2 invariants as expected.
- Toolchain: `python3 -m blackheart tools verify` -> **3 functional** in this
  sandbox (forge, cast, anvil). The other 24 registry tools are `missing` here;
  `install.sh` installs them. This is a fresh container, so tool availability is
  re-verified per runtime, never assumed.

## Attacker-engine extensions (this session)

Built on branch `feat/adversarial-exploit-engine-v2` (the original
`feat/adversarial-exploit-engine` is an orphan history from a closed PR and was
deliberately left untouched).

- **Executable attack-chain database** (`blackheart/attackdb.py`): six concrete,
  runnable sequences, each bound to a target + invariant and to a guarded control.
  `python3 -m blackheart chain --run <id>` executes the sequence on both models and
  reports whether the targeted invariant broke. All 6 verify (vulnerable breaks,
  guarded holds).
- **Two more executable attack classes** (`blackheart/invariants/class_targets.py`):
  `callback-reentrancy` (checks-effects-interactions) and `access-control`
  (ungated privileged setter), each with a guarded control. Both produce
  attacker-reachable invariant violations on the vulnerable model and none on the
  guarded model.
- **Foundry generator** (`blackheart/foundry.py`): renders a runnable PoC from an
  executable chain against the real harness API. `forge test --match-contract
  GeneratedPoC` -> 2 passed (vulnerable exploitable, guarded blocks).
- **Regression emitter** (`blackheart/regress.py`): turns a captured counterexample
  into a deterministic, self-contained pytest file. Emitted tests re-run green.
- **Scope registry** (`blackheart/scope.py`): dated, verbatim scope capture with
  append-only registry and per-asset gate decisions; refuses a `verified` record
  with no scope text and refuses invalid classifications.
- **Agent/skill invocation verifier** (`blackheart/agentverify.py`) and
  **discovery provisioner** (`blackheart/provision.py`): load the project's skills
  and agents from the real agent-server; `agents-verify` reports 7 skills and 12
  agents discoverable from the workspace. In a fresh workspace it reports
  `available: true, ok: true` after `provision`.

Portability: the working tree was copied to `/tmp/bh-portable` (no `.openhands`, no
vendored `forge-std`); after `provision` and adding `forge-std`, `pytest tests/`
-> **115 passed**, and `agents-verify` discovered all 7 skills and 12 agents.

## Reference engagement (engine validation)

`python3 -m blackheart engagement --workdir research/private/reference-engagement`

Target: a **local, deliberately-vulnerable reference vault** (not a real
program). Result: 13 objectives, 24 chains, the Python fuzzer found 6
counterexamples on the vulnerable model and 0 on the safe control; the Foundry
PoC passed (attacker extracts value, victim loses); the Foundry vulnerable
invariants broke and the safe control held. The independent verifier classified
the finding **CONFIRMED** with all seven gates PASS, and a report was written.

This validates the *pipeline*. It is **not** a real-world vulnerability.

## Priority research question — Aave aToken / wrapper-share accounting

Mission section 6 asks whether a wrapper share can diverge from the underlying
aToken balance so as to yield unauthorized value extraction.

### Phase 1 — against a documented *model* (engine validation)

The real Twyne source was not initially present, so I first built an explicit
model of the accounting (`blackheart/invariants/wrapper_targets.py`) and attacked
it with a dedicated stateful invariant harness. Two variants, differing only in
the ERC4626 virtual-shares offset:

| Model | runs | steps | failures |
|---|---|---|---|
| `wrapper` (naive) | 2000 | 12 | **6** (material victim loss / attacker profit) |
| `wrapper-guarded` (virtual shares) | 2000 | 12 | **0** |

### Phase 2 — against the *real* in-scope source, on a local mainnet fork

The real Twyne `AaveV3 aToken wrapper` (`0xTwyne/aave-v3-aToken-wrapper`,
pinned `797be33e…`) was fetched and compiled against real dependencies, and
tested against **real Aave V3 on a local mainnet fork** (keyless RPC, nothing
broadcast). Harness: `harnesses/twyne-aave-wrapper/`; driver:
`python3 -m blackheart fork run --target twyne-aave-wrapper`.

Real results (`forge test`, real fork block ~26,386,2xx):

| Id | Hypothesis | Result |
|---|---|---|
| H1 | Donating aTokens moves the share price | **FALSE_POSITIVE** — price is from Aave's supply index, not the wrapper balance |
| H2 | Rounding drift makes `totalSupply` exceed backed aTokens | **FALSE_POSITIVE** — backed balance is exactly `>= totalSupply` after 200 small deposits |
| H3 | A CV accrues aTokens beyond its shares via rebalance rounding | **FALSE_POSITIVE** — 50 rebalances stay exact |
| H4/H5 | A registered collateral vault can pull aTokens with zero shares | **NEEDS_MORE_EVIDENCE** — mechanism real and reproduced; no CV-side path that over-states collateral has been shown |
| H6 | Six-decimal assets (USDC) round-trip losslessly | **FALSE_POSITIVE** — 1m USDC in → 999,999.999999 USDC out |
| H7 | Wrapper shares rebase as Aave yield accrues | **FALSE_POSITIVE** — share count constant; same shares redeem ~1.4% more after a year (intended) |
| H8 | Permissionless `skim()` is attacker profit | **FALSE_POSITIVE** — minted shares are worth `floor(assets/rate) <= assets`; 5 WETH in → 4.9999 WETH of shares |
| H9 | `burnShares_CV` after external liquidation under-backs others | **FALSE_POSITIVE** — a victim's shares stay fully backed after the CV burns seized-collateral shares |
| H10 | An Aave index change *between* operations is arbitrageable | **FALSE_POSITIVE** — a pre-yield depositor keeps principal + real yield; a post-yield depositor extracts exactly its deposit; total out ≤ the wrapper's aToken backing |

## Engagement authorization (2026-11-10)

The official Twyne Immunefi program page was retrieved and hashed; the record is
in the authorization registry (`research/private/authz/`, git-ignored) and the
gate was exercised end-to-end:

- Program **active**; rewards **up to $50,000**; **KYC not required**; **Safe
  Harbor** applies; **PoC required**.
- In scope: `0xTwyne/aave-v3-aToken-wrapper` and `0xTwyne/twyne-contracts-v1`.
- Gate result: the wrapper asset classifies **AUTHORIZED** (active local-fork
  testing permitted); `twyne-contracts-v1` classifies **PASSIVE_ONLY**; any other
  asset is **UNKNOWN** and blocked. No active test runs without an AUTHORIZED
  asset and every program check passing.

Stateful invariants (honest handler: deposit/withdraw/donate/CV-rebalance/
skim/external-liquidation-burn, 7 ops, 1920 calls, 0 reverts): five properties
hold — the wrapper's aTokens always cover the shares held by non-CV holders, the
victim's realised value never exceeds what it deposited, `totalAssets()` stays
consistent with the supply, supply is fully backed by scaled aTokens held by
wrapper+CV, and reported assets never exceed real aToken balances. **No
invariant break.**

### Phase 3 — CV-side source review (H4/H5 continuation)

The full Twyne collateral-vault source (`0xTwyne/twyne-contracts-v1`) was read:
`CollateralVaultBase.sol`, `AaveV3CollateralVault.sol`, `CollateralVaultFactory.sol`.

- `CollateralVaultBase` (711 lines) and `AaveV3CollateralVault` (381 lines) were
  read in full. `rebalanceATokens_CV` is called only from `_handleExcessCredit`
  with `vaultAssets = totalAssetsDepositedOrReserved` (an EVC-authenticated,
  internally-tracked value), and from `handleExternalLiquidation` with `0`.
- The wrapper's `rebalanceATokens_CV(shares)` can **only move aTokens in the
  CV→wrapper direction beyond the shares check** (a higher `shares` is clamped by
  the CV's own aToken balance; a lower `shares` pulls aTokens back to the
  wrapper). It never hands a CV another holder's aTokens, and it never mints
  shares. So the "zero-share pull" in H4/H5 moves a CV's *own* aTokens.
- Every CV operation that changes collateral ends with
  `evc.requireAccountAndVaultStatusCheck`, and `checkVaultStatus` reverts if the
  vault is liquidatable (`VaultStatusLiquidatable`), so an over-statement that
  made the position unhealthy is rejected at the EVC boundary.
- Factory: `isCollateralVault[vault] = true` is set only inside `_deployVault`,
  reached solely through the `create*CollateralVault` functions, which require
  `vaultManager.isIntermediateVault` / `isAllowedTargetVault` /
  `isAllowedTargetAssets`. Registration is governance-gated, not self-service.

**Conclusion.** H4/H5 is a genuine *trust boundary* — the wrapper relies on every
registered CV passing a correct `shares` value — but no CV-side path that
over-states collateral has been found, and the wrapper cannot be drained through
it. Status remains **NEEDS_MORE_EVIDENCE**; it is **not** a demonstrated exploit.

**Interpretation (honest).** The wrapper prices shares from Aave's
`getReserveNormalizedIncome` index, not from its own aToken balance, and rejects
zero-share deposits — so the donation/inflation class does not apply. **No
wrapper-share accounting vulnerability is demonstrated.** The priority hypothesis
is **not confirmed**.

## What was NOT done (and why)

- **No active testing against any live program.** The authorization gate blocks
  active testing without a verified, in-date scope record. All Twyne work above
  is *local fork* testing of published source — permitted by the program, and
  never touching production state.
- **No artifacts from the prior Twyne engagement exist in this repository.** The
  historical results in the mission brief (Euler 287 passed, Morpho 281, Aave 261,
  wrapper 52 with one test bug, 400 randomized invariant runs, no confirmed
  vulnerability) are treated as **user-supplied and unverified here**, not
  independently reproduced.
- **Portability verified in an independent container (2026-11-10).** The engine
  self-test (`87 passed, 3 skipped, 0 failed`), `blackheart doctor` (healthy), and
  `./install.sh --core` (forge 1.9.0) all succeed in a fresh `python:3.13-slim`
  container. See `docs/PORTABILITY.md`.

## Next highest-value attack hypotheses

1. **CV-side collateral over-statement (H4/H5 continuation).** Read the full
   Twyne collateral-vault source (`CollateralVaultBase`, `AaveV3CollateralVault`)
   and search for a path where the CV passes a `shares` value to
   `rebalanceATokens_CV`/`burnShares_CV` larger than its tracked collateral —
   e.g. via `skim()`, teleport, or a re-entrant snapshot. This is the highest
   value open question.
2. **Rebasing-during-operation.** Interleave an Aave index change *inside* a
   wrapper operation (the fork allows warp/roll mid-test). The current tests
   accrue yield discretely.
3. **Factory registration trust.** Verify `isAllowedTargetVault` /
   `isAllowedTargetAssets` and who can register a CV for the wrapper's asset;
   if an attacker can self-register, H4/H5 becomes reachable.
4. **Cross-protocol trust.** Wrapper -> intermediate credit vault -> liquidation
   paths that read the wrapper's reported collateral; attack the divergence
   between reported collateral and redeemable assets.

---

## Twyne Aave aToken wrapper — real-source verification

This section answers hypothesis #1 above ("Twyne wrapper vs real source") by
running the harness against the **actual** wrapper source instead of a model.

**Target.** `0xTwyne/aave-v3-aToken-wrapper` at tag `1.0.1` (commit `797be33`),
files `src/AaveV3ATokenWrapper.sol` and `src/CustomERC4626StataTokenUpgradeable.sol`.
The source is BUSL-1.1 (source-available); it is fetched, not committed, and is
treated as target-confidential. Authorization scope was recorded before testing.

**Harness.** `harnesses/aave-wrapper/` (see its README). The wrapper is compiled
from source against pinned Aave/EVC/OpenZeppelin revisions; the Aave pool and
aToken are minimal mocks. Local, in-process EVM only — no fork, no broadcast, no
real funds.

**Commands and results.**

```
./fetch-deps.sh          # fetches wrapper source + pinned deps (fresh copy, exit 0)
forge test -vv
  AaveWrapperAccountingAttack  3 passed, 0 failed
  AaveWrapperInvariants        1 passed, 0 failed   (stateful fuzz, ~6000 calls)
  total: 4 passed, 0 failed, 0 skipped
```

- Inflation attack (2 wei seed, 10e18 donation, 1e18 victim deposit): **blocked** —
  the wrapper reverts with `StaticATokenInvalidZeroShares()` rather than accept a
  zero-share deposit, so the victim cannot be diluted. A 256-run fuzz over seed /
  donation / victim-deposit space found **no profitable path**.
- Repeated conversions across a yield (rate) change: **no value created**; the
  wrapper never reports more assets than it holds.
- Stateful invariants (`reported_equals_redeemable`, `shares_backed`): **held**
  across ~1200 airdrops, 1177 deposits, 1236 skims, 1183 redeems, 1199 donations.

**Conclusion.** The priority hypothesis is **falsified against the real source**.
No wrapper-share accounting vulnerability is demonstrated. The defence is the
`StaticATokenInvalidZeroShares()` revert on zero-share deposit/skim.

**Harness artefacts found and discarded (honesty).** Two apparent failures during
development were mock bugs, not wrapper vulnerabilities, and were fixed before
any conclusion was drawn: (1) the mock pool was not funded for accrued yield, so
withdrawal underflowed — real Aave liquidity pays yield; (2) the mock pool
returned a different rate than the mock aToken used — in real Aave these are the
same rate. A violation that appears only when a mock is unfunded or internally
inconsistent is a harness artefact.

**Remaining uncertainty.** The pool/aToken are modelled (scaled-balance rebasing),
not the deployed contracts; the EVC collateral-vault interaction is not modelled
here. Next: (a) a fork-based harness against deployed Aave/EVC contracts (local
fork only); (b) collateral-vault (EVC) interaction during liquidation; (c) the
wrapper upgrade/initialize path.
