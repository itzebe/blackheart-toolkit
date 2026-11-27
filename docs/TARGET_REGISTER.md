# Target register

Programs BLACKHEART has independently verified and may research. Each entry
records the official policy, the exact in-scope assets, the testing rules, the
authorization status, and the current investigation status. A target is only
listed as **AUTHORIZED** after its scope was fetched from the official page and
captured verbatim (see `blackheart scope` / `blackheart eligibility`).

Nothing here is invented: every fact below was read from the official program
page, with the retrieval date and a SHA-256 of the retrieved page recorded.

---

## 1. Twyne — Immunefi

| Field | Value |
| --- | --- |
| Program | Twyne |
| Platform | Immunefi |
| Policy URL | https://immunefi.com/bug-bounty/twyne/information/ |
| Submission URL | https://immunefi.com/bug-bounty/twyne/ |
| Page retrieved | 2026-11-11, sha256 `e5c2d2b40c77a0974636af2c97b515ab916507a360a9849715588bc930f4dc5c` |
| Rewards | USDC on Ethereum. Smart Contract Critical: $10,000–$50,000 (10 % of funds directly affected, capped). Primacy of Impact High: $3,000–$10,000 |
| PoC | **Required for all severities** |
| KYC | **Not required** for payout |
| Publication | Responsible Publication Category 3 — approval required before disclosure |
| Safe harbor | Yes (Immunefi safe harbor applies) |

### In-scope assets (Smart Contract)

| Asset | Repository | Status |
| --- | --- | --- |
| AaveV3 aToken wrapper | https://github.com/0xTwyne/aave-v3-aToken-wrapper (pin `797be33e22cce033f6d9c66650d9604ee48fc60d`) | AUTHORIZED |
| Twyne protocol contracts | https://github.com/0xTwyne/twyne-contracts-v1 | AUTHORIZED |

The program page lists 17 total assets (the two repositories above plus deployed
contracts and website assets). Only the two source repositories are researched
here, because they are the parts that can be read and reproduced locally.

### Testing restrictions

- Local, offline analysis and **local-fork** reproduction are permitted and are
  what BLACKHEART performs. `forge test` runs in-process on a fork; nothing is
  broadcast and no production state is touched.
- Live/campaign testing of a deployed asset requires the active-testing gate
  (`blackheart.authz`) to pass for that exact asset.
- Prohibited: denial of service, destructive testing, social engineering, tests
  against third-party infrastructure outside scope, accessing others' private
  data.

### Research method

Public-source review, local static analysis, and local-fork adversarial tests and
stateful invariant fuzzing against real Aave V3 (keyless public RPC). No paid
infrastructure.

### Authorization status

`AUTHORIZED` for public-source review and local-fork reproduction. `PASSIVE_ONLY`
for any activity that would touch a deployed mainnet asset without a fresh,
asset-scoped active-testing authorization.

### Investigation status

INVESTIGATING → strongest candidate **NEEDS_MORE_EVIDENCE** (see
`artifacts/submissions/twyne/aave-wrapper-rebalance-boundary/`). Prior work (PR #30
MPC-001) reached `NEEDS_MORE_EVIDENCE`, not confirmed.

### Prioritization reason

Explicit, well-defined scope; public source; a security-critical transaction and
accounting surface (aToken/share accounting, collateral-vault trust boundary);
deterministic local reproduction possible; no account fee; KYC not required.

---

## Programs evaluated but not selected

| Program | Reason not selected |
| --- | --- |
| Web/API programs with no public source | Cannot be researched without live interaction, which is not authorized for autonomous runs |
| Programs requiring paid infrastructure or identity verification to investigate | Mission constraint: no spend, no unnecessary identity verification just to research |
| Programs with unclear scope | Scope could not be verified verbatim; a target without a verified scope is not researchable |
