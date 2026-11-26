# UMA Protocol adversarial harness

Foundry harness for the UMA Protocol bug-bounty engagement (missions 01–05).
It runs the **real, pinned upstream source** of UMA's Optimistic Oracle V3, the
Data Verification Mechanism (VotingV2), Store and the managed Optimistic Oracle
V2 against lifecycle, accounting and adversarial tests — no model, no mock
protocol.

## Run it

```sh
./fetch.sh          # clone the pinned source into vendor/ and materialise src/
forge test          # 38 tests across 9 suites
```

`fetch.sh` is idempotent and re-enforces every pin on each run. It needs only
public git remotes; no API key, no paid service.

## What is committed and what is fetched

| Path | Status | Why |
| --- | --- | --- |
| `test/` | committed | the harness's own adversarial tests |
| `foundry.toml`, `.gitignore` | committed | build config |
| `fetch.sh`, `README.md` | committed | reproducibility |
| `src/` | **fetched** | verbatim in-scope UMA source (AGPL-3.0) |
| `vendor/`, `vendor-managed-oracle/`, `lib/`, `out/`, `cache/` | **fetched** | pinned upstream checkouts |

The UMA source is AGPL-3.0-only; it is used here only as a locally built,
git-ignored test target — never redistributed, never deployed.

## Pins

| Repo | Commit |
| --- | --- |
| `UMAprotocol/protocol` | `00e962161d9c123de16e3c86c0500a530eaa319b` |
| `UMAprotocol/managed-oracle` | `24a5930ba82bb9a91fb3251d8d7ff243b5d95a7a` |

Override with `UMA_PROTOCOL_PIN` / `UMA_MANAGED_PIN` when re-pinning.

## Coverage

| Suite | Tests | Focus |
| --- | --- | --- |
| `test/uma/OOv3Lifecycle.t.sol` | | assert → dispute → settle accounting |
| `test/uma/OOv3Invariants.t.sol` | 1 invariant | bond solvency under fuzzed call order |
| `test/uma/OOv3AncillaryDoS.t.sol` | | ancillary-data handling |
| `test/uma/EscalationManagerAttacks.t.sol` | | escalation-manager policy paths |
| `test/uma/SuperbondEscalationAttacks.t.sol` | | super-bond escalation |
| `test/voting/VotingV2Lifecycle.t.sol` | | stake / commit / reveal / slash |
| `test/voting/VotingV2Economic.t.sol` | 10 | economic invariants, solvency |
| `test/voting/VotingV2PendingStakes.t.sol` | 2 | pending-stake / slash interaction |
| `test/voting/VotingV2Attacks.t.sol` | | adversarial voting paths |

A passing test is **not** a finding. These tests establish that the modelled
attacks do not break the real code; they are the negative evidence that
supports the mission reports under `research/uma-protocol-0*/`.
