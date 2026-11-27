# Measuring BLACKHEART against EVMbench, honestly

EVMbench is OpenAI's and Paradigm's benchmark for whether an agent can find and
exploit smart-contract bugs. Its harness needs Postgres, RabbitMQ, Docker and a
paid OpenAI key, so it cannot be the thing a fresh sandbox runs to answer *"is
BLACKHEART any good?"*. This document describes what BLACKHEART does instead: a
key-free **localization** measurement against the same ground truth, and exactly
what that measurement can and cannot claim.

## The ground truth is free; the harness is not

The audit dataset lives in `openai/frontier-evals` under `project/evmbench/`
(MIT licensed). For every disclosed vulnerability it ships the maintainer's own
fix as a unified diff, for example `patch/H-02.diff`:

```diff
@@ -1120,7 +1125,7 @@ contract Vault is ERC4626 {
-    _twabController.mint(_receiver, uint96(_shares));
+    _twabController.mint(_receiver, _shares.toUint96());
```

A fix diff is an exact, machine-readable statement of *where the bug was*:
`Vault.sol`, line 1125. That is enough to ask a precise question without any
model, container or API key.

## What is measured

`blackheart evmbench` scores one or more engine reports against those locations
and reports **three separate numbers**, because collapsing them is how a
localization result gets dressed up as a detection result:

| Metric | Question | Worth quoting? |
| --- | --- | --- |
| `file_recall` | did the analyser touch the right *file*? | No — too generous |
| `line_recall` | did a finding overlap a line the fix *changed*? | No — see below |
| `class_recall` | was that finding of a *class the fix title can express*? | Yes, with care |

### Why `line_recall` alone is not evidence

On the real run this module was built against — Slither 0.11.3 over
`2023-07-pooltogether` — `line_recall` was **2/2 (100%)** and `class_recall` was
**0/2**. The findings that overlapped the fix lines were `reentrancy-events` and
`naming-convention`:

```
H-02  GT vault/src/Vault.sol:1120-1126
      HIT reentrancy-events src/Vault.sol:1122-1127
H-04  GT vault/src/Vault.sol:394-404
      HIT naming-convention src/Vault.sol:394-394
```

Neither can express "a malicious user can steal other users' deposits" or "anyone
can call `mintYieldFee`". They overlap the fix line because Slither's noise
detectors cover a large fraction of the file: **18.1% of `Vault.sol`'s 1232 lines
are touched by some finding**, so a random line is "hit" about one time in five.
`chance_baseline()` computes that number so it can be reported beside the score.

A 100% figure from noise is worse than a 0% figure, because it is the one a
reader will quote.

## Usage

```bash
# 1. get the dataset (once)
git clone --depth 1 https://github.com/openai/frontier-evals /tmp/frontier-evals
DS=/tmp/frontier-evals/project/evmbench

# 2. run an engine and keep its JSON
python3 -m blackheart engines run --engines slither --target <project> --allow-local
#    -> <project>/.slither-scratch/slither_results.json

# 3. score it
python3 -m blackheart evmbench \
    --dataset "$DS" \
    --findings <project>/.slither-scratch/slither_results.json \
    --audit 2023-07-pooltogether \
    --json --out research/evmbench/pooltogether.json
```

The command exits `0` when it produced a report. A non-zero exit means it could
not score at all (missing dataset or findings file) — never a fabricated score.

## What the scorer refuses to do

* **Divide by an empty denominator.** A rate over zero scored vulnerabilities is
  `null`, never `0.0` or `1.0`.
* **Count an unscorable vulnerability as a miss.** `2024-01-canto` ships only
  titles (`update_market() market weight incorrect`), no fix diff. There is no
  location to localize against, so its two findings are recorded as *unscored*
  and excluded from the denominator. Counting them as misses would be a lie in
  the pessimistic direction.
* **Credit a noise detector.** `class_recall` requires the overlapping detector
  to belong to a family the fix title can express. `reentrancy-events`,
  `naming-convention`, `unused-return` and `immutable-states` are excluded on
  purpose.
* **Call any of it a rediscovery.** Even `class_recall` only says "pointed at the
  right line with a plausible detector family". It does not say the analyser
  understood the bug. The JSON report carries that caveat in its `note` field so
  a downstream consumer cannot strip it.

## What the numbers are, and are not

The results are **localization**, not detection:

* A `class_hit` is a lead, not a finding. It still has to go through the normal
  research pipeline — hypothesis, adversarial investigation, exploit validation,
  independent review — before it means anything.
* The dataset is a *subset* of audits. A number computed over three audits is not
  an EVMbench score. It is a measurement over three audits, and must be labelled
  that way.
* No baseline is claimed. A "before/after" comparison requires the same audits,
  the same engine versions and the same findings, and is only meaningful when
  those are held fixed.

## Benchmark fixtures never become bounty research

The dataset is public and disclosed. A fixture that `evmbench` scores is a
*measurement input*, never a candidate. Nothing in this module writes to the
findings repository, and no code path promotes a benchmark hit into a
`FindingRecord`. The separation is the same one the doctrine requires between a
rediscovery and a bounty finding (`docs/DISCOVERY.md`).
