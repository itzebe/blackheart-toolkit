# BLACKHEART self-evaluation — what it is missing, and the bugs it actually missed

Date: 2026-11-21 · Repo: `itzebe/blackheart` · Branch: `feat/blackheart-self-evaluation`
Method: run the engine's own evaluators at stated budgets, then check every number
against an independent oracle (the bounded-exhaustive certifier, the guarded twin,
or execution). Every command below was run in this workspace; nothing here is
recalled from memory or estimated.

---

## 1. Does it actually miss bugs? Yes — and the misses were measurable

### 1.1 The differential corpus (28 pairs; the table below is the 27-pair measurement)

`blackheart differential` asserts, for each pair, that the vulnerable model yields
an attacker-reachable violation **and** the guarded twin yields none. That is a
recall-and-precision check with ground truth built in.

| Budget (runs × steps) | Strategy | Pairs detected |
|---|---|---|
| 1 × 2 | random `StatefulFuzzer` | **9 / 27** |
| 12 × 8 | random `StatefulFuzzer` | **23 / 27** |
| 60 × 14 | random `StatefulFuzzer` | **26 / 27** |
| 400 × 10 (default) | random `StatefulFuzzer` | 27 / 27 |
| 0 (no random runs) | certifier, depth 4 | **26 / 27** |
| 0 (no random runs) | certifier, depth 6 | **27 / 27** |

`H29-allowance-reuse` was added after these measurements. It is certified at
depth 1 and reached by the default enhanced budget (`tests/test_corpus_allowance.py`),
but the table above is **not** re-asserted for it: re-measure, do not re-assert.

The miss at 60 × 14 was `hl-pm-liquidation`: the planted bug fires only when debt
is pushed **past the borrow LTV but kept under the liquidation threshold**, then
liquidated. The shortest witness is four steps (`borrow, borrow, borrow,
liquidate`) and sits inside a narrow numeric window, so a uniform random walk over
a 14-symbol alphabet samples it rarely.

**Diagnosis: the model was right and the search was wrong.** The certifier found
it immediately, which is only possible if the target and invariant were correct.

**Fix shipped** (`cmd_differential`, `--depth`, default 6): when the random search
finds nothing on the vulnerable twin, the pair escalates to the bounded-exhaustive
certifier; the escalation is accepted only if the **same** exhaustive search
leaves the guarded twin clean. Result: 26/27 at depth 4, 27/27 at depth 6, 27/27
at the default budget with zero escalations (so the safety net costs nothing when
the sampler succeeds). Regression bar: `tests/test_differential_escalation.py`.

### 1.2 The attack-class evaluation suite

| Command | Result |
|---|---|
| `blackheart evaluate --runs 20 --steps 8 --seed 5` | **9/10** classes detected, 0 control failures |
| `blackheart evaluate --runs 80 --steps 12 --seed 5` | **10/10**, 0 control failures |

The single miss at the low budget was `ASSET-01` (asset/accounting invariant). It
was again **budget-bound, not model-bound**: the same suite at a larger budget
detects it. That is the honest reading of a stochastic search — "not found within
budget" — and it is why the doctrine forbids calling a stochastic negative clean.

### 1.3 The known-answer benchmark had no positive case

`blackheart testsparker --known-answer` reported **934 tests, 0 defect signals**,
and no precision/recall at all. Two distinct defects, found by asking what the
number actually meant:

1. The known-answer corpus declared **16 cases and not one with
   `expect_defect: True`**. A corpus of negatives can only ever prove precision;
   recall was structurally undefined.
2. The generator **dropped the `expect_defect` field**, so even a declared ground
   truth never reached a generated test, and the CLI never called
   `compute_metrics` — the metric was unreachable even in principle.

Both are fixed: a constructed positive case (a published ABI declaring a selector
the dispatcher does not route — the shape of a stale ABI after an upgrade) whose
ground truth is execution, and propagation of that ground truth into the test
expectation, and `precision`/`recall` now printed and included in `--json`.

```
adapter=dispatch seed=0 generated=978
  CONFIRMED_DEFECT: 1
  NO_SIGNAL: 977
  precision: 1.00 (1/1)
  recall: 1.00 (1/1)
  expected_defects=1 false_positives=0 false_negatives=0
```

**Honest caveat:** recall is 1/1. That is a smoke test that the measurement works,
not a calibrated recall figure. One positive case cannot tell you how many
real-world dispatcher defects would be missed.

### 1.4 Model coverage

`blackheart coverage` → **27/30 objective categories have an executable
vulnerable/guarded model**; the three without are the MCP classes that need a live
system (`mcp-consent-bypass`, `mcp-cross-tenant-disclosure`,
`mcp-scope-overreach`), reported as named gaps rather than claimed as coverage.

### 1.5 Oracle liveness

`blackheart assure oracles --target vulnerable` → both declared invariants
**discriminating** (they flip under a reachable-state mutation, 1 and 2 flips
respectively). A clean search result is therefore a bounded negative on a live
oracle, not a silent pass.

---

## 2. What BLACKHEART is missing against the popular tools

Assessed dimension by dimension, with the honest verdict for each. "Loses" means
a widely used tool does it materially better today.

| Dimension | Slither | Echidna / Medusa | Halmos / hevm | CodeQL | Semgrep | BLACKHEART | Verdict |
|---|---|---|---|---|---|---|---|
| Whole-program taint / dataflow | strong (SSA IR, printers) | — | — | excellent | good | **none** | **loses** |
| Breadth of Solidity detectors (60+) | excellent | — | — | good | good | ~30 modelled classes | **loses** |
| Property-based fuzzing on real EVM | — | excellent | — | — | — | model-level + a local EVM subset | **loses on fidelity** |
| Symbolic execution / SMT | — | — | excellent | — | — | bounded-exhaustive enumeration only | **loses** |
| Compiler/IR fidelity (solc AST, viaIR) | excellent | good | good | n/a | n/a | bytecode dispatch model only | **loses** |
| Ruleset ecosystem / custom queries | printers + plugins | — | — | excellent | excellent | Python targets only | **loses** |
| CI speed on a large repo | seconds | minutes | minutes | minutes | seconds | seconds (stdlib) | comparable |
| Output interoperability (SARIF) | yes | partial | partial | yes | yes | **no SARIF** | **loses** |
| Baseline / incremental analysis | partial | — | — | yes | yes | **no baseline diff** | **loses** |
| Ground-truth measurement of its own recall | no | no | no | no | no | **yes, and gated in CI** | **wins** |
| Oracle liveness audit (can an invariant ever fire?) | no | no | no | no | no | **yes** | **wins** |
| Bounded-exhaustive "no counterexample within depth N" | no | no | no | no | no | **yes** | **wins** |
| Guarded-twin discrimination (does the hit discriminate?) | no | no | no | no | no | **yes** | **wins** |
| Economic pricing of a hit (attacker profit, victim loss) | no | no | no | no | no | **yes** | **wins** |
| Authorization gate at the engine boundary | no | no | no | no | no | **yes** | **wins** |
| Objective-first, capability-gated campaign planning | no | no | no | no | no | **yes** (`blackheart adversary`) | **wins** |

**Summary.** BLACKHEART is not a better *detector library* than Slither or CodeQL,
and it is not a better *fuzzer* than Echidna or Medusa. It is better at the thing
none of them do: **deciding whether a result is real**, pricing it, and refusing
to report a negative it has not earned. The gap that matters most is not detector
count — it is that a scanner's "clean" is worthless without an oracle audit and a
bounded-exhaustive bound, and BLACKHEART is the only one of these that produces
that.

---

## 3. Ranked gaps, with the fix and the acceptance bar

Ordered by expected value, not by ease.

1. **No whole-program dataflow/taint analysis.** Every finding is
   model-level or sequence-level; a value flowing through three contracts is
   invisible. *Fix:* a SSA-lite value-flow pass over the bytecode dispatch graph,
   feeding the statespace alphabet with cross-contract taint edges. *Bar:* a
   three-contract taint fixture the model cannot express today is detected, with a
   guarded twin that is not.
2. **No SARIF output.** Cannot report into GitHub code scanning, so the findings
   cannot live where developers already look. *Fix:* a `--sarif` writer over the
   findings repository. *Bar:* the output validates against the SARIF 2.1.0 schema
   and round-trips a `CONFIRMED` finding with its evidence references.
3. **No baseline/incremental analysis.** Every run re-does everything, so a
   regression is invisible in the noise. *Fix:* a content-addressed baseline of
   `(target, invariant, witness)` triples, diffed on the next run. *Bar:* a
   re-run with one new model reports exactly the new hits.
4. **Recall is measured on one positive case.** *Fix:* grow the known-answer
   corpus per adapter until each has ≥ 10 positives and ≥ 10 negatives, with the
   ground truth recorded per case. *Bar:* `blackheart testsparker --known-answer`
   prints precision and recall with a denominator ≥ 10.
5. **Fuzzing fidelity is a local EVM subset, not a real chain.** *Fix:* route
   `hunt`/`statespace` execution through `anvil`/`revm` when available, keeping the
   local model as the fallback, and label which engine ran. *Bar:* the same
   fixture produces the same verdict on both paths, and the record says which.
6. **Three MCP categories have no executable model.** *Fix:* a local MCP server
   fixture with a consent, tenant and scope boundary. *Bar:* `blackheart coverage`
   reports 30/30.
7. **No symbolic execution.** Bounded enumeration is exponential in depth; a
   solver would reach depth 20 where enumeration reaches 6. *Fix:* a path-condition
   export from the statespace explorer, discharged by an SMT solver when one is
   installed (optional dependency, never required). *Bar:* a bug requiring 12
   ordered steps is found with a solver and missed by depth-6 enumeration.

---

## 4. From scanner to an adversary that thinks

A scanner asks *"does this pattern exist here?"*. The measured weakness above is
not a pattern problem — it is that a scanner has no **objective**, no **budget**,
no **patience**, and no **precondition model**. Three concrete upgrades, in
increasing order of ambition:

1. **Search escalation (shipped).** A strategy that cannot find anything must hand
   the question to one that cannot miss within a bound. Implemented in
   `cmd_differential`; the same shape belongs in `hunt` and `campaign`.
2. **Objective-first planning (shipped).** `blackheart adversary` starts from the
   outcome, checks the profile can afford the preconditions, and emits a staged
   campaign with the engine per stage, the evidence each stage must produce, and
   the condition the actor must wait for. A one-transaction profile gets no
   `trigger` stage and no `persist` stage — the plan says why. Capabilities no
   local engine may exercise (validator control, supply chain, insider, social
   engineering) appear as `MODEL_ONLY` and are never executable.
3. **Adversary-conditioned search (next).** Feed the profile's dwell and capital
   into the search itself: an actor that can wait 180 days should be given
   `trigger`-aware strategies (state-dependent, long-horizon), while a
   one-transaction actor should be restricted to the atomic alphabet. *Bar:* the
   same target yields different, profile-appropriate witness sets, and every
   witness is reproducible.

What is deliberately **not** built: anything that models a real person, a real
nation, or a real organisation. The variable that changes a plan is capability and
constraint. Modelling a capability is not authorising its use, and the
authorization gate is upstream of every stage.

---

## 5. Remaining research gaps (stated plainly)

- Recall figures above are from **modelled targets with planted bugs**, not from
  live protocols. They prove the pipeline finds what it models; they do not prove
  it finds what it does not model.
- The differential corpus is 27 pairs; a class with no pair is invisible to every
  strategy, including the certifier (`blackheart coverage` names those gaps).
- Depth 6 is a real bound. A bug needing 7 ordered steps is missed by the
  escalation, and the record must say so rather than imply otherwise.
- No whole-program taint, no symbolic execution, no SARIF, no baseline diff.
- The known-answer recall denominator is 1.

## 6. Commands used

```bash
python3 -m blackheart differential --runs 1   --steps 2  --seed 3 --depth 0
python3 -m blackheart differential --runs 12  --steps 8  --seed 7 --depth 0
python3 -m blackheart differential --runs 60  --steps 14 --seed 7
python3 -m blackheart differential --runs 0   --steps 0  --depth 4
python3 -m blackheart differential --runs 0   --steps 0  --depth 6
python3 -m blackheart differential --depth 6            # default budget
python3 -m blackheart evaluate --runs 20 --steps 8 --seed 5
python3 -m blackheart evaluate --runs 80 --steps 12 --seed 5
python3 -m blackheart testsparker --known-answer
python3 -m blackheart coverage
python3 -m blackheart assure oracles --target vulnerable
```

---

## 7. Delta after the 2026-11-22 improvement pass

The ranked gaps above are the baseline; this section records what actually
landed, and what remains.

| Gap | Status after this pass | Evidence |
|---|---|---|
| No whole-program dataflow/taint | **Narrowed, not closed.** An SSA-lite def-use pass propagates parameters, `msg.sender`/`msg.value`, external-call returns and state through internal calls, merges branches with phi nodes, and reports source -> sink flows with a function path and line. | `blackheart dataflow`, `tests/test_dataflow.py` |
| No SARIF output | **Closed for findings.** The repository exports SARIF 2.1.0 and `pipeline --sarif` writes it. | `blackheart findings sarif`, `tests/test_sarif.py` |
| No baseline/incremental analysis | **Closed for findings.** Content-addressed new/resolved/changed/unchanged, with `pipeline --baseline --fail-on-new`. | `blackheart baseline`, `tests/test_baseline.py` |
| Fuzzing fidelity is a local EVM subset | **Narrowed.** `blackheart evm-exec` routes a message to a real ephemeral anvil node when Foundry is installed, and labels the local fallback with its reason. The coverage fuzzer itself still runs on the local interpreter. | `tests/test_execution_route.py` |
| No symbolic execution | **Narrowed.** The bounded symbolic layer can now discharge path conditions through optional Z3 (`--smt`); a SAT model is re-checked against the constraints and finite domains. The default remains the bounded solver, and Z3 is not a dependency. | `tests/test_smt.py` |
| Witness traces are model-level only | **Narrowed.** A certified step maps to contract, function, source line and statement; unmapped steps are explicit. | `tests/test_witness.py`, `pipeline --source` |
| Recall is measured on one positive case | **Open.** The known-answer denominator is still small. | `docs/DISCOVERY.md` |
| Three MCP categories are prose-only | **Open.** A live consent/tenant/scope flow is still required. | `blackheart coverage` |

Honest bottom line: the pass improves **finding recall, execution fidelity,
symbolic depth, debugging traceability and CI usability**. It does not change the
headline answer: `can_find_payable_bug_unaided` remains **false**, because the
analysis is still a source-level approximation and a payable bug still needs a
human hypothesis and a real reproduction.
