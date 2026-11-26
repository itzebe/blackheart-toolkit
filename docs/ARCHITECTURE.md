# Architecture

BLACKHEART is a Python package (`blackheart/`) plus a Foundry harness
(`harnesses/`), specialist agents (`agents/`), and skills (`skills/`). Everything
in `blackheart/` uses only the Python standard library, so the engine runs in any
sandbox with no network and no paid service.

The project has an identity, and it is the core: BLACKHEART is **a wise and
dangerous hacker with a black heart** (`blackheart/mindset.py`; see `AGENTS.md`).
It is wise (patient, methodical, honest with itself) and dangerous (precise,
relentless toward a real weakness, unhurried until the impact is proven). The
black heart is a method, not a licence. That identity leads the initial prompt
every role and every mission inherits.

Every stage below is run under a single question, held from the position of an
ordinary, unprivileged attacker: *what transaction sequence, inputs, timing,
account state, or market conditions can I create or manipulate to receive more
assets than I am entitled to, bypass a restriction, or make another user's
position absorb my loss?* That question and the doctrine that follows from it
live in `blackheart/mindset.py` and reach the objective engine, the hypothesis
engine, the multi-model roles, and the campaign loop from there.

```
threat model -> objectives -> attack surface -> chains -> adversarial tests
  -> stateful fuzzing -> exploit attempts -> minimisation -> verification
  -> impact -> report -> new hypotheses
```

## Modules

| Module | Responsibility |
|---|---|
| `blackheart/models.py` | Typed records for every artefact (Objective, AttackChain, InvariantFailure, Finding, Evidence, ToolRecord, AuthorizationRecord). All serialise to JSON. |
| `blackheart/mindset.py` | The attacker question, the three outcomes, the five levers, and the doctrine. Single source of truth; `blackheart mindset` renders it. |
| `blackheart/doctrine.py` | The operational doctrine: identity, the six-phase research lifecycle, attack surfaces, hypothesis shape, methods, validation/verdicts, review questions, the A–J finding record, the transparent prioritisation model, the nine research responsibilities, and the non-negotiable security invariants — each mapped to the module that implements it. `blackheart doctrine` renders it; every role prompt carries a compact block. |
| `blackheart/findings/` | The findings documentation engine and persistent repository: the A–J `FindingRecord`, an append-only hash-chained log, evidence-gated confirmation, search, additive linking, duplicate-by-root-cause, Markdown/JSON export, and a consolidated report. `blackheart findings`. |
| `blackheart/authz/` | The authorization gate. Pure, fails-closed logic + an append-only registry. |
| `blackheart/objectives/` | `TargetProfile` -> attacker `Objective` list, before any function-level review. |
| `blackheart/chains/` | `Objective` -> multi-operation `AttackChain` hypotheses. |
| `blackheart/invariants/engine.py` | Generic stateful fuzzer: random op sequences, invariant checks, seed-preserving minimisation, attacker-reachability triage. |
| `blackheart/fuzz/` | Coverage-guided corpus fuzzer: keeps inputs that reach new *behavioural* coverage, grows the deepest-reaching prefixes one operation at a time (deterministic coverage beam) to cross ordered state gates, then havoc-mutates the corpus; prices each hit with the value engine. `blackheart fuzz --strategy corpus`, `blackheart fuzz-bench`. |
| `blackheart/value/` | Universal value & profitability engine: classifies any target's snapshot by *structure* (asset/liability/permission/protocol/other) and prices a sequence as attacker profit, victim loss, protocol loss, conservation residual, repeatability and max extraction. `discovery/economic.py` is a facade over it; the account rides on `Finding.economic` and is rendered in every report. `blackheart value`. |
| `blackheart/assurance/` | The completeness layer: a **bounded-exhaustive certifier** (`certify`) that enumerates every sequence up to a depth over the declared alphabet -- the only search allowed to say "no counterexample exists", up to its bound -- and a **search portfolio** (`run_portfolio`) that runs every strategy, unions the counterexamples (a strict superset of any single strategy) and reports a coverage ledger. `blackheart assure certify`, `blackheart assure portfolio`. |
| `blackheart/invariants/reference_targets.py` | Vulnerable + safe ERC4626 vault models used to validate the engine (non-vacuity). |
| `blackheart/invariants/wrapper_targets.py` | Aave aToken / wrapper-share accounting models (the priority research question). |
| `blackheart/invariants/attack_targets.py` | Executable vulnerable/guarded models for the oracle-manipulation, permit-replay, and proxy-initializer classes (each with its guarded control). |
| `blackheart/invariants/class_targets.py` | Executable models for the callback-reentrancy and access-control classes (each with its guarded control). |
| `blackheart/invariants/registry.py` | Name -> target class map and the vulnerable/guarded differential pairs. |
| `blackheart/attackdb.py` | **Executable** attack-chain database: concrete sequences bound to a target + invariant, run against both the vulnerable and guarded model. |
| `blackheart/foundry.py` | Render a runnable Foundry PoC from an executable chain (concrete Solidity API, vuln + guarded assertions). |
| `blackheart/regress.py` | Turn a recorded invariant counterexample into a deterministic, self-contained pytest regression test. |
| `blackheart/scope.py` | Dated engagement-authorization evidence: capture verbatim scope, append to the registry, evaluate per-asset decisions. |
| `blackheart/environments/` | Environment adapters (HTTP, shell, file, browser). The HTTP adapter is the one that leaves the host, so it carries the egress boundary: `destination.py` canonicalizes the URL, resolves it, and classifies **every** answer against a fail-closed policy (private, loopback, link-local, multicast and cloud-metadata ranges are refused; a mixed DNS answer is refused whole rather than filtered, because the safe-looking answer is the rebinding primitive), and `pinned_transport.py` opens the socket to the *validated address* so a second resolution cannot change where the connection lands. Each redirect hop is re-authorized end to end: scheme, host **and port** must match the authorized asset, so a grant at `app:8080` is not a licence to port-scan `app:22`. `blocked_attempts` distinguishes "not executed" from "searched clean". |
| `blackheart/agentverify.py` | Load the project's skills and agents from the real OpenHands agent-server and report what is discoverable (never fabricates success). |
| `blackheart/provision.py` | Create the `.openhands/{skills,agents}` discovery layout (relative symlinks, copy fallback). |
| `blackheart/demonstrations.py` | Drive any registered pair through the full pipeline (fuzz -> finding -> verify -> report). |
| `blackheart/verify/` | The independent verifier: seven quality gates + adversarial challenges. Gate 6 records the reviewer's real provenance (`INDEPENDENT_MODEL` / `SAME_MODEL` / `UNRECORDED`) and fails a same-model review rather than calling it independent. |
| `blackheart/evidence/` | Content-addressed, immutable, tamper-evident evidence store. |
| `blackheart/ledger/` | Append-only engagement ledger + hypothesis database (never re-runs disproven hypotheses). |
| `blackheart/report/` | Report renderer that refuses to present a hypothesis as a vulnerability. |
| `blackheart/tools/` | Tool registry: install/version/functional verification states kept distinct. |
| `blackheart/research/` | Persistent, searchable research memory: one `ResearchRecord` per investigation, four strictly-separated buckets, confirmed-only attack knowledge, lessons retrieval, tamper-evident log. |
| `blackheart/research/queue.py` | Resumable research queue: bounded, crash-safe, and re-checks the authorization gate on every dequeue. |
| `blackheart/hypothesis/` | Autonomous hypothesis engine: generate, score (exploitability/impact/novelty/evidence/feasibility), rank, select, and explain the next investigation. |
| `blackheart/hypothesis/surface.py` | Target-surface applicability model: damp classes whose required surface (oracle/signature/proxy/callback/shares/access-control/bridge) is absent; negation- and CamelCase-aware. |
| `blackheart/exploit/toolselect.py` | Class -> tool plan: which tools can demonstrate a vulnerability class, with a secure control and rationale. |
| `blackheart/learning/` | Self-improvement engine: extract lessons, propose a strategy improvement, demonstrate the old weakness, benchmark against historical + negative corpora, adopt only on non-regression, freeze the lesson as a regression test. |
| `blackheart/learning/benchmark.py` | Ranking benchmark: historical + negative (anti-overfitting) corpora; top-1, MRR, and surface-suppression metrics. |
| `blackheart/campaign/` | The continuous attack loop, authorization-gated. |
| `blackheart/engines/` | External engine integration (Strix, Shannon, PentAGI) as **untrusted, subordinate** evidence sources: adapter contract, unified finding schema, cross-engine orchestrator (dedup, corroboration, contradiction, attack-chain correlation, prior-art), authorization-gated session, and md/json/SARIF reporting. `blackheart engines`. |
| `blackheart/engines/orchestrator.py` | Cross-engine coordination: normalise, cluster by engine-independent fingerprint, mark corroboration, preserve contradictions, correlate chains on real enabling edges, flag prior art. Corroboration never confirms. |
| `blackheart/reference_engagement.py` | End-to-end reference run used as an acceptance test. |
| `blackheart/cli.py` | `blackheart` CLI. |

## Data flow

1. **Objectives** are generated from a `TargetProfile` (assets, entry points,
   trust boundaries, roles, external deps) — not from a CVE checklist, so the
   search is not limited to documented weaknesses.
2. **Chains** combine operations across actors, contracts, and state transitions.
3. **Invariants** are properties that must hold across *arbitrary* op sequences.
   The fuzzer generates random sequences, records the seed, minimises any failing
   sequence (op-removal then value-shrinking, under a bounded budget), and marks
   whether the failure is reachable by an attacker-controlled actor.
4. **The Foundry harness** provides a real EVM-level PoC and stateful invariant
   tests for contract targets.
5. **The independent verifier** re-derives a verdict from evidence and the seven
   gates; it may downgrade a finding at any point. Gate 6 states *who* reviewed
   the finding: a separately authenticated model (`INDEPENDENT_MODEL`), the same
   model in a fresh adversarial context (`SAME_MODEL`), or an unrecorded
   provenance. A same-model review is real but is **not** independent
   verification, so it fails gate 6 and can never be read back as CONFIRMED. The
   reviewer model is optional: `resolve_reviewer_model` separates `configured`
   (a key is present) from `verified` (a liveness probe proved it works), so an
   invalid or expired credential is never mistaken for an independent reviewer.
   With no verified reviewer the workflow falls back to a same-model review and
   records that honestly. Provenance is a claim, so it is checked against the
   gate-6 result it describes: a finding whose gate-6 detail contradicts an
   `INDEPENDENT_MODEL` claim is not submission-ready, and a record whose reviewer
   label contradicts it is refused at `CONFIRMED`. `blackheart.models.gate6_detail`
   is the one definition the verifier and every consumer share.
6. **Evidence** for every claim is written to the content-addressed store; the
   ledger records hypothesis status so disproven hypotheses are not re-run.

## Design rules

- **Business logic is I/O-free.** The gate, objectives, chains, the fuzzer, and
  the verifier are pure and unit-testable without network or filesystem.
- **Fails closed.** The authorization gate blocks unless everything required is
  affirmatively recorded.
- **Honest by construction.** `Finding.gates_pass()` requires seven PASSes;
  `report.is_submission_ready()` requires CONFIRMED + all gates + a scope
  reference. A hypothesis cannot be rendered as a vulnerability.
- **No fabricated data.** Every evidence id refers to bytes produced by a real
  command; the fuzzer reports the seed it actually used.

## Execution routing, SMT and CI artifacts

`blackheart/execution/route.py` selects a real ephemeral `anvil` node when Foundry
is installed and the local `evmworld` interpreter otherwise. The selected engine,
the requested engine and the fallback reason travel with the result, so a local
model run is never presented as a chain run. `revm` is detected but has no stable
CLI contract and is not executed.

`blackheart/symbolic/smt.py` is an optional Z3 discharge for the symbolic path
conditions. Z3 is not a dependency: absent means `UNKNOWN` with a reason; a SAT
model is re-evaluated against every constraint and declared domain; UNSAT is
accepted only over those finite domains. The solver name is carried in the
symbolic result.

`pipeline --sarif`, `--write-baseline`, `--baseline` and `--fail-on-new` connect
the findings repository to the places developers already watch: SARIF for code
scanning and a content-addressed baseline for CI regression gates.
