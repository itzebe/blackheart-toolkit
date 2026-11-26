# Adversarial state-machine discovery

BLACKHEART already asks, of a single call, "is this function vulnerable?" and can
fuzz a target's state with random operation sequences
(`blackheart/invariants/engine.py`). The state-machine engine asks the harder,
higher-value question the random fuzzer cannot answer well: **what can an attacker
achieve by combining individually-legitimate operations** — by reordering them,
acting across identities, exploiting a privilege or ownership change between two
operations, leaving a partial state after a half-failure, or violating an
invariant that no single call violates?

The pipeline is a strict chain, and nothing downstream may claim more than the
step before it established:

```
SystemModel  --(HypothesisGenerator)-->  hypotheses (falsifiable claims)
             --(StateSpaceExplorer)-->   violations (minimal sequences)
             --(IndependentSequenceVerifier)-->  dispositions
```

A **hypothesis** is a claim about intended behaviour. A **violation** is a
sequence that broke a stated invariant — not a confirmed vulnerability. Only the
independent verifier may return `INDEPENDENTLY_VERIFIED`, and even then the result
is a claim about a *modelled* target unless it was run against a real, authorized
one.

## Reuse, not a parallel model

The engine reuses BLACKHEART's existing invariant engine rather than introducing a
second target abstraction. It consumes the `Target` protocol, `OpSpec` and
`InvariantSpec` from `blackheart.invariants.engine`, and the delta-debugging
minimiser shape. A `SystemModel` can be derived from an existing
`blackheart.threatmodel.ThreatModel` via `model_from_threatmodel`, so a threat
model that already lists assets, invariants and guard transitions feeds the
engine without a hand-written model.

## The model (`blackheart/statespace/model.py`)

`SystemModel` is the minimum a state-machine search needs:

- **actors** — each with roles and an `unprivileged` flag (the attacker is the
  unprivileged actor);
- **operations** — each with the roles allowed to invoke it, the asset it touches,
  whether it is **sensitive** (an invariant is stated about it), a precondition, a
  guard and the roles that guard admits;
- **transitions** — a named guard change (e.g. "revoke") with the roles it admits;
- **invariants** — a statement, the assets it applies to, and an expression;
- **assets**, **trust boundaries**, **dependencies**, **intended behaviours**,
  **evidence**.

`is_complete()` is a gate: a model missing its summary, actors, a sensitive
operation or an invariant cannot be searched, and `HypothesisGenerator` refuses it
with `ModelIncomplete` rather than inventing a model.

## The ten strategies (`blackheart/statespace/hypotheses.py`)

Every generated hypothesis carries the **eight required fields** — capability,
preconditions, asset, vulnerable sequence, expected secure behaviour, evidence
needed, falsification, authorization boundary — and a strategy id. Duplicate
sequence *shapes* are suppressed across strategies, and hypotheses are ranked
deterministically.

| Strategy | The question it encodes |
|---|---|
| `ordering` | Does reordering two sensitive operations break an invariant? |
| `repetition` | Does doing a sensitive operation twice break it? |
| `cross-user` | Does a second actor reach another actor's asset or a shared one? |
| `privilege-change` | Does a sensitive operation between a grant and a revoke use the stale grant? |
| `ownership-change` | Does ownership moving between the setup and the action matter? |
| `partial-failure` | Does a failure part-way through leave a state a later operation abuses? |
| `concurrency` | Do two actors' interleaved operations break atomicity? |
| `stale-state` | Is a captured value (a session right, a cached price) used after it changed? |
| `replay` | Is a one-time token/right reusable? |
| `cross-component` | Does a dependency (an oracle, an external call) desynchronise two components? |

## The explorer (`blackheart/statespace/explore.py`)

The explorer searches an **ordered candidate list**: first the model's own
predictions (short sequences over the *relevant* operation set — sensitive
operations, transition operations, and the operations a hypothesis already
names — ranked so cross-actor, sensitive-ending shapes come first), then the
heuristic perturbations of the hypotheses. Each candidate is run against a fresh
target; a sequence that breaks an invariant is recorded and **minimised** by delta
debugging (drop steps, then shrink numeric values) to the shortest reproducing
sequence. The explorer is deterministic given a seed, and it reports
`sequences_tried` and `steps_evaluated` so its cost is auditable.

The **relevant-operation filter is the model guidance**. On a target with many
decoy operations, a pure brute force over the whole operation space is diluted by
operations that cannot participate in any stated invariant; filtering to what the
model says matters is what keeps the search tractable (see the benchmark).

## The verifier (`blackheart/statespace/verify.py`)

`IndependentSequenceVerifier` is the adversary of the explorer. It re-runs the
sequence from a fresh target, then checks, in order:

1. **scope and authorization** — was the sequence in scope and behind an
   authorization gate?
2. **independent reproduction** — does the minimal sequence still break the
   invariant when re-run?
3. **attacker reachability** — can an *unprivileged* actor run it, or is it
   privileged-only?
4. **control integrity** — does the invariant **hold** on the secure control? A
   sequence that also "breaks" the control is not discriminating and is rejected.
5. **precondition satisfiability** — is the precondition actually reachable?
6. **not intended** — is the behaviour documented/intended rather than a defect?
7. **not duplicate** — is the sequence already known?

Any failed check ⇒ `REJECTED`. A sequence that does not reproduce ⇒
`INSUFFICIENT_EVIDENCE`. Only a sequence that passes every check ⇒
`INDEPENDENTLY_VERIFIED`.

Scope is **three-valued**, because "not established" is not "authorized".
`VerifyConfig.in_scope` and `authorization_gate_passed` are `True` / `False` /
`None`; `None` records the check as unestablished, the sequence is still reported
as `REPRODUCED` (it really did reproduce), and it can never reach
`INDEPENDENTLY_VERIFIED`. A known `False` still rejects.

The same rule governs invariant evaluation. `InvariantSpec.evaluate()` returns
`True` / `False` / `None`, and `None` means the predicate raised on that state --
*unevaluable*, not satisfied. `run_sequence`, the fuzzer, the explorer, the
portfolio, the hunt and the CLI all carry the resulting `unevaluable` list, so a
run that found nothing while an invariant could not be evaluated says "could not
tell" instead of "clean".

## The benchmark — an honest ablation

`blackheart statespace benchmark` compares the guided engine against the existing
random fuzzer (`StatefulFuzzer`) on the same fixtures and invariants, using the
fuzzer's **own** sequence generator for the baseline so the comparison is
apples-to-apples. It reports, per case and in aggregate:

- detection rate and **false-positive rate** on the secure controls (a non-zero
  false-positive rate is a failure and is reported, not hidden);
- sequences tried, steps evaluated, seconds;
- **sequences-to-first-detection**, the budget-controlled efficiency metric;
- a separate **held-out** suite (fixtures not used during development) and a
  **hard** suite of the same bugs embedded among eight decoy operations.

The measured result: on the decoy-laden hard suite the guided engine's cost is
essentially unchanged (it does not enumerate decoys) while the random baseline
degrades sharply, and the guided engine reaches its first detection in far fewer
sequences. On the small development fixtures both engines succeed; the engine's
value there is not raw speed but *sequence-level, minimised, cross-actor discovery
with a stated invariant and an independent verifier*.

## Skills and portability

`blackheart statespace skills --write skills/` renders ten adversarial research
skills under `skills/adversarial-<id>/`, each of which drives one or more of the
strategies above (for example `adversarial-business-logic` drives
`partial-failure`; `adversarial-counterfactual-reasoning` drives `ordering`). The
`adversarial-` prefix means they never collide with BLACKHEART's hand-written
skills (for example the existing `skills/exploit-verification/`), and the writer
refuses to overwrite a file that does not carry its generated marker. `blackheart provision` links the whole
`skills/` tree into a project's `.openhands/skills/`, so a project provisioned
through BLACKHEART — existing, recent, or new — inherits the adversarial skill
library without any per-project change.

## Using it

```bash
blackheart statespace strategies                       # the ten strategies
blackheart statespace --fixture stale-authorization model
blackheart statespace --fixture stale-authorization hypotheses
blackheart statespace --fixture stale-authorization explore
blackheart statespace --fixture stale-authorization discover   # explore + verify
blackheart statespace benchmark                        # the ablation
blackheart statespace --model threat-model.json model           # adapt a ThreatModel
blackheart statespace --model threat-model.json hypotheses      # its hypotheses
```

Every command above executes the repository's own fixtures, so it runs under the
repository self-test record. The Python API is gated too: `run_sequence`,
`StateSpaceExplorer.explore`, `run_evm_case` and `run_runtime_discovery` take
`compatibility=` and refuse to touch a target without a validated record bound to
it. See `docs/SECURITY_TOOL_COMPATIBILITY.md` section E2.

`--model` accepts either a `SystemModel` JSON or a `ThreatModel` JSON (adapted via
`model_from_threatmodel`). A model alone supports `model` and `hypotheses`;
`explore` and `discover` need an *executable* target and therefore a `--fixture`,
because a `SystemModel` carries no runtime semantics. The CLI says so and exits 2
rather than pretending to search a model it cannot run.

## Executable targets (`blackheart/statespace/runtime/`)

The engine above searches a *model*. The runtime layer makes the same pipeline
search a *running application*: the `HypothesisGenerator`, `StateSpaceExplorer`
and `IndependentSequenceVerifier` are unchanged, but they now drive an
`ExecutionAdapter` — a real application — through a `RuntimeTarget` bridge.
`RuntimeTarget.step` dispatches the operation for real and writes the observed
post-operation state into the object the explorer threads through the sequence,
so a violation is established from **runtime evidence**, not from the model's
prediction.

Three kinds of operation are kept distinct, and the distinction travels with every
result (`ExecRecord.provenance`):

- **abstract** — an operation named in a `SystemModel`; a claim, not a run;
- **fixture** — an operation run against an in-memory object;
- **executed** — an operation actually dispatched to a running application.

Adapters:

- `HttpExecutionAdapter` drives a loopback HTTP application. It refuses any
  non-loopback host, refuses to follow a redirect (a 3xx cannot move execution off
  the approved origin), and refuses cloud-metadata/link-local addresses.
- `ProcessExecutionAdapter` drives a local application as a child process over a
  line-JSON protocol. It requires `LocalScope(allow_process_exec=True)`, runs a
  fixed argv (never a shell string), and always terminates the child on close.
- `EvmExecutionAdapter` drives a **real EVM**: an ephemeral local `anvil` node with
  the exact pinned application bytecode deployed to it, and each engine operation
  dispatched as a real transaction over JSON-RPC. It exists to run the engine
  against *unfamiliar, independently-maintained* source compiled to bytecode — not
  a Python model of the logic and not a BLACKHEART fixture. The node is spawned
  locally (there is no RPC-URL parameter a caller could point at a remote chain),
  state is snapshotted and reverted per sequence, and the case is declared as data
  (`EvmCase`): contracts, setup calls, operations with actor and parameter domains,
  invariants, and the read-only snapshot. A concrete case is the
  `blackheart/statespace/runtime/evm_cases.py` library over vendored Damn
  Vulnerable DeFi v4.1.0; the verifier's differential control is a minimal patched
  contract in `harnesses/dvdf-external/controls`.

Scope is enforced **before** execution, fail-closed, by `LocalScope.check`: an
authorized flag *and* a non-empty authorization reference are required, and the
destination must be loopback. Operation, per-sequence and wall-clock budgets are
enforced and raise rather than return a partial result as if it were complete.

The evaluation applications live in `harness_apps.py`: a **development** target
(`orders`, a stale-authorization flaw) and a **held-out** target (`market`, a
non-atomic settlement that duplicates value), each with a secure control that
differs by exactly the defence. The vulnerable sequences are *not* encoded in the
engine — it derives its model from the app's declared operations and invariants and
searches for what breaks.

### External research (capability #9)

After a runtime finding, `research_finding` asks BLACKHEART's existing
external-intelligence layer (You.com first, then the free keyless providers)
whether the same weakness is already known. External text is passed through
`quarantine_sources` before use, so an injected instruction in a fetched page
cannot steer the engine. A missing key is reported as `unavailable` with a setup
hint — never as a fabricated result or a fake negative.

### Using the runtime engine

```bash
blackheart statespace runtime --list-apps               # the harness apps
blackheart statespace runtime --app orders --declare    # the auditable model
blackheart statespace runtime --app orders              # execute + verify
blackheart statespace runtime --app market --research   # + external research
blackheart statespace runtime-bench                      # executed vs baseline
blackheart statespace evm --list-cases                   # external EVM cases (all targets)
blackheart statespace evm --case dvdf-truster            # discover + verify on real bytecode
blackheart statespace evm --all                          # every external case
blackheart statespace evm-bench --all                    # guided vs random vs upstream test
```

The external EVM path needs the vendored targets built once:

```bash
harnesses/dvdf-external/fetch.sh          # clone DVDF v4.1.0, build it + the controls
harnesses/ethernaut-external/fetch.sh     # clone OpenZeppelin Ethernaut, build it + the controls
harnesses/euler-v1/fetch.sh               # clone Euler V1, build it + the harness + controls
```

Three independently-maintained external applications are registered: **Damn
Vulnerable DeFi** v4.1.0 (`harnesses/dvdf-external/`), **OpenZeppelin Ethernaut**
(`harnesses/ethernaut-external/`) and **Euler V1** (`harnesses/euler-v1/`, a real
production diamond-proxy lending protocol). The engine and adapter are unchanged
across all three — each additional target exists to show the capability is not
overfitted to one codebase. `evm-bench` runs a fair comparison against a uniform
random stateful fuzzer over the *same* space and records the upstream project's own
test as a provenance column (never as a detection result).

## Safety and authorization

The fixture engine is a **local, model-driven** search: it runs operation sequences
against in-memory fixtures, never against a live target. The runtime engine
executes against a target, but only a target that is explicitly authorized and
restricted to loopback: a controlled BLACKHEART harness app, or an operator's own
authorized local service. It is not a scanner — it issues exactly the operations in
the target's declared model, with the declared actors — and it never follows a
redirect or contacts a non-loopback host. The verifier's first check is scope and
authorization, and it fails closed. A violation is an input to the existing
finding/verification pipeline; it is not a submitted report. Nothing in this
package escalates to a real remote system.
