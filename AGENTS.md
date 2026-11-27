# AGENTS.md — working in BLACKHEART

This file is the durable guide for **any** agent working in this repository, in
this session or any future one. It leads with the identity that is the core of
BLACKHEART, because everything else follows from it.

## The core: who BLACKHEART is

> **BLACKHEART is a wise and dangerous hacker with a black heart.**

This is the identity, not a tagline, and it is the core of the project and of all
future work. Hold it before you hold anything else.

- **Wise** — patient, methodical, unhurried, economical with effort, and honest
  with yourself above all. The hard bug is found by the operator still reading
  the code when the others have moved on.
- **Dangerous** — precise where others are careless, relentless toward a real
  weakness, and unhurried until the impact is proven. A real weakness, proven,
  beats ten plausible ones described.
- **A black heart is a *method*, not a mood** — no mercy for your own
  assumptions, no vanity, no wishful thinking. You never dress a guess as a
  finding, and you never confuse activity with progress.

A black heart is never a licence. BLACKHEART works only inside authorized scope,
never harms real users or funds, and stops when an action could reach
out-of-scope systems.

The canonical, machine-readable form of this identity lives in
`blackheart/mindset.py` (`BLACKHEART_PERSONA`, `PERSONA_TRAITS`,
`PERSONA_TAGLINE`). Render it with `python3 -m blackheart mindset --persona`.
Do not restate it by hand — read it from the module.

## The question every mission answers

Under that identity, every mission answers one question, from the position of the
weakest actor in the system:

> I am an ordinary, unprivileged attacker: what transaction sequence, inputs,
> timing, account state, or market conditions can I create or manipulate to
> receive more assets than I am entitled to, bypass a restriction, or make
> another user's position absorb my loss?

The question, the three **outcomes**, the five **levers**, and the **doctrine**
that follows from them are defined in `blackheart/mindset.py` and are already
wired into the engine:

- `blackheart/providers/roles.py` — the identity + question lead every role's
  system prompt.
- `blackheart/objectives/` — every `Objective` carries `attacker_outcome` and
  `attacker_levers`, and its rationale is framed by the lens.
- `blackheart/hypothesis/` (+ `generation.py`) — every hypothesis carries the
  outcome it targets and the levers it uses; explanations answer the question.
- `blackheart/campaign/` — every `CampaignResult` records the question verbatim.

Read the mindset from the module; never paraphrase it inline, or the mission
drifts.

## How the operation is run: the operational doctrine

The mindset is *who we are and what we ask*. The **operational doctrine**
(`blackheart/doctrine.py`) is *how the operation is run*: the authoritative
mission definition, the six-phase research lifecycle (target intelligence →
attack-surface discovery → hypothesis development → adversarial investigation →
exploit validation → independent adversarial review), the attack surfaces, the
shape a hypothesis must take, the investigation methods, the validation
requirements and the seven finding verdicts, the independent-review questions, the
A–J finding record, the transparent prioritisation model, the nine logical
research responsibilities, and the non-negotiable security invariants — each
mapped to the module that already implements it.

It introduces **no new engine**. Every phase and rule points at code that exists
and is tested. Render it with `python3 -m blackheart doctrine` (or `--json` for
the machine-readable form, `--phase KEY` for one phase). A compact block from it
is prepended to every role prompt alongside the persona, so the operation is run
the same way everywhere.

**Language-aware tool selection is mandatory** (`LANGUAGE_AWARE_POLICY` in
`blackheart/doctrine.py`, rendered in the doctrine and in every role prompt). No
engine runs before the stack is identified from source, manifests and build
configuration, the tool's documented compatibility is verified against it, and a
compatibility smoke test passes. `blackheart/toolchain/` enforces it: a verified
per-language registry (Solidity, Vyper, Rust/Substrate, Python, Go, C/C++, Move, Cairo,
JavaScript/TypeScript, each with official documentation, known incompatibilities
and a verification date), a fail-closed gate (`blackheart compat check`, exit 2)
and a stack detector (`blackheart compat detect`) that reports a language seen only
by file extension as **unconfirmed**. Execution is reported with exactly one of
`PASS` / `BLOCKED` / `INCOMPLETE` / `NO_FINDINGS`; a parser failure is not a failed
reproduction and a clean scan is not a secure protocol. Policy and registry:
`docs/SECURITY_TOOL_COMPATIBILITY.md`; acceptance bar:
`tests/test_tool_compatibility.py`.

**The gate is enforced at the engine boundary, not only at the CLI**
(`blackheart/toolchain/enforce.py`). `run_sequence` in both executors, the statespace
explorer, `hunt()`, `Campaign.run_active`, `EngineOrchestrator.run`, every
`EngineAdapter.execute_scan` (wrapped in `__init_subclass__`, so adapters written
later are covered) and the EVM/live runtimes take `compatibility=` and refuse to
touch a target without a validated record **bound to it** (`target_component`,
`repository`, `commit`, plus an optional `control_component` for the guarded twin
a differential check compares against — a comparison, never a grant for a third
component); nested runs inherit an authority and cannot widen it. A registry alias
and the model's canonical name are one component, so the entry point declares
both resolved names on the authority (`Authority.grants`) and the hunt boundary
and the engine boundary bind the same record. On
the CLI that is `--compatibility RECORD` for `hunt`, `campaign` and `engines run`;
a blocked run exits 2 and names the failed field and the remedy. The repository's
own fixtures execute under `self_test_record()` (wildcard component, bound to
`repository="blackheart"`, which is why it cannot authorise a third-party target),
installed by `@_fixture_command` for fixture-only commands and by
`tests/conftest.py` for the suite. Acceptance bar:
`tests/test_engine_enforcement.py` — a blocked run must leave the engine's
invocation count at zero, not merely print an error.

The **findings repository** (`blackheart/findings/`, `blackheart findings`) is
where every meaningful investigation leaves its permanent record. Confirmation is
evidence-gated: a finding cannot become `CONFIRMED` without evidence, an
independent verification result, and a named reviewer, and the CLI's only path to
`CONFIRMED` resolves every evidence reference against the evidence store.

The repository exports **SARIF 2.1.0** (`blackheart findings sarif`,
`findings export --format sarif`). The result `level` is only a presentation
hint: the record's verdict and the **evidence-gated** `confirmed` answer travel
in `properties`, the full A-J record is embedded for a lossless round-trip, and
`from_sarif` re-applies the confirmation gate and checks the record digest, so a
hand-edited log cannot launder a `CONFIRMED` claim. Acceptance bar:
`tests/test_sarif.py`; see `docs/SARIF.md`.

The **incremental baseline** (`blackheart/baseline.py`, `blackheart baseline`)
stores each finding's content fingerprint -- the same one SARIF emits -- and
compares a fresh repository against it as **new / resolved / changed /
unchanged**. A re-recorded finding with a new id or title is unchanged; a verdict
or severity move is changed, not new; `--fail-on-new` exits 1 for CI. It covers
findings, not raw ingest flags, and a moved root-cause line is a new identity.
Acceptance bar: `tests/test_baseline.py`; see `docs/BASELINE.md`.

**Reviewer-model support is optional, never a hard dependency.** Gate 6 of the
verifier records the reviewer's real provenance
(`ReviewIndependence.INDEPENDENT_MODEL` / `SAME_MODEL` / `UNRECORDED`) and refuses
to call a same-model review independent. `resolve_reviewer_model` reports three
distinct states — `configured` (a distinct provider has a key), `verified` (a
liveness probe proved the credential works), and `available` (both) — so a key that
is present but invalid is never read as an independent reviewer. When no verified
reviewer is configured, the workflow falls back to a **same-model adversarial
review in a fresh context**, recorded honestly as `SAME_MODEL`, refused at
`CONFIRMED` and at report submission. Core research and release run with zero
providers; `blackheart models reviewer` shows the resolution without ever failing.
Provenance is a *claim* and the gate-6 result is the *record*, so both are checked
against each other: a record whose reviewer label contradicts an
`INDEPENDENT_MODEL` claim, a finding whose gate-6 detail contradicts it, or an
`INDEPENDENT_MODEL` claim resting on a legacy detail that names no provenance,
fails closed rather than being read as independent. The rule lives in one place,
`blackheart.models.evidenced_review_independence`, and both the report layer and
the findings repository apply it, so neither path is the weaker one;
`blackheart.models.gate6_detail` is the single definition of the canonical detail.
See `docs/MULTI_MODEL.md` §7.

**The official bounty policy is the sole eligibility authority**
(`blackheart/bounty/gate.py`, `blackheart bounty gate`). A candidate is
submission-ready only when it passes four gates: **A** official policy
verification (program, policy URL, retrieval date, revision, scope, exclusions,
severity definitions, required impact, reward conditions), **B** technical
validation (component + version, attack path, prerequisites, impact, affected
deployment, independent reproduction, evidence, root cause), **C** eligibility
assessment against the published rules (scope, class, severity definition,
exclusions, known/fixed/duplicate, extra evidence, reward availability, cited
policy sections) and **D** a disposition of `A_SUBMISSION_READY`,
`B_POTENTIALLY_PAYABLE`, `C_VALID_NOT_PAYABLE`, `D_INVALID_OR_DISPROVEN`,
`E_INFORMATIONAL` or `F_NOT_ASSESSED`. Dispositions are not severity classes: a
valid Low or Medium stays eligible when the program's own rules say so. **No
internal score, generic numeric threshold, or universal severity-to-payout
assumption may decide eligibility** — `research_score` is prioritisation metadata
the gate never reads, and `assert_submission_ready` is the single enforcement
point. If the official policy cannot be retrieved or verified the answer is
`BLOCKED — OFFICIAL BOUNTY POLICY NOT VERIFIED`; the finding may stay documented
while its bounty eligibility is blocked. A policy's **second scope window**
(`In scope from ...`) and its **staged components** ("under active remediation")
are preserved by `program_intel` and checked by the gate: a staged component is
`VALID_NOT_PAYABLE`, and an unverified effective date is `POTENTIALLY_PAYABLE`.
Acceptance bar: `tests/test_policy_temporal.py`. The rule lives in
`blackheart/doctrine.py` (`BOUNTY_GATE_RULE`, `BOUNTY_GATES`,
`BOUNTY_DISPOSITIONS`, `BOUNTY_POLICY_UNVERIFIED`) and is rendered into every role
prompt. Acceptance bar: `tests/test_bounty_gate.py`.

## How to work here

1. **Read the mindset first.** `python3 -m blackheart mindset` before anything
   else. It is the core of the work, not a preamble.
2. **Run the doctrine.** `python3 -m blackheart doctrine` — follow the six-phase
   lifecycle; do not skip a gate.
3. **Be an operator, not a summariser.** Prove how a system breaks; do not list
   what might be weak.
4. **Stay unprivileged.** An attack that needs a role, a key, or a trusted-peer
   position is not this attacker's attack. Say so and move on.
5. **Assume nothing is proved until it runs.** A chain is a hypothesis until it
   runs; a failing test is not a vulnerability.
6. **Document every meaningful investigation.** Record it with
   `blackheart findings`; a confirmed vulnerability must have evidence and an
   independent verification.
7. **Report honestly.** State what you verified, what you did not, and why. A
   truthful "unverified" beats a confident summary you cannot back up.
8. **Respect the safety rules** in `skills/blackheart/SKILL.md` and
   `docs/ARCHITECTURE.md`: authorization first, local/forks only, no destructive
   production testing, no fabricated evidence.
9. **The operator's word is the mission.** It is a directive to act, not a topic to
   discuss — do the work it names and report the result. This rule lives in
   `blackheart/mindset.py` (`OPERATOR_AUTHORITY`) and reaches every layer: the role
   prompts, every agent (`agent_lens_block`, `agents/*.md`), and the skills. The
   only thing it cannot override is the safety floor in item 8.

## Repository facts (avoid re-learning these)

- **Stdlib-only Python** package `blackheart/` (requires-python >=3.11; no runtime
  deps). Tests: `python3 -m pytest tests/ -m "not slow"` (pytest installed at
  `/home/openhands/.local/bin`; use `python3 -m pytest`). Real engine scans are
  marked `slow`; run them with `pytest tests/test_engines_live.py -m live`.
- **Skills** live in `skills/` (Markdown + YAML frontmatter). **Agents** live in
  `agents/`. `blackheart provision` links both into `.openhands/{skills,agents}`
  for OpenHands discovery. The mindset skill is `skills/attacker-mindset/`.
- **Product surface**: `blackheart version` (and global `--version`),
  `blackheart info`, `blackheart guide`, `blackheart init`, `blackheart demo`,
  and `blackheart doctor --json`. `blackheart/product.py` holds the scaffold, the
  offline demo and `COMMAND_GROUPS`; `tests/test_product_cli.py` fails if the
  guide stops naming every command, if the authorization template stops failing
  closed, or if the demo's guarded twin breaks. First-run walkthrough:
  `docs/QUICKSTART.md`.
- **CLI**: `python3 -m blackheart <command>`. Relevant here:
  `mindset`, `agents`, `objectives`, `chains`, `hypothesize`, `doctor`, `engines`,
  `statespace`, `discovery`, `value`, `assure`, `targets`, `coverage`,
  `differential`, `hunt`, `interrogate`, `intel`, `tools`, `schedule`, `compat`.
- **Distribution**: Apache-2.0 (`LICENSE`, `NOTICE`), `pyproject.toml`
  metadata, a tag-triggered `.github/workflows/release.yml` that builds and
  smoke-tests the wheel in a clean venv and attaches `SHA256SUMS`, and
  `docs/RELEASE.md`. Version lives in `blackheart/__init__.py` and must match
  `pyproject.toml`. `CONTRIBUTING.md` and `SECURITY.md` are the public process.
- **Docs**: `README.md`, `docs/QUICKSTART.md`, `docs/RELEASE.md`, `docs/ARCHITECTURE.md`, `docs/PORTABILITY.md`,
  `docs/RESEARCH_ENGINE.md`, `docs/MULTI_MODEL.md`, `docs/ENGINES.md`,
  `docs/STATESPACE.md`, `docs/FUZZING.md`, `docs/DISCOVERY.md`, `docs/VALUE.md`,
  `docs/COVERAGE.md`, `docs/HUNT.md`, `docs/INTERROGATE.md`, `docs/INTELLIGENCE.md`, `docs/SCHEDULER.md`,
  `docs/SECURITY_TOOL_COMPATIBILITY.md`.
- **Repository ingestion** lives in `blackheart/ingest/` and is driven by
  `blackheart ingest <path>`. The lexer is the default; `blackheart/ingest/ast_surface.py`
  maps a solc source-unit AST or combined-json payload into the same
  `ContractSurface` model, used by `pipeline --source --ast FILE` and
  `--compiler-ast` (pin the binary with `--compiler PATH`; `--include-path` and
  `--remapping` extend discovery). The compile is narrowed to the target's
  import closure, and Foundry `foundry.toml`/`remappings.txt` plus ancestor
  `node_modules` are discovered automatically. `--ast` accepts a source-unit
  AST, combined-json payload, Foundry build-info file or build-info directory.
  The AST path never repairs an unresolvable body: it stays
  empty and unmodelled. Foundry 1.10 emits the compiler's standard JSON, so
  `compile_sources` asks for `forge build --json --ast` and reads the AST from
  `sources[path][*].source_file.ast`; older flat artifact shapes are still read.
  Acceptance bars: `tests/test_ast_surface.py`, `tests/test_ingest_compile.py`.
  Ingestion removes the hand-transcription step that opened every earlier mission: a lexer-grade Solidity scanner recovers contracts,
  functions (visibility, mutability, modifiers, params, line, body), state
  variables and declared modifiers, then twelve rules emit `CandidateFlag`s with
  the exact `file:line` as evidence. Every rule maps to a category in
  `objectives._OBJECTIVE_CATALOG` and the mapping is validated at import, so the
  taxonomy and the rules cannot drift. Test/snapshot/script trees are excluded by
  default. **A flag is a lead, never a finding** — the guarded twin must not fire,
  and `tests/test_ingest.py` pins that. `ingest --synthesize` builds a `Target`
  from a contract's own functions (a source-ordered statement subset:
  assignment and compound assignment, unary inc/dec, `delete`, mapping and
  struct-field writes, arrays with `push`/`length`, function-local scalar
  declarations, nested `if/else if/else`, `require`/`if-revert`/direct `revert`
  in source order, an early `return` that halts later writes, inherited
  functions/state, literal-bound loops, statement-level external calls in source
  order, and a single unconditional call return value; anything else is marked
  unmodelled and not simulated) and runs the certifier on it — scoped to unprivileged
  actors only, so a guarded function is unreachable until an unguarded one takes
  the owner slot. It derives conservation and `authorization:<owner>`
  invariants. A protocol composition applies recorded external calls in source
  order, rolls the caller back when a callee reverts, and assigns a single
  unconditional return value (into a local frame or state); a call with no known
  outcome is `UNMODELLED` and aborts the path, never treated as success. An
  interface/base-typed receiver resolves to the one concrete implementation and
  two candidates are ambiguous, never guessed. `Link` supports explicit
  `param_map`/`return_map`, nested calls execute in the callee sub-state, and a
  `nonReentrant` guard refuses recursive entry; an unguarded recursion stops at a
  named depth limit. Acceptance bar: `tests/test_protocol_semantics.py`. A
  single-contract step does not compose external state. `blackheart/ingest/runner.py` runs
  `forge test` behind the compatibility gate, fail-closed (a blocked run never
  invokes the tool). See `docs/INGEST.md`.
- **Bytecode, deployment and venue depth** lives in `blackheart/symbolic/`,
  `blackheart/evm_fuzz.py`, `blackheart/ingest/verified.py`,
  `blackheart/ingest/storage_layout.py` and `blackheart/venues/amm.py`, driven by
  `symbolic-evm`, `evm-diff`, `evm-fuzz`, `verified-model`, `layout diff`,
  `layout extract` and `poc run`. The symbolic EVM wraps constants at 256 bits,
  folds shifts / `SIGNEXTEND` / `ADDMOD` / `MULMOD` / `EXP`, computes `SHA3` of
  concrete memory, and prunes with the linear solver. `--wrap` forks symbolic
  ADD/SUB/MUL on overflow/underflow; symbolic AND/OR/XOR are carried with sound
  interval bounds, while symbolic EXP and division stay unbounded. A witness or a
  differential divergence becomes a runnable Foundry test with `--poc-out`
  (`symbolic/poc.py`); `poc run` writes it into a minimal Foundry project and
  runs `forge test` only after the compatibility gate admits the target (a
  blocked run never invokes forge), and `--minimize` shrinks the calldata while
  the divergence or terminal outcome still holds (`symbolic/minimize.py`). A
  verified source is rebound to the deployed runtime (metadata stripped, proxy
  resolved) only when the caller supplies a recompiler; a decompiler's surface is
  parsed with every body unmodelled; a storage-layout diff refuses a moved or
  type-changed variable; the AMM prices a multi-hop constant-product sandwich net
  of gas.
  Honest limits:
  `docs/EVM_DEPTH.md`; acceptance bars: `tests/test_symbolic_evm.py`,
  `tests/test_poc.py`, `tests/test_poc_runner.py`, `tests/test_minimize.py`,
  `tests/test_evm_fuzz.py`, `tests/test_verified_pipeline.py`,
  `tests/test_decompiled_ingest.py`,
  `tests/test_storage_layout.py`, `tests/test_venues_amm.py`,
  `tests/test_cli_evm.py`.
- **More than one environment is ingested, and each is fail-closed.** `blackheart ingest` detects the
  stack from the tree and dispatches: `blackheart/ingest/solidity.py` for Solidity,
  `blackheart/ingest/rust.py` for Rust/Substrate **and Solana/Anchor**
  (`--language rust` forces it), and
  `blackheart/ingest/golang.py` for Go / Cosmos SDK (`--language go`). The Rust
  scanner recovers Substrate pallets/dispatchables **and** Anchor instruction
  handlers (`#[program]` plus every `Context<T>` function) with their
  `#[derive(Accounts)]` structs, per-field constraints, multi-line attributes and
  cross-field `has_one` bindings. Two Anchor rules emit leads: an unbound writable
  raw `UncheckedAccount`/`AccountInfo`, and a CPI with no program-id check. FRAME
  rules (`origin`, `weight`) are skipped on Anchor because its authorization lives
  in the Accounts struct. A `/// CHECK:` comment is an assertion, not a check, so
  it never clears a lead. Acceptance bars: `tests/test_ingest_rust.py`,
  `tests/test_ingest_anchor.py`. The Go
  scanner recovers packages, functions, receivers, message handlers, consensus
  entry points, cgo/FFI boundaries, build flavors (`community` / `full` /
  `unconditional`) and **stubs** (`//go:build !full`, `ErrNotImplemented`), so a
  public build that omits a module is reported as a stub, never as the full
  build's implementation. `ingest/golang_flags.py` turns the reachable surface
  into category-linked leads. Acceptance bar: `tests/test_golang_ingest.py`.
- **Language coverage is fail-closed.** `blackheart/ingest/coverage.py` compares
  the production languages detected in a tree against the scanner that actually
  ran. `FULL` means every language carrying production code was opened; a tree
  with Go plus an unscanned Solidity/C surface is `BLOCKED`, never "clean".
  `--allow-unscanned LANG` records an explicit partial exception. The gate is
  wired into `ingest`, `interrogate` and `pipeline --source`.
- **A Cosmos chain now has a reference model, not only a scanner.**
  `blackheart/cosmos/` supplies an executable accounting target (send, delegate,
  undelegate, redelegate, governance deposit/withdraw, lock/unlock, slash) with
  supply, non-negative-balance, self-bond and locked-coin invariants and a
  deliberate double-credit vulnerable twin. `blackheart cosmos model|certify|
  from-go` drives it. It is a model of the accounting shape, not a devnet: IBC,
  BeginBlock/EndBlock, governance execution, the EVM lane, cgo/FFI and slashing
  rounding are declared unmodelled. Acceptance bar: `tests/test_cosmos.py`; see
  `docs/GO_COSMOS.md`.
  The Rust scanner recovers pallets, dispatchables, weights, storage items and
  bodies, and `ingest/rust_flags.py` turns them into category-linked leads. It
  must handle **both** `#[pallet::call]` and
  `#[pallet::call(weight(<T as Config>::WeightInfo))]`: matching only the bare
  form reported `pallet-assets` (34 dispatchables) as having none. Rules judge
  only dispatchables, because a `pub fn` no dispatchable calls is not reachable by
  an unprivileged account. Acceptance bar: `tests/test_ingest_rust.py`.
- **`blackheart interrogate` questions the code instead of suspecting it.** It
  derives the claims the source makes (authorization, loop termination, write
  ordering, supply conservation, one-shot initialization, no-panic, bounded work,
  declared weight) and tries to falsify each. Every claim ends `FALSIFIED`,
  `SURVIVED` or `UNTESTABLE`; a `SURVIVED` verdict always carries the blind spot
  it could not see, and `UNTESTABLE` is never rendered as clean. Two precision
  rules are load-bearing and must not be loosened: a bare `ensure!` is not an
  origin check, and a bare `msg.sender` is not a guard. Acceptance bar:
  `tests/test_interrogate.py`. See `docs/INTERROGATE.md`.
- **Model coverage is a contract, not a footnote** (`blackheart/ingest/model_coverage.py`,
  `blackheart closure coverage`, `ingest --coverage`). Every function, statement,
  call edge and function-level path is classified `MODELLED` / `UNMODELLED` /
  `UNREACHABLE` / `EXTERNAL` with `file:line` evidence, and the ledger is carried
  on `SynthesisReport`, `ProtocolReport`, `CoverageCertificate`,
  `PortfolioResult`, `HuntResult`, `VerifiedModel` and `PipelineResult`. If a
  reachable item is outside the model, a no-violation result is
  `INCOMPLETE MODEL COVERAGE`, never `CERTIFIED CLEAN`, `NO_VIOLATION` or
  `NOT FOUND`. `UNREACHABLE` items do not block. Path coverage is function-level;
  branch enumeration remains the certifier's bounded job. Acceptance bar:
  `tests/test_model_coverage.py`. See `docs/CLOSURE.md`.
- **The capability statement** lives in `blackheart/capability.py` and is driven by
  `blackheart capability [--json]`. It is the honest, machine-readable answer to
  "can BLACKHEART find a payable bug unaided?" — currently **no**: it can drive
  the doctrine, model 27 of 30 objective categories, search state machines, ingest
  real source and bind a verified deployment to its runtime, but it cannot compile
  or execute arbitrary third-party Solidity, synthesise every statement from source,
  or see the logic inside a closed component. Every
  capability carries its evidence and its limitation, and the diagnosis keeps both
  fixed and open gaps. Read it before claiming coverage; `tests/test_capability.py`
  keeps it from being quietly softened.
- **Close-the-loop pipeline** lives in `blackheart/pipeline.py` and is driven by
  `blackheart pipeline`. It has two entry points: `run_pipeline` for a verified
  deployment and `run_source_pipeline` for a local `.sol` tree. The source-only
  path needs no address and no hand-written hypothesis: the certifier enumerates
  every declared invariant, the value engine ranks the witnesses, a fresh model
  re-runs the selected one, an optional guarded source contract supplies the
  control, and `--poc` can render and run a Foundry test. `--protocol` composes
  every recovered contract and infers caller→callee links; a multi-contract PoC
  deploys each called contract and routes each step to its owner.
  `--require-independent-engine` refuses a same-engine replay as a confirmation,
  and a passing Foundry PoC supplies the distinct `foundry` engine. It never
  claims a deployment binding, and scope/authorization remain operator
  declarations. Acceptance bars: `tests/test_pipeline.py`,
  `tests/test_pipeline_source.py`, `tests/test_protocol_pipeline.py`,
  `tests/test_verification_independence.py`.
  It composes the verified-source attestation, source
  synthesis, bounded-exhaustive certifier, value engine, independent verifier,
  evidence store and findings repository into one operation. A finding is
  `CONFIRMED` only when the verifier's disposition is `INDEPENDENTLY_VERIFIED`
  **and** the caller established scope/authorization; otherwise it is
  `STRONGLY_SUPPORTED`. The reproduction is model-level, not a Foundry PoC, and
  the result says so. Acceptance bar: `tests/test_pipeline.py`.
- **Automatic deployment binding** lives in `blackheart/ingest/deployment.py` and
  is driven by `blackheart deployment bind`. One command resolves a live RPC,
  fetches the verified source, proves it is bound to the deployed runtime, recovers
  the component surface, runs the native compiler as a smoke test and emits a
  complete `CompatibilityRecord` (plus a loadable `.record.json`). It refuses a
  missing repository/commit, an unbound source and an unknown component; a
  verified source is not a semantic-equivalence proof. Acceptance bar:
  `tests/test_deployment_binding.py`.
- **Directed certification** lives in `blackheart/discovery/certify.py`
  (`certify_directed`) and is driven by `blackheart closure certify` and
  `blackheart assure directed`. It spends a bounded budget on value-moving paths:
  the actor in `to`/`from`, the protocol contracts in `spender`/`target`, and the
  maximum numeric corners, keeping the most active states in a beam. It records
  `exhaustive: false`; a miss is never a proof of safety. On the ERC4626 pair it
  finds the first-depositor path without the exhaustive budget. Acceptance bar:
  `tests/test_directed_certification.py`.
- **Generated invariants are not ERC4626-only** (`blackheart/ingest/
  generated_invariant.py`). `render_surface_invariant` selects the ERC4626
  non-zero-shares property, an explicit-owner unchanged property, or a
  caller-supplied Solidity body, and fuzzes every state-changing function it can
  model. An ambiguous surface is refused, and unsupported parameters are listed in
  `GeneratedInvariant.skipped`. Acceptance bars:
  `tests/test_generated_invariant.py`, `tests/test_generated_invariant_general.py`.
- **The close-the-loop pipeline** (`blackheart/pipeline.py`, `blackheart pipeline`)
  is the one operation from verified deployment or local source to a priced,
  independently re-run finding. `--source --protocol` composes every recovered
  contract into one `ProtocolTarget`, infers caller→callee links, carries the
  aggregated model-coverage ledger, traces each step to its owning contract, and
  renders a multi-contract Foundry PoC for the four supported invariant forms.
  `--require-independent-engine` records the producer and verifier engine and
  refuses `INDEPENDENTLY_VERIFIED` when they are the same or unrecorded; a
  passing Foundry PoC supplies the distinct `foundry` engine. Strict mode is
  opt-in because a fresh instance of the same engine is a re-run, not an
  independent engine. Acceptance bars: `tests/test_protocol_pipeline.py`,
  `tests/test_verification_independence.py`.
- **Universal hunt** lives in `blackheart/hunt/` and is driven by `blackheart hunt`.
  It is the single composition of every engine, in the order the doctrine requires
  (recall → search → certify → verify → order → remember), and introduces **no new
  engine** — every stage calls a tested module and the result carries that module's
  own verdict. It never upgrades a lead: only a fully verified attack
  (`INDEPENDENTLY_VERIFIED`) is written back to the cross-target memory. Acceptance
  bar: `tests/test_hunt.py`. See `docs/HUNT.md`.
- **Durable autonomous execution** lives in `blackheart/scheduler/` and is driven
  by `blackheart schedule`. It is the *dispatcher* the research engine lacked
  (`docs/RESEARCH_ENGINE.md` §8): an append-only, hash-chained job log rebuilt by
  replay, a `TRANSITIONS` lifecycle, lease ownership fenced by a **monotonic
  epoch** (so a stale worker can never complete a job it no longer owns),
  stale-lease recovery, deterministic bounded-exponential retry with dead-letter,
  misfire recovery, idempotent dedupe, and authorization re-checked at claim, in
  the executor, and on recovery. It adds reliability, not research insight: every
  job runs an existing engine and records its verdict verbatim. Acceptance bar:
  `tests/test_scheduler.py`. See `docs/SCHEDULER.md`.
- **The reviewer model is optional and must stay optional.** BLACKHEART's core
  research and release workflow never requires a separately configured reviewer API
  key. `resolve_reviewer_model` (`blackheart/providers/router.py`) returns
  `available=False` with a reason when no *verified* credential exists, and the
  workflow performs a **same-model adversarial review in a fresh context**, recorded
  as `ReviewIndependence.SAME_MODEL` — never as an independent-model review. A
  present key is `configured`, not `available`: only a successful liveness probe
  makes it available, and `_same_model_family` refuses to call two providers serving
  identical weights independent. `FindingRecord.missing_confirmation_fields` refuses
  `CONFIRMED` on a same-model review, so the limitation can never be laundered into
  a confirmation. The mandatory release gates (`doctor`, `coverage`, `differential`)
  run with every provider key stripped; `tests/test_reviewer_optional.py` is the
  acceptance bar that fails if a hard dependency is reintroduced. Do not add one.
- **Every `forge` lookup goes through `resolve_tool`, not `shutil.which`.**
  The PoC runner, the ingest runner, fork campaigns and live-V3 fork execution
  all resolve the binary from `~/.foundry/bin`; a shell PATH that omits Foundry
  must not make an installed tool look absent. A test that simulates absence
  patches the resolver, not `PATH`. Acceptance bars:
  `tests/test_poc_runner.py`, `tests/test_runner.py`.
- **The toolchain covers more than the EVM, and the resolver does not trust
  `PATH`.** `install.sh` installs a Rust/Substrate toolchain (rustc/cargo stable,
  a **nightly** for cargo-fuzz, clippy, cargo-fuzz, cargo-audit, cargo-deny) and a
  live-protocol layer (nuclei/httpx/subfinder/katana/dnsx/gau/naabu/ffuf/gobuster/
  dalfox/nmap/sqlmap/wafw00f/arjun/gitleaks/trivy). Every Python tool lives in its
  own venv under `~/.blackheart/venvs/<tool>`; `resolve_tool` searches
  `~/.foundry/bin`, `~/go/bin`, `~/.cargo/bin`, `~/.local/bin` and
  `/usr/local/go/bin` explicitly, because a tool found only by luck of the shell
  environment vanishes in the next process. That defect once made every engine
  report "not found" on a host where all of them were installed. Acceptance bar:
  `tests/test_toolchain.py`, and `blackheart tools verify` must report 0 missing.
  A stack with no verified tool is `BLOCKED` at `compat check`, never "clean".
- **Whole-program taint** lives in `blackheart/dataflow/` and is driven by
  `blackheart dataflow <path>`. It is an SSA-lite def-use pass over the scanner's
  statement subset: parameters, `msg.sender`/`msg.value`, external-call returns
  and state are propagated through internal calls to a fixpoint, `if` branches
  merge with phi nodes, and a flow carries its function path and source line. A
  recognised owner/admin guard is recorded on the flow rather than hidden. A
  flow is a **lead**, never a finding; acceptance bar `tests/test_dataflow.py`.
  `pipeline --source --dataflow` adds the lead stage to the loop.
- **Execution routing** lives in `blackheart/execution/route.py` and is driven
  by `blackheart evm-exec`. It runs one bytecode message on a real ephemeral
  `anvil` node through `eth_call` when Foundry is installed, and otherwise on the
  local `evmworld` interpreter. The engine and the fallback reason are carried
  with the result, so a local model run is never labelled as a chain run. `revm`
  is detected but has no stable CLI contract here. Acceptance bar
  `tests/test_execution_route.py`.
- **SMT path conditions** are optional in `blackheart/symbolic/smt.py` and
  selected with `--smt` on `symbolic-evm` / `ingest --symbolic`. Z3 is not a
  dependency: when absent the answer is an explicit `UNKNOWN` with a reason; a
  SAT model is re-evaluated against every constraint and declared domain, and
  UNSAT is accepted only over those finite domains. Acceptance bar
  `tests/test_smt.py`.
- **Witness source mapping** lives in `blackheart/witness.py`: a certified step
  maps to its contract, function, source line and statement, and an unmapped step
  says why. `pipeline --source` carries the trace; acceptance bar
  `tests/test_witness.py`.
- **CI artifacts** are wired into `blackheart pipeline`: `--sarif` exports the
  findings repository as SARIF 2.1.0, `--write-baseline` / `--baseline` /
  `--fail-on-new` give a content-addressed regression gate. The existing
  `blackheart baseline` and `blackheart findings sarif` commands remain the
  lower-level entry points.
- **Bytecode tools** are pinned in the `bytecode_tools` section of
  `blackheart/engines/toolchain.json` and installed/verified by the same
  `engines bootstrap` / `engines doctor` machinery as the source engines —
  currently **Heimdall** (MIT, bare-binary release, SHA-256 pinned), which
  decompiles runtime bytecode into an ABI and CFG so a *closed* component is no
  longer a blank wall. It is a lead generator: decompiled output is a
  reconstruction, never source, and never a finding without a reproduction.
  `aderyn` was **removed**: upstream retired it and withdrew every download, so
  the pinned URL 404s. A registry entry nobody can install is a lie about the
  toolchain, and `tests/test_toolchain.py` fails if one returns.
- **Universal RPC resolution** lives in `blackheart/rpc.py`. No fork test or
  `deployed` check hardcodes an endpoint any more: `resolve_rpc` honours the
  operator's `--rpc`/`$BLACKHEART_ETH_RPC` verbatim, then the keyless
  `chainid.network` registry, then **You.com** discovery
  (`blackheart.intelligence.discover`), then a probed fallback list — and returns
  only an endpoint that *answered* `eth_chainId`. Acceptance bar: `tests/test_rpc.py`.
- **Universal value & profitability engine** lives in `blackheart/value/` and is
  driven by `blackheart value`. It is the single accounting layer every other
  engine shares: it classifies any target's snapshot value **by structure, not a
  name allow-list** (asset/liability/permission/protocol/other) and prices a
  sequence as attacker profit, victim loss, protocol loss, conservation residual,
  repeatability and max extraction. `discovery/economic.py` is a facade over it.
  The adaptive explorer prices every candidate when `profit_guided=True` (default),
  re-ranks its pending work toward value-moving `(actor, operation)` pairs, and
  minimises a violation while *keeping* the value movement. Never fabricate an
  impact: an untracked account, not an assumed zero. Acceptance bar:
  `tests/test_value.py`, `tests/test_adaptive_discovery.py`. See `docs/VALUE.md`.
- **Universal research intake** lives in four packages and makes the research
  workflow independent of the environment a target lives in. They add **no new
  search engine**: each plugs into the existing pipeline and keeps its verdicts.
  * `blackheart/coverage_engine/` (`blackheart coverage-engine {taxonomy,assess}`) —
    an extensible 39-class taxonomy, target-aware applicability (a thin profile is
    `UNRESOLVED`, never a guessed `INAPPLICABLE`), multi-stage attack-path
    composition, an adaptive strategy space that terminates, and a coverage ledger
    that **refuses** `INAPPLICABLE`/`BLOCKED`/`REPRODUCED` without a reason or
    evidence. Its linkage invariant is enforced in both directions by test: a
    taxonomy link must resolve to a **modelled** objective category, and every
    modelled category must be nameable by the taxonomy.
  * `blackheart/environments/` (`blackheart environment {list,route}`) — pluggable
    execution backends (local source, HTTP service, sequence model, and a bounded
    local compose devnet) that declare
    only capabilities **probed on this host**, behind a **single central
    authorization gate an adapter may not override**. Evidence tier is carried and
    never upgraded.
  * `blackheart/program_intel/` (`blackheart program {normalize,requirement}`) —
    normalizes a published policy while preserving scope, class rules, the derived
    severity floor and provenance; anything unparsed is an **uncertainty**, never a
    guess. Eligibility is three-valued: unknown is not excluded.
  * `blackheart/mail_intel/` (`blackheart mail {status,import}`) — read-only Gmail
    (`gmail.readonly` only; no write method exists), an honest restricted-scope
    blocker with sources, an untrusted-data boundary that flags injection and never
    follows links, and a **zero-OAuth manual-import** fallback. An email creates an
    opportunity *candidate*, never an authorization — delivery still passes the
    `TriggerReceiver` gate. Acceptance bars: `tests/test_coverage_engine.py`,
    `tests/test_environments.py`, `tests/test_environment_agnostic.py`,
    `tests/test_program_intel.py`, `tests/test_mail_intel.py`.
    See `docs/UNIVERSAL_RESEARCH.md`.
- **Adversarial state-machine discovery** lives in `blackheart/statespace/` and is
  driven by `blackheart statespace`. It reuses the invariant engine's `Target`,
  `OpSpec` and `InvariantSpec`; do not introduce a parallel target model. The ten
  strategy skills are generated under `skills/adversarial-*/` (prefixed so they
  never collide with the hand-written skills) by
  `blackheart statespace skills --write skills/`. A `SystemModel` can be derived
  from a `ThreatModel` via `model_from_threatmodel`.
- **Completeness assurance** lives in `blackheart/assurance/` and is driven by
  `blackheart assure certify` and `blackheart assure portfolio`. It adds the two
  things the sampling searches cannot: a **bounded-exhaustive certifier** that
  enumerates *every* sequence up to a depth over the declared alphabet (the only
  search allowed to say "no counterexample exists", up to its bound, which it
  prints with its limits) and a **search portfolio** that runs every strategy,
  unions the counterexamples (a strict superset of any single strategy) and reports
  a coverage ledger. The doctrine (`mindset.COVERAGE_DOCTRINE`, "## The coverage
  bar" in every agent, `skills/completeness-assurance/`) is that a stochastic
  negative is "not found within budget", never "clean". Acceptance bar:
  `tests/test_assurance.py`. See `docs/COVERAGE.md`.
- **Attack-class model coverage** lives in `blackheart/invariants/coverage.py` and
  is driven by `blackheart coverage`. The engine can only break a class it has an
  executable **vulnerable/guarded pair** for, so a category with no model is
  invisible to *every* strategy including the certifier. The ledger maps every
  objective category to the registered model that covers it (resolved against
  `TARGET_SPECS`, never asserted by hand); an unmodelled category is a **named
  gap** and the command exits non-zero. Honest framing: a model is a
  *representative, not exhaustive* coverage of the class. The classes that were
  prose-only now have pairs: the first three in
  `blackheart/invariants/logic_targets.py` (`rounding-precision`,
  `ordering-timing`, `info-disclosure`) and the next eight in
  `blackheart/invariants/defi_targets.py` (`cross-chain-replay`,
  `slippage-manipulation`, `silent-transfer-failure`, `governance-manipulation`,
  `denial-of-service`, `reward-manipulation`, `storage-collision`,
  `decimals-mismatch`); each guarded twin differs from its vulnerable twin in
  exactly one method. **All 25 objective categories are modelled** (22
  vulnerable/guarded pairs). The gate is enforced in `blackheart doctor` (a *hard*
  failure, not a setup warning) and in CI (`.github/workflows/ci.yml`), so a new
  category with no model cannot merge silently. Doctrine:
  `mindset.MODEL_DOCTRINE`, "## The model bar" in every agent. Acceptance bars:
  `tests/test_logic_classes.py`, `tests/test_defi_classes.py`.
- **Coverage-guided corpus fuzzing** lives in `blackheart/fuzz/` and is driven by
  `blackheart fuzz --strategy corpus` (and `blackheart fuzz-bench` for the
  corpus-vs-random ablation). It is the *third* search strategy beside the
  enumerating explorer and the random `StatefulFuzzer`: it keeps inputs that reach
  new *behavioural* coverage, grows the deepest-reaching prefixes one operation at a
  time to cross ordered state gates, then havoc-mutates the corpus, and prices each
  hit with the universal value engine. Its claim is deliberately narrow — deep,
  ordered, gated bugs — and `fuzz-bench` measures it honestly. The `DeepGatedEscalation`
  fixture lives in a separate `DEEP_PAIRS` list (NOT `HARD_PAIRS`, whose contract is
  explorer-detectability). See `docs/FUZZING.md`; acceptance bar `tests/test_fuzz.py`.
- **Historical-rediscovery discovery engine** lives in `blackheart/discovery/` and
  is driven by `blackheart discovery`. It measures the engine against a corpus of
  real, publicly-disclosed vulnerabilities (`discovery/corpus.py`), derives the
  model from the target surface (`harness.model_from_target`), searches with
  parameter-boundary variation (`discovery/search.py`), accounts attacker profit
  (`discovery/economic.py`), classifies misses by pipeline stage
  (`discovery/missed.py`), and reproduces three classes for real in
  `harnesses/historical-corpus/` (`discovery/foundry_corpus.py`). A "detection" is
  a rediscovery, never a bounty finding. Acceptance bar: `tests/test_discovery.py`
  (full-benchmark tests are marked `slow`). See `docs/DISCOVERY.md`.
- **Production trigger monitoring** lives in `blackheart/triggers/` and is driven
  by `blackheart trigger`. A trigger is external, hostile input, so it is
  authenticated (HMAC webhook / manual / recurring source), replay- and
  duplicate-deduped, closed-schema validated, rate-limited, and **authorized
  against the configured record — never the payload** — before it enqueues a
  scheduler job. It adds no engine: a trigger runs exactly what an operator would
  run by hand, and its record only says EXECUTED/COMPLETED once the job actually
  did. Every delivery (accepted or rejected) is appended to a tamper-evident
  ledger via `blackheart/chainedlog.py`, the one chaining primitive the job,
  trigger and bounty ledgers share. Acceptance bar: `tests/test_triggers.py`. See
  `docs/TRIGGERS.md`.
- **Program-specific bounty intelligence** lives in `blackheart/bounty/` and is
  driven by `blackheart bounty`. It keeps technical validity, severity, scope and
  payout as **four separate axes** and reports one of ten outcomes, so a
  valid-but-non-payable finding is never called invalid and a payable Low/Medium
  is never suppressed (`evaluate()` takes no confidence score). **No invented
  numeric threshold decides submission or severity** — not 80/100, not any
  composite; the seven mandatory gates (deployment, eligibility, reachability,
  security violation, impact, novelty, reportability) are independent and
  non-compensating, and an "informational" observation is class C because it fails
  the impact gate. Policies are captured as immutable, provenance-carrying
  snapshots (source URL, date, text SHA-256); a policy change re-evaluates without
  rewriting prior decisions.
  Submission is *prepared*, never sent. **Eligibility is decided by the program's
  own published policy, never by a score** (`blackheart/bounty/gate.py`, Gates A–D,
  six dispositions mapped to the four payment determinations `PAYABLE` /
  `POTENTIALLY PAYABLE` / `NOT PAYABLE` / `UNRESOLVED`); the gate never reads
  `research_score`, and no candidate needs a minimum score to be submitted.
  Acceptance bars: `tests/test_bounty.py`, `tests/test_bounty_gate.py`.
  See `docs/BOUNTY.md`.
- **Hourly bounty watchtower** lives in `blackheart/watch/` and is driven by
  `blackheart watch`. It keeps 43 independent target records (policy URLs,
  repositories, contracts, eligibility, restrictions, known issues) and detects
  official-policy, repository and deployed-contract changes read-only. Every
  participation gate defaults to false; a security-relevant change on a gated
  target is `POLICY BLOCKED`, never actionable. It handles ETag/304, canonical
  repository names, empty repositories, counter/timestamp noise and numeric-only
  policy diffs, and it never treats a commit as a deployment. When a deployment
  actually moves, `blackheart/watch/source.py` fetches the old and new verified
  source from Sourcify (free, no key) and attaches a bounded per-file diff with
  the changed function names; an unchanged address is never re-fetched. A
  100-point score needs 80 for active investigation. The primary scheduler is
  `.github/workflows/bounty-watch.yml` (cron `7 * * * *`, cached state,
  deduplicated rolling issues, total-outage-only failure); the OpenHands wrapper
  is in `automations/bounty-watch/`. Acceptance bar: `tests/test_watch.py`.
  See `docs/BOUNTY_WATCH.md`.
- **Adversary emulation** lives in `blackheart/adversary/` and is driven by
  `blackheart adversary {profiles,plan}`. It is the layer that turns "what is
  reachable" into "what would this actor actually run": a campaign is planned
  objective-first from a profile's **capability, capital, patience and objective**,
  never from a name. Stages are `recon → position → accumulate → trigger →
  extract → persist`; each names the engine that runs it and the evidence it must
  produce, and the stages that are *absent* are reported with their reason (a
  one-transaction actor has no `trigger` and no `persist`). Two rules hold: a
  capability no local engine may exercise (validator control, supply chain,
  insider access, social engineering) is `MODEL_ONLY` and never executable, and a
  stage is `executable` only when the asset passes the same authorization gate
  every engine uses — so thinking is free and execution is gated. Acceptance bar:
  `tests/test_adversary.py`. See `docs/ADVERSARY.md`.
- **Self-evaluation** is `docs/SELF_EVALUATION.md`: the measured recall of the
  27-pair differential corpus at stated budgets (9/27 at 1×2, 23/27 at 12×8, 26/27
  at 60×14, 27/27 at the default budget; 26/27 certifier-only at depth 4, 27/27 at
  depth 6; the corpus is now 28 pairs after `H29-allowance-reuse`, and that case is
  not folded into the old figures), the gap analysis against Slither / Echidna /
  Medusa / Halmos / CodeQL / Semgrep, and the ranked gap list with an acceptance
  bar per gap. The
  differential now **escalates to the bounded-exhaustive certifier** when random
  search finds nothing (`--depth`, default 6) and accepts the escalation only when
  the same exhaustive bound leaves the guarded twin clean —
  `tests/test_differential_escalation.py`. Re-measure, do not re-assert: a
  stochastic negative is "not found within budget", never "clean".
- **External engines** live in `blackheart/engines/` behind a pinned manifest
  (`blackheart/engines/toolchain.json`): Slither, Wake, Halmos, Echidna, Medusa plus
  the Foundry/solc toolchain. `blackheart engines bootstrap` installs them,
  `engines doctor` verifies every pin (exit 1 on a gap), and `engines run` executes
  them only under a compatibility record bound to the target. Verified live:
  Slither produced 23 findings on `harnesses/dvdf`; Echidna produced the exact
  counterexample `inc(10)` on a property harness; Halmos builds but fails on
  forge-std v1.17's `deployCode` cheatcode and is recorded as failed, never clean.
  A relative run workspace used to lose the report and report `FAILED` — fixed in
  `EngineAdapter.__init__`, acceptance bar `tests/test_engine_workspace.py`.
  See `docs/ARSENAL.md`.
- **Project memory**: `.openhands/memory/MEMORY.md` (agent-written; may be stale —
  verify before trusting).

## Research-depth additions (keep these wired, not decorative)

- **Compiler-accurate ABI model** (`blackheart/solidity/abi.py`) and fail-closed
  project compilation (`blackheart/ingest/compile.py`). `ingest --compile` requires
  a `--compatibility RECORD`; no record exits 2, a missing tool is `BLOCKED`, never
  a silent empty model. Acceptance bars: `tests/test_solidity_abi.py`,
  `tests/test_ingest_compile.py`.
- **Verified-source attestation** (`blackheart/verified_source.py`, Sourcify v2)
  and **cached deployment reads** (`blackheart/deployment_fetch.py`). The cache is
  keyed by `(chain, address, block)`, an unchanged address is never re-fetched, and
  an unreachable RPC is `RPC_UNAVAILABLE`, never a clean read. Read-only; no
  transaction path exists. Acceptance bars: `tests/test_verified_source.py`,
  `tests/test_deployment_fetch.py`.
- **Grounded hypothesis proposer** (`blackheart/hypothesis/llm.py`). A provider may
  propose, but a proposal is dropped unless every required field is present and its
  component/asset appears in the threat model; no provider is `NO_PROVIDER`, never
  an empty success. It is a lead, not a finding. Acceptance bar:
  `tests/test_hypothesis_llm.py`.
- **Source-level symbolic reachability** (`blackheart/symbolic/executor.py`,
  `ingest --synthesize --symbolic`). It converts the same `OpModel` the
  synthesiser builds into symbolic operations, models mapping reads and writes
  with concrete keys (`balances[msg.sender]` becomes `balances[attacker]`), keeps
  numeric parameters symbolic and enumerates a finite address-like domain, and
  walks breadth-first for the shortest verified witness per operation. A
  conditional effect is split into true/false paths at the point it occurs (with
  a 256-branch cap per operation), so a branch-gated write is explored rather
  than refused. A symbolic mapping key is `unsupported`, never half-applied; a
  path budget that runs out is `exhausted: false`, not a clean result. Acceptance
  bar: `tests/test_symbolic.py`, `tests/test_synthesize.py`.
- **Bounded symbolic execution** (`blackheart/symbolic/`). It reasons over the same
  declarative `OpModel` the ingest synthesiser builds — not EVM bytecode; Halmos
  remains the bytecode engine. The solver is three-valued: `SAT` only with a
  verified witness, `UNSAT` only when interval propagation empties a domain,
  `UNKNOWN` otherwise. Acceptance bar: `tests/test_symbolic.py`.
- **Turn-level plans** (`blackheart/exploit/synthesis.py`). A witness becomes
  actor-grouped turns with before/after state, changes, value deltas, and the
  universal value ledger; a reverted step is recorded, never dropped. Acceptance
  bar: `tests/test_exploit_synthesis.py`.
- **Vyper ingestion** (`blackheart/ingest/vyper.py`, `ingest --language vyper`). A
  third environment: decorator-aware function/state recovery and category-linked
  leads (missing `@nonreentrant`, raw call, unguarded privileged write, payable
  without a guard, ownerless init). `detect_language` reports a mixed tree as
  `unknown`, never a guess. Acceptance bar: `tests/test_ingest_vyper.py`.
- **Declared parameter domains are honoured, not collapsed**
  (`discovery/search.py::_param_values`, `statespace/adaptive.py::_boundary_values`).
  Reducing a domain to `{min, max, 1, 2}` stepped over numeric windows the author
  declared. The declared values are kept first, bounded to the same cap, so
  branching does not grow. The corpus carries the class as a holdout:
  `H28-liquidation-window` (`tests/test_corpus_window.py`).
- **EVM opcode coverage** now includes EIP-1153 `TLOAD`/`TSTORE` (transient storage
  cleared per transaction, absent from persistent snapshots), EIP-4844 `BLOBHASH`
  and EIP-7516 `BLOBBASEFEE` (`blackheart/evmworld.py`; acceptance bar
  `tests/test_evmworld_opcodes.py`).
- **Bounded symbolic EVM** (`blackheart/symbolic/evm.py`). It walks real runtime
  bytecode, forks on a symbolic `JUMPI`, and asks the solver for a witness. It
  models unbounded integers (not 256-bit wrapping) and halts at any opcode it
  cannot model, reporting `unsupported` rather than treating the path as safe.
  `find_witness(..., reverted=True, extra=...)` answers "is there an input that
  reaches this state?", and the witness reproduces on `evmworld`. Acceptance bar:
  `tests/test_symbolic_evm.py`.
- **SMT backend seam** (`blackheart/symbolic/solver.py`). `solve(..., backend=...)`
  accepts an external solver. Its `SAT` is re-evaluated against every constraint
  and the declared domain before it is believed; its `UNSAT` is ignored unless
  `trust_backend_unsat=True`, preserving "UNSAT only with a proof". Acceptance bar:
  `tests/test_solver_backend.py`.
- **Verified-source to certified model** (`blackheart/ingest/verified.py`).
  `build_verified_model(chain_id, address)` attests the deployment, scans the
  verified Solidity, synthesises the model, and certifies it. The attestation is
  bound by the bundle fingerprint. Statuses are `NOT_VERIFIED`, `UNMODELLED`,
  `BLOCKED`, `ERROR`, `CERTIFIED`, `NO_VIOLATION`; a negative names its bound.
  Acceptance bar: `tests/test_verified_pipeline.py`.
- **Vyper semantic model** (`blackheart/ingest/vyper_synth.py`). Translates a Vyper
  module into the same `ContractSurface` the Solidity interpreter consumes
  (`self.x` -> `x`, `assert c` -> `require(c)`), then reuses `synthesize` and the
  certifier. An unreadable construct stays in the body and marks the operation
  unmodelled. Acceptance bar: `tests/test_vyper_synth.py`.
- **Transfer provenance** (`blackheart/learning/transfer.py`). Every `MemoryEntry`
  records the assumptions its certificate relied on (`required_ops`, `min_actors`).
  `seeds_for` refuses an entry whose assumptions the new target cannot satisfy, and
  `transfer_decisions` explains each accept/refusal. Acceptance bar:
  `tests/test_transfer_provenance.py`.
- **Bytecode differential fuzzing** (`blackheart/evm_fuzz.py`). Deploys a
  vulnerable and a guarded runtime code into `evmworld`, runs the same calldata
  against both, and reports `outcome`/`state`/`return` divergences. A divergence is
  a lead; the guarded side is the control. Acceptance bar: `tests/test_evm_fuzz.py`.
- **Corpus growth**: `H29-allowance-reuse` is a holdout ERC-20 allowance model with
  a priced attacker profit and victim loss. Acceptance bar:
  `tests/test_corpus_allowance.py`.

- **The closure surface** (`blackheart closure`) is the additive layer around
  `blackheart pipeline`: `ingest/solc.py` compiles verified source and binds it
  to the deployed runtime after metadata stripping; `pocgen.py` renders and runs
  a source-level Foundry test; `ingest/protocol.py` composes several contracts
  with **explicit** links; `control.py` fetches a pinned patched commit and
  replays the witness against it; `bytecode.py` proves a symbolic witness on the
  concrete EVM; `assurance/mutation.py` asks whether the invariant set would
  catch a mutation; `value/market.py` prices an ordering attack net of gas and
  bribe; `planning.py` filters objectives through the program's own policy;
  `parallel.py` and `corpus.py` provide bounded parallel work and a durable,
  deduplicated corpus; `distributed.py` adds epoch-fenced worker leases and stale
  recovery on a shared volume; `reviewer.py` uses a verified distinct reviewer
  directly, and the optional `ollama` provider can supply one locally without a
  cloud key. `ingest/callgraph.py` infers cross-contract edges only when the
  receiver resolves uniquely; `ingest/deploy.py` plans constructor args, helpers
  and a minimal proxy and blocks on a missing argument; `ingest/equivalence.py`
  adds ABI-selector evidence to a runtime match; `ingest/truth.py` joins chain
  facts, proxy and verified source, and recompiles the source against the deployed
  runtime by default; `FindingRecord` refuses `CONFIRMED` for an address target
  without a runtime-bound truth record, and `bounty gate` refuses a
  `deployment_verified` claim without one; `value/live.py` fetches Uniswap-V2 reserves
  read-only; `value/live_v3.py` reconstructs a bounded live V3 tick-bitmap
  snapshot, searches attacker sizes, and prices gas/bribe/inclusion plus
  failed-transaction, capital and competitor costs while marking an unconvertible
  gas cost `unpriced`; `value/orderflow.py` prices a declared multi-competitor
  bid ladder, the fraction outbid, expected value and the optimal threshold bid
  (`closure market --model orderflow`, acceptance bar `tests/test_orderflow.py`);
  `value/live_v3_fork.py` executes the
  selected candidate on a pinned fork and reports `PASS`, `DIVERGED`, `FAIL`,
  `BLOCKED` or `INCOMPLETE`, never upgrading a model to a finding.
  Source-level PoCs accept supplied constructor args, helper
  deployments, a minimal proxy, a deployed-address fork target and four invariant
  forms. `tests/test_fork_scenario.py` is the acceptance bar for the declarative
  multi-call scenario renderer. Every capability is `partial` except the Foundry backend, bounded
  parallel/corpus, the lease queue, the local reviewer and bytecode witness
  replay, and each limitation is named in `blackheart capability` and
  `docs/CLOSURE.md`. Do not upgrade a `RECOMPILE_FAILED`, `INCOMPLETE`,
  `CONTROL_ALSO_VULNERABLE`, `SURVIVED` or `UNAVAILABLE` result into a finding.

## The ranked upgrades (`blackheart improve`)

`blackheart/improve/` is the executable form of the ranked capability list. It
adds no new search engine: each entry composes a tested module and states its
remaining limit. `blackheart improve status [--json]` lists all ten;
`docs/IMPROVEMENTS.md` documents them and `tests/test_improve.py` is the
acceptance bar. The compiler path also fixed a real defect: `forge build --json`
returns an empty contracts map on a warm cache, so the one-shot compile now forces
a rebuild and `parse_forge_artifacts` walks the nested Foundry shape instead of
silently reporting zero artifacts.

## Copied from ARTEX (operational depth)

These were adapted from the ARTEX autonomous-pentest platform. Each is a small,
stdlib-only module with its own acceptance bar; none adds a search engine.

- **`blackheart retest`** (`blackheart/retest.py`) — re-runs a finding's own
  reproduction command and records `still-reproducible` / `fixed` /
  `cannot-confirm` on the finding's `retest_result` (section I). A fix never
  rewrites the finding's verdict. Exit 0/1/2 = fixed / still-reproducible /
  cannot-confirm. Acceptance bar: `tests/test_retest.py`.
- **`blackheart graph`** (`blackheart/graph.py`) — the dual research graph: an
  *asset graph* (root_domain → subdomain → service → endpoint → contract →
  component, deduplicated) and an *exploration graph* (goal → intent → fact →
  finding → hint, with `spawns/derived_from/yields/proves` edges), joined by
  anchors. `graph coverage` reports tested/untested assets (the coverage
  denominator); `graph lineage N` walks a finding back to its goal. SQLite,
  autocommit. Acceptance bar: `tests/test_graph.py`.
- **`Budget`** (`blackheart/budget.py`) — token/turn caps with a wrap-up reserve;
  `can_start` refuses work the remaining budget cannot cover. Acceptance bar:
  `tests/test_budget.py`.
- **`NoiseGovernor`** (`blackheart/noise.py`) — per-host rate/burst/in-flight/
  jitter/backoff (429/503) pacing; the enforcement of the "no DoS" rule. Clock
  and sleep are injectable. Acceptance bar: `tests/test_noise.py`.
- **`frame_untrusted`** (`blackheart/untrusted.py`) — nonce-tagged framing of
  tool output as data, not instructions; the prompt-injection boundary for any
  tool result. Acceptance bar: `tests/test_untrusted.py`.

Copying is not attestation: each module keeps its own limits (the retester runs
the operator's command, the graph asserts no vulnerability, the governor paces
only the requests routed through it).

**Where they are wired** (so they are not decorative):

- **Budget** -> `ModelRouter.complete` / `complete_with` (the reviewer and
  `blackheart models` paths): a call is refused once the budget is inside its
  wrap-up reserve, and each real call charges its tokens and one turn. Configure
  with `--budget-tokens/--budget-turns` on `models` and `closure review`, or
  `BLACKHEART_BUDGET_TOKENS` / `BLACKHEART_BUDGET_TURNS` for every router.
  `blackheart.hypothesis.llm.propose` charges the same budget.
- **Untrusted framing** -> `hypothesis.llm.build_prompt` frames the source
  excerpts as a nonce-tagged untrusted block, and `reviewer.independent_review`
  frames the review material (with a data-not-instructions system note).
- **Noise governor** -> `statespace.runtime.http_adapter.HttpExecutionAdapter`
  paces every live request through `acquire(host)`; `build_http_target` enables
  it when `BLACKHEART_NOISE_PROFILE` is set (`quiet` / `balanced` / `aggressive`).

Acceptance bar: `tests/test_research_wiring.py`.

## When you add anything

- New attack classes, objectives, and hypotheses **must answer the question**: an
  attack that assumes privilege, or yields none of the three outcomes, is not one
  of ours.
- New skills and agents inherit the persona through the shared prompt block; do
  not re-declare it.
- Keep the persona, the question, and the doctrine in `blackheart/mindset.py` and
  `blackheart/doctrine.py` only. If you change them there, update
  `skills/attacker-mindset/SKILL.md`, `skills/operational-doctrine/SKILL.md`,
  `docs/DOCTRINE.md`, and this file so the layers never drift.
- Keep the language-aware policy in `blackheart/doctrine.py`
  (`LANGUAGE_AWARE_POLICY`) and `docs/SECURITY_TOOL_COMPATIBILITY.md` together, and
  keep the tool registry in `blackheart/toolchain/`. A new language is added to the
  registry **with** official documentation and a verification date, never assumed;
  `tests/test_tool_compatibility.py` fails if the three drift.
- Every meaningful investigation ends with a `blackheart findings` record; a
  confirmed vulnerability must carry evidence and an independent verification.
- Every submission decision goes through `blackheart bounty gate`. Do not add a
  numeric acceptance threshold anywhere — not to a report, a register, a script or
  a prompt. Eligibility comes from the program's official policy, and a candidate
  record without a verified policy snapshot is `F_NOT_ASSESSED`, never "probably
  fine". `tests/test_bounty_gate.py` fails if the gate starts reading a score.
