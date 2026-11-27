"""Language-aware tool compatibility gate.

The doctrine (`blackheart.doctrine.LANGUAGE_AWARE_POLICY`) makes four things
mandatory before a security engine runs: identify the stack, verify the tool's
documented compatibility with *that* stack, record the pre-execution gate, and
smoke-test it. This module is where those rules are enforced rather than
described:

* :data:`TOOLCHAINS` -- the verified registry: per language, the supported
  versions, frameworks, runtime, native tools with their official documentation,
  native testing approaches, and known incompatibilities.
* :class:`CompatibilityRecord` -- the record a mission must fill in before a tool
  runs. Its required fields are read from
  `blackheart.doctrine.COMPATIBILITY_GATE_FIELDS`, so the policy and the gate
  cannot disagree about what "documented" means.
* :func:`admit` -- the gate. It refuses a record that is incomplete, that names a
  language with no verified toolchain, that names a tool not verified for that
  language, that cites evidence that is not official documentation, or that has
  not passed its smoke test.
* :class:`CompletionReport` -- the policy's final acceptance criteria (section H),
  so "complete" is a checked claim, not an assertion.

The gate never runs a tool and never fabricates a result: it decides whether a
tool may be used and records why. Execution statuses (PASS / BLOCKED / INCOMPLETE
/ NO_FINDINGS) are the policy's, read from `blackheart.doctrine.EXECUTION_STATUSES`
and kept distinct from this gate's ADMIT / BLOCK decision, because "the tool was
allowed to run" is not "the analysis passed".
"""

from __future__ import annotations

import re
from dataclasses import dataclass, fields
from typing import Optional

from ..doctrine import (
    COMPATIBILITY_GATE_FIELDS,
    COMPLETION_ACCEPTANCE,
    EXECUTION_STATUSES,
    NATIVE_TESTING_METHODS,
)

#: The date the official documentation URLs below were checked (HTTP 200).
REGISTRY_VERIFIED_AT = "2026-11-20"


# --------------------------------------------------------------------------- #
# The verified registry
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class NativeTool:
    """One verified native tool: what it is for, and its official documentation."""

    name: str
    official_docs: str
    classes: tuple[str, ...]

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "official_docs": self.official_docs,
            "classes": list(self.classes),
        }


@dataclass(frozen=True)
class LanguageToolchain:
    """A language and the native tooling verified against it."""

    language: str
    versions: str
    frameworks: tuple[str, ...]
    runtime: str
    tools: tuple[NativeTool, ...]
    native_approaches: tuple[str, ...]
    known_incompatibilities: tuple[str, ...]
    verified_at: str = REGISTRY_VERIFIED_AT

    def tool(self, name: str) -> Optional[NativeTool]:
        """The registered tool matching ``name`` (case-insensitive), else ``None``."""
        wanted = name.strip().casefold()
        for tool in self.tools:
            if tool.name.casefold() == wanted:
                return tool
        return None

    def to_dict(self) -> dict:
        return {
            "language": self.language,
            "versions": self.versions,
            "frameworks": list(self.frameworks),
            "runtime": self.runtime,
            "tools": [t.to_dict() for t in self.tools],
            "native_approaches": list(self.native_approaches),
            "known_incompatibilities": list(self.known_incompatibilities),
            "verified_at": self.verified_at,
        }


#: The registry. Keys are the same canonical language names as
#: `blackheart.doctrine.NATIVE_TESTING_METHODS`, so a detected stack resolves here
#: without an alias table that could drift. Every entry lists only tools whose
#: official documentation was checked on :data:`REGISTRY_VERIFIED_AT`; an
#: unregistered language is a BLOCKED tool, not a guess.
TOOLCHAINS: tuple[LanguageToolchain, ...] = (
    LanguageToolchain(
        language="Solidity",
        versions="0.4.x-0.8.x via solc-select; Foundry uses the solc pinned by the project",
        frameworks=("Foundry (forge/cast/anvil)", "Hardhat", "Truffle"),
        runtime="EVM (local anvil or an authorized fork)",
        tools=(
            NativeTool("Foundry", "https://book.getfoundry.sh/",
                       ("business logic", "access control", "invariant violation",
                        "reentrancy", "arithmetic", "oracle manipulation")),
            NativeTool("Slither", "https://github.com/crytic/slither",
                       ("static analysis", "reentrancy", "access control",
                        "dangerous constructs")),
            NativeTool("Echidna", "https://github.com/crytic/echidna",
                       ("property-based fuzzing", "invariant violation",
                        "stateful sequences")),
            NativeTool("Medusa", "https://github.com/crytic/medusa",
                       ("stateful fuzzing", "invariant violation", "coverage")),
            NativeTool("Halmos", "https://github.com/a16z/halmos",
                       ("symbolic execution", "assertion violation",
                        "bounded input space")),
        ),
        native_approaches=(
            "forge test / forge script (local only, never --broadcast)",
            "invariant and stateful fuzz campaigns on a dedicated harness",
            "symbolic execution of a single assertion",
            "static analysis before dynamic testing",
        ),
        known_incompatibilities=(
            "Slither needs a solc the toolchain can install and a compilable build; "
            "it cannot analyse a project whose compiler version is unavailable",
            "Halmos requires a Foundry project and a symbolic-friendly harness",
            "Echidna and Medusa need their own harness contract; pointing them at a "
            "production entrypoint is not a test",
            "a fork test is only as faithful as the block it pins; record the block",
        ),
    ),
    LanguageToolchain(
        language="Vyper",
        versions="0.3.x-0.4.x via the compiler the project pins (Foundry builds .vy with it)",
        frameworks=("Foundry (Vyper sources)", "Ape", "Titanoboa", "Brownie"),
        runtime="EVM (local anvil or Titanoboa's in-process EVM; never a broadcast)",
        tools=(
            NativeTool("vyper", "https://docs.vyperlang.org/",
                       ("compiler", "arithmetic", "access control", "reentrancy",
                        "storage layout")),
            NativeTool("Foundry", "https://book.getfoundry.sh/",
                       ("build", "local test harness", "invariant violation",
                        "reentrancy", "arithmetic")),
            NativeTool("Slither", "https://github.com/crytic/slither",
                       ("static analysis", "reentrancy", "access control",
                        "dangerous constructs")),
            NativeTool("Titanoboa", "https://github.com/vyperlang/titanoboa",
                       ("in-process EVM harness", "unit tests", "trace debugging",
                        "stateful sequences")),
            NativeTool("Hypothesis", "https://hypothesis.readthedocs.io/",
                       ("property-based fuzzing", "invariant violation",
                        "stateful sequences")),
        ),
        native_approaches=(
            "boa + pytest harness against the local EVM (never a broadcast)",
            "Hypothesis property campaigns driven through Titanoboa",
            "forge build with the project's pinned vyper, then forge test locally",
            "static analysis before dynamic testing",
        ),
        known_incompatibilities=(
            "Echidna, Medusa and Halmos do not analyse Vyper; use Titanoboa and "
            "Hypothesis instead of substituting an EVM tool that ignores the source",
            "Foundry compiles Vyper only when the pinned compiler is installed and "
            "the build is configured for it; record the vyper version",
            "Vyper `flag` members are 1-based (the first member is 1), unlike a "
            "Solidity enum; an empty flag is 0 and is a distinct value",
            "a fork test is only as faithful as the block it pins; record the block",
        ),
        verified_at="2026-11-21",
    ),
    LanguageToolchain(
        language="Rust/Substrate",
        versions="stable Rust for host tests; the runtime's pinned nightly for WASM builds",
        frameworks=("Substrate FRAME", "ink!", "Solana programs (cargo-build-sbf)"),
        runtime="native host tests + wasm32-unknown-unknown runtime",
        tools=(
            NativeTool("Cargo", "https://doc.rust-lang.org/cargo/commands/cargo-test.html",
                       ("unit tests", "integration tests", "doc tests")),
            NativeTool("proptest", "https://docs.rs/proptest/latest/proptest/",
                       ("property-based testing", "input-space exploration")),
            NativeTool("cargo-fuzz", "https://rust-fuzz.github.io/book/cargo-fuzz.html",
                       ("coverage-guided fuzzing", "parser and codec bugs",
                        "panic reachability")),
        ),
        native_approaches=(
            "cargo test on the pallet/runtime crate under test",
            "FRAME mock runtime integration tests for extrinsics and origins",
            "proptest strategies over the SCALE codec and arithmetic",
            "cargo-fuzz targets for decoding and dispatch",
        ),
        known_incompatibilities=(
            "cargo-fuzz needs nightly and a libFuzzer-compatible toolchain",
            "FRAME unit tests do not exercise the compiled WASM runtime; build and "
            "benchmark the runtime separately",
            "a property test that restates the implementation's own arithmetic "
            "proves nothing (use an independent oracle)",
        ),
    ),
    LanguageToolchain(
        language="Python",
        versions="3.11+ (this repository's floor)",
        frameworks=("pytest", "Django", "Flask", "FastAPI"),
        runtime="CPython",
        tools=(
            NativeTool("pytest", "https://docs.pytest.org/en/stable/",
                       ("unit tests", "integration tests", "regression tests")),
            NativeTool("Hypothesis", "https://hypothesis.readthedocs.io/en/latest/",
                       ("property-based testing", "boundary conditions",
                        "stateful testing")),
            NativeTool("Bandit", "https://bandit.readthedocs.io/en/latest/",
                       ("static analysis", "injection", "credential handling",
                        "unsafe deserialization")),
        ),
        native_approaches=(
            "pytest for deterministic reproductions",
            "Hypothesis state machines for ordered, stateful protocols",
            "Bandit as a first pass, never as proof of absence",
        ),
        known_incompatibilities=(
            "Bandit is pattern-based: it cannot see a flaw that spans functions or "
            "depends on runtime configuration",
            "a passing test suite says nothing about a code path no test reaches",
        ),
    ),
    LanguageToolchain(
        language="Go",
        versions="1.18+ for native fuzzing; the target module's go directive otherwise",
        frameworks=("net/http", "gRPC", "Cosmos SDK", "go-ethereum"),
        runtime="Go runtime",
        tools=(
            NativeTool("go test", "https://pkg.go.dev/testing",
                       ("unit tests", "integration tests", "race detection")),
            NativeTool("native fuzzing", "https://go.dev/doc/security/fuzz/",
                       ("coverage-guided fuzzing", "parser bugs", "panics")),
            NativeTool("govulncheck", "https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck",
                       ("dependency vulnerabilities", "reachable-vulnerability analysis")),
        ),
        native_approaches=(
            "go test -race for concurrency findings",
            "go test -fuzz with a seed corpus for decoders and validators",
            "govulncheck to separate a present module from a reachable call",
        ),
        known_incompatibilities=(
            "native fuzzing requires Go 1.18 or newer",
            "govulncheck reports reachability from its own call graph; a 'not "
            "reachable' answer is bounded by that analysis, not proof",
        ),
    ),
    LanguageToolchain(
        language="C/C++",
        versions="any clang/gcc with sanitizer support; clang for libFuzzer",
        frameworks=("CMake", "Autotools", "Make"),
        runtime="native process",
        tools=(
            NativeTool("compiler sanitizers",
                       "https://clang.llvm.org/docs/AddressSanitizer.html",
                       ("memory safety", "undefined behaviour", "use-after-free",
                        "buffer overflow")),
            NativeTool("libFuzzer", "https://llvm.org/docs/LibFuzzer.html",
                       ("coverage-guided fuzzing", "parser bugs", "memory safety")),
            NativeTool("AFL++", "https://github.com/AFLplusplus/AFLplusplus",
                       ("coverage-guided fuzzing", "binary-only targets",
                        "long-running campaigns")),
        ),
        native_approaches=(
            "an instrumented build (-fsanitize=address,undefined) of the component",
            "libFuzzer or AFL++ targets around the parser/decoder entrypoint",
            "differential testing against a reference implementation",
        ),
        known_incompatibilities=(
            "sanitizers require rebuilding the target with instrumentation; an "
            "uninstrumented binary proves nothing",
            "AddressSanitizer and MemorySanitizer are mutually exclusive",
            "fuzzing an entrypoint that is not the production one tests the harness",
        ),
    ),
    LanguageToolchain(
        language="Move",
        versions="Move 2024 (Aptos) and Sui Move -- the two frameworks differ",
        frameworks=("Aptos Framework", "Sui Framework"),
        runtime="Move VM",
        tools=(
            NativeTool("native Move testing", "https://aptos.dev/build/smart-contracts/",
                       ("unit tests", "access control", "resource safety")),
            NativeTool("Sui Move testing", "https://docs.sui.io/",
                       ("unit tests", "object model", "access control")),
            NativeTool("Move Prover",
                       "https://github.com/move-language/move/tree/main/language/move-prover",
                       ("formal verification", "abort conditions", "invariants")),
        ),
        native_approaches=(
            "`aptos move test` / `sui move test` on the module under test",
            "Move Prover specifications for value-conservation properties",
            "framework-specific test harnesses; Aptos and Sui code are not portable",
        ),
        known_incompatibilities=(
            "Aptos and Sui Move are separate dialects with separate toolchains; a "
            "test written for one does not compile for the other",
            "Move Prover covers specified properties only; an unspecified invariant "
            "is unproven, not safe",
        ),
    ),
    LanguageToolchain(
        language="Cairo",
        versions="Cairo 1/2 with the Scarb version the project pins",
        frameworks=("Scarb", "Starknet Foundry (snforge/sncast)", "Starknet contracts"),
        runtime="Cairo VM / Starknet",
        tools=(
            NativeTool("Cairo testing", "https://docs.swmansion.com/scarb/",
                       ("unit tests", "integration tests", "compilation")),
            NativeTool("Starknet Foundry", "https://foundry-rs.github.io/starknet-foundry/",
                       ("contract tests", "cheatcodes", "fork testing")),
        ),
        native_approaches=(
            "scarb build/test for the package under test",
            "snforge tests with cheatcodes for caller and block context",
            "fork tests against an authorized network snapshot",
        ),
        known_incompatibilities=(
            "Scarb and snforge versions are coupled to the Cairo compiler version; "
            "a mismatch fails to compile rather than silently mis-analysing",
            "Cairo 0 and Cairo 1 syntax are incompatible",
        ),
    ),
    LanguageToolchain(
        language="JavaScript/TypeScript",
        versions="Node 18+ (native test runner); the project's pinned Node otherwise",
        frameworks=("Node.js", "React", "Next.js", "Express", "Hardhat (JS)"),
        runtime="Node.js / browser",
        tools=(
            NativeTool("native test frameworks", "https://nodejs.org/api/test.html",
                       ("unit tests", "integration tests", "API behaviour")),
            NativeTool("Vitest", "https://vitest.dev/",
                       ("unit tests", "mocking", "coverage")),
            NativeTool("fast-check", "https://fast-check.dev/",
                       ("property-based testing", "boundary conditions",
                        "stateful model testing")),
            NativeTool("Semgrep", "https://semgrep.dev/docs/",
                       ("static analysis", "injection", "insecure defaults")),
        ),
        native_approaches=(
            "the project's own runner (node:test / vitest / jest) for reproductions",
            "fast-check model-based testing for state machines",
            "Semgrep with the TypeScript/JavaScript rulesets as a first pass",
        ),
        known_incompatibilities=(
            "a TypeScript analyser sees the types, not the runtime value a caller "
            "can actually send",
            "Node and browser runtimes differ; test the one the product ships",
        ),
    ),
)

TOOLCHAIN_BY_LANGUAGE: dict[str, LanguageToolchain] = {
    t.language: t for t in TOOLCHAINS
}


def resolve_language(name: str) -> Optional[LanguageToolchain]:
    """Resolve a language name to its verified toolchain, or ``None``.

    Accepts the canonical name (``Rust/Substrate``) case-insensitively and each
    component of a compound name (``Rust``, ``Substrate``, ``C++``, ``TypeScript``).
    """
    wanted = name.strip().casefold()
    if not wanted:
        return None
    for canonical, chain in TOOLCHAIN_BY_LANGUAGE.items():
        if canonical.casefold() == wanted:
            return chain
        parts = [p.strip().casefold() for p in canonical.split("/")]
        if wanted in parts:
            return chain
    return None


def registry(language: str = "") -> dict:
    """The registry, optionally narrowed to one language (for the CLI and docs)."""
    if language:
        chain = resolve_language(language)
        if chain is None:
            return {"languages": [], "unknown": language}
        return {"languages": [chain.to_dict()], "verified_at": REGISTRY_VERIFIED_AT}
    return {"languages": [t.to_dict() for t in TOOLCHAINS],
            "verified_at": REGISTRY_VERIFIED_AT}


# --------------------------------------------------------------------------- #
# The pre-execution compatibility gate (policy section E)
# --------------------------------------------------------------------------- #

#: Maps each policy gate field to the record fields that satisfy it. The keys are
#: `blackheart.doctrine.COMPATIBILITY_GATE_FIELDS` verbatim; a test asserts the two
#: never drift, so a new policy field cannot be silently unenforced.
GATE_FIELD_MAP: dict[str, tuple[str, ...]] = {
    "target component": ("target_component",),
    "identified language and version": ("language", "language_version"),
    "framework and runtime": ("framework", "runtime"),
    "selected tool": ("tool",),
    "official compatibility evidence": ("compatibility_evidence",),
    "reason for tool selection": ("selection_reason",),
    "expected test coverage": ("expected_coverage",),
    "known limitations": ("known_limitations",),
}

_URL_RE = re.compile(r"^https?://\S+$")
_REGISTRY_REF_PREFIX = "registry:"

#: Framework and runtime names that belong to exactly one registered language.
#: A record pairing a language with *another* language's toolchain is a
#: compatibility error the registry can prove, so the gate rejects it rather than
#: leaving it to the researcher's judgement. Only distinctive names are listed:
#: a token that is also ordinary prose would cause false blocks.
FOREIGN_TOKENS: dict[str, tuple[str, ...]] = {
    "Solidity": ("Foundry", "forge", "anvil", "Hardhat", "Truffle"),
    # Foundry builds Vyper sources as well as Solidity ones, so the two languages
    # share it; naming it in a Vyper record is not a mixed-stack claim.
    "Vyper": ("Foundry", "vyper"),
    "Rust/Substrate": ("FRAME", "ink!", "Substrate", "cargo-build-sbf"),
    "Python": ("Django", "Flask", "FastAPI", "CPython"),
    "Go": ("Cosmos SDK", "go-ethereum", "golang"),
    "C/C++": ("CMake", "Autotools"),
    "Move": ("Aptos Framework", "Sui Framework", "Move VM"),
    "Cairo": ("Scarb", "Starknet Foundry", "snforge", "sncast", "Cairo VM"),
    "JavaScript/TypeScript": ("React", "Next.js", "Express", "Node.js"),
}


def cross_language_mismatch(record: "CompatibilityRecord",
                            chain: Optional["LanguageToolchain"] = None) -> tuple[str, ...]:
    """Framework/runtime names in the record that belong to another language.

    ``Solidity`` + ``FRAME`` is not a judgement call: ``FRAME`` is the Substrate
    framework, so the record describes two different stacks. Reported as blockers
    by :func:`admit`.
    """
    if chain is None:
        chain = resolve_language(record.language)
    if chain is None:
        return ()
    own = tuple(tok.casefold() for tok in FOREIGN_TOKENS.get(chain.language, ()))
    text = f"{record.framework} {record.runtime}"
    reasons: list[str] = []
    for language, tokens in FOREIGN_TOKENS.items():
        if language == chain.language:
            continue
        for token in tokens:
            # "Starknet Foundry" is Cairo's own harness, not Solidity's: a token
            # that is part of a phrase this language owns is not foreign.
            if any(token.casefold() in phrase for phrase in own):
                continue
            if re.search(rf"(?<![\w.]){re.escape(token)}(?![\w])", text, re.IGNORECASE):
                reasons.append(
                    f"framework/runtime names '{token}', which is a {language} tool, "
                    f"not a {chain.language} one; a record describes one stack"
                )
    return tuple(reasons)


@dataclass(frozen=True)
class CompatibilityRecord:
    """What a mission documents before running a security tool (policy section E)."""

    target_component: str = ""
    language: str = ""
    language_version: str = ""
    framework: str = ""
    runtime: str = ""
    tool: str = ""
    compatibility_evidence: str = ""
    selection_reason: str = ""
    expected_coverage: str = ""
    known_limitations: str = ""
    smoke_test: str = "not-run"       # "passed" | "failed" | "not-run"
    #: Identity binding, enforced by :func:`blackheart.toolchain.enforce.bind`:
    #: the record must name the target it was verified against, and the
    #: repository and commit when the execution declares them.
    repository: str = ""
    commit: str = ""
    #: The guarded twin this record also authorises for a differential check
    #: (``hunt --control``, the verifier's discriminating control). A record
    #: authorises one *comparison*, never an open set: ``target_component`` names
    #: the target under test and this names the control it is compared against.
    #: Empty means "no control authorised", so a differential check still fails
    #: closed rather than inheriting the primary's authority.
    control_component: str = ""

    @classmethod
    def from_dict(cls, data: dict) -> "CompatibilityRecord":
        known = {f.name for f in fields(cls)}
        # Keys beginning with `_` are commentary: `compat template` emits
        # `_policy` and `_statuses` to explain the record, and a file written
        # from that template must still load. Every other unknown key is a
        # typo and fails closed.
        unknown = sorted(k for k in set(data) - known if not str(k).startswith("_"))
        if unknown:
            raise ValueError(f"unknown compatibility field(s): {', '.join(unknown)}")
        return cls(**{k: str(v) for k, v in data.items() if k in known})

    def to_dict(self) -> dict:
        return {f.name: getattr(self, f.name) for f in fields(self)}

    def missing_fields(self) -> tuple[str, ...]:
        """The policy gate fields this record does not satisfy, in policy order."""
        missing: list[str] = []
        for policy_field, record_fields in GATE_FIELD_MAP.items():
            if not all(str(getattr(self, f, "")).strip() for f in record_fields):
                missing.append(policy_field)
        return tuple(missing)

    @property
    def complete(self) -> bool:
        return not self.missing_fields()


@dataclass(frozen=True)
class GateDecision:
    """ADMIT or BLOCK, with every reason stated. Never a substitute for a result."""

    decision: str                  # "ADMIT" | "BLOCK"
    reasons: tuple[str, ...]
    language: str = ""
    tool: str = ""

    @property
    def admitted(self) -> bool:
        return self.decision == "ADMIT"

    def to_dict(self) -> dict:
        return {
            "decision": self.decision,
            "admitted": self.admitted,
            "reasons": list(self.reasons),
            "language": self.language,
            "tool": self.tool,
        }


def _cited_registry_tool(value: str,
                         chain: Optional[LanguageToolchain]) -> Optional[str]:
    """The tool a ``registry:<language>/<tool>`` reference names, or ``None``.

    A registered language name may itself contain a slash (``Rust/Substrate``,
    ``C/C++``), so the reference is split against the language key rather than on
    its first slash: splitting on the first slash would read
    ``registry:Rust/Substrate/Cargo`` as language ``Rust`` and tool
    ``Substrate/Cargo``, which no record could ever cite.
    """
    if chain is None or not value.startswith(_REGISTRY_REF_PREFIX):
        return None
    ref = value[len(_REGISTRY_REF_PREFIX):]
    prefix = f"{chain.language}/"
    if not ref.startswith(prefix):
        return None
    return ref[len(prefix):]


def evidence_is_official(value: str, chain: Optional[LanguageToolchain] = None,
                         tool: str = "") -> bool:
    """True when the evidence cites official documentation or a registry entry.

    Accepted: an ``http(s)`` URL, or ``registry:<language>/<tool>`` for the
    record's own tool when the registry lists it for that language. A README
    path, a memory of a prior engagement, or a bare tool name is not evidence.
    """
    value = value.strip()
    if _URL_RE.match(value):
        return True
    if not tool:
        return False
    cited = _cited_registry_tool(value, chain)
    return cited == tool and chain.tool(tool) is not None


def admit(record: CompatibilityRecord) -> GateDecision:
    """Decide whether a tool may run against this target.

    Fails closed: every unmet requirement is a blocker, and any blocker means
    BLOCK. Nothing here executes a tool or infers compatibility.
    """
    blockers: list[str] = []

    missing = record.missing_fields()
    if missing:
        blockers.append(
            "missing required compatibility fields: " + ", ".join(missing)
        )

    chain: Optional[LanguageToolchain] = None
    if record.language.strip():
        chain = resolve_language(record.language)
        if chain is None:
            blockers.append(
                f"no verified native toolchain is registered for "
                f"'{record.language}'; research an appropriate alternative and add "
                f"it to the registry (docs/SECURITY_TOOL_COMPATIBILITY.md)"
            )

    if chain is not None and record.tool.strip():
        if chain.tool(record.tool) is None:
            available = ", ".join(t.name for t in chain.tools)
            blockers.append(
                f"'{record.tool}' is not a verified tool for {chain.language} "
                f"(verified: {available}); a tool that worked on another protocol "
                f"is not evidence of compatibility here"
            )

    if chain is not None:
        blockers.extend(cross_language_mismatch(record, chain))

    if record.compatibility_evidence.strip() and not evidence_is_official(
        record.compatibility_evidence, chain, record.tool
    ):
        blockers.append(
            "compatibility evidence must cite official documentation (an http(s) "
            "URL) or a registry entry (registry:<language>/<tool>); "
            f"got '{record.compatibility_evidence}'"
        )

    if record.smoke_test == "not-run":
        blockers.append(
            "compatibility smoke test has not run; run it before full analysis"
        )
    elif record.smoke_test == "failed":
        blockers.append(
            "compatibility smoke test failed; BLOCK the tool and research an "
            "alternative rather than substituting one that happens to be installed"
        )
    elif record.smoke_test != "passed":
        blockers.append(
            "smoke_test must be 'passed', 'failed' or 'not-run'; "
            f"got '{record.smoke_test}'"
        )

    return GateDecision(
        decision="BLOCK" if blockers else "ADMIT",
        reasons=tuple(blockers),
        language=record.language,
        tool=record.tool,
    )


# --------------------------------------------------------------------------- #
# Honest execution reporting (policy section F) and completion (section H)
# --------------------------------------------------------------------------- #

def statuses() -> dict[str, str]:
    """The four execution statuses and their one permitted meaning."""
    return dict(EXECUTION_STATUSES)


def status_meaning(status: str) -> str:
    """The meaning of one execution status; unknown statuses are an error."""
    try:
        return EXECUTION_STATUSES[status]
    except KeyError:
        raise ValueError(
            f"unknown execution status '{status}'; use one of "
            f"{', '.join(EXECUTION_STATUSES)}"
        ) from None


#: Maps each completion criterion (policy section H) to the report field that
#: records it. Keys are `blackheart.doctrine.COMPLETION_ACCEPTANCE` verbatim.
COMPLETION_FIELD_MAP: dict[str, str] = {
    "technology stack is documented": "stack_documented",
    "tool compatibility is verified": "tool_compatibility_verified",
    "relevant security-critical components have been examined":
        "security_critical_components_examined",
    "appropriate native tests have been performed": "native_tests_performed",
    "vulnerability hypotheses have been independently assessed":
        "hypotheses_independently_assessed",
    "coverage gaps and untested components are disclosed": "coverage_gaps_disclosed",
}


@dataclass(frozen=True)
class CompletionReport:
    """The policy's final acceptance criteria, as checkable flags."""

    stack_documented: bool = False
    tool_compatibility_verified: bool = False
    security_critical_components_examined: bool = False
    native_tests_performed: bool = False
    hypotheses_independently_assessed: bool = False
    coverage_gaps_disclosed: bool = False

    def missing(self) -> tuple[str, ...]:
        return tuple(
            criterion for criterion, attr in COMPLETION_FIELD_MAP.items()
            if not getattr(self, attr)
        )

    @property
    def complete(self) -> bool:
        return not self.missing()

    def to_dict(self) -> dict:
        return {
            "complete": self.complete,
            "missing": list(self.missing()),
            **{f.name: getattr(self, f.name) for f in fields(self)},
        }


def template() -> dict:
    """A blank pre-execution record, matching ``templates/tool-compatibility.json``."""
    record = CompatibilityRecord()
    return {
        "_policy": "docs/SECURITY_TOOL_COMPATIBILITY.md",
        "_statuses": list(EXECUTION_STATUSES),
        **record.to_dict(),
    }


__all__ = [
    "REGISTRY_VERIFIED_AT", "NativeTool", "LanguageToolchain", "TOOLCHAINS",
    "TOOLCHAIN_BY_LANGUAGE", "resolve_language", "registry",
    "FOREIGN_TOKENS", "cross_language_mismatch",
    "GATE_FIELD_MAP", "CompatibilityRecord", "GateDecision",
    "evidence_is_official", "admit",
    "statuses", "status_meaning", "COMPLETION_FIELD_MAP", "CompletionReport",
    "template", "COMPATIBILITY_GATE_FIELDS", "NATIVE_TESTING_METHODS",
]
