"""Repository ingestion: from real source to a machine-derived attack surface.

Before this package, every mission began by hand-transcribing a target's
interface into the engine's ``Target``/``OpSpec`` model. That is the step where
a research engine stops being a research engine and becomes a text editor. This
package closes it for the first stage -- surface extraction and candidate
weakness flags -- while being explicit that the executable model is still
authored by a human (see ``blackheart.capability``).

Public surface:

* :func:`blackheart.ingest.solidity.ingest` -- scan a file or directory.
* :func:`blackheart.ingest.flags.evaluate` -- rule-match the surface.
* :func:`blackheart.ingest.report.render_markdown` / ``as_dict`` -- output.
* :func:`blackheart.ingest.rust.ingest_rust` /
  :func:`blackheart.ingest.rust_flags.evaluate_rust` -- the same for Rust /
  Substrate and Solana / Anchor, because a runtime is an environment the EVM
  engines cannot read.
* :func:`detect_language` -- decide which scanner a tree needs, from its files,
  rather than from what the operator happened to pass.
"""

from __future__ import annotations

from .compile import (
    CompileOutcome,
    CompiledArtifact,
    compile_project,
    find_compiler,
    models_from_compiled,
    parse_forge_artifacts,
    parse_solc_combined_json,
)
from .coverage import (
    CoverageError,
    LanguageCoverage,
    SCANNER_FOR_LANGUAGE,
    assert_coverage,
    assess_coverage,
)
from .flags import RULES, CandidateFlag, Rule, evaluate
from .golang import (
    GoBoundary,
    GoFunction,
    GoPackage,
    GoSurfaceReport,
    GoType,
    ingest_go,
)
from .golang_calls import (
    AUTHORITY_GUARD_PATTERN,
    STATE_WRITE_PATTERN,
    GoCallEdge,
    GoCallGraph,
    GoCallSummary,
)
from .golang_flags import GO_RULES, GoRule, evaluate_go
from .report import DISCLAIMER, as_dict, render_markdown, render_synthesis, synthesis_as_dict
from .runner import (
    RunOutcome,
    ToolAvailability,
    detect,
    run_foundry,
    solidity_record,
    write_harness,
)
from .rust import RustFunction, RustModule, RustSurfaceReport, ingest_rust, strip_rust_noise
from .rust_flags import RUST_RULES, RustRule, evaluate_rust
from .vyper import (
    VyperFlag,
    VyperFunction,
    VyperSurfaceReport,
    evaluate_vyper,
    render_vyper_markdown,
    scan_vyper,
    strip_vyper_noise,
    vyper_as_dict,
)
from .storage_layout import (
    LayoutChange,
    LayoutDiff,
    StorageEntry,
    diff_layouts,
    layouts_from_build_info,
    parse_layout,
)
from .synthesize import SynthesisReport, SynthesizedTarget, synthesize
from .solidity import (
    ContractSurface,
    FunctionSurface,
    SurfaceReport,
    ingest,
    scan_source,
    strip_noise,
)

def detect_language(path: str) -> str:
    """Which scanner this tree needs: ``"go"``, ``"rust"``, ``"solidity"``,
    ``"vyper"`` or ``"unknown"``.

    A crate root is decided by its manifest, not by counting files: a Polkadot
    pallet directory may hold more markdown than Rust, and a Foundry project may
    vendor a ``.rs`` file. Ties are reported honestly as ``unknown`` rather than
    guessed, because the wrong scanner produces a confident, empty surface.
    """
    from pathlib import Path

    root = Path(path).expanduser()
    if root.is_file():
        return {"rs": "rust", "sol": "solidity", "vy": "vyper", "go": "go"}.get(
            root.suffix.lstrip("."), "unknown")
    if not root.is_dir():
        return "unknown"

    skip = {"target", "vendor", "node_modules", ".git", "lib", "out", "cache"}
    counts = {"rust": 0, "solidity": 0, "vyper": 0, "go": 0}
    if (root / "Cargo.toml").is_file():
        counts["rust"] += 100
    if (root / "go.mod").is_file():
        counts["go"] += 100
    for candidate in root.rglob("*"):
        if any(part in skip for part in candidate.parts):
            continue
        language = {".rs": "rust", ".sol": "solidity", ".vy": "vyper", ".go": "go"}.get(candidate.suffix)
        if language:
            counts[language] += 1
    present = {k: v for k, v in counts.items() if v > 0}
    if not present:
        return "unknown"
    # A unique maximum is a decision; a tie is reported as unknown, not guessed.
    best = max(present.values())
    winners = [k for k, v in present.items() if v == best]
    return winners[0] if len(winners) == 1 else "unknown"


_SCANNABLE = {".sol": "solidity", ".rs": "rust", ".vy": "vyper", ".go": "go"}
_UNREAD_SKIP = {
    "target", "vendor", "node_modules", ".git", "lib", "out", "cache",
    "benches", "tests", "test", "examples", "mocks", "mock",
}


def language_census(path: str) -> dict[str, int]:
    """Count the scannable source files per language under ``path``.

    Used to explain an ``unknown`` verdict honestly: "no source found" and "both
    found, pick one" are different facts and must not share a message.
    """
    from pathlib import Path

    root = Path(path).expanduser()
    if root.is_file():
        language = _SCANNABLE.get(root.suffix)
        return {language: 1} if language else {}
    if not root.is_dir():
        return {}
    counts: dict[str, int] = {}
    for candidate in root.rglob("*"):
        if any(part in _UNREAD_SKIP for part in candidate.parts):
            continue
        language = _SCANNABLE.get(candidate.suffix)
        if language:
            counts[language] = counts.get(language, 0) + 1
    return counts


def unread_sources(path: str, language: str) -> tuple[str, ...]:
    """Sources of another scannable language present but not read.

    A mixed tree is the easiest way to believe a scan covered more than it did:
    one scanner runs, the other language is never mentioned, and the report looks
    complete. This names the omission so it cannot be mistaken for coverage.
    """
    from pathlib import Path

    root = Path(path).expanduser()
    if not root.is_dir():
        return ()
    counts: dict[str, int] = {}
    for candidate in root.rglob("*"):
        if any(part in _UNREAD_SKIP for part in candidate.parts):
            continue
        other = _SCANNABLE.get(candidate.suffix)
        if other and other != language:
            counts[other] = counts.get(other, 0) + 1
    return tuple(
        f"{count} {other} source file(s) present but not read "
        f"(scanner used: {language}); pass --language {other} to include them"
        for other, count in sorted(counts.items())
    )


__all__ = [
    "RULES",
    "RUST_RULES",
    "CandidateFlag",
    "CoverageError",
    "GO_RULES",
    "AUTHORITY_GUARD_PATTERN",
    "GoBoundary",
    "GoCallEdge",
    "GoCallGraph",
    "GoCallSummary",
    "GoFunction",
    "GoPackage",
    "GoRule",
    "GoSurfaceReport",
    "GoType",
    "STATE_WRITE_PATTERN",
    "LanguageCoverage",
    "SCANNER_FOR_LANGUAGE",
    "ContractSurface",
    "DISCLAIMER",
    "FunctionSurface",
    "Rule",
    "RustFunction",
    "RustModule",
    "RustRule",
    "RustSurfaceReport",
    "SurfaceReport",
    "RunOutcome",
    "SynthesisReport",
    "SynthesizedTarget",
    "ToolAvailability",
    "as_dict",
    "assert_coverage",
    "assess_coverage",
    "detect",
    "detect_language",
    "language_census",
    "evaluate",
    "evaluate_go",
    "evaluate_rust",
    "ingest",
    "ingest_go",
    "ingest_rust",
    "render_markdown",
    "render_synthesis",
    "run_foundry",
    "scan_source",
    "solidity_record",
    "strip_noise",
    "strip_rust_noise",
    "synthesis_as_dict",
    "synthesize",
    "unread_sources",
    "write_harness",
]
