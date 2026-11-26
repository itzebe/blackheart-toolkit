"""Language-coverage gate for source ingestion.

A scanner that reads one language and silently ignores another is the most
dangerous kind of false negative: the report says "0 leads", the reader hears
"clean", and the language that carries the protocol was never opened.

This module makes that impossible at the CLI boundary. It compares the stack
detected from manifests and production source against the scanner that actually
ran, and refuses to present a partial scan as a complete one.

The gate is deliberately not a proof of coverage: a language can have a scanner
and still be only partly modelled. It only answers the narrower, checkable
question -- *was the language that carries production code opened at all?*
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from ..toolchain.detect import detect_stack

#: Scanner names (as the CLI spells them) mapped to the canonical stack names
#: used by :mod:`blackheart.toolchain.detect`.
SCANNER_FOR_LANGUAGE: dict[str, str] = {
    "Solidity": "solidity",
    "Rust/Substrate": "rust",
    "Vyper": "vyper",
    "Go": "go",
}
LANGUAGE_FOR_SCANNER: dict[str, str] = {v: k for k, v in SCANNER_FOR_LANGUAGE.items()}


class CoverageError(RuntimeError):
    """The requested scan would leave production source unread."""

    def __init__(self, message: str, coverage: "LanguageCoverage") -> None:
        super().__init__(message)
        self.coverage = coverage


@dataclass(frozen=True)
class LanguageCoverage:
    """What the tree contains, what was scanned, and what was not."""

    root: str
    detected: dict[str, int] = field(default_factory=dict)
    scanned_language: str = ""
    covered: tuple[str, ...] = ()
    unscanned: tuple[str, ...] = ()
    allowed_unscanned: tuple[str, ...] = ()
    reasons: tuple[str, ...] = ()

    @property
    def status(self) -> str:
        if not self.detected:
            return "UNKNOWN"
        if not self.unscanned:
            # An explicitly allowed language is still a partial result; it is
            # not blocked, but it must never be rendered as full coverage.
            return "PARTIAL" if self.allowed_unscanned else "FULL"
        if not self.covered:
            return "BLOCKED"
        return "PARTIAL"

    @property
    def blocked(self) -> bool:
        return bool(self.unscanned)

    def to_dict(self) -> dict:
        return {
            "root": self.root,
            "detected": dict(sorted(self.detected.items())),
            "scanned_language": self.scanned_language,
            "covered": list(self.covered),
            "unscanned": list(self.unscanned),
            "allowed_unscanned": list(self.allowed_unscanned),
            "status": self.status,
            "blocked": self.blocked,
            "reasons": list(self.reasons),
        }

    def block_message(self) -> str:
        lines = [
            "BLOCKED — LANGUAGE COVERAGE",
            f"Root: {self.root}",
            f"Scanned: {self.scanned_language or '(none)'}",
            "Detected production source: "
            + (", ".join(f"{k} ({v} files)" for k, v in sorted(self.detected.items()))
               or "(none)"),
        ]
        if self.unscanned:
            lines.append("Not scanned: " + ", ".join(self.unscanned))
        for reason in self.reasons:
            lines.append(f"- {reason}")
        lines.append(
            "A scan that did not open the language carrying production code is not "
            "a clean result. Add a scanner for it, or pass --allow-unscanned LANG "
            "to record an explicit, partial exception."
        )
        return "\n".join(lines)


def assess_coverage(
    path: str | Path, scanned_language: str, *,
    allow_unscanned: tuple[str, ...] = (),
) -> LanguageCoverage:
    """Compare the detected stack with the scanner that actually ran.

    ``allow_unscanned`` is an operator's explicit exception, not a coverage
    claim: the language remains in the report, but the command may continue.
    """
    root = str(Path(path).expanduser())
    report = detect_stack(path)
    detected = {
        e.language: e.production_files
        for e in report.languages
        if e.production_files > 0
    }
    if not detected:
        return LanguageCoverage(root=root, scanned_language=scanned_language)

    scanned_canonical = SCANNER_FOR_LANGUAGE.get(
        LANGUAGE_FOR_SCANNER.get(scanned_language, scanned_language), scanned_language
    ).casefold()
    covered: list[str] = []
    unscanned: list[str] = []
    reasons: list[str] = []
    allowed = {a.casefold() for a in allow_unscanned}
    for language, count in sorted(detected.items()):
        canonical = SCANNER_FOR_LANGUAGE.get(language, language).casefold()
        if canonical == scanned_canonical:
            covered.append(language)
            continue
        if language.casefold() in allowed or canonical.casefold() in allowed:
            reasons.append(
                f"{language}: {count} production file(s) explicitly allowed unscanned "
                f"(partial coverage, not a clean result)"
            )
            continue
        unscanned.append(language)
        if language in SCANNER_FOR_LANGUAGE:
            reasons.append(
                f"{language}: {count} production file(s); scanner '{SCANNER_FOR_LANGUAGE[language]}' "
                f"exists but was not the scanner used"
            )
        else:
            reasons.append(
                f"{language}: {count} production file(s); no scanner exists for this "
                f"language in BLACKHEART"
            )
    return LanguageCoverage(
        root=root,
        detected=detected,
        scanned_language=scanned_language,
        covered=tuple(covered),
        unscanned=tuple(unscanned),
        allowed_unscanned=tuple(sorted(allowed)),
        reasons=tuple(reasons),
    )


def assert_coverage(
    path: str | Path, scanned_language: str, *,
    allow_unscanned: tuple[str, ...] = (),
) -> LanguageCoverage:
    """Return coverage, or raise :class:`CoverageError` when source is unread."""
    coverage = assess_coverage(path, scanned_language, allow_unscanned=allow_unscanned)
    if coverage.blocked:
        raise CoverageError(coverage.block_message(), coverage)
    return coverage
