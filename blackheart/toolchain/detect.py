"""Stack detection from source, manifests and build configuration.

Policy section A is explicit: identify every security-relevant implementation
language from the source files, manifests, compiler configuration, dependencies
and build system, distinguish production code from tests, documentation,
generated code and frontend code, and *never* infer the complete stack from a
README or a file extension alone.

This module implements exactly that, and nothing more:

* a language seen only by file extension is reported **unconfirmed** -- it is a
  hypothesis about the stack, not a fact;
* a language backed by a build manifest (`foundry.toml`, `Cargo.toml`,
  `go.mod`, `Scarb.toml`, ...) is reported **confirmed**, with the manifest named;
* a language seen only under documentation/test paths is reported as such, so it
  cannot be mistaken for production code;
* README files are never evidence.

It never guesses a framework from a name and never claims the stack is complete:
the report says what it saw and what it could not confirm.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


#: Canonical language names, shared with `blackheart.doctrine.NATIVE_TESTING_METHODS`
#: and `blackheart.toolchain.TOOLCHAINS` so a detected stack resolves to a verified
#: toolchain without an alias table.
LANGUAGE_BY_EXT: dict[str, str] = {
    ".sol": "Solidity",
    ".vy": "Vyper", ".vyi": "Vyper", ".vyper": "Vyper",
    ".rs": "Rust/Substrate",
    ".py": "Python",
    ".go": "Go",
    ".c": "C/C++", ".h": "C/C++", ".cc": "C/C++", ".cpp": "C/C++",
    ".cxx": "C/C++", ".hpp": "C/C++", ".hxx": "C/C++",
    ".move": "Move",
    ".cairo": "Cairo",
    ".fc": "TON FunC/Tact", ".func": "TON FunC/Tact", ".tact": "TON FunC/Tact",
    ".tolk": "TON FunC/Tact",
    ".js": "JavaScript/TypeScript", ".jsx": "JavaScript/TypeScript",
    ".mjs": "JavaScript/TypeScript", ".cjs": "JavaScript/TypeScript",
    ".ts": "JavaScript/TypeScript", ".tsx": "JavaScript/TypeScript",
}

#: Build manifests: the evidence that makes a language *confirmed*. Exact filename.
MANIFESTS: dict[str, str] = {
    "foundry.toml": "Solidity",
    "hardhat.config.js": "Solidity",
    "hardhat.config.ts": "Solidity",
    "Cargo.toml": "Rust/Substrate",
    "pyproject.toml": "Python",
    "setup.py": "Python",
    "requirements.txt": "Python",
    "go.mod": "Go",
    "CMakeLists.txt": "C/C++",
    "Move.toml": "Move",
    "Scarb.toml": "Cairo",
    "package.json": "JavaScript/TypeScript",
    "tsconfig.json": "JavaScript/TypeScript",
    "vyproject.toml": "Vyper",
    "ape-config.yaml": "Vyper",
    "brownie-config.yaml": "Vyper",
}

#: Manifests that build more than one language. Foundry compiles the project's
#: Vyper sources alongside its Solidity ones, so `foundry.toml` confirms Vyper
#: *when the repository actually contains production `.vy` files* -- never on the
#: manifest's presence alone.
SHARED_MANIFESTS: dict[str, tuple[str, ...]] = {
    "foundry.toml": ("Vyper",),
}

#: Directories that are never security-relevant source: dependencies, build
#: output, caches. ``vendor`` and ``lib`` are excluded because a vendored
#: dependency's language says nothing about the protocol's own code.
SKIP_DIRS: frozenset[str] = frozenset({
    ".git", ".hg", ".svn", "node_modules", "vendor", "third_party", "lib",
    "target", "dist", "build", "out", "artifacts", "cache", "__pycache__",
    ".venv", "venv", "env", ".mypy_cache", ".pytest_cache", "coverage",
})

#: Skipped directories worth naming in a report: they can hold a whole component,
#: so a reader must know they were excluded. Caches and VCS metadata are skipped
#: too but are not worth reporting.
REPORTED_SKIPS: frozenset[str] = frozenset({
    "node_modules", "vendor", "third_party", "lib", "target", "dist", "build",
    "out", "artifacts",
})

#: Path segments that mark non-production code. A file under these is still
#: counted (it is part of the repository) but never as production.
ROLE_BY_SEGMENT: dict[str, str] = {
    "test": "test", "tests": "test", "spec": "test", "specs": "test",
    "__tests__": "test",
    "doc": "documentation", "docs": "documentation", "documentation": "documentation",
    "example": "documentation", "examples": "documentation",
    "generated": "generated", "gen": "generated", "autogen": "generated",
    "frontend": "frontend", "web": "frontend", "ui": "frontend",
    "client": "frontend",
}

#: The roles a component can have; production is the default.
ROLES: tuple[str, ...] = ("production", "test", "documentation", "generated", "frontend")


@dataclass
class LanguageEvidence:
    """What the repository shows about one language."""

    language: str
    files: int = 0
    by_role: dict[str, int] = field(default_factory=dict)
    manifests: list[str] = field(default_factory=list)

    @property
    def confirmed(self) -> bool:
        """True only when a build manifest backs the language."""
        return bool(self.manifests)

    @property
    def production_files(self) -> int:
        return self.by_role.get("production", 0)

    def to_dict(self) -> dict:
        return {
            "language": self.language,
            "files": self.files,
            "by_role": dict(sorted(self.by_role.items())),
            "manifests": list(self.manifests),
            "confirmed": self.confirmed,
        }


@dataclass
class StackReport:
    """The honest result of a stack scan."""

    root: str
    languages: list[LanguageEvidence] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    truncated: bool = False

    @property
    def confirmed_languages(self) -> list[str]:
        return [e.language for e in self.languages if e.confirmed]

    @property
    def unconfirmed_languages(self) -> list[str]:
        return [e.language for e in self.languages if not e.confirmed]

    @property
    def security_relevant_languages(self) -> list[str]:
        """Confirmed languages with production code, in registry order."""
        return [e.language for e in self.languages
                if e.confirmed and e.production_files > 0]

    @property
    def mixed_language(self) -> bool:
        """True when more than one language carries production code."""
        return len(self.security_relevant_languages) > 1

    @property
    def complete(self) -> bool:
        """Never complete from extensions alone, and never after a truncated scan."""
        return bool(self.languages) and not self.unconfirmed_languages and not self.truncated

    def limitations(self) -> list[str]:
        notes: list[str] = []
        if not self.languages:
            notes.append("no security-relevant source files were found")
        for language in self.unconfirmed_languages:
            notes.append(
                f"{language}: seen by file extension only, with no build manifest -- "
                f"unconfirmed, not a fact about the stack"
            )
        if self.mixed_language:
            notes.append(
                "mixed-language protocol: "
                + ", ".join(self.security_relevant_languages)
                + " -- every security-relevant component is its own target"
            )
        if self.truncated:
            notes.append("scan stopped at the file limit; the stack list may be partial")
        reported = sorted({s for s in self.skipped if s in REPORTED_SKIPS})
        if reported:
            notes.append(
                "skipped vendored/build directories (their language is not the "
                "protocol's own code): " + ", ".join(reported)
            )
        notes.append("README and documentation files are not evidence of the stack")
        return notes

    def to_dict(self) -> dict:
        return {
            "root": self.root,
            "languages": [e.to_dict() for e in self.languages],
            "confirmed": self.confirmed_languages,
            "unconfirmed": self.unconfirmed_languages,
            "security_relevant": self.security_relevant_languages,
            "mixed_language": self.mixed_language,
            "complete": self.complete,
            "limitations": self.limitations(),
            "skipped_dirs": sorted(set(self.skipped)),
            "truncated": self.truncated,
        }


def _role_for(path: Path) -> str:
    """Classify a file by its path segments; production unless a marker says otherwise."""
    for part in path.parts[:-1]:
        role = ROLE_BY_SEGMENT.get(part.casefold())
        if role:
            return role
    return "production"


def detect_stack(root: str | Path, *, max_files: int = 50_000) -> StackReport:
    """Scan ``root`` for languages, their roles, and the manifests that confirm them.

    Deterministic and offline. Never follows a symlink out of the tree, never reads
    file contents (so it cannot be fooled by a README claiming a language), and
    never asserts completeness.
    """
    base = Path(root)
    report = StackReport(root=str(base))
    if not base.is_dir():
        report.limitations()
        report.skipped.append(str(base))
        return report

    evidence: dict[str, LanguageEvidence] = {}
    shared_seen: list[tuple[str, str]] = []
    seen = 0
    for dirpath, dirnames, filenames in os.walk(base, followlinks=False):
        here = Path(dirpath)
        report.skipped.extend(sorted(
            d for d in dirnames if d.casefold() in SKIP_DIRS
        ))
        dirnames[:] = sorted(d for d in dirnames if d.casefold() not in SKIP_DIRS)
        for name in sorted(filenames):
            rel = (here / name).relative_to(base)
            if name in MANIFESTS:
                language = MANIFESTS[name]
                entry = evidence.setdefault(language, LanguageEvidence(language))
                entry.manifests.append(str(rel))
                if name in SHARED_MANIFESTS:
                    shared_seen.append((name, str(rel)))
                continue
            if name in SHARED_MANIFESTS:
                shared_seen.append((name, str(rel)))
                continue
            language = LANGUAGE_BY_EXT.get(Path(name).suffix.casefold())
            if language is None:
                continue
            seen += 1
            if seen > max_files:
                report.truncated = True
                break
            entry = evidence.setdefault(language, LanguageEvidence(language))
            entry.files += 1
            role = _role_for(rel)
            entry.by_role[role] = entry.by_role.get(role, 0) + 1
        if report.truncated:
            break

    # A shared manifest confirms a second language only when that language has
    # production source of its own; a bare `foundry.toml` never claims Vyper.
    for name, rel in shared_seen:
        for language in SHARED_MANIFESTS[name]:
            entry = evidence.get(language)
            if entry is not None and entry.production_files > 0:
                entry.manifests.append(rel)

    order = {language: i for i, language in enumerate(_registry_order())}
    report.languages = sorted(
        evidence.values(), key=lambda e: (order.get(e.language, 999), e.language)
    )
    return report


def _registry_order() -> tuple[str, ...]:
    """Registry order, so a report reads like the policy table."""
    from . import TOOLCHAINS
    return tuple(t.language for t in TOOLCHAINS)


__all__ = [
    "LANGUAGE_BY_EXT", "MANIFESTS", "SHARED_MANIFESTS", "SKIP_DIRS", "REPORTED_SKIPS",
    "ROLE_BY_SEGMENT", "ROLES",
    "LanguageEvidence", "StackReport", "detect_stack",
]
