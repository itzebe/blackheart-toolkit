"""Vyper ingestion: a third environment the EVM engines cannot read directly.

Vyper is not Solidity with different keywords. It has no inheritance, no modifier
blocks, explicit `@external`/`@payable`/`@nonreentrant` decorators, and `self.`
state access. A Solidity lexer pointed at it produces a confident, empty surface,
which is worse than refusing. This scanner reads the subset it understands and
flags what it sees; every flag is a lead with its line, never a finding.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterable

from ..objectives import _OBJECTIVE_CATALOG

SEVERITIES = ("info", "low", "medium")

_COMMENT_RE = re.compile(r"#[^\n]*")
_STRING_RE = re.compile(r'"""(?:.|\n)*?"""|\'\'\'(?:.|\n)*?\'\'\'|"(?:[^"\\]|\\.)*"|\'(?:[^\'\\]|\\.)*\'')
_FUNCTION_RE = re.compile(r"^def\s+([A-Za-z_]\w*)\s*\((.*?)\)", re.S)
_STATE_RE = re.compile(r"^([A-Za-z_]\w*)\s*:\s*(.+)$")
_NON_DECL = ("def ", "@", "from ", "import ", "struct ", "event ", "interface ",
             "implements ", "enum ", "flag ", "pass")


@dataclass(frozen=True)
class VyperFunction:
    name: str
    decorators: tuple[str, ...]
    params: str
    body: str
    line: int

    @property
    def external(self) -> bool:
        return any(d in ("@external", "@public") for d in self.decorators)

    @property
    def payable(self) -> bool:
        return "@payable" in self.decorators

    @property
    def nonreentrant(self) -> bool:
        return any(d.startswith("@nonreentrant") for d in self.decorators)

    def writes_state(self) -> bool:
        return re.search(r"\bself\.[A-Za-z_]\w*\s*(?:\[[^\]]*\])?\s*(?:=|\+=|-=)", self.body) is not None


@dataclass
class VyperSurfaceReport:
    path: str
    functions: list[VyperFunction] = field(default_factory=list)
    state_vars: dict[str, str] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "functions": [
                {"name": f.name, "decorators": list(f.decorators),
                 "external": f.external, "payable": f.payable, "line": f.line}
                for f in self.functions
            ],
            "state_vars": dict(self.state_vars),
            "errors": list(self.errors),
        }


@dataclass(frozen=True)
class VyperFlag:
    rule: str
    category: str
    severity_hint: str
    function: str
    path: str
    line: int
    evidence: str
    rationale: str

    def as_dict(self) -> dict:
        return {
            "rule": self.rule, "category": self.category,
            "severity_hint": self.severity_hint, "function": self.function,
            "location": f"{self.path}:{self.line}", "evidence": self.evidence,
            "rationale": self.rationale,
        }


def strip_vyper_noise(source: str) -> str:
    """Blank comments and strings while preserving line numbers."""
    def blank(match: re.Match) -> str:
        return "".join("\n" if c == "\n" else " " for c in match.group(0))

    return _COMMENT_RE.sub(blank, _STRING_RE.sub(blank, source))


def scan_vyper(source: str, path: str = "<memory>") -> VyperSurfaceReport:
    """Recover functions, decorators and module-level state variables."""
    report = VyperSurfaceReport(path=path)
    text = strip_vyper_noise(source)
    lines = text.splitlines()

    for line in lines:
        if not line or line[0].isspace() or line.startswith(_NON_DECL):
            continue
        match = _STATE_RE.match(line.strip())
        if match:
            name, decl = match.groups()
            if name not in ("def", "return"):
                report.state_vars[name] = decl.split("=")[0].strip()

    i = 0
    decorators: list[str] = []
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()
        if stripped.startswith("@"):
            decorators.append(stripped)
            i += 1
            continue
        match = _FUNCTION_RE.match(stripped)
        if match:
            name, params = match.group(1), match.group(2)
            body_lines: list[str] = []
            j = i + 1
            while j < len(lines):
                nxt = lines[j]
                if nxt and not nxt[0].isspace():
                    break
                body_lines.append(nxt)
                j += 1
            report.functions.append(
                VyperFunction(name, tuple(decorators), params,
                              "\n".join(body_lines), i + 1))
            decorators = []
            i = j
            continue
        if stripped and not stripped.startswith("#"):
            decorators = []
        i += 1
    return report


def evaluate_vyper(report: VyperSurfaceReport) -> list[VyperFlag]:
    """Turn the surface into category-linked leads."""
    flags: list[VyperFlag] = []

    def add(rule: str, category: str, severity: str, fn: VyperFunction,
            evidence: str, rationale: str) -> None:
        if category not in _OBJECTIVE_CATALOG:
            raise ValueError(f"vyper rule {rule!r} maps to unknown category {category!r}")
        flags.append(VyperFlag(rule, category, severity, fn.name, report.path,
                               fn.line, evidence, rationale))

    for fn in report.functions:
        if not fn.external:
            continue
        if fn.writes_state() and not fn.nonreentrant:
            add("vyper-missing-nonreentrant", "callback-reentrancy", "medium", fn,
                f"@external {fn.name} writes self.* without @nonreentrant",
                "an external call during the write can re-enter the same state")
        if "raw_call(" in fn.body:
            add("vyper-raw-call", "callback-reentrancy", "medium", fn,
                f"raw_call in {fn.name}", "a raw call hands control to an arbitrary callee")
        if fn.payable and "assert " not in fn.body:
            add("vyper-payable-without-guard", "unbacked-debt", "low", fn,
                f"@payable {fn.name} has no assert",
                "value is accepted with no guard on how it is credited")
        if re.search(r"\bself\.(owner|admin)\s*=", fn.body) and "msg.sender" not in fn.body:
            add("vyper-unguarded-privileged-write", "access-control", "medium", fn,
                f"{fn.name} writes self.owner/admin without msg.sender",
                "any caller may take the privileged slot")

    has_init = any(fn.name == "__init__" for fn in report.functions)
    uses_owner = any(re.search(r"\bself\.(owner|admin)\b", fn.body) for fn in report.functions)
    if uses_owner and not has_init:
        first = report.functions[0] if report.functions else VyperFunction(
            "<module>", (), "", "", 1)
        add("vyper-ownerless-init", "access-control", "info", first,
            "self.owner is used but no __init__ assigns it",
            "the owner slot may never be set, or set by an unexpected path")
    return flags


def vyper_as_dict(report: VyperSurfaceReport, flags: Iterable[VyperFlag]) -> dict:
    return {"surface": report.to_dict(), "flags": [f.as_dict() for f in flags]}


def render_vyper_markdown(report: VyperSurfaceReport, flags: Iterable[VyperFlag]) -> str:
    lines = [f"# Vyper surface: {report.path}", ""]
    if report.errors:
        lines += ["## Errors", "", *[f"- {e}" for e in report.errors], ""]
    lines += ["## State variables", ""]
    lines += [f"- `{name}: {typ}`" for name, typ in report.state_vars.items()] or ["- none"]
    lines += ["", "## Functions", ""]
    for fn in report.functions:
        deco = " ".join(fn.decorators)
        lines.append(f"- `{fn.name}({fn.params})` {deco}".rstrip())
    lines += ["", "## Candidate leads (a lead, not a finding)", ""]
    lines += [f"- **{f.rule}** [{f.category}] {report.path}:{f.line} — {f.rationale}"
              for f in flags] or ["- none"]
    return "\n".join(lines) + "\n"
