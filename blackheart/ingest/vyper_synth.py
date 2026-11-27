"""Turn a Vyper module into the same executable model Solidity uses.

The scanner in :mod:`blackheart.ingest.vyper` recovers the surface; this module
translates that surface into the Solidity-shaped ``ContractSurface`` the existing
interpreter already understands, then reuses :func:`synthesize` unchanged. That
keeps one model, one certifier and one value engine for both languages.

Translation is deliberately literal: ``self.x`` becomes ``x``, ``assert c`` becomes
``require(c)``, and anything the interpreter cannot read (a ``for`` loop, a raw
call, ``raise``) stays in the body and marks the operation *unmodelled*. No
Vyper construct is silently treated as a no-op.
"""

from __future__ import annotations

import re
from typing import Optional

from .solidity import ContractSurface, FunctionSurface
from .synthesize import SynthesisReport, SynthesizedTarget, synthesize
from .vyper import VyperFunction, scan_vyper


def _split_top(text: str, sep: str = ",") -> list[str]:
    out: list[str] = []
    depth = 0
    current: list[str] = []
    for char in text:
        if char in "([{":
            depth += 1
        elif char in ")]}":
            depth -= 1
        if char == sep and depth == 0:
            out.append("".join(current))
            current = []
            continue
        current.append(char)
    if current:
        out.append("".join(current))
    return [part.strip() for part in out if part.strip()]


def _solidity_params(raw: str) -> tuple[str, ...]:
    params: list[str] = []
    for part in _split_top(raw):
        if ":" in part:
            name, typ = part.split(":", 1)
            params.append(f"{typ.strip()} {name.strip()}")
        else:
            params.append(part)
    return tuple(params)


def _strip_assert(line: str) -> Optional[str]:
    match = re.match(r"assert\s+(.+)$", line)
    if not match:
        return None
    condition = _split_top(match.group(1))[0]
    return f"require({condition})"


def _to_solidity_body(body: str) -> str:
    statements: list[str] = []
    for raw in body.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line in ("pass", "..."):
            continue
        line = re.sub(r"\bself\.", "", line)
        line = re.sub(r"\bself\b", "", line)
        assert_form = _strip_assert(line)
        if assert_form is not None:
            line = assert_form
        statements.append(line)
    return "; ".join(statements)


def _function(fn: VyperFunction, contract: str) -> FunctionSurface:
    decorators = set(fn.decorators)
    visibility = "external" if fn.external else "internal"
    if "@view" in decorators or "@pure" in decorators:
        mutability = "view"
    elif "@payable" in decorators:
        mutability = "payable"
    else:
        mutability = "nonpayable"
    modifiers = ("nonreentrant",) if fn.nonreentrant else ()
    params = _solidity_params(fn.params)
    return FunctionSurface(
        contract=contract,
        name=fn.name,
        signature=f"{fn.name}({', '.join(params)})",
        visibility=visibility,
        mutability=mutability,
        modifiers=modifiers,
        params=params,
        body=_to_solidity_body(fn.body),
        line=fn.line,
    )


def vyper_to_surface(source: str, name: str = "Vyper", path: str = "<vyper>") -> ContractSurface:
    """Recover a ``ContractSurface`` from Vyper source without guessing."""
    report = scan_vyper(source, path)
    functions = tuple(_function(fn, name) for fn in report.functions)
    modifiers = ("nonreentrant",) if any(f.nonreentrant for f in report.functions) else ()
    return ContractSurface(
        name=name,
        kind="contract",
        path=path,
        line=1,
        functions=functions,
        state_vars=tuple(report.state_vars),
        modifiers_defined=modifiers,
    )


def synthesize_vyper(source: str, name: str = "Vyper",
                     path: str = "<vyper>") -> tuple[SynthesizedTarget, SynthesisReport]:
    """Build the executable model for a Vyper module."""
    return synthesize(vyper_to_surface(source, name=name, path=path))
