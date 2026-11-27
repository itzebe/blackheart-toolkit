"""Solidity source ingestion.

Turns a real repository into a machine-derived attack surface so a mission
starts from code instead of a hand-transcribed interface. This is a
lexer-grade scanner, not a compiler: it strips comments and string literals
while preserving byte offsets (so every finding keeps a real ``file:line``),
then walks contract and function blocks by brace matching.

It deliberately claims less than a parser: it can be fooled by exotic syntax.
That is why every downstream flag is a *lead* with its evidence attached, never
a finding.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator

VISIBILITIES = frozenset({"public", "external", "internal", "private"})
MUTABILITIES = frozenset({"view", "pure", "payable", "nonpayable", "constant"})
_HEADER_NOISE = frozenset(
    {"virtual", "override", "returns", "memory", "calldata", "storage", "indexed"}
)

_CONTRACT_RE = re.compile(
    r"\b(abstract\s+contract|contract|library|interface)\s+([A-Za-z_]\w*)"
    r"([^{;]*)\{"
)
_FUNCTION_RE = re.compile(r"\bfunction\s+([A-Za-z_]\w*)\s*\(")
_MODIFIER_RE = re.compile(r"\bmodifier\s+([A-Za-z_]\w*)\s*(?:\([^)]*\))?\s*\{")
_STATE_RE = re.compile(
    r"((?:mapping\s*\([^;]*\)|[A-Za-z_][\w\.\[\]]*))\s+"
    r"(?:(?:public|private|internal|external|constant|immutable|override|virtual|transient)\s+)*"
    r"([A-Za-z_]\w*)\s*(?:=[^;]*)?;"
)
_STRUCT_RE = re.compile(r"\bstruct\s+([A-Za-z_]\w*)\s*\{")
_STATE_SKIP = frozenset(
    {"event", "error", "using", "import", "pragma", "function", "modifier",
     "constructor", "struct", "enum", "type", "return", "emit", "require",
     "assert", "revert"}
)


@dataclass(frozen=True)
class FunctionSurface:
    contract: str
    name: str
    signature: str
    visibility: str
    mutability: str
    modifiers: tuple[str, ...]
    params: tuple[str, ...]
    body: str
    line: int
    returns: tuple[str, ...] = ()
    #: True for an interface/abstract declaration with no body. It is an external
    #: entry point and must be reported, but it is not an implementation to model.
    declaration_only: bool = False

    @property
    def state_changing(self) -> bool:
        return self.mutability not in ("view", "pure", "constant")

    @property
    def externally_callable(self) -> bool:
        return self.visibility in ("public", "external")


@dataclass(frozen=True)
class ContractSurface:
    name: str
    kind: str
    path: str
    line: int
    functions: tuple[FunctionSurface, ...] = ()
    state_vars: tuple[str, ...] = ()
    modifiers_defined: tuple[str, ...] = ()
    bases: tuple[str, ...] = ()
    state_types: tuple[tuple[str, str], ...] = ()
    structs: tuple[tuple[str, tuple[tuple[str, str], ...]], ...] = ()

    @property
    def has_access_control(self) -> bool:
        """True when the contract defines its own guard vocabulary."""
        return bool(self.modifiers_defined) or any(
            v in ("owner", "admin", "admins", "governance", "authority")
            for v in self.state_vars
        )


@dataclass(frozen=True)
class SurfaceReport:
    root: str
    files: tuple[str, ...] = ()
    contracts: tuple[ContractSurface, ...] = ()
    errors: tuple[str, ...] = field(default_factory=tuple)

    @property
    def functions(self) -> tuple[FunctionSurface, ...]:
        return tuple(f for c in self.contracts for f in c.functions)


def strip_noise(src: str) -> str:
    """Blank comments and string/char literals, preserving length and newlines.

    Offsets stay identical to the original, so ``line_of`` on the stripped text
    matches the real file.
    """
    out: list[str] = []
    i, n = 0, len(src)
    while i < n:
        c = src[i]
        nxt = src[i + 1] if i + 1 < n else ""
        if c == "/" and nxt == "/":
            while i < n and src[i] != "\n":
                out.append(" ")
                i += 1
        elif c == "/" and nxt == "*":
            out.append(" ")
            out.append(" ")
            i += 2
            while i < n and not (src[i] == "*" and i + 1 < n and src[i + 1] == "/"):
                out.append("\n" if src[i] == "\n" else " ")
                i += 1
            if i < n:
                out.append(" ")
                out.append(" ")
                i += 2
        elif c in ('"', "'"):
            quote = c
            out.append(quote)
            i += 1
            while i < n and src[i] != quote:
                if src[i] == "\\" and i + 1 < n:
                    out.append(" ")
                    out.append(" ")
                    i += 2
                    continue
                out.append("\n" if src[i] == "\n" else " ")
                i += 1
            if i < n:
                out.append(quote)
                i += 1
        else:
            out.append(c)
            i += 1
    return "".join(out)


def line_of(src: str, index: int) -> int:
    return src.count("\n", 0, index) + 1


def _match_brace(src: str, open_index: int) -> int:
    """Index of the brace closing ``src[open_index]`` (which must be ``{``)."""
    depth = 0
    i = open_index
    n = len(src)
    while i < n:
        c = src[i]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return n - 1


def _match_paren(src: str, open_index: int) -> int:
    depth = 0
    i = open_index
    n = len(src)
    while i < n:
        c = src[i]
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return n - 1


def _split_params(raw: str) -> tuple[str, ...]:
    raw = raw.strip()
    if not raw:
        return ()
    parts, depth, start = [], 0, 0
    for i, c in enumerate(raw):
        if c in "([":
            depth += 1
        elif c in ")]":
            depth -= 1
        elif c == "," and depth == 0:
            parts.append(raw[start:i])
            start = i + 1
    parts.append(raw[start:])
    return tuple(p.strip() for p in parts if p.strip())


def _param_type(param: str) -> str:
    return param.split()[0] if param.split() else param


def _parse_header(header: str) -> tuple[str, str, tuple[str, ...]]:
    header = re.sub(r"\breturns\s*\([^)]*\)", " ", header)
    tokens = re.findall(r"[A-Za-z_]\w*(?:\s*\([^)]*\))?", header)
    visibility = "public"
    mutability = "nonpayable"
    modifiers: list[str] = []
    for tok in tokens:
        bare = tok.split("(")[0].strip()
        if bare in VISIBILITIES:
            visibility = bare
        elif bare in MUTABILITIES:
            mutability = bare
        elif bare in _HEADER_NOISE:
            continue
        else:
            modifiers.append(bare)
    return visibility, mutability, tuple(modifiers)


def _scan_functions(
    stripped: str, contract: str, body_start: int, body_end: int
) -> Iterator[FunctionSurface]:
    region = stripped[body_start:body_end]
    for m in _FUNCTION_RE.finditer(region):
        name = m.group(1)
        paren_open = body_start + m.end() - 1
        paren_close = _match_paren(stripped, paren_open)
        params = _split_params(stripped[paren_open + 1:paren_close])
        header_start = paren_close + 1
        brace = stripped.find("{", header_start)
        semi = stripped.find(";", header_start)
        declaration_only = brace == -1 or (semi != -1 and semi < brace)
        header_end = semi if declaration_only else brace
        if header_end == -1:
            continue
        header = stripped[header_start:header_end]
        returns_match = re.search(r"\breturns\s*\(([^)]*)\)", header)
        returns = _split_params(returns_match.group(1)) if returns_match else ()
        visibility, mutability, modifiers = _parse_header(header)
        body = "" if declaration_only else stripped[brace + 1:_match_brace(stripped, brace)]
        yield FunctionSurface(
            contract=contract,
            name=name,
            signature=f"{name}({','.join(_param_type(p) for p in params)})",
            visibility=visibility,
            mutability=mutability,
            modifiers=modifiers,
            params=params,
            body=body,
            line=line_of(stripped, body_start + m.start()),
            returns=returns,
            declaration_only=declaration_only,
        )


def _scan_state_vars(stripped: str, body_start: int, body_end: int) -> tuple[str, ...]:
    return tuple(name for name, _typ in _scan_state_types(stripped, body_start, body_end))


def _scan_state_types(
    stripped: str, body_start: int, body_end: int
) -> tuple[tuple[str, str], ...]:
    out: list[tuple[str, str]] = []
    depth = 0
    stmt_start = body_start
    for i in range(body_start, body_end):
        c = stripped[i]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                stmt_start = i + 1
        elif c == ";" and depth == 0:
            stmt = stripped[stmt_start:i + 1]
            stmt_start = i + 1
            head = stmt.strip().split()[0] if stmt.strip() else ""
            if head in _STATE_SKIP or "function" in stmt or "modifier" in stmt:
                continue
            m = _STATE_RE.search(stmt)
            if m:
                out.append((m.group(2), m.group(1).strip()))
        elif c == ";" and depth < 0:
            depth = 0
    return tuple(out)


def _scan_structs(
    stripped: str, body_start: int, body_end: int
) -> tuple[tuple[str, tuple[tuple[str, str], ...]], ...]:
    out: list[tuple[str, tuple[tuple[str, str], ...]]] = []
    region = stripped[body_start:body_end]
    for match in _STRUCT_RE.finditer(region):
        open_brace = body_start + match.end() - 1
        close = _match_brace(stripped, open_brace)
        fields: list[tuple[str, str]] = []
        inner = stripped[open_brace + 1:close]
        for stmt in inner.split(";"):
            m = _STATE_RE.search(stmt + ";")
            if m:
                fields.append((m.group(2), m.group(1).strip()))
        out.append((match.group(1), tuple(fields)))
    return tuple(out)


def _parse_bases(tail: str) -> tuple[str, ...]:
    text = tail.strip()
    if not text.startswith("is "):
        return ()
    text = text[3:]
    names: list[str] = []
    depth = 0
    start = 0
    for i, c in enumerate(text):
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
        elif c == "," and depth == 0:
            names.append(text[start:i])
            start = i + 1
    names.append(text[start:])
    out = []
    for item in names:
        m = re.match(r"\s*([A-Za-z_]\w*)", item)
        if m:
            out.append(m.group(1))
    return tuple(out)


def scan_source(src: str, path: str = "<memory>") -> tuple[ContractSurface, ...]:
    stripped = strip_noise(src)
    contracts: list[ContractSurface] = []
    for m in _CONTRACT_RE.finditer(stripped):
        kind = re.sub(r"\s+", " ", m.group(1))
        name = m.group(2)
        open_brace = m.end() - 1
        close = _match_brace(stripped, open_brace)
        functions = tuple(_scan_functions(stripped, name, open_brace + 1, close))
        state_types = _scan_state_types(stripped, open_brace + 1, close)
        state_vars = tuple(var for var, _typ in state_types)
        mods = tuple(mm.group(1) for mm in _MODIFIER_RE.finditer(stripped[open_brace + 1:close]))
        contracts.append(
            ContractSurface(
                name=name,
                kind=kind,
                path=path,
                line=line_of(stripped, m.start()),
                functions=functions,
                state_vars=state_vars,
                modifiers_defined=mods,
                bases=_parse_bases(m.group(3)),
                state_types=state_types,
                structs=_scan_structs(stripped, open_brace + 1, close),
            )
        )
    return tuple(contracts)


def ingest(root: str | Path, *, max_files: int = 2000, include_tests: bool = False) -> SurfaceReport:
    """Scan every ``.sol`` file under ``root`` (a file or a directory).

    Test, snapshot, script and mock trees are skipped by default: a lead in a
    test harness is noise, and noise is how a triage sheet stops being read.
    """
    root_path = Path(root)
    errors: list[str] = []
    files: list[str] = []
    contracts: list[ContractSurface] = []

    if root_path.is_file():
        candidates = [root_path]
    else:
        candidates = sorted(root_path.rglob("*.sol"))
    if len(candidates) > max_files:
        errors.append(f"truncated: {len(candidates)} .sol files, scanned {max_files}")
        candidates = candidates[:max_files]

    skip = ("/lib/", "/node_modules/", "/out/", "/cache/", "/.git/")
    if not include_tests:
        skip = skip + (
            "/test/", "/tests/", "/snapshots/", "/scripts/", "/mock/", "/mocks/", "/dev/",
        )
    for path in candidates:
        posix = path.as_posix()
        if any(part in posix for part in skip):
            continue
        if not include_tests and (posix.endswith(".t.sol") or posix.endswith(".s.sol")):
            continue
        try:
            src = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:  # pragma: no cover - unreadable file
            errors.append(f"{posix}: {exc}")
            continue
        files.append(posix)
        try:
            contracts.extend(scan_source(src, posix))
        except Exception as exc:  # pragma: no cover - defensive
            errors.append(f"{posix}: {exc}")

    return SurfaceReport(
        root=str(root_path), files=tuple(files), contracts=tuple(contracts), errors=tuple(errors)
    )
