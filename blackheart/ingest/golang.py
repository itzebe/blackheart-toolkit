"""Go / Cosmos SDK attack-surface ingestion.

The Solidity and Rust scanners answer "what can an unprivileged account call
here?" for their environments. A Cosmos SDK chain is a third environment, and
its reachable surface is a message server, an ante handler, a BeginBlocker or an
EndBlocker -- not a Solidity ABI and not a FRAME dispatchable.

This module is a lexer-grade scanner, not a Go compiler. It recovers packages,
types, functions, receivers, message handlers, consensus entry points, build
flavors, stub files and cgo boundaries. Everything it could not parse is recorded
in ``errors``; a stub is reported as a stub, never as the implementation it
replaces.

The build-flavor pass is deliberately part of the scanner. Open-core projects
ship a public build whose security-critical keepers are ``//go:build !full``
stubs and a private full build with the real code. Scanning the stub and calling
the result clean is the exact false negative this scanner exists to prevent.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator, Optional

from .solidity import line_of

SKIP_DIRS = {
    ".git", ".hg", ".svn", "node_modules", "vendor", "third_party",
    "target", "dist", "build", "out", "cache", "__pycache__",
    ".venv", "venv", "testdata",
}

_FUNC = re.compile(
    r"\bfunc\s*(?:\(\s*([^)]*?)\s*\)\s*)?([A-Za-z_]\w*)\s*\("
)
_PACKAGE = re.compile(r"^\s*package\s+([A-Za-z_]\w*)", re.MULTILINE)
_TYPE = re.compile(
    r"\btype\s+([A-Za-z_]\w*)\s+(struct|interface|[A-Za-z_]\w*)\b"
)
_IMPORT_BLOCK = re.compile(r"\bimport\s*\((.*?)\)", re.DOTALL)
_IMPORT_LINE = re.compile(r'\bimport\s+(?:_\s+)?(?:[A-Za-z_]\w*\s+)?"([^"]+)"')
_IMPORT_LINE_FULL = re.compile(
    r'\bimport\s+(?:(?P<alias>[A-Za-z_]\w*|_|\.)\s+)?"(?P<path>[^"]+)"'
)
_IMPORT_SPEC = re.compile(
    r'(?:(?P<alias>[A-Za-z_]\w*|_|\.)\s+)?"(?P<path>[^"]+)"'
)
_BUILD_GO = re.compile(r"^\s*//go:build\s+(.+?)\s*$", re.MULTILINE)
_BUILD_OLD = re.compile(r"^\s*//\s*\+build\s+(.+?)\s*$", re.MULTILINE)
_CALL = re.compile(r"\b([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)\s*\(")

_CONSENSUS_NAMES = frozenset({
    "BeginBlock", "EndBlock", "InitGenesis", "PrepareProposal",
    "ProcessProposal", "AnteHandle", "ValidateBasic", "GetSigners",
})
_HANDLER_RECEIVERS = ("MsgServer", "msgServer", "msg_server", "AnteHandler")


def strip_go_noise(src: str) -> str:
    """Blank Go comments and literals, preserving length and newlines.

    Raw strings (backticks), interpreted strings, rune literals and both comment
    forms are removed. Offsets stay identical to the original, so ``line_of`` on
    the stripped text is the real line.
    """
    out = list(src)
    i, n = 0, len(src)

    def blank(start: int, end: int) -> None:
        for k in range(start, min(end, n)):
            if out[k] != "\n":
                out[k] = " "

    while i < n:
        c = src[i]
        if c == "/" and i + 1 < n and src[i + 1] == "/":
            end = src.find("\n", i)
            end = n if end == -1 else end
            blank(i, end)
            i = end
            continue
        if c == "/" and i + 1 < n and src[i + 1] == "*":
            end = src.find("*/", i + 2)
            end = n if end == -1 else end + 2
            blank(i, end)
            i = end
            continue
        if c == "`":
            end = src.find("`", i + 1)
            end = n if end == -1 else end + 1
            blank(i, end)
            i = end
            continue
        if c in ('"', "'"):
            quote = c
            j = i + 1
            while j < n and src[j] != quote:
                j += 2 if src[j] == "\\" else 1
            end = min(j + 1, n)
            blank(i, end)
            i = end
            continue
        i += 1
    return "".join(out)


def _match_brace(src: str, open_index: int) -> int:
    depth = 0
    for i in range(open_index, len(src)):
        if src[i] == "{":
            depth += 1
        elif src[i] == "}":
            depth -= 1
            if depth == 0:
                return i
    return len(src) - 1


def _match_paren(src: str, open_index: int) -> int:
    depth = 0
    for i in range(open_index, len(src)):
        if src[i] == "(":
            depth += 1
        elif src[i] == ")":
            depth -= 1
            if depth == 0:
                return i
    return len(src) - 1


def _split_top(raw: str, sep: str = ",") -> tuple[str, ...]:
    parts: list[str] = []
    depth = 0
    start = 0
    for i, c in enumerate(raw):
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        elif c == sep and depth == 0:
            parts.append(raw[start:i])
            start = i + 1
    parts.append(raw[start:])
    return tuple(p.strip() for p in parts if p.strip())


def _receiver_type(receiver: str) -> str:
    # `(s msgServer)` / `(k *Keeper)` -- the type is the last identifier, not
    # the receiver variable.
    names = re.findall(r"[A-Za-z_]\w*", receiver.replace("*", " "))
    return names[-1] if names else ""


def _build_flavor(src: str) -> tuple[str, str]:
    """Return ``(flavor, expression)`` for a Go file's build constraints."""
    m = _BUILD_GO.search(src)
    expr = m.group(1) if m else ""
    if not expr:
        m = _BUILD_OLD.search(src)
        expr = m.group(1) if m else ""
    if not expr:
        return "unconditional", ""
    compact = expr.replace(" ", "")
    if "!full" in compact:
        return "community", expr
    if "full" in compact:
        return "full", expr
    return "tagged", expr


def _parse_imports(raw: str) -> tuple[tuple[str, str], ...]:
    """Return ``(alias, path)`` for every import, with Go's default alias.

    This is a lexical pass, not module resolution: the caller matches the path
    suffix against packages it actually scanned. A blank or dot import is
    dropped: it does not introduce a package qualifier the call graph may use.
    """
    specs: set[tuple[str, str]] = set()
    candidates = list(_IMPORT_LINE_FULL.finditer(raw))
    for block in _IMPORT_BLOCK.findall(raw):
        candidates.extend(_IMPORT_SPEC.finditer(block))
    for match in candidates:
        path = match.group("path")
        alias = match.group("alias") or path.rsplit("/", 1)[-1]
        if alias and alias not in ("_", "."):
            specs.add((alias, path))
    return tuple(sorted(specs))


def _is_stub_body(body: str, stub_file: bool) -> bool:
    compact = " ".join(body.split())
    if "ErrNotImplemented" in compact or "not implemented" in compact.lower():
        return True
    if not stub_file:
        return False
    if not compact:
        return True
    return bool(re.fullmatch(r"return(?:\s+[A-Za-z0-9_.,{}\s]+)?", compact))


@dataclass(frozen=True)
class GoFunction:
    package: str
    path: str
    receiver: str
    name: str
    signature: str
    params: tuple[str, ...]
    returns: tuple[str, ...]
    body: str
    line: int
    build_flavor: str
    build_expression: str
    stub: bool
    calls: tuple[str, ...]

    @property
    def is_method(self) -> bool:
        return bool(self.receiver)

    @property
    def is_exported(self) -> bool:
        return self.name[:1].isupper()

    @property
    def is_handler(self) -> bool:
        if self.name in _CONSENSUS_NAMES:
            return True
        if not any(x in self.receiver for x in _HANDLER_RECEIVERS):
            return False
        # A message server also has registration/lifecycle methods; only a
        # method that takes a message is an unprivileged entry point.
        return bool(re.search(r"\*?types\.Msg|\bsdk\.Msg\b|\bmsg\s+\*", self.signature))

    @property
    def is_consensus(self) -> bool:
        if self.name in _CONSENSUS_NAMES:
            return True
        return self.receiver.endswith("AppModule") and self.name in (
            "BeginBlock", "EndBlock", "InitGenesis", "ExportGenesis",
        )


@dataclass(frozen=True)
class GoType:
    package: str
    name: str
    kind: str
    fields: tuple[str, ...]
    line: int


@dataclass(frozen=True)
class GoBoundary:
    package: str
    path: str
    line: int
    kind: str
    detail: str


@dataclass(frozen=True)
class GoPackage:
    name: str
    path: str
    files: tuple[str, ...] = ()
    functions: tuple[GoFunction, ...] = ()
    types: tuple[GoType, ...] = ()
    #: ``(alias, import path)`` pairs from the package's files. The alias is
    #: the default last path segment when the source does not name one.
    imports: tuple[tuple[str, str], ...] = ()
    #: The package's module-qualified import path, when ``go.mod`` names one.
    import_path: str = ""


@dataclass(frozen=True)
class GoSurfaceReport:
    root: str
    files: tuple[str, ...] = ()
    packages: tuple[GoPackage, ...] = ()
    boundaries: tuple[GoBoundary, ...] = ()
    errors: tuple[str, ...] = field(default_factory=tuple)
    build_flavors: tuple[tuple[str, int], ...] = ()
    stub_files: tuple[str, ...] = ()
    full_files: tuple[str, ...] = ()

    @property
    def functions(self) -> tuple[GoFunction, ...]:
        return tuple(f for p in self.packages for f in p.functions)

    @property
    def handlers(self) -> tuple[GoFunction, ...]:
        return tuple(f for f in self.functions if f.is_handler)

    @property
    def consensus(self) -> tuple[GoFunction, ...]:
        return tuple(f for f in self.functions if f.is_consensus)

    @property
    def stubs(self) -> tuple[GoFunction, ...]:
        return tuple(f for f in self.functions if f.stub)


def _scan_types(
    stripped: str, package: str, start: int, end: int
) -> tuple[GoType, ...]:
    out: list[GoType] = []
    region = stripped[start:end]
    for m in _TYPE.finditer(region):
        name, kind = m.group(1), m.group(2)
        if kind not in ("struct", "interface"):
            continue
        brace = stripped.find("{", start + m.end() - 1)
        if brace == -1 or brace > end:
            continue
        close = _match_brace(stripped, brace)
        fields: list[str] = []
        for raw in stripped[brace + 1:close].splitlines():
            line = raw.strip()
            if not line or line.startswith("//"):
                continue
            fields.append(line)
        out.append(GoType(package=package, name=name, kind=kind,
                          fields=tuple(fields), line=line_of(stripped, start + m.start())))
    return tuple(out)


def _scan_functions(
    stripped: str, package: str, path: str, start: int, end: int,
    flavor: str, expression: str, stub_file: bool,
) -> tuple[GoFunction, ...]:
    out: list[GoFunction] = []
    region = stripped[start:end]
    for m in _FUNC.finditer(region):
        receiver = _receiver_type(m.group(1) or "")
        name = m.group(2)
        paren_open = start + m.end() - 1
        paren_close = _match_paren(stripped, paren_open)
        if paren_close <= paren_open or paren_close > end:
            continue
        header_start = paren_close + 1
        brace = stripped.find("{", header_start)
        semi = stripped.find(";", header_start)
        if brace == -1 or brace > end or (semi != -1 and semi < brace):
            continue
        close = _match_brace(stripped, brace)
        body = stripped[brace + 1:close]
        params = _split_top(stripped[paren_open + 1:paren_close])
        ret_raw = stripped[header_start:brace].strip()
        if ret_raw.startswith("(") and ret_raw.endswith(")"):
            returns = _split_top(ret_raw[1:-1])
        elif ret_raw:
            returns = (ret_raw,)
        else:
            returns = ()
        calls = tuple(sorted({c for c in _CALL.findall(body)
                              if c not in ("if", "for", "switch", "select", "func",
                                           "return", "make", "new", "append", "len",
                                           "cap", "copy", "delete", "panic", "recover")}))
        stub = stub_file or _is_stub_body(body, stub_file)
        out.append(GoFunction(
            package=package,
            path=path,
            receiver=receiver,
            name=name,
            signature=" ".join(stripped[start + m.start():brace].split()),
            params=params,
            returns=returns,
            body=body,
            line=line_of(stripped, start + m.start()),
            build_flavor=flavor,
            build_expression=expression,
            stub=stub,
            calls=calls,
        ))
    return tuple(out)


def _module_info(start: Path) -> tuple[str, Optional[Path]]:
    """The nearest ``go.mod`` module path and its directory.

    A monorepo can hold more than one module; the file's own module decides its
    import path, not the scan root.
    """
    current = start if start.is_dir() else start.parent
    while True:
        manifest = current / "go.mod"
        try:
            for line in manifest.read_text(encoding="utf-8").splitlines():
                stripped = line.strip()
                if stripped.startswith("module "):
                    return stripped[len("module "):].strip().strip('"'), current
        except OSError:
            pass
        if current.parent == current:
            return "", None
        current = current.parent


def _scan_file(path: Path, root: Path, errors: list[str], *,
               module: str = "", module_root: Optional[Path] = None) -> tuple[
    Optional[GoPackage], list[GoBoundary], str, str
]:
    try:
        raw = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:  # pragma: no cover - unreadable file
        errors.append(f"{path}: {exc}")
        return None, [], "", ""
    if "package " not in raw:
        return None, [], "", ""
    package_match = _PACKAGE.search(raw)
    package = package_match.group(1) if package_match else path.parent.name
    flavor, expression = _build_flavor(raw)
    stub_file = flavor == "community" or path.name.endswith("_stub.go")
    stripped = strip_go_noise(raw)
    rel = str(path.relative_to(root)) if path.is_relative_to(root) else str(path)
    functions = _scan_functions(stripped, package, rel, 0, len(stripped), flavor,
                                expression, stub_file)
    types = _scan_types(stripped, package, 0, len(stripped))

    imports = set(_IMPORT_LINE.findall(raw))
    for block in _IMPORT_BLOCK.findall(raw):
        imports.update(re.findall(r'"([^"]+)"', block))
    boundaries: list[GoBoundary] = []
    for imp in sorted(imports):
        if imp == "C" or "/ffi" in imp or "libqore" in imp or imp.endswith("/svm"):
            boundaries.append(GoBoundary(
                package=package,
                path=str(path.relative_to(root)) if path.is_relative_to(root) else str(path),
                line=line_of(raw, raw.find(imp)),
                kind="cgo" if imp == "C" else "ffi-import",
                detail=imp,
            ))

    base = module_root or root
    rel_dir = (str(path.parent.relative_to(base))
               if path.parent.is_relative_to(base) else str(path.parent))
    import_path = ""
    if module:
        import_path = module if rel_dir in ("", ".") else f"{module}/{rel_dir}"
    pkg = GoPackage(name=package, path=rel_dir,
                    files=(rel,), functions=functions, types=types,
                    imports=_parse_imports(raw), import_path=import_path)
    return pkg, boundaries, flavor, expression


def _walk(root: Path, include_tests: bool) -> Iterator[Path]:
    for path in sorted(root.rglob("*.go")):
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if not include_tests and path.name.endswith("_test.go"):
            continue
        yield path


def ingest_go(path: str | Path, *, include_tests: bool = False,
              max_files: int = 20000) -> GoSurfaceReport:
    """Scan a Go file or module root into a :class:`GoSurfaceReport`."""
    root_path = Path(path).expanduser()
    errors: list[str] = []
    files: list[str] = []
    packages: dict[tuple[str, str], GoPackage] = {}
    boundaries: list[GoBoundary] = []
    flavors: dict[str, int] = {}
    stub_files: list[str] = []
    full_files: list[str] = []

    if root_path.is_file():
        candidates = [root_path]
    elif root_path.is_dir():
        candidates = list(_walk(root_path, include_tests))
    else:
        return GoSurfaceReport(root=str(root_path),
                               errors=(f"path does not exist: {root_path}",))
    if len(candidates) > max_files:
        errors.append(f"truncated: {len(candidates)} .go files, scanned {max_files}")
        candidates = candidates[:max_files]

    module_cache: dict[Path, tuple[str, Optional[Path]]] = {}
    for file_path in candidates:
        module, module_root = module_cache.setdefault(
            file_path.parent, _module_info(file_path.parent))
        pkg, bounds, flavor, _expr = _scan_file(
            file_path, root_path, errors, module=module, module_root=module_root)
        if pkg is None:
            continue
        files.append(pkg.files[0])
        boundaries.extend(bounds)
        flavors[flavor] = flavors.get(flavor, 0) + 1
        if flavor == "community":
            stub_files.append(pkg.files[0])
        elif flavor == "full":
            full_files.append(pkg.files[0])
        key = (pkg.name, pkg.path)
        existing = packages.get(key)
        if existing is None:
            packages[key] = pkg
        else:
            packages[key] = GoPackage(
                name=existing.name, path=existing.path,
                files=existing.files + pkg.files,
                functions=existing.functions + pkg.functions,
                types=existing.types + pkg.types,
                imports=tuple(sorted(set(existing.imports + pkg.imports))),
                import_path=existing.import_path or pkg.import_path,
            )

    return GoSurfaceReport(
        root=str(root_path),
        files=tuple(files),
        packages=tuple(sorted(packages.values(), key=lambda p: (p.path, p.name))),
        boundaries=tuple(boundaries),
        errors=tuple(errors),
        build_flavors=tuple(sorted(flavors.items())),
        stub_files=tuple(stub_files),
        full_files=tuple(full_files),
    )
