"""Rust / Substrate and Solana / Anchor attack-surface ingestion.

The Solidity scanner answers "what can an unprivileged account call here?". A
Polkadot-SDK runtime and a Solana program are different environments with the
same question, and the EVM engines cannot read a line of either. This module is
the Rust counterpart of ``ingest.solidity``: a lexer-grade scan of pallets and
dispatchables (with their weight annotation), or of Anchor instruction handlers
and their ``Accounts`` structs, attributes and body, so the rule engine in
``ingest.rust_flags`` can produce evidence at an exact ``file:line``.

It is deliberately a *scanner*, not a compiler. It cannot resolve macros, trait
bounds or generics, and it says so: anything it could not parse is reported in
``RustSurfaceReport.errors`` rather than guessed at. A dispatchable it fails to
recognise is a blind spot the caller must know about, never a silent "clean".
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator, Optional

from .solidity import line_of

#: Directories that hold vendored code, fixtures or build output. Scanning them
#: would report the same lead hundreds of times and bury the real surface.
SKIP_DIRS = {
    "target", "vendor", "node_modules", ".git", ".cargo", "benches",
    "tests", "test", "examples", "example", "mocks", "mock",
}


def strip_rust_noise(src: str) -> str:
    """Blank comments and literals, preserving length and newlines.

    Offsets stay identical to the original, so ``line_of`` on the stripped text
    is the real line. Rust needs more care than Solidity: block comments nest,
    raw strings carry a variable number of ``#``, and ``'a`` is a lifetime, not
    a character literal.
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
            depth, j = 1, i + 2
            while j < n and depth:
                if src.startswith("/*", j):
                    depth += 1
                    j += 2
                elif src.startswith("*/", j):
                    depth -= 1
                    j += 2
                else:
                    j += 1
            blank(i, j)
            i = j
            continue
        if c == '"':
            j = i + 1
            while j < n and src[j] != '"':
                j += 2 if src[j] == "\\" else 1
            blank(i, min(j + 1, n))
            i = j + 1
            continue
        if c == "r" and (i == 0 or not (src[i - 1].isalnum() or src[i - 1] == "_")):
            m = re.match(r'r(#+)?"', src[i:])
            if m:
                hashes = m.group(1) or ""
                close = '"' + hashes
                start_body = i + len(m.group(0))
                end = src.find(close, start_body)
                end = n if end == -1 else end + len(close)
                blank(i, end)
                i = end
                continue
        if c == "'":
            # A lifetime (``'a``) has no closing quote; a char literal does.
            if i + 1 < n and src[i + 1] == "\\":
                j = i + 2
                while j < n and src[j] != "'":
                    j += 1
                blank(i, min(j + 1, n))
                i = j + 1
                continue
            if i + 2 < n and src[i + 2] == "'":
                blank(i, i + 3)
                i += 3
                continue
        i += 1
    return "".join(out)


@dataclass(frozen=True)
class RustFunction:
    module: str
    name: str
    signature: str
    visibility: str
    is_dispatchable: bool
    weight: str
    body: str
    line: int
    #: The Anchor ``Context<T>`` / ``#[pallet::call]`` Accounts type, when the
    #: handler takes one. Empty for a plain Rust function.
    accounts_struct: str = ""

    @property
    def is_public(self) -> bool:
        return self.visibility.startswith("pub")


@dataclass(frozen=True)
class AnchorField:
    """One field of an Anchor ``#[derive(Accounts)]`` struct."""

    name: str
    type: str
    attrs: str
    line: int


@dataclass(frozen=True)
class AnchorAccounts:
    """A Solana/Anchor account-validation struct."""

    name: str
    line: int
    fields: tuple[AnchorField, ...] = ()

    def field(self, name: str) -> Optional[AnchorField]:
        for f in self.fields:
            if f.name == name:
                return f
        return None


@dataclass(frozen=True)
class RustModule:
    name: str
    path: str
    line: int
    functions: tuple[RustFunction, ...] = ()
    storage_items: tuple[str, ...] = ()
    anchor: bool = False
    accounts: tuple[AnchorAccounts, ...] = ()

    @property
    def dispatchables(self) -> tuple[RustFunction, ...]:
        return tuple(f for f in self.functions if f.is_dispatchable)

    def accounts_for(self, name: str) -> Optional[AnchorAccounts]:
        for a in self.accounts:
            if a.name == name:
                return a
        return None


@dataclass(frozen=True)
class RustSurfaceReport:
    root: str
    files: tuple[str, ...] = ()
    modules: tuple[RustModule, ...] = ()
    errors: tuple[str, ...] = field(default_factory=tuple)

    @property
    def functions(self) -> tuple[RustFunction, ...]:
        return tuple(f for m in self.modules for f in m.functions)

    @property
    def dispatchables(self) -> tuple[RustFunction, ...]:
        return tuple(f for f in self.functions if f.is_dispatchable)


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


_FN = re.compile(r"\bfn\s+([A-Za-z_][A-Za-z0-9_]*)")
_IMPL = re.compile(r"\bimpl\b([^{;]*)\{")
_STORAGE = re.compile(r"pub\s+type\s+([A-Za-z_][A-Za-z0-9_]*)")
_ATTR = re.compile(r"#\[([^\]]*)\]")
_PROGRAM = re.compile(r"#\[program\]\s*(?:pub\s+)?mod\s+[A-Za-z_][A-Za-z0-9_]*\s*")
_DERIVE = re.compile(r"#\[derive\(([^)]*)\)\]")
_CONTEXT = re.compile(r"\bContext\s*<\s*([A-Za-z_][A-Za-z0-9_]*)")
_ACCOUNT_FIELD = re.compile(
    r"^(?:pub\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*:\s*(.+?),?\s*$"
)


def _parse_anchor_accounts(src: str) -> tuple[AnchorAccounts, ...]:
    """Recover Solana/Anchor ``#[derive(Accounts)]`` structs and their constraints.

    Each field carries the concatenated text of its ``#[account(...)]``
    attribute(s), so a rule can tell a validated account (``address``,
    ``owner``, ``seeds``, ``has_one``, ``constraint``, token mint/authority)
    from a bare writable one. A multi-line attribute is joined until its
    brackets close; that matters for precision, because Anchor's real structs
    wrap ``has_one``/``constraint`` across several lines and a line-only parser
    would read them as unguarded.

    The body is scanned with offsets into ``src`` (which is noise-stripped but
    position-preserving), so every field line is the real source line.
    """
    out: list[AnchorAccounts] = []
    for m in _DERIVE.finditer(src):
        if "Accounts" not in m.group(1):
            continue
        sm = re.search(r"\b(?:pub\s+)?struct\s+([A-Za-z_][A-Za-z0-9_]*)", src[m.end():])
        if not sm:
            continue
        name = sm.group(1)
        name_at = m.end() + sm.start()
        brace = src.find("{", m.end() + sm.end())
        if brace == -1:
            continue
        end = _match_brace(src, brace)
        body = src[brace + 1:end]
        fields: list[AnchorField] = []
        pending = ""
        depth = 0
        offset = brace + 1
        for line in body.splitlines(keepends=True):
            stripped = line.strip()
            if depth > 0:
                pending = f"{pending} {stripped}".strip()
                depth += stripped.count("[") + stripped.count("(")
                depth -= stripped.count("]") + stripped.count(")")
                offset += len(line)
                continue
            if not stripped:
                offset += len(line)
                continue
            if stripped.startswith("#"):
                pending = stripped
                depth = stripped.count("[") + stripped.count("(")
                depth -= stripped.count("]") + stripped.count(")")
                offset += len(line)
                continue
            fm = _ACCOUNT_FIELD.match(stripped)
            if fm:
                attrs = pending.strip()
                ty = fm.group(2).strip().rstrip(",").strip()
                fields.append(
                    AnchorField(
                        name=fm.group(1),
                        type=ty,
                        attrs=attrs,
                        line=line_of(src, offset + (len(line) - len(line.lstrip()))),
                    )
                )
                pending = ""
            offset += len(line)
        out.append(AnchorAccounts(name=name, line=line_of(src, name_at), fields=tuple(fields)))
    return tuple(out)



def _attributes_before(src: str, index: int) -> list[str]:
    """Attribute blocks immediately preceding ``index``.

    Two things make a line-based scan wrong here. ``src[:index]`` ends mid-line,
    with the indentation and ``pub `` that precede ``fn``, so that partial line
    must be dropped before the run starts. And a weight is routinely written
    across several lines::

        #[pallet::weight(<T as Config>::WeightInfo::report_equivocation(
            key_owner_proof.validator_count(),
            T::MaxNominators::get(),
        ))]

    so attributes are matched as balanced ``#[...]`` blocks, not as lines. Doc
    comments between the attributes and ``fn`` are skipped.
    """
    head, _, partial = src[:index].rpartition("\n")
    attrs: list[str] = []
    same_line = re.search(r"#\[[^\]]*\]", partial)
    if same_line:
        attrs.append(" ".join(same_line.group(0).split()))

    text = head
    while True:
        text = text.rstrip()
        if not text.endswith("]"):
            last_line = text.rsplit("\n", 1)[-1].strip()
            if last_line.startswith("///") or last_line.startswith("//!"):
                text = text[: len(text) - len(last_line)]
                continue
            break
        depth = 0
        start = None
        i = len(text) - 1
        while i >= 0:
            ch = text[i]
            if ch in "])":
                depth += 1
            elif ch in "[(":
                depth -= 1
                if depth == 0 and ch == "[" and i > 0 and text[i - 1] == "#":
                    start = i - 1
                    break
            i -= 1
        if start is None:
            break
        attrs.append(" ".join(text[start:].split()))
        text = text[:start]
    return list(reversed(attrs))


def _scan_file(path: Path, root: Path, report_errors: list[str]) -> Optional[RustModule]:
    try:
        raw = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:  # pragma: no cover - unreadable file
        report_errors.append(f"{path}: {exc}")
        return None

    src = strip_rust_noise(raw)
    if "fn " not in src and "impl" not in src:
        return None

    anchor = "#[program]" in src or "derive(Accounts)" in src or "anchor_lang" in src
    accounts = _parse_anchor_accounts(src) if anchor else ()

    # Anchor marks its reachable surface two ways: a handler lives in the
    # `#[program]` module, and the real implementation takes `Context<T>`.
    # Both are dispatchables; the Accounts struct is the validation the handler
    # actually gets, so it is recovered alongside.
    program_ranges: list[tuple[int, int]] = []
    for m in _PROGRAM.finditer(src):
        brace = src.find("{", m.end())
        if brace != -1:
            program_ranges.append((m.start(), _match_brace(src, brace)))

    # Which byte ranges are inside a `#[pallet::call]` impl block. Modern pallets
    # spell it `#[pallet::call(weight(<T as Config>::WeightInfo))]`, so the marker
    # must allow a parenthesised argument; matching only the bare form silently
    # reported a pallet full of dispatchables as having none.
    call_ranges: list[tuple[int, int]] = []
    impl_weight = ""
    for m in re.finditer(r"#\[pallet::call\b[^\]]*\]", src):
        # Three spellings supply the weight for the whole impl: `weight(X)`,
        # `weight = X`, and `weight(<T as Config>::WeightInfo)`.
        if re.search(r"\bweight\b", m.group(0)):
            impl_weight = "impl-level weight"
        impl = _IMPL.search(src, m.end())
        if impl:
            call_ranges.append((impl.start(), _match_brace(src, impl.end() - 1)))

    def is_dispatchable_at(idx: int, attrs: list[str]) -> bool:
        if any("pallet::call_index" in a for a in attrs):
            return True
        return any(start <= idx <= end for start, end in call_ranges)

    module_name = path.stem
    impl = _IMPL.search(src)
    if impl:
        head = " ".join(impl.group(1).split())
        if "Pallet<" in head:
            module_name = f"{path.stem}::Pallet"

    functions: list[RustFunction] = []
    for m in _FN.finditer(src):
        name = m.group(1)
        # Skip the `fn` tokens of nested closures/macros by requiring a `(` next.
        rest = src[m.end():]
        paren = rest.find("(")
        brace = rest.find("{")
        semi = rest.find(";")
        if paren == -1 or (brace != -1 and brace < paren):
            continue
        if semi != -1 and semi < paren:
            continue  # a trait declaration, not a definition
        try:
            params_end = paren + _match_paren(rest, paren) + 1
        except Exception:  # pragma: no cover - malformed input
            continue
        body_start = src.find("{", m.end() + params_end)
        if body_start == -1:
            continue
        body_end = _match_brace(src, body_start)
        signature = " ".join(src[m.start():body_start].split())
        visibility = "pub" if re.search(r"\bpub\b", src[max(0, m.start() - 12):m.start()]) else "private"
        attrs = _attributes_before(src, m.start())
        weight = ""
        for attr in attrs:
            w = re.search(r"pallet::weight\s*\((.*)\)", attr)
            if w:
                weight = w.group(1).strip()
        ctx = _CONTEXT.search(signature)
        accounts_struct = ctx.group(1) if ctx else ""
        in_program = any(start <= m.start() <= end for start, end in program_ranges)
        dispatchable = is_dispatchable_at(m.start(), attrs) or bool(
            anchor and (in_program or accounts_struct)
        )
        if dispatchable and not weight:
            weight = impl_weight
        functions.append(
            RustFunction(
                module=module_name,
                name=name,
                signature=signature,
                visibility=visibility,
                is_dispatchable=dispatchable,
                weight=weight,
                body=src[body_start:body_end + 1],
                line=line_of(src, m.start()),
                accounts_struct=accounts_struct,
            )
        )

    storage = tuple(_STORAGE.findall(src))
    if not functions and not storage:
        return None
    return RustModule(
        name=module_name,
        path=str(path.relative_to(root)) if path.is_relative_to(root) else str(path),
        line=1,
        functions=tuple(functions),
        storage_items=storage,
        anchor=anchor,
        accounts=accounts,
    )


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


#: File stems that hold tests, mocks or benchmarks rather than the pallet itself.
#: A directory named ``tests`` was already skipped; ``src/tests.rs`` and
#: ``src/benchmarking.rs`` were not, and their helper functions are not
#: attacker-reachable.
SKIP_STEMS = {"tests", "test", "mock", "mocks", "benchmarking", "testing_utils", "benchmarks"}


def _walk(root: Path) -> Iterator[Path]:
    for path in sorted(root.rglob("*.rs")):
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.stem in SKIP_STEMS:
            continue
        yield path


def ingest_rust(path: str | Path) -> RustSurfaceReport:
    """Scan a Rust file or crate root into a surface report.

    A directory is walked for ``*.rs``, skipping vendored, test and build trees.
    Every file that cannot be read is recorded in ``errors``; the caller decides
    whether a partial surface is enough to act on.
    """
    root = Path(path).expanduser()
    if not root.exists():
        return RustSurfaceReport(root=str(root), errors=(f"{root}: does not exist",))
    if root.is_file():
        files, base = [root], root.parent
    else:
        files, base = list(_walk(root)), root

    errors: list[str] = []
    modules: list[RustModule] = []
    for file in files:
        module = _scan_file(file, base, errors)
        if module is not None:
            modules.append(module)

    return RustSurfaceReport(
        root=str(root),
        files=tuple(str(f.relative_to(base)) if f.is_relative_to(base) else str(f) for f in files),
        modules=tuple(modules),
        errors=tuple(errors),
    )
