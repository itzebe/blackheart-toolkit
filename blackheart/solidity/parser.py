"""A declaration-level Solidity parser built on the lexer.

It extracts the structure the model needs -- contracts, their state variables,
their functions and modifiers with visibility / state-mutability / role-bearing
modifier names -- and nothing else. It does not evaluate expressions, resolve
inheritance across imports, or type-check; those are ``solc``'s job, and where
they matter the extractor says so rather than guessing.

The scan is structural: a contract body is the token span between its braces, and
a function is a header (up to its body brace or ``;``) plus its body span. Body
spans are tracked so a call nested inside a function is never read as a
top-level declaration -- the failure mode of every regex-based "Solidity
extractor" that ends up inventing functions.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .lexer import Token, lex

_VISIBILITY = {"public", "private", "internal", "external"}
_MUTABILITY = {"pure", "view", "payable"}
_FUNCTION_KEYWORDS = {"function", "constructor", "fallback", "receive"}


@dataclass
class FunctionDecl:
    name: str                 # "constructor"/"fallback"/"receive" for those
    line: int
    visibility: str = ""      # public/private/internal/external ("" if unspecified)
    mutability: str = ""      # pure/view/payable ("" if non-payable non-view)
    modifiers: list[str] = field(default_factory=list)   # non-keyword modifier names
    params: list[tuple[str, str]] = field(default_factory=list)  # (type, name)
    returns: list[str] = field(default_factory=list)
    is_constructor: bool = False
    is_interface: bool = False
    body_present: bool = False
    calls: list[str] = field(default_factory=list)        # bare callee names in the body

    @property
    def mutating(self) -> bool:
        """A state-changing function: not view/pure and (unless interface) has a body."""
        return self.mutability not in ("view", "pure") and not self.is_interface

    @property
    def role_modifiers(self) -> list[str]:
        """Modifier names that read like an authorization guard."""
        return [m for m in self.modifiers if _looks_like_role(m)]


@dataclass
class StateVariable:
    name: str
    type: str
    line: int
    visibility: str = "internal"
    is_immutable: bool = False
    is_constant: bool = False


@dataclass
class ModifierDecl:
    name: str
    line: int


@dataclass
class ContractDecl:
    name: str
    kind: str                 # contract | interface | library | abstract
    line: int
    bases: list[str] = field(default_factory=list)
    functions: list[FunctionDecl] = field(default_factory=list)
    state_variables: list[StateVariable] = field(default_factory=list)
    modifiers: list[ModifierDecl] = field(default_factory=list)
    events: list[str] = field(default_factory=list)
    uses_reentrancy_guard: bool = False


@dataclass
class ParsedSource:
    path: str
    contracts: list[ContractDecl] = field(default_factory=list)
    pragma: str = ""
    imports: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def all_functions(self) -> list[tuple[ContractDecl, FunctionDecl]]:
        return [(c, f) for c in self.contracts for f in c.functions]


_ROLE_HINTS = (
    "onlyowner", "onlyadmin", "onlyrole", "onlygovernance", "onlygov",
    "onlygovernor", "onlyguardian", "onlymanager", "onlyoperator",
    "onlycontroller", "onlyvault", "onlykeeper", "onlypool", "onlyliquidator",
    "auth", "authorized", "requiresauth", "onlyminter", "onlyburner",
    "onlyoperatorrole", "restricted", "gated", "onlyregulator", "onlywhitelisted",
)


def _looks_like_role(name: str) -> bool:
    low = name.lower()
    if low in ("nonreentrant", "initializer", "reentrancyguard", "whennotpaused", "whenpaused"):
        return False
    if low.startswith("only") or low.startswith("requires"):
        return True
    return any(hint in low for hint in _ROLE_HINTS)


def _depth_scan(tokens: list[Token], start: int) -> int:
    """Return the index of the token just past the brace/paren group starting at
    ``start`` (which must be ``{`` or ``(``), or ``start`` if unbalanced."""
    opener = tokens[start].value
    closer = "}" if opener == "{" else ")"
    depth = 0
    i = start
    while i < len(tokens):
        v = tokens[i].value
        if v == opener:
            depth += 1
        elif v == closer:
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return len(tokens)


def _split_params(tokens: list[Token]) -> list[tuple[str, str]]:
    """Parse a parameter token list into (type, name) pairs.

    ``uint256 amount, address to`` -> ``[("uint256","amount"), ("address","to")]``.
    A parameter with no name keeps an empty name; a mapping/array type is joined
    into a single type string. Never invents a name.
    """
    params: list[tuple[str, str]] = []
    group: list[Token] = []
    depth = 0
    for tok in tokens + [Token("op", ",", 0, 0, 0)]:
        if tok.value in ("(", "["):
            depth += 1
        elif tok.value in (")", "]"):
            depth -= 1
        if tok.value == "," and depth == 0:
            params.append(_one_param(group))
            group = []
            continue
        group.append(tok)
    return [p for p in params if p[0] or p[1]]


def _one_param(group: list[Token]) -> tuple[str, str]:
    # Drop parameter-level keywords that are not part of the type.
    words = [t for t in group if t.kind in ("ident", "keyword", "number", "op")]
    # Location/data-availability specifiers are not part of the type name.
    specifiers = {"memory", "storage", "calldata", "indexed"}
    type_parts: list[str] = []
    name = ""
    for t in words:
        if t.value in specifiers:
            continue
        type_parts.append(t.value)
    # The last bare identifier is the parameter name if there is more than one
    # token and the last token is an identifier (not part of a type).
    if len(type_parts) >= 2 and group and group[-1].kind == "ident":
        name = type_parts[-1]
        type_parts = type_parts[:-1]
    return ("".join(type_parts).strip(), name)


def _read_decl_header(tokens: list[Token], i: int) -> tuple[FunctionDecl | None, int]:
    """Read a function declaration starting at ``tokens[i]`` (a function keyword).

    Returns the declaration and the index just past its header (at its body ``{``
    or its terminating ``;``). The caller consumes the body.
    """
    kw = tokens[i].value
    j = i + 1
    name = kw
    if kw == "function":
        # Optional name; `function () external` (fallback style) has none.
        if j < len(tokens) and tokens[j].kind in ("ident",):
            name = tokens[j].value
            j += 1
        elif j < len(tokens) and tokens[j].value == "(":
            name = "fallback"
    decl = FunctionDecl(name=name, line=tokens[i].line,
                        is_constructor=(kw == "constructor"))

    # Parameter list
    if j < len(tokens) and tokens[j].value == "(":
        end = _depth_scan(tokens, j)
        decl.params = _split_params(tokens[j + 1:end - 1])
        j = end

    # Modifiers / visibility / mutability / returns, up to body or ';'
    while j < len(tokens) and tokens[j].value not in ("{", ";"):
        t = tokens[j]
        if t.value == "returns":
            if j + 1 < len(tokens) and tokens[j + 1].value == "(":
                end = _depth_scan(tokens, j + 1)
                decl.returns = [tp for tp, _ in _split_params(tokens[j + 2:end - 1])]
                j = end
                continue
        if t.value in _VISIBILITY:
            decl.visibility = t.value
        elif t.value in _MUTABILITY:
            decl.mutability = t.value
        elif t.kind == "ident":
            decl.modifiers.append(t.value)
        j += 1
    return decl, j


def _collect_calls(tokens: list[Token]) -> list[str]:
    """Bare callee names invoked in a body: ``foo(...)`` -> ``foo``; ``x.foo(...)`` -> ``foo``."""
    calls: list[str] = []
    for k in range(len(tokens) - 1):
        if tokens[k + 1].value == "(" and tokens[k].kind == "ident":
            calls.append(tokens[k].value)
    return calls


def parse_source(path: str, text: str) -> ParsedSource:
    """Parse Solidity source text into contracts, functions, and state variables."""
    parsed = ParsedSource(path=path)
    try:
        tokens = lex(text)
    except ValueError as exc:
        parsed.errors.append(str(exc))
        return parsed

    i = 0
    n = len(tokens)
    while i < n:
        tok = tokens[i]
        if tok.value == "pragma":
            j = i + 1
            parts = []
            while j < n and tokens[j].value != ";":
                parts.append(tokens[j].value)
                j += 1
            parsed.pragma = " ".join(parts)
            i = j
            continue
        if tok.value == "import":
            j = i + 1
            parts = []
            while j < n and tokens[j].value != ";":
                parts.append(tokens[j].value)
                j += 1
            parsed.imports.append(" ".join(parts))
            i = j
            continue
        if tok.value in ("contract", "interface", "library", "abstract"):
            kind = tok.value
            j = i + 1
            if kind == "abstract" and j < n and tokens[j].value == "contract":
                j += 1
            if j >= n or tokens[j].kind != "ident":
                i += 1
                continue
            cname = tokens[j].value
            cdecl = ContractDecl(name=cname, kind=kind, line=tok.line)
            j += 1
            # Bases: `is A, B(...)`
            if j < n and tokens[j].value == "is":
                j += 1
                while j < n and tokens[j].value != "{":
                    if tokens[j].kind == "ident":
                        cdecl.bases.append(tokens[j].value)
                    j += 1
            if j < n and tokens[j].value == "{":
                body_end = _depth_scan(tokens, j)
                _parse_contract_body(tokens[j + 1:body_end - 1], cdecl, kind)
                parsed.contracts.append(cdecl)
                i = body_end
                continue
            parsed.contracts.append(cdecl)
            i = j
            continue
        i += 1

    return parsed


def _parse_contract_body(tokens: list[Token], cdecl: ContractDecl, kind: str) -> None:
    is_iface = kind == "interface"
    i = 0
    n = len(tokens)
    while i < n:
        tok = tokens[i]
        if tok.value in _FUNCTION_KEYWORDS:
            decl, j = _read_decl_header(tokens, i)
            if decl is None:
                i += 1
                continue
            decl.is_interface = is_iface
            if j < n and tokens[j].value == "{":
                body_end = _depth_scan(tokens, j)
                decl.body_present = True
                decl.calls = _collect_calls(tokens[j + 1:body_end - 1])
                if any(m.lower() in ("nonreentrant", "reentrancyguard") for m in decl.modifiers):
                    cdecl.uses_reentrancy_guard = True
                i = body_end
            else:
                i = j + 1
            cdecl.functions.append(decl)
            continue
        if tok.value == "modifier":
            if i + 1 < n and tokens[i + 1].kind == "ident":
                cdecl.modifiers.append(ModifierDecl(name=tokens[i + 1].value, line=tok.line))
            i += 1
            continue
        if tok.value in ("event", "error", "struct", "enum"):
            if i + 1 < n and tokens[i + 1].kind == "ident":
                cdecl.events.append(tokens[i + 1].value)
            i += 1
            continue
        # State variable: `Type [visibility] [immutable|constant] name [= ...];`
        if tok.kind in ("ident", "keyword") and tok.value not in ("using", "mapping"):
            sv = _try_state_variable(tokens, i)
            if sv is not None:
                var, j = sv
                cdecl.state_variables.append(var)
                i = j
                continue
        # mapping type
        if tok.value == "mapping":
            sv = _try_state_variable(tokens, i)
            if sv is not None:
                var, j = sv
                cdecl.state_variables.append(var)
                i = j
                continue
        i += 1


def _try_state_variable(tokens: list[Token], i: int) -> tuple[StateVariable, int] | None:
    """Attempt to read a state variable declaration at ``i``. Returns (var, next_i)."""
    n = len(tokens)
    j = i
    type_parts: list[str] = []
    # Read a type: ident/keyword plus optional mapping(...) and [] suffixes.
    if tokens[j].value == "mapping":
        type_parts.append("mapping")
        j += 1
        if j < n and tokens[j].value == "(":
            end = _depth_scan(tokens, j)
            type_parts.append("".join(t.value for t in tokens[j:end]))
            j = end
    else:
        if tokens[j].kind not in ("ident", "keyword"):
            return None
        type_parts.append(tokens[j].value)
        j += 1
        # Array suffixes
        while j < n and tokens[j].value == "[":
            end = _depth_scan(tokens, j)
            type_parts.append("".join(t.value for t in tokens[j:end]))
            j = end

    visibility = "internal"
    is_immutable = False
    is_constant = False
    name = ""
    # Optional specifiers then the name.
    while j < n:
        v = tokens[j].value
        if v in _VISIBILITY:
            visibility = v
            j += 1
            continue
        if v == "immutable":
            is_immutable = True
            j += 1
            continue
        if v == "constant":
            is_constant = True
            j += 1
            continue
        if tokens[j].kind == "ident":
            name = v
            j += 1
        break

    if not name:
        return None
    # Must terminate the declaration with ';' or an initialiser then ';'.
    k = j
    depth = 0
    while k < n:
        v = tokens[k].value
        if v in ("(", "["):
            depth += 1
        elif v in (")", "]"):
            depth -= 1
        elif v == ";" and depth == 0:
            break
        elif v == "{" and depth == 0:
            # This is a function/block, not a state variable.
            return None
        k += 1
    if k >= n or tokens[k].value != ";":
        return None
    var = StateVariable(name=name, type="".join(type_parts), line=tokens[i].line,
                        visibility=visibility, is_immutable=is_immutable,
                        is_constant=is_constant)
    return var, k + 1
