"""Recover the scanner's surface from solc's AST, not from a lexer.

The lexer scanner in :mod:`blackheart.ingest.solidity` is deliberately
dependency-free and tolerant of partial source. A compiler AST is the stronger
input when one is available: it already resolved inheritance, struct fields,
modifier names, parameter types and return types. This module maps that AST into
the same :class:`ContractSurface` / :class:`FunctionSurface` objects, so every
downstream engine -- synthesis, certification, pricing, verification -- consumes
one model shape regardless of where the surface came from.

Nothing is guessed. A node whose ``src`` cannot be resolved keeps an empty body
and is therefore unmodelled by the interpreter, never silently treated as a
no-op. A source unit with no contract definitions returns an empty tuple.
"""

from __future__ import annotations

from typing import Any, Iterable, Optional

from .solidity import ContractSurface, FunctionSurface


def _source_list(sources: dict[str, str] | Iterable[str] | None) -> list[str]:
    if sources is None:
        return []
    if isinstance(sources, dict):
        return [sources[k] for k in sorted(sources)]
    return [str(s) for s in sources]


def _src(src: Any) -> tuple[int, int, int]:
    if not isinstance(src, str):
        return 0, 0, 0
    parts = src.split(":")
    try:
        start = int(parts[0])
        length = int(parts[1])
        index = int(parts[2]) if len(parts) > 2 else 0
    except (ValueError, IndexError):
        return 0, 0, 0
    return start, length, index


def _source_for(sources: list[str], index: int) -> str:
    if 0 <= index < len(sources):
        return sources[index]
    return ""


def _slice(text: str, src: Any) -> str:
    start, length, _ = _src(src)
    if length <= 0 or start < 0 or start >= len(text):
        return ""
    return text[start:start + length]


def _line(text: str, src: Any) -> int:
    start, _, _ = _src(src)
    if start < 0:
        return 1
    return text.count("\n", 0, start) + 1


def _type_string(node: dict) -> str:
    desc = node.get("typeDescriptions") or {}
    value = desc.get("typeString") if isinstance(desc, dict) else ""
    if value:
        return str(value)
    name = node.get("typeName") or {}
    if isinstance(name, dict):
        return str(name.get("name") or name.get("typeString") or "")
    return ""


def _param(node: dict) -> str:
    typ = _type_string(node)
    name = str(node.get("name") or "")
    return f"{typ} {name}".strip()


def _signature(name: str, params: Iterable[dict]) -> str:
    return f"{name}({','.join(_type_string(p) for p in params)})"


def _body(text: str, node: dict) -> str:
    raw = _slice(text, node.get("src"))
    if not raw:
        return ""
    start, end = raw.find("{"), raw.rfind("}")
    if 0 <= start < end:
        return raw[start + 1:end]
    return raw


def _modifier_names(node: dict) -> tuple[str, ...]:
    names: list[str] = []
    for mod in node.get("modifiers") or []:
        if not isinstance(mod, dict):
            continue
        name = (mod.get("modifierName") or {}).get("name")
        if name and name not in names:
            names.append(str(name))
    return tuple(names)


def _function(node: dict, contract: str, text: str) -> Optional[FunctionSurface]:
    if node.get("nodeType") != "FunctionDefinition":
        return None
    kind = str(node.get("kind") or "function")
    if kind == "constructor":
        return None
    name = str(node.get("name") or kind)
    params_node = node.get("parameters") or {}
    params = tuple(_param(p) for p in (params_node.get("parameters") or [])
                   if isinstance(p, dict))
    returns_node = node.get("returnParameters") or {}
    returns = tuple(_type_string(p) for p in (returns_node.get("parameters") or [])
                    if isinstance(p, dict))
    visibility = str(node.get("visibility") or "public")
    mutability = str(node.get("stateMutability") or "nonpayable")
    return FunctionSurface(
        contract=contract,
        name=name,
        signature=_signature(name, params_node.get("parameters") or []),
        visibility=visibility,
        mutability=mutability,
        modifiers=_modifier_names(node),
        params=params,
        body=_body(text, node),
        line=_line(text, node.get("src")),
        returns=returns,
    )


def _contract(node: dict, sources: list[str]) -> Optional[ContractSurface]:
    if node.get("nodeType") != "ContractDefinition":
        return None
    text = _source_for(sources, _src(node.get("src"))[2])
    name = str(node.get("name") or "")
    state_vars: list[str] = []
    state_types: list[tuple[str, str]] = []
    structs: list[tuple[str, tuple[tuple[str, str], ...]]] = []
    modifiers: list[str] = []
    functions: list[FunctionSurface] = []
    bases: list[str] = []
    for base in node.get("baseContracts") or []:
        if not isinstance(base, dict):
            continue
        base_name = (base.get("baseName") or {}).get("name")
        if base_name:
            bases.append(str(base_name))
    for child in node.get("nodes") or []:
        if not isinstance(child, dict):
            continue
        kind = child.get("nodeType")
        if kind == "VariableDeclaration" and child.get("stateVariable"):
            var = str(child.get("name") or "")
            if var:
                state_vars.append(var)
                state_types.append((var, _type_string(child)))
        elif kind == "StructDefinition":
            members = tuple(
                (str(m.get("name") or ""), _type_string(m))
                for m in (child.get("members") or []) if isinstance(m, dict)
            )
            structs.append((str(child.get("name") or ""), members))
        elif kind == "ModifierDefinition":
            mod = str(child.get("name") or "")
            if mod:
                modifiers.append(mod)
        elif kind == "FunctionDefinition":
            func = _function(child, name, text)
            if func is not None:
                functions.append(func)
    if not name:
        return None
    return ContractSurface(
        name=name,
        kind=str(node.get("contractKind") or "contract"),
        path=_source_for(sources, _src(node.get("src"))[2]),
        line=_line(text, node.get("src")),
        functions=tuple(functions),
        state_vars=tuple(state_vars),
        modifiers_defined=tuple(modifiers),
        bases=tuple(bases),
        state_types=tuple(state_types),
        structs=tuple(structs),
    )


def surfaces_from_ast(
    ast: Any,
    sources: dict[str, str] | Iterable[str] | None = None,
) -> tuple[ContractSurface, ...]:
    """Map one solc source-unit AST into contract surfaces.

    ``sources`` is the source text for every file index in ``src``. A mapping is
    ordered by path (the order solc uses); a sequence is used as supplied. An AST
    wrapped as ``{"AST": {...}}`` is unwrapped. A non-AST value returns ``()``.
    """
    if not isinstance(ast, dict):
        return ()
    if "AST" in ast and isinstance(ast["AST"], dict):
        ast = ast["AST"]
    nodes = ast.get("nodes")
    if not isinstance(nodes, list):
        return ()
    texts = _source_list(sources)
    out: list[ContractSurface] = []
    for node in nodes:
        contract = _contract(node, texts)
        if contract is not None:
            out.append(contract)
    return tuple(out)


__all__ = ["surfaces_from_ast"]
