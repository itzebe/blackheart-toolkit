"""Check that a source build is equivalent to a deployment, beyond raw bytes.

A metadata-stripped runtime match proves the bytes match. It does not prove the
ABI the source claims is the ABI the deployment dispatches. This module adds the
cheap, honest checks that can be made without a decompiler:

* recompile the source and compare the runtime with the deployed runtime;
* derive function selectors from the compiled ABI and from the deployed
  dispatcher's ``PUSH4`` values;
* report selectors the source claims but the deployment never dispatches, and
  selectors the deployment dispatches that the source does not claim.

``PUSH4`` scanning is a heuristic: an immediate value that happens to look like a
selector can be a false positive. A missing source selector is therefore a strong
signal, while an extra deployed selector is reported, not treated as a failure.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Optional

from .solc import compile_sources
from .verified import bind_runtime

STATUSES = ("EQUIVALENT", "SELECTOR_MISMATCH", "LAYOUT_MISMATCH",
            "AST_MISMATCH", "BYTECODE_MISMATCH", "INCOMPLETE", "NO_COMPILER")


@dataclass
class EquivalenceReport:
    status: str
    detail: str = ""
    binding: dict = field(default_factory=dict)
    source_selectors: list[str] = field(default_factory=list)
    deployed_selectors: list[str] = field(default_factory=list)
    missing_in_deployment: list[str] = field(default_factory=list)
    extra_in_deployment: list[str] = field(default_factory=list)
    compiler: str = ""
    artifact: str = ""
    layout: dict = field(default_factory=dict)
    ast_fingerprint: str = ""
    layout_match: Optional[bool] = None
    ast_match: Optional[bool] = None

    @property
    def equivalent(self) -> bool:
        return self.status == "EQUIVALENT"

    def to_dict(self) -> dict:
        return {"status": self.status, "equivalent": self.equivalent,
                "detail": self.detail, "binding": dict(self.binding),
                "source_selectors": list(self.source_selectors),
                "deployed_selectors": list(self.deployed_selectors),
                "missing_in_deployment": list(self.missing_in_deployment),
                "extra_in_deployment": list(self.extra_in_deployment),
                "compiler": self.compiler, "artifact": self.artifact,
                "layout": dict(self.layout), "ast_fingerprint": self.ast_fingerprint,
                "layout_match": self.layout_match, "ast_match": self.ast_match}


def selector_from_signature(signature: str) -> str:
    """A Solidity function selector. Keccak is not stdlib, so this is imported lazily."""
    from ..deployed import keccak256

    return keccak256(signature.encode("utf-8"))[:4].hex()


def selectors_from_abi(abi: list[dict]) -> set[str]:
    out: set[str] = set()
    for item in abi:
        if not isinstance(item, dict) or item.get("type") != "function":
            continue
        name = item.get("name")
        if not name:
            continue
        inputs = item.get("inputs") or []
        types = []
        for arg in inputs:
            if not isinstance(arg, dict):
                types = []
                break
            typ = str(arg.get("type", ""))
            if typ.startswith("tuple"):
                components = arg.get("components") or []
                inner = ",".join(str(c.get("type", "")) for c in components
                                 if isinstance(c, dict))
                typ = "(" + inner + ")" + typ[5:]
            types.append(typ)
        if len(types) != len(inputs):
            continue
        out.add(selector_from_signature(f"{name}({','.join(types)})"))
    return out


def selectors_in_bytecode(code: bytes) -> set[str]:
    """``PUSH4`` immediates in a runtime blob, as a selector heuristic."""
    out: set[str] = set()
    data = bytes(code)
    for i, op in enumerate(data[:-4]):
        if op == 0x63:  # PUSH4
            out.add(data[i + 1:i + 5].hex())
    return out


def _choose_artifact(artifacts: dict[str, Any], deployed: bytes):
    best = None
    for artifact in artifacts.values():
        raw = artifact.runtime_bytecode or artifact.bytecode
        text = raw[2:] if str(raw).startswith(("0x", "0X")) else str(raw)
        try:
            code = bytes.fromhex(text)
        except ValueError:
            continue
        if bind_runtime(code, deployed).bound:
            return artifact, code
        if best is None or len(code) > len(best[1]):
            best = (artifact, code)
    return best if best is not None else (None, b"")


_AST_DROP = frozenset({
    "src", "id", "documentation", "scope", "referencedDeclaration",
    "typeIdentifier", "exportedSymbols",
})


def _canonical_ast(node: Any) -> Any:
    """Drop compiler-local ids and source offsets, keep semantic fields."""
    if isinstance(node, dict):
        return {key: _canonical_ast(value) for key, value in sorted(node.items())
                if key not in _AST_DROP}
    if isinstance(node, list):
        return [_canonical_ast(value) for value in node]
    return node


def ast_fingerprint(ast: dict) -> str:
    """A stable semantic digest of a Solidity AST.

    Compiler ids, source offsets and documentation are removed; node types,
    names, operators, literals, visibility and type strings remain. The digest
    is not an equivalence proof for arbitrary compiler versions, so callers
    report it as evidence and never as a bytecode-level guarantee.
    """
    if not ast:
        return ""
    payload = json.dumps(_canonical_ast(ast), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def storage_signature(layout: dict) -> tuple[tuple[str, str, int, str], ...]:
    """Stable ``(label, slot, offset, type)`` rows from a solc storage layout."""
    rows = []
    for item in (layout or {}).get("storage") or []:
        if not isinstance(item, dict):
            continue
        rows.append((str(item.get("label", "")), str(item.get("slot", "")),
                     int(item.get("offset", 0) or 0), str(item.get("type", ""))))
    return tuple(sorted(rows))


def check_equivalence(
    files: dict[str, str],
    deployed_runtime: bytes,
    *,
    compiler: str = "",
    expected_abi: Optional[list[dict]] = None,
    expected_storage_layout: Optional[dict] = None,
    expected_ast: Optional[dict | str] = None,
    runner: Any = None,
    timeout: int = 180,
) -> EquivalenceReport:
    """Compile, bind and compare the source's selectors with the deployment's."""
    if not files:
        return EquivalenceReport("INCOMPLETE", "no source files")
    if not deployed_runtime:
        return EquivalenceReport("INCOMPLETE", "no deployed runtime was supplied")
    requested = compiler
    if not requested and (expected_storage_layout is not None or expected_ast is not None):
        from ..engines.solidity.base import resolve_tool
        if resolve_tool("solc") is not None:
            requested = "solc"
    outcome = compile_sources(files, compiler=requested, timeout=timeout, runner=runner)
    if not outcome.ok:
        status = "NO_COMPILER" if outcome.status == "NO_COMPILER" else "INCOMPLETE"
        return EquivalenceReport(status, outcome.reason, compiler=outcome.tool)
    artifact, code = _choose_artifact(outcome.artifacts, deployed_runtime)
    if artifact is None:
        return EquivalenceReport("INCOMPLETE", "the compiler produced no usable artifact",
                                 compiler=outcome.tool)
    binding = bind_runtime(code, deployed_runtime)
    source_selectors = selectors_from_abi(artifact.abi)
    if expected_abi is not None:
        source_selectors |= selectors_from_abi(expected_abi)
    deployed_selectors = selectors_in_bytecode(deployed_runtime)
    missing = sorted(source_selectors - deployed_selectors) if deployed_selectors else []
    extra = sorted(deployed_selectors - source_selectors) if source_selectors else []
    layout = dict(artifact.storage_layout or {})
    layout_match: Optional[bool] = None
    ast_match: Optional[bool] = None
    fingerprint = ast_fingerprint(artifact.ast or {})
    detail = binding.detail
    if not binding.bound:
        status = "BYTECODE_MISMATCH"
    elif missing:
        status = "SELECTOR_MISMATCH"
        detail += f"; {len(missing)} source selector(s) are not dispatched"
    else:
        status = "EQUIVALENT"
        detail += "; source selectors are dispatched"
        if not deployed_selectors:
            detail += " (no PUSH4 selector was recovered; bytecode-only check)"
    if expected_storage_layout is not None:
        if not layout:
            status = "INCOMPLETE"
            detail += "; the compiler produced no storage layout to compare"
        else:
            layout_match = storage_signature(layout) == storage_signature(
                expected_storage_layout)
            if not layout_match:
                status = "LAYOUT_MISMATCH"
                detail += "; storage layout differs from the expected layout"
    if expected_ast is not None:
        if not fingerprint:
            status = "INCOMPLETE"
            detail += "; the compiler produced no AST to compare"
        else:
            wanted = expected_ast if isinstance(expected_ast, str) else ast_fingerprint(
                expected_ast)
            ast_match = fingerprint == wanted
            if not ast_match:
                status = "AST_MISMATCH"
                detail += "; the AST fingerprint differs from the expected source"
    return EquivalenceReport(
        status, detail, binding.to_dict(), sorted(source_selectors),
        sorted(deployed_selectors), missing, extra, outcome.tool,
        artifact.contract, layout, fingerprint, layout_match, ast_match,
    )
