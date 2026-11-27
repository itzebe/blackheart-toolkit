"""Derive a runtime operation model from source, then validate it against reality.

The mission's Phase 2: "Use source inspection to propose models, but validate
those models against executable application behaviour. Static analysis alone is
not proof of runtime semantics."

This module does exactly that, in two clearly separated steps:

  1. **Propose** -- :func:`propose_model_from_source` reads a Python source file
     with :mod:`ast` (no imports, no execution) and proposes operations, actors,
     entry points, and invariants. Every proposal carries a *provenance* string
     (``path:lineno``) linking it to the exact declaration it came from. This is a
     proposal, never a claim.

  2. **Validate** -- :func:`validate_against_adapter` checks the proposal against
     a *running* adapter: does each proposed operation actually exist and dispatch?
     Which operations does the running app expose that the source did not reveal?
     The validated model is the one the engine should use, and the discrepancies
     are reported rather than hidden.

Where extraction is unreliable (an operation whose name reveals nothing, a guard
that is not statically visible), the extractor refuses to invent behaviour: it
emits the operation with ``source`` set to the declaration and leaves the guard
blank, and the *explicit adapter declaration* (the app's own ``model()``) supplies
the authoritative semantics. A model that invents an architecture is worse than no
model, so the proposal is always cross-checked against execution.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from ..model import SystemModel


@dataclass
class Proposal:
    """One operation proposed from source, with the provenance of the claim."""

    name: str
    provenance: str                       # "path:lineno"
    roles: tuple[str, ...] = ()
    entry_point: str = ""
    kind: str = ""                        # "handler" | "declared" | "route"

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "provenance": self.provenance,
            "roles": list(self.roles),
            "entry_point": self.entry_point,
            "kind": self.kind,
        }


@dataclass
class SourceModelProposal:
    source: str
    operations: list[Proposal] = field(default_factory=list)
    actors: list[str] = field(default_factory=list)
    invariants: list[dict] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "source": self.source,
            "operations": [o.to_dict() for o in self.operations],
            "actors": list(self.actors),
            "invariants": list(self.invariants),
            "notes": list(self.notes),
        }


def _string_arg(node: ast.AST) -> Optional[str]:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _str_tuple(node: ast.AST) -> tuple[str, ...]:
    if isinstance(node, (ast.Tuple, ast.List)):
        out = []
        for elt in node.elts:
            s = _string_arg(elt)
            if s is not None:
                out.append(s)
        return tuple(out)
    return ()


def propose_model_from_source(path: str | Path) -> SourceModelProposal:
    """Propose an operation model from a Python source file (no execution).

    Recognises two declaration styles:

    * ``Op("name", ("role", ...), handler, entry="POST /path")`` -- the harness
      app style; roles and entry point are read directly.
    * ``def op_<name>(self, state, actor, params)`` -- a handler method; the
      operation name is the suffix and the roles are unknown from the signature
      (recorded as empty, never guessed).

    Also reads ``AppInvariant("id", "title", ...)`` declarations for invariants.
    """
    src = Path(path)
    text = src.read_text(encoding="utf-8")
    tree = ast.parse(text, filename=str(src))
    proposal = SourceModelProposal(source=str(src))
    seen: set[str] = set()

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            fname = _callee_name(node.func)
            if fname == "Op":
                name = _string_arg(node.args[0]) if node.args else None
                if not name:
                    continue
                roles = _str_tuple(node.args[1]) if len(node.args) > 1 else ()
                entry = ""
                for kw in node.keywords:
                    if kw.arg == "entry":
                        entry = _string_arg(kw.value) or ""
                proposal.operations.append(Proposal(
                    name=name, provenance=f"{src}:{node.lineno}", roles=roles,
                    entry_point=entry or f"POST /{name}", kind="declared"))
                seen.add(name)
            elif fname == "AppInvariant":
                inv_id = _string_arg(node.args[0]) if node.args else None
                title = _string_arg(node.args[1]) if len(node.args) > 1 else ""
                if inv_id:
                    proposal.invariants.append({
                        "inv_id": inv_id, "statement": title,
                        "provenance": f"{src}:{node.lineno}"})
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.name.startswith("op_") and node.name[3:] not in seen:
                opname = node.name[3:]
                proposal.operations.append(Proposal(
                    name=opname, provenance=f"{src}:{node.lineno}",
                    entry_point=f"POST /{opname}", kind="handler"))
                seen.add(opname)

    if not proposal.operations:
        proposal.notes.append(
            "no operations could be extracted from source; an explicit, auditable "
            "adapter declaration is required rather than an invented model")
    return proposal


def _callee_name(func: ast.AST) -> str:
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return ""


@dataclass
class ValidationResult:
    validated: bool
    matched: list[str] = field(default_factory=list)
    missing_at_runtime: list[str] = field(default_factory=list)   # proposed, not executable
    undeclared_at_source: list[str] = field(default_factory=list)  # executable, not proposed
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "validated": self.validated,
            "matched": list(self.matched),
            "missing_at_runtime": list(self.missing_at_runtime),
            "undeclared_at_source": list(self.undeclared_at_source),
            "notes": list(self.notes),
        }


def validate_against_adapter(proposal: SourceModelProposal, adapter) -> ValidationResult:
    """Cross-check a source proposal against a *running* adapter's operations.

    Static analysis is not proof: an operation the source appears to define may
    not be executable, and a running app may expose operations the source scan did
    not reveal. Both discrepancies are reported; ``validated`` is True only when
    every proposed operation is actually executable.
    """
    runtime_ops = set(adapter.operations())
    proposed = {op.name for op in proposal.operations}
    res = ValidationResult(validated=False)
    res.matched = sorted(proposed & runtime_ops)
    res.missing_at_runtime = sorted(proposed - runtime_ops)
    res.undeclared_at_source = sorted(runtime_ops - proposed)
    if res.missing_at_runtime:
        res.notes.append(
            "proposed operations are not executable at runtime; the source model is "
            "not a valid runtime model")
    if res.undeclared_at_source:
        res.notes.append(
            "the running app exposes operations the source scan did not reveal; "
            "rely on the executable model, not the source proposal")
    res.validated = not res.missing_at_runtime and bool(proposed)
    return res


def model_from_source_and_runtime(path: str | Path, adapter) -> tuple[SystemModel, dict]:
    """Propose from source, validate against runtime, and return the runtime model.

    The returned model is the *executable* one (from the adapter), because only
    executed behaviour is proof. The validation result explains where the source
    proposal agreed or disagreed, so the derivation is auditable.
    """
    proposal = propose_model_from_source(path)
    validation = validate_against_adapter(proposal, adapter)
    return adapter.model(), {"proposal": proposal.to_dict(), "validation": validation.to_dict()}
