"""A ledger of what the executable model actually covers.

The statement-subset interpreter is deliberately honest at *runtime*: an
unmodelled call aborts the path and is recorded. That is not enough for a clean
verdict, because a target can contain a reachable function the alphabet never
included. The search would then be complete over its model while saying nothing
about the target.

This module makes that gap explicit before a search runs. Every function,
statement, call edge and function-level path is classified as:

``MODELLED``
    The model represents it and a search can exercise it.
``UNMODELLED``
    It is reachable but outside the model, with a reason and ``file:line``.
``UNREACHABLE``
    It is not reachable from an external entry point, so its absence from the
    model does not weaken a clean result.
``EXTERNAL``
    An external call that a single-contract model cannot apply. A protocol
    composition can resolve it; until then it is a named gap.

A ledger with any reachable ``UNMODELLED``/``EXTERNAL`` item is **incomplete**.
Callers must report ``INCOMPLETE``, never ``CLEAN`` or ``NO_FINDINGS``.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, replace
from typing import Any, Iterable, Optional

from .solidity import ContractSurface, FunctionSurface, strip_noise

MODELLED = "MODELLED"
UNMODELLED = "UNMODELLED"
UNREACHABLE = "UNREACHABLE"
EXTERNAL = "EXTERNAL"

#: Names that look like calls but are Solidity syntax, builtins or type casts.
_NON_CALLS = frozenset({
    "if", "else", "for", "while", "do", "return", "returns", "emit", "revert",
    "require", "assert", "new", "delete", "type", "abi", "address", "payable",
    "string", "bytes", "uint", "uint8", "uint16", "uint32", "uint64", "uint128",
    "uint256", "int", "int8", "int16", "int32", "int64", "int128", "int256",
    "bool", "byte", "mapping", "function", "constructor", "modifier", "event",
    "error", "struct", "enum", "contract", "interface", "library", "using",
    "unchecked", "assembly", "try", "catch", "super", "this",
})

_BARE_CALL = re.compile(r"(?<![\w.])([A-Za-z_]\w*)\s*\(")


@dataclass(frozen=True)
class StatementCoverage:
    contract: str
    function: str
    path: str
    line: int
    statement: str
    status: str
    reason: str = ""

    def to_dict(self) -> dict:
        return {
            "contract": self.contract,
            "function": self.function,
            "path": self.path,
            "line": self.line,
            "statement": self.statement,
            "status": self.status,
            "reason": self.reason,
        }


@dataclass(frozen=True)
class FunctionCoverage:
    contract: str
    name: str
    signature: str
    path: str
    line: int
    visibility: str
    reachable: bool
    status: str
    reason: str = ""
    modelled_statements: int = 0

    def to_dict(self) -> dict:
        return {
            "contract": self.contract,
            "name": self.name,
            "signature": self.signature,
            "path": self.path,
            "line": self.line,
            "visibility": self.visibility,
            "reachable": self.reachable,
            "status": self.status,
            "reason": self.reason,
            "modelled_statements": self.modelled_statements,
        }


@dataclass(frozen=True)
class CallEdgeCoverage:
    caller: str
    caller_op: str
    callee: str
    callee_op: str
    status: str
    reachable: bool = True
    reason: str = ""
    evidence: str = ""
    kind: str = ""

    def to_dict(self) -> dict:
        return {
            "caller": self.caller,
            "caller_op": self.caller_op,
            "callee": self.callee,
            "callee_op": self.callee_op,
            "status": self.status,
            "reachable": self.reachable,
            "reason": self.reason,
            "evidence": self.evidence,
            "kind": self.kind,
        }


@dataclass(frozen=True)
class PathCoverage:
    contract: str
    function: str
    path: str
    line: int
    status: str
    reason: str = ""
    branches: int = 0

    def to_dict(self) -> dict:
        return {
            "contract": self.contract,
            "function": self.function,
            "path": self.path,
            "line": self.line,
            "status": self.status,
            "reason": self.reason,
            "branches": self.branches,
        }


@dataclass
class ModelCoverage:
    contracts: tuple[str, ...] = ()
    functions: tuple[FunctionCoverage, ...] = ()
    statements: tuple[StatementCoverage, ...] = ()
    call_edges: tuple[CallEdgeCoverage, ...] = ()
    paths: tuple[PathCoverage, ...] = ()
    notes: tuple[str, ...] = ()
    available: bool = True

    @property
    def complete(self) -> bool:
        return self.available and not self.gaps

    @property
    def gaps(self) -> list[dict]:
        out: list[dict] = []
        for f in self.functions:
            if f.reachable and f.status != MODELLED:
                out.append({"kind": "function", **f.to_dict()})
        for s in self.statements:
            if s.status != MODELLED:
                out.append({"kind": "statement", **s.to_dict()})
        for e in self.call_edges:
            if e.reachable and e.status != MODELLED:
                out.append({"kind": "call_edge", **e.to_dict()})
        return out

    @property
    def summary(self) -> dict:
        reachable = [f for f in self.functions if f.reachable]
        return {
            "contracts": len(self.contracts),
            "functions": len(self.functions),
            "reachable_functions": len(reachable),
            "modelled_functions": sum(1 for f in reachable if f.status == MODELLED),
            "unmodelled_functions": sum(1 for f in reachable if f.status == UNMODELLED),
            "unreachable_functions": sum(1 for f in self.functions if not f.reachable),
            "statements": len(self.statements),
            "unmodelled_statements": sum(1 for s in self.statements
                                          if s.status != MODELLED),
            "call_edges": len(self.call_edges),
            "unmodelled_call_edges": sum(1 for e in self.call_edges
                                         if e.reachable and e.status != MODELLED),
            "gaps": len(self.gaps),
        }

    @property
    def fingerprint(self) -> str:
        payload = {
            "contracts": list(self.contracts),
            "functions": [f.to_dict() for f in self.functions],
            "statements": [s.to_dict() for s in self.statements],
            "call_edges": [e.to_dict() for e in self.call_edges],
            "paths": [p.to_dict() for p in self.paths],
        }
        return hashlib.sha256(
            json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
        ).hexdigest()[:16]

    def block_message(self) -> str:
        gaps = self.gaps
        if not gaps:
            return ""
        first = gaps[0]
        where = f"{first.get('path', '')}:{first.get('line', '')}"
        what = (first.get("statement") or first.get("callee_op")
                or first.get("name") or "unknown")
        return (f"model coverage incomplete: {len(gaps)} reachable gap(s); "
                f"first at {where} ({first.get('kind')}: {what})")

    def to_dict(self) -> dict:
        return {
            "available": self.available,
            "complete": self.complete,
            "fingerprint": self.fingerprint,
            "summary": self.summary,
            "contracts": list(self.contracts),
            "functions": [f.to_dict() for f in self.functions],
            "statements": [s.to_dict() for s in self.statements],
            "call_edges": [e.to_dict() for e in self.call_edges],
            "paths": [p.to_dict() for p in self.paths],
            "gaps": self.gaps,
            "notes": list(self.notes),
        }

    @classmethod
    def from_dict(cls, payload: dict) -> "ModelCoverage":
        if not payload:
            return cls(available=False)
        notes = payload.get("notes") or ()
        if isinstance(notes, str):
            notes = (notes,)
        return cls(
            contracts=tuple(payload.get("contracts") or ()),
            functions=tuple(FunctionCoverage(**f) for f in payload.get("functions") or ()),
            statements=tuple(StatementCoverage(**s) for s in payload.get("statements") or ()),
            call_edges=tuple(CallEdgeCoverage(**e) for e in payload.get("call_edges") or ()),
            paths=tuple(PathCoverage(**p) for p in payload.get("paths") or ()),
            notes=tuple(notes),
            available=bool(payload.get("available", True)),
        )


def _statement_line(func: FunctionSurface, statement: str) -> int:
    body = func.body or ""
    idx = body.find(statement) if statement else -1
    return func.line + (body[:idx].count("\n") if idx >= 0 else 0)


def _internal_calls(func: FunctionSurface, names: set[str]) -> set[str]:
    body = strip_noise(func.body or "")
    found: set[str] = set()
    for match in _BARE_CALL.finditer(body):
        name = match.group(1)
        if name in names and name not in _NON_CALLS:
            found.add(name)
    return found


def _reachable_internal(contract: ContractSurface) -> set[str]:
    """Names of internal functions reachable from an external entry point."""
    names = {f.name for f in contract.functions}
    external = {f.name for f in contract.functions
                if f.externally_callable and not f.declaration_only}
    edges: dict[str, set[str]] = {}
    for f in contract.functions:
        edges[f.name] = _internal_calls(f, names)
    reached = set(external)
    work = list(external)
    while work:
        name = work.pop()
        for callee in edges.get(name, set()):
            if callee not in reached:
                reached.add(callee)
                work.append(callee)
    return reached


def _coverage_for_contract(
    contract: ContractSurface,
    report: Any,
    target: Optional[Any],
) -> ModelCoverage:
    op_models = {}
    if target is not None and hasattr(target, "op_models"):
        op_models = {m.name: m for m in target.op_models()}
    reachable_internal = _reachable_internal(contract)
    function_cov: list[FunctionCoverage] = []
    statement_cov: list[StatementCoverage] = []
    edge_cov: list[CallEdgeCoverage] = []
    path_cov: list[PathCoverage] = []
    notes: list[str] = []

    # Internal call edges first, so a function that calls a non-operation helper
    # is marked unmodelled even when the statement parser accepted the call.
    internal_targets: dict[str, set[str]] = {}
    for func in contract.functions:
        internal_targets[func.name] = _internal_calls(
            func, {f.name for f in contract.functions})

    for func in contract.functions:
        model = op_models.get(func.name)
        reachable = func.externally_callable or func.name in reachable_internal
        status = MODELLED
        reason = ""
        modelled_statements = 0
        if func.externally_callable:
            if func.declaration_only:
                status, reason = UNMODELLED, "interface declaration has no body"
            elif model is None:
                status, reason = UNMODELLED, "no executable operation was synthesized"
            elif not model.modelled:
                status, reason = UNMODELLED, "the statement parser rejected at least one statement"
            else:
                modelled_statements = len(model.effects) + len(model.calls)
        elif reachable:
            status = UNMODELLED
            reason = ("internal function is reachable but is not an operation in "
                      "the model alphabet; its body is not simulated")
        else:
            status = UNREACHABLE
            reason = ("internal/private function is not called by any externally "
                      "reachable function")

        # A modelled external function that calls a non-operation internal helper
        # is not actually modelled: the runtime would abort at that call.
        for callee in sorted(internal_targets.get(func.name, ())):
            callee_func = next((f for f in contract.functions if f.name == callee), None)
            if callee_func is None or not callee_func.externally_callable:
                if status == MODELLED:
                    status = UNMODELLED
                    reason = (f"calls internal function {callee!r}, which is not an "
                              "operation in the model alphabet")

        function_cov.append(FunctionCoverage(
            contract=contract.name,
            name=func.name,
            signature=func.signature,
            path=contract.path,
            line=func.line,
            visibility=func.visibility,
            reachable=reachable,
            status=status,
            reason=reason,
            modelled_statements=modelled_statements,
        ))

        if model is not None and model.unmodelled:
            for statement in model.unmodelled:
                statement_cov.append(StatementCoverage(
                    contract=contract.name,
                    function=func.name,
                    path=contract.path,
                    line=_statement_line(func, statement),
                    statement=statement,
                    status=UNMODELLED,
                    reason="statement outside the modelled subset",
                ))

        # Internal edges are a gap when their target is not an operation.
        for callee in sorted(internal_targets.get(func.name, ())):
            callee_func = next((f for f in contract.functions if f.name == callee), None)
            if callee_func is None:
                continue
            edge_cov.append(CallEdgeCoverage(
                caller=contract.name,
                caller_op=func.name,
                callee=contract.name,
                callee_op=callee,
                status=(MODELLED if callee_func.externally_callable
                        and callee in op_models and op_models[callee].modelled
                        else UNMODELLED),
                reachable=reachable,
                reason=("internal call target is an operation in the model"
                        if callee_func.externally_callable
                        and callee in op_models and op_models[callee].modelled
                        else "internal call target is not an operation in the model"),
                evidence=f"{contract.name}.{func.name} -> {callee}",
                kind="internal",
            ))

        # External calls are not applied by a single-contract model.
        if model is not None:
            for call in model.calls:
                if not getattr(call, "receiver", ""):
                    continue
                edge_cov.append(CallEdgeCoverage(
                    caller=contract.name,
                    caller_op=func.name,
                    callee=getattr(call, "receiver", ""),
                    callee_op=getattr(call, "op", ""),
                    status=EXTERNAL,
                    reachable=reachable,
                    reason=("external call is applied only by a protocol composition; "
                            "a single-contract model does not move the callee state"),
                    evidence=f"{contract.name}.{func.name} -> {call.receiver}.{call.op}",
                    kind="external",
                ))

        branches = len([e for e in (model.effects if model is not None else ())
                        if getattr(e, "condition", None) is not None])
        path_cov.append(PathCoverage(
            contract=contract.name,
            function=func.name,
            path=contract.path,
            line=func.line,
            status=status,
            reason=("function-level path coverage only; branch enumeration is "
                    "bounded by the certifier depth" if status == MODELLED else reason),
            branches=branches,
        ))

    if not contract.functions:
        notes.append("the contract exposes no function surface")
    if any(f.status == UNMODELLED and f.reachable for f in function_cov):
        notes.append("at least one reachable function is outside the model; "
                     "a clean search result is not a clean target result")
    if any(e.status == EXTERNAL and e.reachable for e in edge_cov):
        notes.append("external calls are unresolved in this single-contract ledger; "
                     "compose the protocol to resolve them")

    return ModelCoverage(
        contracts=(contract.name,),
        functions=tuple(function_cov),
        statements=tuple(statement_cov),
        call_edges=tuple(edge_cov),
        paths=tuple(path_cov),
        notes=tuple(notes),
    )


def coverage_for_contract(contract: ContractSurface, report: Any,
                          target: Optional[Any] = None) -> ModelCoverage:
    """Build the ledger for one contract's synthesized model."""
    return _coverage_for_contract(contract, report, target)


def coverage_for_target(target: Any) -> ModelCoverage:
    """The ledger for any target, including hand-written registry targets.

    A hand-written target declares its operations directly; every declared
    operation is modelled by construction. A synthesized target carries its own
    ledger, which is returned unchanged. A target that declares the field but
    carries no ledger was supposed to be measured, so an absent measurement is
    never silently upgraded to "complete".
    """
    payload = getattr(target, "model_coverage", None)
    if isinstance(payload, ModelCoverage):
        return payload
    if isinstance(payload, dict) and payload:
        return ModelCoverage.from_dict(payload)
    if hasattr(target, "model_coverage"):
        return ModelCoverage(
            available=False,
            notes=("the target declares a model-coverage field but carries no "
                   "ledger; an absent measurement is not a complete model",),
        )
    ops = target.ops() if hasattr(target, "ops") else []
    functions = tuple(FunctionCoverage(
        contract=getattr(target, "name", "target"),
        name=op.name,
        signature=op.name,
        path="",
        line=0,
        visibility="external",
        reachable=True,
        status=MODELLED,
        reason="declared operation of a hand-written target",
    ) for op in ops)
    return ModelCoverage(
        contracts=(getattr(target, "name", "target"),),
        functions=functions,
        notes=("hand-written target: every declared operation is modelled by "
               "construction; no source-level statement ledger exists",),
    )


def protocol_coverage(targets: dict[str, Any],
                      links: Iterable[Any] = (),
                      graph: Optional[Any] = None) -> ModelCoverage:
    """Aggregate per-contract ledgers and resolve declared links.

    A link turns a matching ``EXTERNAL`` edge into ``MODELLED`` only when the
    callee operation is itself modelled. An unresolved edge stays a named gap.
    """
    functions: list[FunctionCoverage] = []
    statements: list[StatementCoverage] = []
    edges: list[CallEdgeCoverage] = []
    paths: list[PathCoverage] = []
    contracts: list[str] = []
    notes: list[str] = []
    for name, target in targets.items():
        part = coverage_for_target(target)
        contracts.extend(part.contracts)
        functions.extend(part.functions)
        statements.extend(part.statements)
        edges.extend(part.call_edges)
        paths.extend(part.paths)
        notes.extend(part.notes)

    # A declaration-only interface is not an executable entry point when a
    # concrete contract in the composition implements it. Leaving it as a
    # reachable gap made every interface-based protocol permanently INCOMPLETE
    # even though the implementation was modelled.
    implemented: set[tuple[str, str]] = set()
    for target in targets.values():
        surface = target.contract
        concrete = {f.name for f in surface.functions if not f.declaration_only}
        for name in (surface.name, *surface.bases):
            for op in concrete:
                implemented.add((name, op))

    def implemented_elsewhere(item: FunctionCoverage) -> bool:
        return (item.contract, item.name) in implemented

    functions = [
        replace(item, reachable=False, status=UNREACHABLE,
                reason=("interface declaration has no body; a concrete "
                        "implementation is modelled in the composed protocol"))
        if (item.status == UNMODELLED
            and item.reason == "interface declaration has no body"
            and implemented_elsewhere(item))
        else item
        for item in functions
    ]
    paths = [
        replace(item, status=UNREACHABLE,
                reason=("interface declaration has no body; a concrete "
                        "implementation is modelled in the composed protocol"))
        if (item.status == UNMODELLED
            and item.reason == "interface declaration has no body"
            and (item.contract, item.function) in implemented)
        else item
        for item in paths
    ]

    link_by_key: dict[tuple[str, str, str], Any] = {}
    for link in links:
        link_by_key[(link.caller, link.caller_op, link.callee_op)] = link
        callee = targets.get(link.callee)
        model = callee.op_model(link.callee_op) if callee is not None else None
        status = MODELLED if model is not None and model.modelled else UNMODELLED
        reason = ("declared link to a modelled operation"
                  if status == MODELLED else
                  f"link target {link.callee}.{link.callee_op} is not modelled")
        if link.caller not in targets or link.callee not in targets:
            status = UNMODELLED
            reason = "link names a contract outside the composed set"
        edges.append(CallEdgeCoverage(
            caller=link.caller, caller_op=link.caller_op,
            callee=link.callee, callee_op=link.callee_op,
            status=status, reachable=True, reason=reason,
            evidence=f"link {link.caller}.{link.caller_op} -> "
                     f"{link.callee}.{link.callee_op}",
            kind=getattr(link, "kind", "link"),
        ))

    resolved: list[CallEdgeCoverage] = []
    for edge in edges:
        if edge.status == EXTERNAL:
            link = link_by_key.get((edge.caller, edge.caller_op, edge.callee_op))
            if link is not None:
                callee = targets.get(link.callee)
                model = callee.op_model(link.callee_op) if callee is not None else None
                if model is not None and model.modelled:
                    resolved.append(CallEdgeCoverage(
                        caller=edge.caller, caller_op=edge.caller_op,
                        callee=link.callee, callee_op=link.callee_op,
                        status=MODELLED, reachable=edge.reachable,
                        reason="external edge resolved by a declared link",
                        evidence=edge.evidence, kind="resolved-link",
                    ))
                    continue
        resolved.append(edge)

    if graph is not None:
        for item in getattr(graph, "unresolved", ()) or ():
            resolved.append(CallEdgeCoverage(
                caller=str(item.get("caller", "")),
                caller_op=str(item.get("caller_op", "")),
                callee=str(item.get("receiver", "")),
                callee_op=str(item.get("callee_op", "")),
                status=UNMODELLED, reachable=True,
                reason=str(item.get("reason", "receiver could not be resolved")),
                evidence="callgraph unresolved", kind="unresolved",
            ))

    if not any(item.reachable and item.status != MODELLED for item in functions):
        notes = [note for note in notes
                 if not note.startswith("at least one reachable function")]
    if not any(edge.status == EXTERNAL for edge in resolved):
        notes = [note for note in notes
                 if "external calls are unresolved" not in note]

    cov = ModelCoverage(
        contracts=tuple(sorted(set(contracts))),
        functions=tuple(functions),
        statements=tuple(statements),
        call_edges=tuple(resolved),
        paths=tuple(paths),
        notes=tuple(dict.fromkeys(notes)),
    )
    if not cov.complete:
        cov.notes = cov.notes + (cov.block_message(),)
    return cov
