"""Infer cross-contract call edges from source, without pretending to be a compiler.

The protocol composer needs to know that ``Vault.deposit`` calls
``Token.mint``. A real compiler answers that from types; this module answers it
from the stripped function bodies with two rules:

* an explicit receiver type -- ``IERC20(token).transfer(...)`` or
  ``Token(token).mint(...)`` -- names the callee contract;
* a bare receiver -- ``token.mint(...)`` -- is resolved only when exactly one
  known contract exposes that function. An ambiguous receiver is reported as
  unresolved, never guessed.

Deployments (``new Helper()``) are recorded separately: a constructor is not a
modelled operation, so it does not become a link. Every inference is a lead; the
operator can still override it with an explicit ``Link``.
"""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional

from .solidity import ContractSurface

_RECEIVER_CALL = re.compile(
    r"\b([A-Za-z_]\w*)\s*(?:\([^;{}]*\))?\s*\.\s*([A-Za-z_]\w*)\s*(?:\{[^}]*\})?\s*\(")
_NEW = re.compile(r"\bnew\s+([A-Za-z_]\w*)\s*\(")
_IGNORED_RECEIVERS = frozenset({
    "msg", "block", "tx", "abi", "super", "this", "address", "type", "payable",
    "string", "bytes", "uint", "int", "bool", "keccak256", "sha256", "ecrecover",
})


@dataclass(frozen=True)
class CallEdge:
    caller: str
    caller_op: str
    callee: str
    callee_op: str
    evidence: str
    kind: str = "inferred"

    def to_dict(self) -> dict:
        return {"caller": self.caller, "caller_op": self.caller_op,
                "callee": self.callee, "callee_op": self.callee_op,
                "evidence": self.evidence, "kind": self.kind}


@dataclass
class CallGraph:
    edges: tuple[CallEdge, ...] = ()
    deployments: tuple[dict, ...] = ()
    unresolved: tuple[dict, ...] = ()
    notes: tuple[str, ...] = ()

    def to_dict(self) -> dict:
        return {"edges": [e.to_dict() for e in self.edges],
                "deployments": list(self.deployments),
                "unresolved": list(self.unresolved),
                "notes": list(self.notes)}


def _concrete(surface: ContractSurface) -> bool:
    return any(not func.declaration_only for func in surface.functions)


def _known_ops(contracts: dict[str, ContractSurface]) -> dict[str, set[str]]:
    # A declaration-only interface is not an implementation. Counting it here
    # made a single implementation look ambiguous whenever its interface was in
    # the same scan.
    return {name: {f.name for f in surface.functions
                   if f.externally_callable and not f.declaration_only}
            for name, surface in contracts.items()
            if _concrete(surface)}


def infer_calls(contracts: dict[str, ContractSurface]) -> CallGraph:
    """Infer call edges among the supplied contracts, resolving only uniquely."""
    known_ops = _known_ops(contracts)
    by_op: dict[str, list[str]] = {}
    for contract, ops in known_ops.items():
        for op in ops:
            by_op.setdefault(op, []).append(contract)

    def resolve(caller: str, receiver: str, op: str) -> tuple[str, str]:
        """Return ``(callee, reason)``; an empty callee is an explicit gap."""
        if receiver in contracts and _concrete(contracts[receiver]):
            return receiver, ""
        typ = dict(contracts[caller].state_types).get(receiver, "")
        declared = typ or (receiver if receiver in contracts else "")
        if declared:
            candidates = sorted(
                name for name, surface in contracts.items()
                if _concrete(surface)
                and (name == declared or declared in surface.bases)
            )
            if len(candidates) == 1:
                return candidates[0], ""
            if candidates:
                return "", (f"ambiguous interface/base {declared}: "
                            f"{', '.join(candidates)}")
        candidates = by_op.get(op, [])
        if len(candidates) == 1:
            return candidates[0], ""
        return "", "receiver cannot be resolved to one known contract"

    edges: list[CallEdge] = []
    deployments: list[dict] = []
    unresolved: list[dict] = []
    seen: set[tuple[str, str, str, str]] = set()
    for caller, surface in sorted(contracts.items()):
        for func in surface.functions:
            if not func.externally_callable:
                continue
            body = func.body
            for match in _RECEIVER_CALL.finditer(body):
                receiver, op = match.group(1), match.group(2)
                if receiver in _IGNORED_RECEIVERS:
                    continue
                evidence = f"{caller}.{func.name}: {receiver}.{op}()"
                callee, reason = resolve(caller, receiver, op)
                if not callee or callee == caller:
                    if callee == caller:
                        continue
                    unresolved.append({"caller": caller, "caller_op": func.name,
                                       "receiver": receiver, "callee_op": op,
                                       "reason": reason})
                    continue
                key = (caller, func.name, callee, op)
                if key in seen:
                    continue
                seen.add(key)
                edges.append(CallEdge(caller, func.name, callee, op, evidence))
            for match in _NEW.finditer(body):
                deployments.append({"caller": caller, "caller_op": func.name,
                                    "contract": match.group(1),
                                    "evidence": f"{caller}.{func.name}: new {match.group(1)}()"})
    notes: list[str] = []
    if unresolved:
        notes.append(f"{len(unresolved)} call receiver(s) could not be resolved uniquely")
    if deployments:
        notes.append(f"{len(deployments)} deployment(s) recorded; constructors are not "
                     "modelled operations, so they are not links")
    return CallGraph(tuple(edges), tuple(deployments), tuple(unresolved), tuple(notes))


def parse_slither_call_graph(dot: str) -> tuple[CallEdge, ...]:
    """Read Slither's ``all_contracts.call-graph.dot`` into external call edges.

    Slither's node ids are compiler ids (``30_go``), so the contract and function
    names are recovered from the cluster labels and node labels. Edges inside one
    contract are internal calls, not protocol links, and are dropped.
    """
    node_contract: dict[str, str] = {}
    node_func: dict[str, str] = {}
    current = ""
    edges: list[CallEdge] = []
    for line in dot.splitlines():
        label = re.search(r'label\s*=\s*"([^"]+)"', line)
        if label and not re.search(r'\[label\s*=', line):
            current = label.group(1)
        for match in re.finditer(r'"([^"]+)"\s*\[label\s*=\s*"([^"]+)"\]', line):
            node_contract[match.group(1)] = current
            node_func[match.group(1)] = match.group(2)
        for match in re.finditer(r'"([^"]+)"\s*->\s*"([^"]+)"', line):
            left, right = match.group(1), match.group(2)
            caller, callee = node_contract.get(left, ""), node_contract.get(right, "")
            caller_op, callee_op = node_func.get(left, ""), node_func.get(right, "")
            if not all((caller, callee, caller_op, callee_op)) or caller == callee:
                continue
            edges.append(CallEdge(
                caller, caller_op, callee, callee_op,
                f"slither call-graph: {caller}.{caller_op} -> {callee}.{callee_op}",
                kind="compiler",
            ))
    seen: set[tuple[str, str, str, str]] = set()
    unique: list[CallEdge] = []
    for edge in edges:
        key = (edge.caller, edge.caller_op, edge.callee, edge.callee_op)
        if key not in seen:
            seen.add(key)
            unique.append(edge)
    return tuple(unique)


def infer_calls_compiler(
    root: str | Path,
    contracts: dict[str, ContractSurface],
    *,
    runner: Optional[Callable[..., subprocess.CompletedProcess]] = None,
    timeout: int = 300,
) -> CallGraph:
    """Ask Slither for the compiler call graph, or say why it could not.

    The fallback is never a guessed edge: an absent tool, a failed run or a
    missing dot file returns an empty graph with a named note, and the caller can
    still use the source-regex inference.
    """
    from ..engines.solidity.base import resolve_tool

    found = resolve_tool("slither")
    if found is None:
        return CallGraph(notes=("slither is not installed; compiler call graph unavailable",))
    root_path = Path(root)
    invoke = runner or subprocess.run
    try:
        proc = invoke([found.binary, ".", "--print", "call-graph"],
                      cwd=str(root_path), capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return CallGraph(notes=(f"slither call graph failed: {exc}",))
    dot_path = root_path / "all_contracts.call-graph.dot"
    if not dot_path.is_file():
        reason = (proc.stderr or proc.stdout or "").strip().splitlines()[:2]
        return CallGraph(notes=("slither produced no all_contracts.call-graph.dot",
                                *reason))
    edges = parse_slither_call_graph(dot_path.read_text(encoding="utf-8", errors="replace"))
    known = {name: {f.name for f in surface.functions} for name, surface in contracts.items()}
    kept = tuple(edge for edge in edges
                 if edge.caller in known and edge.callee in known
                 and edge.caller_op in known[edge.caller]
                 and edge.callee_op in known[edge.callee])
    notes = [f"compiler call graph: {len(kept)} external edge(s)"]
    if len(kept) != len(edges):
        notes.append(f"{len(edges) - len(kept)} edge(s) named a contract or function "
                     "outside the supplied surfaces")
    return CallGraph(kept, (), (), tuple(notes))
