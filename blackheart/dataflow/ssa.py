"""SSA-lite whole-program taint/dataflow over Solidity source.

The analysis builds a per-function SSA-ish environment (one definition per
assignment, a phi merge at an ``if``), propagates taint through internal calls to
a fixpoint, and reports source -> sink flows with the function path and a source
line. A flow is a lead, never a finding; a recognised authorization guard is
recorded on the flow instead of hiding it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Iterable, Optional

from ..ingest.solidity import ContractSurface, FunctionSurface, scan_source
from ..ingest.synthesize import (
    _ASSIGN_RE, _CALL_ASSIGN_RE, _CALL_STMT_RE, _DELETE_RE, _IF_REVERT_RE,
    _PUSH_RE, _REQUIRE_RE, _UNARY_RE, _first_arg, _parse_statements,
    _split_args, parse_expression,
)

_CALL_SINKS = frozenset({
    "call", "delegatecall", "staticcall", "send", "transfer", "transferFrom",
    "approve", "mint", "burn", "selfdestruct", "sweep", "withdraw", "claim",
    "upgradeTo", "upgradeToAndCall", "setOwner", "setAdmin", "grantRole",
    "revokeRole", "initialize",
})
_SENSITIVE_STATE = frozenset({
    "owner", "admin", "governance", "authority", "implementation", "oracle",
    "price", "fee", "fees", "balance", "balances", "allowance", "allowances",
    "totalSupply", "debt", "collateral", "rewardRate", "reward", "rewards",
})
_GUARD_MODIFIERS = ("onlyowner", "onlyadmin", "onlyrole", "onlygovernance",
                    "auth", "authorized", "requiresauth")
_BARE_CALL = re.compile(r"^([A-Za-z_]\w*)\s*\((.*)\)$", re.S)
_TUPLE_CALL = re.compile(
    r"^\(([^)]*)\)\s*=\s*([A-Za-z_]\w*)(?:\([^()]*\))?\.([A-Za-z_]\w*)"
    r"\s*(?:\{([^{}]*)\})?\s*\((.*)\)$", re.S)


@dataclass(frozen=True)
class Taint:
    sources: frozenset[str] = frozenset()
    path: tuple[str, ...] = ()

    def merge(self, other: "Taint") -> "Taint":
        return Taint(self.sources | other.sources,
                     tuple(dict.fromkeys(self.path + other.path)))

    @property
    def tainted(self) -> bool:
        return bool(self.sources)

    def label(self) -> str:
        return ", ".join(sorted(self.sources)) or "clean"


CLEAN = Taint()


@dataclass(frozen=True)
class SSAValue:
    name: str
    version: int
    taint: Taint
    uses: tuple[str, ...] = ()
    line: int = 0
    text: str = ""


@dataclass
class Flow:
    source: str
    sink: str
    sink_kind: str
    contract: str
    function: str
    line: int
    snippet: str
    expression: str
    path: tuple[str, ...]
    guarded: bool = False
    guard: str = ""
    interprocedural: bool = False
    reachable: bool = True

    @property
    def unprivileged(self) -> bool:
        return self.reachable and not self.guarded

    def to_dict(self) -> dict:
        return {
            "source": self.source, "sink": self.sink,
            "sink_kind": self.sink_kind, "contract": self.contract,
            "function": self.function, "line": self.line,
            "snippet": self.snippet, "expression": self.expression,
            "path": list(self.path), "guarded": self.guarded,
            "guard": self.guard, "unprivileged": self.unprivileged,
            "reachable": self.reachable, "interprocedural": self.interprocedural,
        }


@dataclass
class DataflowResult:
    contracts: list[str] = field(default_factory=list)
    functions: int = 0
    ssa_nodes: int = 0
    call_edges: list[dict] = field(default_factory=list)
    flows: list[Flow] = field(default_factory=list)
    unsupported: list[str] = field(default_factory=list)
    rounds: int = 0

    @property
    def unprivileged(self) -> list[Flow]:
        return [f for f in self.flows if f.unprivileged]

    def to_dict(self) -> dict:
        return {
            "contracts": list(self.contracts), "functions": self.functions,
            "ssa_nodes": self.ssa_nodes, "call_edges": list(self.call_edges),
            "flows": [f.to_dict() for f in self.flows],
            "unprivileged_flows": [f.to_dict() for f in self.unprivileged],
            "unsupported": list(self.unsupported), "rounds": self.rounds,
        }


def _idents(node: Any) -> set[str]:
    if not isinstance(node, tuple):
        return set()
    kind = node[0]
    if kind == "id":
        return {node[1]}
    if kind == "sender":
        return {"msg.sender"}
    if kind in ("num",):
        return set()
    if kind in ("not", "neg"):
        return _idents(node[1])
    if kind == "bin":
        return _idents(node[2]) | _idents(node[3])
    if kind == "index":
        return _idents(node[1]) | _idents(node[2])
    if kind == "member":
        base, field_name = node[1], node[2]
        if isinstance(base, tuple) and base[0] == "id":
            return {f"{base[1]}.{field_name}", base[1]}
        return _idents(base)
    return set()


def _render(node: Any) -> str:
    if not isinstance(node, tuple):
        return str(node)
    kind = node[0]
    if kind == "num":
        return str(node[1])
    if kind == "sender":
        return "msg.sender"
    if kind == "id":
        return node[1]
    if kind == "not":
        return f"!{_render(node[1])}"
    if kind == "neg":
        return f"-{_render(node[1])}"
    if kind == "bin":
        return f"({_render(node[2])} {node[1]} {_render(node[3])})"
    if kind == "index":
        return f"{_render(node[1])}[{_render(node[2])}]"
    if kind == "member":
        return f"{_render(node[1])}.{node[2]}"
    return "?"


def _expr_taint(node: Any, env: dict[str, SSAValue], state: dict[str, Taint],
                sources: dict[str, str]) -> Taint:
    out = CLEAN
    for name in _idents(node):
        if name in sources:
            out = out.merge(Taint({sources[name]}, (sources[name],)))
        if name in env:
            out = out.merge(env[name].taint)
        elif name in state:
            out = out.merge(state[name])
        else:
            prefix = name + "."
            for key, taint in state.items():
                if key == name or key.startswith(prefix):
                    out = out.merge(taint)
    return out


def _options_text(statement: str) -> str:
    match = re.search(r"\{([^{}]*)\}", statement)
    return match.group(1) if match else ""


def _line_for(function: FunctionSurface, statement: str) -> int:
    body = function.body or ""
    tokens = statement.split()
    pattern = r"\s+".join(re.escape(token) for token in tokens) if tokens else ""
    match = re.search(pattern, body) if pattern else None
    index = match.start() if match else body.find(statement)
    return function.line + (body[:index].count("\n") if index >= 0 else 0)


def _sink_kind(call: str, receiver: str) -> str:
    if call in ("delegatecall", "call", "staticcall", "send", "transfer"):
        return "external-call"
    if call in ("mint", "burn", "sweep", "withdraw", "claim"):
        return "asset-movement"
    if call in ("setOwner", "setAdmin", "grantRole", "revokeRole",
                "upgradeTo", "upgradeToAndCall", "initialize"):
        return "privileged-write"
    if receiver and receiver not in ("msg", "block", "tx", "abi", "address"):
        return "external-call"
    return "call"


def _state_sink(name: str) -> Optional[str]:
    root = name.split("[", 1)[0].split(".", 1)[0]
    if root in _SENSITIVE_STATE or any(part in root.lower() for part in _SENSITIVE_STATE):
        return "state-write"
    return None


@dataclass
class _Summary:
    flows: list[Flow] = field(default_factory=list)
    calls: list[dict] = field(default_factory=list)
    return_taint: Taint = CLEAN
    nodes: int = 0
    guarded: bool = False


class _Analyser:
    def __init__(self, contract: ContractSurface, function: FunctionSurface,
                 param_taint: dict[str, Taint], state_taint: dict[str, Taint]):
        self.contract, self.function = contract, function
        self.state = dict(state_taint)
        self.sources = {
            "msg.sender": "msg.sender", "msg.value": "msg.value",
            "tx.origin": "tx.origin", "block.timestamp": "block.timestamp",
            "block.number": "block.number",
        }
        self.env: dict[str, SSAValue] = {}
        for param in function.params:
            name = param.split()[-1]
            if not name.isidentifier():
                continue
            taint = param_taint.get(name, Taint({f"param:{function.name}:{name}"},
                                               (f"param:{function.name}:{name}",)))
            self.env[name] = SSAValue(name, 1, taint, (), function.line, param)
        self.version = {name: 1 for name in self.env}
        self.nodes = list(self.env.values())
        self.flows: list[Flow] = []
        self.calls: list[dict] = []
        self.unsupported: list[str] = []
        self.return_taint = CLEAN
        self.guard = ""
        self.guarded = any(m.lower().replace("_", "") in _GUARD_MODIFIERS
                           for m in function.modifiers)

    def _define(self, name: str, taint: Taint, uses: Iterable[str],
                line: int, text: str) -> SSAValue:
        version = self.version.get(name, 0) + 1
        self.version[name] = version
        value = SSAValue(name, version, taint, tuple(uses), line, text)
        self.env[name] = value
        self.nodes.append(value)
        return value

    def _flow(self, taint: Taint, sink: str, kind: str, line: int,
              snippet: str, expression: str) -> None:
        if taint.tainted:
            self.flows.append(Flow(
                taint.label(), sink, kind, self.contract.name, self.function.name,
                line, snippet.strip(), expression.strip(),
                taint.path or (taint.label(),), self.guarded, self.guard,
                reachable=self.function.externally_callable))

    def _call(self, receiver: str, op: str, args_text: str, line: int,
              snippet: str, assign_to: str = "", options_text: str = "") -> None:
        args = []
        for arg in _split_args(args_text):
            try:
                args.append(parse_expression(arg))
            except ValueError:
                # A string literal or an ABI blob carries no local taint; it
                # must not discard the call's receiver/options taint.
                continue
        arg_taint = CLEAN
        if receiver and receiver not in ("msg", "block", "tx", "abi", "address"):
            arg_taint = arg_taint.merge(
                _expr_taint(("id", receiver), self.env, self.state, self.sources))
        for arg in args:
            arg_taint = arg_taint.merge(_expr_taint(arg, self.env, self.state, self.sources))
        for option in _split_args(options_text):
            value = option.split(":", 1)[-1]
            try:
                arg_taint = arg_taint.merge(
                    _expr_taint(parse_expression(value), self.env, self.state, self.sources))
            except ValueError:
                pass
        target = f"{receiver}.{op}" if receiver else op
        self.calls.append({"receiver": receiver, "operation": op, "target": target,
                           "function": self.function.name, "line": line,
                           "args": [_render(a) for a in args],
                           "arg_taint": arg_taint.label()})
        if op in _CALL_SINKS:
            self._flow(arg_taint, target, _sink_kind(op, receiver), line,
                       snippet, args_text)
        if assign_to:
            self._define(assign_to, Taint({f"external_return:{target}"},
                                          (f"external_return:{target}",)),
                         [target], line, snippet)

    def _simple(self, stmt: str, line: int) -> None:
        stmt = " ".join(stmt.split())
        if not stmt:
            return
        if stmt.startswith("return "):
            try:
                expr = parse_expression(stmt[len("return "):].rstrip(";"))
            except ValueError:
                self.unsupported.append(stmt)
                return
            self.return_taint = self.return_taint.merge(
                _expr_taint(expr, self.env, self.state, self.sources))
            return
        if stmt.startswith(("emit ", "//", "/*")):
            return
        match = _REQUIRE_RE.match(stmt) or _IF_REVERT_RE.match(stmt)
        if match:
            try:
                expr = parse_expression(_first_arg(match.group(1)))
            except ValueError:
                self.unsupported.append(stmt)
                return
            self.guard = _render(expr)
            lowered = self.guard.replace(" ", "")
            if any(token in lowered for token in (
                    "msg.sender==owner", "msg.sender==admin", "owner==msg.sender",
                    "admin==msg.sender", "msg.sender==governance",
                    "hasrole(", "onlyowner", "onlyadmin")):
                self.guarded = True
            return
        match = _TUPLE_CALL.match(stmt)
        if match:
            names, receiver, op, options_text, args_text = match.groups()
            assign_to = next((part.strip().split()[-1] for part in names.split(",")
                              if part.strip()), "")
            self._call(receiver, op, args_text, line, stmt, assign_to, options_text or "")
            return
        match = _CALL_ASSIGN_RE.match(stmt)
        if match:
            assign_to, receiver, op, args_text = match.groups()
            self._call(receiver, op, args_text, line, stmt, assign_to,
                       options_text=_options_text(stmt))
            return
        match = _CALL_STMT_RE.match(stmt)
        if match:
            self._call(match.group(1), match.group(2), match.group(3), line, stmt,
                       options_text=_options_text(stmt))
            return
        match = _BARE_CALL.match(stmt)
        if match:
            self._call("", match.group(1), match.group(2), line, stmt)
            return
        match = _PUSH_RE.match(stmt)
        if match:
            target, value_text = match.groups()
            try:
                value = parse_expression(_first_arg(value_text))
            except ValueError:
                self.unsupported.append(stmt)
                return
            taint = _expr_taint(value, self.env, self.state, self.sources)
            self._define(target, taint, _idents(value), line, stmt)
            self.state[target] = self.state.get(target, CLEAN).merge(taint)
            return
        match = _DELETE_RE.match(stmt)
        if match:
            self._define(match.group(1), CLEAN, (), line, stmt)
            self.state[match.group(1)] = CLEAN
            return
        match = _UNARY_RE.match(stmt)
        if match:
            target = match.group(2) or match.group(3)
            taint = _expr_taint(("id", target), self.env, self.state, self.sources)
            self._define(target, taint, (target,), line, stmt)
            self.state[target] = self.state.get(target, CLEAN).merge(taint)
            return
        match = _ASSIGN_RE.match(stmt)
        if match:
            base, index_text, member, op, value_text = match.groups()
            target = base
            try:
                value = parse_expression(value_text)
                index = parse_expression(index_text) if index_text else None
            except ValueError:
                self.unsupported.append(stmt)
                return
            taint = _expr_taint(value, self.env, self.state, self.sources)
            if index is not None:
                taint = taint.merge(_expr_taint(index, self.env, self.state, self.sources))
            if member:
                taint = taint.merge(_expr_taint(("id", f"{base}.{member}"), self.env,
                                               self.state, self.sources))
            if op != "=":
                taint = taint.merge(_expr_taint(("id", target), self.env,
                                               self.state, self.sources))
            root = target.split(".", 1)[0]
            kind = _state_sink(target)
            if root in self.contract.state_vars:
                self.state[target] = self.state.get(target, CLEAN).merge(taint)
                if kind is not None:
                    self._flow(taint, target, kind, line, stmt, value_text)
            else:
                self._define(target, taint, _idents(value), line, stmt)
            return
        self.unsupported.append(stmt)

    def _block(self, text: str) -> None:
        for item in _parse_statements(text):
            if item[0] == "simple":
                self._simple(item[1], _line_for(self.function, item[1]))
                continue
            _, condition_text, then_text, else_text = item
            try:
                condition = parse_expression(_first_arg(condition_text))
            except ValueError:
                self.unsupported.append(f"if ({condition_text})")
                continue
            cond_taint = _expr_taint(condition, self.env, self.state, self.sources)
            before, before_state = dict(self.env), dict(self.state)
            self._block(then_text)
            then_env, then_state = self.env, self.state
            self.env, self.state = dict(before), dict(before_state)
            self._block(else_text)
            else_env, else_state = self.env, self.state
            merged: dict[str, SSAValue] = {}
            for name in set(before) | set(then_env) | set(else_env):
                left = then_env.get(name, before.get(name))
                right = else_env.get(name, before.get(name))
                if left is None:
                    left = right
                if right is None:
                    right = left
                if left is None or right is None:
                    continue
                uses = tuple(dict.fromkeys(left.uses + right.uses))
                merged[name] = self._define(
                    name, left.taint.merge(right.taint).merge(cond_taint),
                    uses, left.line, f"phi({name})")
            self.env = merged or self.env
            for name in set(before_state) | set(then_state) | set(else_state):
                self.state[name] = then_state.get(name, CLEAN).merge(
                    else_state.get(name, CLEAN))

    def run(self) -> _Summary:
        self._block(self.function.body or "")
        return _Summary(self.flows, self.calls, self.return_taint,
                        len(self.nodes), self.guarded)


def self_guard(summary: _Summary) -> str:
    return "caller is authorization-guarded" if summary.guarded else ""


def analyse_source(files: dict[str, str], *, contract_name: str = "",
                   max_rounds: int = 4) -> DataflowResult:
    """Analyse every contract (or one contract) in ``files`` for taint flows."""
    contracts: list[ContractSurface] = []
    for path, text in sorted(files.items()):
        contracts.extend(scan_source(text, path))
    if contract_name:
        contracts = [c for c in contracts if c.name == contract_name]
    result = DataflowResult(contracts=[c.name for c in contracts],
                            functions=sum(len(c.functions) for c in contracts))
    by_name: dict[str, list[tuple[ContractSurface, FunctionSurface]]] = {}
    for contract in contracts:
        for function in contract.functions:
            by_name.setdefault(function.name, []).append((contract, function))
    keys = [(c, f) for c in contracts for f in c.functions]
    param_taint = {key: {p.split()[-1]: Taint({f"param:{key[1].name}:{p.split()[-1]}"},
                                              (f"param:{key[1].name}:{p.split()[-1]}",))
                         for p in key[1].params if p.split()[-1].isidentifier()}
                   for key in keys}
    summaries: dict[tuple[str, str], _Summary] = {}
    state_taint = {key: {} for key in keys}

    for round_index in range(max_rounds):
        result.rounds = round_index + 1
        changed = False
        for contract, function in keys:
            analyser = _Analyser(contract, function, param_taint[(contract, function)],
                                 state_taint[(contract, function)])
            summary = analyser.run()
            summaries[(contract.name, function.name)] = summary
            result.unsupported.extend(analyser.unsupported)
            result.ssa_nodes += summary.nodes
            for flow in summary.flows:
                if flow not in result.flows:
                    result.flows.append(flow)
            for call in summary.calls:
                result.call_edges.append(call)
                if call["arg_taint"] == "clean":
                    continue
                for target_contract, target_function in by_name.get(call["operation"], []):
                    if target_function is function:
                        continue
                    slot = param_taint[(target_contract, target_function)]
                    for name in (p.split()[-1] for p in target_function.params):
                        if name in slot:
                            merged = slot[name].merge(Taint({call["arg_taint"]},
                                                            (call["arg_taint"],)))
                            if merged != slot[name]:
                                slot[name] = merged
                                changed = True
        if not changed:
            break

    for contract, function in keys:
        summary = summaries.get((contract.name, function.name))
        if summary is None:
            continue
        for call in summary.calls:
            for target_contract, target_function in by_name.get(call["operation"], []):
                target = summaries.get((target_contract.name, target_function.name))
                if target is None:
                    continue
                for flow in target.flows:
                    result.flows.append(Flow(
                        flow.source, flow.sink, flow.sink_kind, flow.contract,
                        flow.function, flow.line, flow.snippet, flow.expression,
                        (f"{contract.name}.{function.name}", *flow.path),
                        flow.guarded or summary.guarded,
                        flow.guard or (self_guard(summary)), True,
                        function.externally_callable or flow.reachable))
    unique: dict[tuple, Flow] = {}
    for flow in result.flows:
        unique[(flow.contract, flow.function, flow.line, flow.sink, flow.source,
                flow.path, flow.guarded, flow.reachable)] = flow
    result.flows = sorted(unique.values(),
                          key=lambda f: (not f.unprivileged, f.contract, f.function,
                                         f.line, f.sink))
    result.unsupported = sorted(set(result.unsupported))
    return result


__all__ = ["Taint", "SSAValue", "Flow", "DataflowResult", "analyse_source"]
