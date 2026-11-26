"""A small, conservative call graph over the Go scanner's surface.

A Cosmos message handler usually does not write state itself. It delegates to a
keeper, and the keeper writes the store. Judging only the handler body therefore
reports "no write" for the exact code path an attacker reaches.

This module resolves the calls the scanner already recorded:

  * ``s.keeper.CreatePool(...)`` where ``keeper`` is a field of the handler's
    receiver type,
  * ``k.Set(...)`` where ``k`` is the receiver variable,
  * an unqualified ``helper(...)`` in the same package,

and follows the resolved methods to a bounded depth. Interface fields are
resolved only when exactly one concrete implementation in the same package
declares the method; two candidates are reported as ambiguous, never guessed.

It is not a Go type checker. It resolves a package-qualified call through the
scanned package's import table, and a method/interface through a *unique* global
candidate when the receiver's package cannot be proven. Two candidates are
ambiguous, never guessed. Embedded interfaces, generics and method values remain
unresolved. Every call it cannot resolve is recorded so the report can say what
it did not follow.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional

from .golang import GoFunction, GoSurfaceReport, GoType

#: A direct store/account write, kept in one place so the rules and the Cosmos
#: surface cannot drift.
STATE_WRITE_PATTERN = (
    r"\.Set\(|\.SetParams\(|SendCoins|MintCoins|BurnCoins|Delegate\(|"
    r"Undelegate\(|Redelegate\(|SetValidator|SetAccount|"
    r"\b[A-Za-z_]\w*\.(?:authority|params|store|state)\s*="
)

#: A signer/authority check. A bare `msg.sender` is not a Go guard; these are
#: the Cosmos forms.
AUTHORITY_GUARD_PATTERN = (
    r"govauth\.Assert\s*\(|ValidateBasic\s*\(|GetSigners\s*\(|"
    r"CheckAuthority\s*\(|authz|"
    r"(?:if|require|ensure)\s+[^;{]{0,240}"
    r"(?:Authority|GetAuthority|Sender|Creator|Owner|FromAddress)"
    r"\s*(?:!=|==|<=|>=|<|>)|"
    r"(?:if|require|ensure)\s+[^;{]{0,240}(?:!=|==)\s*[^;{]{0,80}"
    r"(?:Authority|GetAuthority|Sender|Creator|Owner|FromAddress)"
)

_RECEIVER = re.compile(r"^\s*func\s*\(\s*([A-Za-z_]\w*)\s+([^)]*)\)")
_QUALIFIED = re.compile(r"^[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*$")


@dataclass(frozen=True)
class GoCallEdge:
    caller: GoFunction
    expression: str
    callee: Optional[GoFunction] = None
    kind: str = "unresolved"       # method | interface | package | unresolved
    detail: str = ""


@dataclass(frozen=True)
class GoCallSummary:
    resolved: int = 0
    unresolved: int = 0
    delegated_writes: tuple[tuple[str, str, str, int], ...] = ()
    unresolved_dispatches: tuple[tuple[str, str], ...] = ()

    def to_dict(self) -> dict:
        return {
            "resolved": self.resolved,
            "unresolved": self.unresolved,
            "delegated_writes": [
                {"handler": h, "callee": c, "path": p, "line": n}
                for h, c, p, n in self.delegated_writes
            ],
            "unresolved_dispatches": [
                {"handler": h, "expression": e}
                for h, e in self.unresolved_dispatches
            ],
        }


def _norm_type(raw: str) -> str:
    raw = raw.strip().split()[0] if raw.strip() else ""
    raw = raw.replace("*", "").replace("[]", "")
    if "." in raw:
        raw = raw.rsplit(".", 1)[-1]
    return raw


def _entrypoint(func: GoFunction) -> bool:
    """A message/consensus entry point, not a keeper implementation."""
    if any(x in func.receiver for x in ("MsgServer", "msgServer", "msg_server")):
        return True
    return func.name in {
        "AnteHandle", "BeginBlock", "EndBlock", "InitGenesis", "ExportGenesis",
        "PrepareProposal", "ProcessProposal", "ValidateBasic", "GetSigners",
    }


def _receiver_var(func: GoFunction) -> tuple[str, str]:
    m = _RECEIVER.match(func.signature)
    if not m:
        return "", _norm_type(func.receiver)
    return m.group(1), _norm_type(m.group(2))


def _field_types(types: tuple[GoType, ...]) -> dict[tuple[str, str], dict[str, str]]:
    out: dict[tuple[str, str], dict[str, str]] = {}
    for typ in types:
        fields: dict[str, str] = {}
        for line in typ.fields:
            line = line.split("//", 1)[0].strip()
            if "`" in line:
                line = line.split("`", 1)[0].strip()
            parts = line.split()
            if len(parts) >= 2:
                fields[parts[0]] = _norm_type(parts[1])
            elif len(parts) == 1:
                name = _norm_type(parts[0])
                fields[name] = name
        out[(typ.package, typ.name)] = fields
    return out


def _field_qualifiers(types: tuple[GoType, ...]) -> dict[tuple[str, str], dict[str, str]]:
    """The package qualifier on a field type, e.g. ``keeper`` in ``keeper.Keeper``."""
    out: dict[tuple[str, str], dict[str, str]] = {}
    for typ in types:
        fields: dict[str, str] = {}
        for line in typ.fields:
            line = line.split("//", 1)[0].strip()
            if "`" in line:
                line = line.split("`", 1)[0].strip()
            parts = line.split()
            if len(parts) >= 2:
                raw = parts[1].replace("*", "").replace("[]", "")
                if "." in raw:
                    fields[parts[0]] = raw.rsplit(".", 1)[0]
        out[(typ.package, typ.name)] = fields
    return out


class GoCallGraph:
    """Resolve the calls in a :class:`GoSurfaceReport` without guessing types."""

    def __init__(self, report: GoSurfaceReport) -> None:
        self.report = report
        self.methods: dict[tuple[str, str, str], list[GoFunction]] = {}
        self.functions: dict[tuple[str, str], list[GoFunction]] = {}
        #: Global indexes are used only when the answer is unique.
        self.method_index: dict[tuple[str, str], list[GoFunction]] = {}
        self.function_index: dict[str, list[GoFunction]] = {}
        self.package_functions: dict[tuple[str, str], list[GoFunction]] = {}
        self.types: dict[tuple[str, str], GoType] = {}
        self.imports: dict[tuple[str, str], str] = {}
        for pkg in report.packages:
            for typ in pkg.types:
                self.types[(pkg.name, typ.name)] = typ
            for func in pkg.functions:
                if func.receiver:
                    receiver = _norm_type(func.receiver)
                    self.methods.setdefault((func.package, receiver, func.name), []).append(func)
                    self.method_index.setdefault((receiver, func.name), []).append(func)
                else:
                    self.functions.setdefault((func.package, func.name), []).append(func)
                    self.function_index.setdefault(func.name, []).append(func)
                    self.package_functions.setdefault((pkg.path, func.name), []).append(func)
        all_types = tuple(t for p in report.packages for t in p.types)
        self.fields = _field_types(all_types)
        self.field_qualifiers = _field_qualifiers(all_types)
        self._interfaces = {
            (pkg.name, typ.name)
            for pkg in report.packages for typ in pkg.types if typ.kind == "interface"
        }
        self._interface_names: dict[str, list[str]] = {}
        for pkg_name, type_name in self._interfaces:
            self._interface_names.setdefault(type_name, []).append(pkg_name)
        for pkg in report.packages:
            for alias, import_path in pkg.imports:
                target = self._match_import(import_path)
                if target:
                    self.imports[(pkg.name, alias)] = target.path

    # -- resolution ---------------------------------------------------- #

    def _pick(self, candidates: list[GoFunction]) -> GoFunction:
        # Prefer a real implementation over a public-build stub, but never hide
        # that the stub was the only implementation present.
        return next((c for c in candidates if not c.stub), candidates[0])

    def _match_import(self, import_path: str) -> Optional[GoPackage]:  # noqa: F821  annotation-only
        """Match an import path to a package actually scanned in this tree.

        The module-qualified path from ``go.mod`` is authoritative: it removes
        the ambiguity two packages with the same trailing directory would
        otherwise create. The suffix rule remains only for trees without a
        manifest, and only when exactly one package matches.
        """
        norm = import_path.strip("/")
        exact = [pkg for pkg in self.report.packages
                 if pkg.import_path.strip("/") == norm]
        if len(exact) == 1:
            return exact[0]
        if exact:
            return None
        matches = [
            pkg for pkg in self.report.packages
            if pkg.path.strip("/")
            and (norm == pkg.path.strip("/")
                 or norm.endswith("/" + pkg.path.strip("/")))
        ]
        if len(matches) == 1:
            return matches[0]
        return None

    def _package_functions(self, package_path: str, name: str) -> list[GoFunction]:
        return self.package_functions.get((package_path, name), [])

    def _fields_for(self, package: str, type_name: str) -> dict[str, str]:
        fields = self.fields.get((package, type_name))
        if fields is not None:
            return fields
        # A receiver field may name a type from an imported package. The scanner
        # strips the qualifier, so use the global field table only when exactly
        # one scanned type has that name.
        candidates = [value for (pkg, name), value in self.fields.items()
                      if name == type_name]
        return candidates[0] if len(candidates) == 1 else {}

    def _interface_impls(self, package: str, interface: str, method: str) -> list[GoFunction]:
        out: list[GoFunction] = []
        for (pkg, receiver, name), candidates in self.methods.items():
            if pkg != package or name != method or (pkg, receiver) in self._interfaces:
                continue
            out.extend(c for c in candidates if not _entrypoint(c))
        if out:
            return out
        # The interface may live in another scanned package. Only use the global
        # index when the interface name itself is unique, otherwise a common
        # name such as `Keeper` would silently bind the wrong implementation.
        owners = self._interface_names.get(interface, [])
        if len(owners) != 1:
            return []
        return [c for (pkg, receiver, name), candidates in self.methods.items()
                for c in candidates
                if name == method and (pkg, receiver) not in self._interfaces
                and not _entrypoint(c)]

    def resolve(self, func: GoFunction, expression: str) -> GoCallEdge:
        if not _QUALIFIED.match(expression):
            return GoCallEdge(func, expression)
        parts = expression.split(".")
        if len(parts) == 1:
            candidates = self.functions.get((func.package, expression), [])
            if candidates:
                return GoCallEdge(func, expression, self._pick(candidates),
                                  "package", f"{func.package}.{expression}")
            return GoCallEdge(func, expression)

        recv_var, recv_type = _receiver_var(func)
        if parts[0] == recv_var:
            current = recv_type
        else:
            imported = self.imports.get((func.package, parts[0]))
            if imported and len(parts) == 2:
                candidates = self._package_functions(imported, parts[1])
                if candidates:
                    return GoCallEdge(
                        func, expression, self._pick(candidates), "package",
                        f"{imported}.{parts[1]} (cross-package)",
                    )
                return GoCallEdge(
                    func, expression, kind="unresolved",
                    detail=f"{parts[0]}.{parts[1]} is not a function in {imported}",
                )
            current = self._fields_for(func.package, recv_type).get(parts[0], "")
            if not current:
                return GoCallEdge(func, expression)

        # `s.keeper.CreatePool`: one field hop then the method. A longer chain
        # (`s.keeper.bankKeeper.SendCoins`) is only followed while every hop is a
        # concrete field type we can see.
        for part in parts[1:-1]:
            fields = self._fields_for(func.package, current)
            nxt = fields.get(part, "")
            if not nxt:
                return GoCallEdge(
                    func, expression, kind="unresolved",
                    detail=f"field {current}.{part} is not declared in the scanned tree",
                )
            current = nxt

        method = parts[-1]
        candidates = self.methods.get((func.package, current, method), [])
        if not candidates:
            # A receiver field may name an imported type. The qualifier plus the
            # exact go.mod import path selects that package; without both, the
            # global table is used only when one *file* declares the method.
            field_name = parts[1] if len(parts) >= 3 and parts[0] == recv_var else parts[0]
            qualifier = self.field_qualifiers.get(
                (func.package, recv_type), {}).get(field_name, "")
            imported = self.imports.get((func.package, qualifier)) if qualifier else None
            global_candidates = self.method_index.get((current, method), [])
            if imported:
                global_candidates = [
                    c for c in global_candidates
                    if c.path in (imported, imported + "/")
                    or c.path.startswith(imported + "/")
                    or c.path.startswith(imported + "\\")
                ]
                if len(global_candidates) == 1:
                    return GoCallEdge(
                        func, expression, global_candidates[0], "method",
                        f"{current}.{method} (cross-package {imported})",
                    )
                if len(global_candidates) > 1:
                    return GoCallEdge(
                        func, expression, kind="unresolved",
                        detail=f"{current}.{method} has {len(global_candidates)} candidates in {imported}",
                    )
            unique = {(c.package, c.path, c.receiver, c.name) for c in global_candidates}
            if len(unique) == 1:
                candidates = list(global_candidates)
            elif len(unique) > 1:
                return GoCallEdge(
                    func, expression, kind="unresolved",
                    detail=f"{current}.{method} has {len(unique)} candidates across packages",
                )
            else:
                candidates = []
        if candidates:
            callee = self._pick(candidates)
            detail = f"{current}.{method}"
            if callee.package != func.package:
                detail += f" (cross-package {callee.package})"
            return GoCallEdge(func, expression, callee, "method", detail)
        if (func.package, current) in self._interfaces:
            impls = self._interface_impls(func.package, current, method)
            if len(impls) == 1:
                impl = impls[0]
                return GoCallEdge(
                    func, expression, impl, "interface",
                    f"{current}.{method} -> {impl.receiver}.{impl.name}"
                    + (" (public-build stub)" if impl.stub else ""),
                )
            if len(impls) > 1:
                return GoCallEdge(
                    func, expression, kind="unresolved",
                    detail=f"{current}.{method} has {len(impls)} concrete candidates",
                )
            return GoCallEdge(
                func, expression, kind="unresolved",
                detail=f"{current}.{method} has no implementation in the scanned tree",
            )
        return GoCallEdge(
            func, expression, kind="unresolved",
            detail=f"{current}.{method} is not declared in the scanned tree",
        )

    def edges(self, func: GoFunction) -> tuple[GoCallEdge, ...]:
        return tuple(self.resolve(func, c) for c in func.calls)

    # -- reachability -------------------------------------------------- #

    def reachable(self, func: GoFunction, *, max_depth: int = 2) -> tuple[GoCallEdge, ...]:
        """Every resolved edge reachable from ``func`` up to ``max_depth``."""
        seen: set[tuple[str, str, str]] = {(func.package, func.receiver, func.name)}
        out: list[GoCallEdge] = []
        frontier = [(func, 0)]
        while frontier:
            current, depth = frontier.pop(0)
            if depth >= max_depth:
                continue
            for edge in self.edges(current):
                out.append(edge)
                if edge.callee is None:
                    continue
                key = (edge.callee.package, edge.callee.receiver, edge.callee.name)
                if key in seen:
                    continue
                seen.add(key)
                frontier.append((edge.callee, depth + 1))
        return tuple(out)

    def delegated_writes(self, func: GoFunction, *, max_depth: int = 2) -> tuple[GoFunction, ...]:
        out: list[GoFunction] = []
        for edge in self.reachable(func, max_depth=max_depth):
            callee = edge.callee
            if callee is None or callee.stub:
                continue
            if re.search(STATE_WRITE_PATTERN, callee.body):
                out.append(callee)
        return tuple(out)

    def delegated_guards(self, func: GoFunction, *, max_depth: int = 2) -> tuple[GoFunction, ...]:
        out: list[GoFunction] = []
        for edge in self.reachable(func, max_depth=max_depth):
            callee = edge.callee
            if callee is None or callee.stub:
                continue
            if re.search(AUTHORITY_GUARD_PATTERN, callee.body):
                out.append(callee)
        return tuple(out)

    def summary(self, *, max_items: int = 40) -> GoCallSummary:
        resolved = unresolved = 0
        writes: list[tuple[str, str, str, int]] = []
        missing: list[tuple[str, str]] = []
        for func in self.report.functions:
            if func.stub:
                continue
            for edge in self.edges(func):
                if edge.callee is not None:
                    resolved += 1
                else:
                    unresolved += 1
                    if (func.is_handler and not func.is_consensus
                            and edge.detail and len(missing) < max_items):
                        missing.append((func.name, edge.expression))
            if func.is_handler and not func.is_consensus:
                for callee in self.delegated_writes(func):
                    if len(writes) < max_items:
                        writes.append((func.name, f"{callee.receiver}.{callee.name}",
                                       callee.path, callee.line))
        return GoCallSummary(
            resolved=resolved,
            unresolved=unresolved,
            delegated_writes=tuple(writes),
            unresolved_dispatches=tuple(missing),
        )
