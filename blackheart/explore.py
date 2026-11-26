"""Interactive exploration of a recovered project surface.

``blackheart explore <path>`` opens a small shell over what the scanner already
recovered: contracts, functions, rule leads, interrogation verdicts, dataflow
flows and the inferred call graph. ``explore <path> --query "..."`` runs one
query and exits, so it is usable from a script.

It adds no engine and executes nothing. Every line it prints is a lead or a
description, never a finding.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Iterable, Optional

DISCLAIMER = "Explore is a map of leads, not a finding engine. Nothing here executes the target."

_HELP = """\
Commands:
  help                     this message
  contracts                contracts / packages recovered
  functions [contract]     functions, optionally for one contract
  function <name>          explain one function (also: explain <name>)
  leads [severity]         candidate rule leads (info|low|medium)
  claims                   interrogation verdicts (falsified / survived / untestable)
  flows                    unprivileged dataflow flows (Solidity)
  callgraph                inferred call edges and unresolved receivers
  quit | exit              leave
"""


def _func_meta(func: Any) -> tuple[str, str, bool, tuple[str, ...]]:
    """Language-neutral function metadata (Solidity and Rust carry different fields)."""
    visibility = getattr(func, "visibility", "") or ""
    is_dispatchable = bool(getattr(func, "is_dispatchable", False))
    mutability = getattr(func, "mutability", "dispatchable" if is_dispatchable else "")
    changing = bool(getattr(func, "state_changing", is_dispatchable))
    modifiers = tuple(getattr(func, "modifiers", ()) or ())
    return visibility, mutability, changing, modifiers


def _sol_files(path: Path) -> dict[str, str]:
    if path.is_file():
        try:
            return {str(path): path.read_text(encoding="utf-8", errors="replace")}
        except OSError:
            return {}
    files: dict[str, str] = {}
    for item in sorted(path.rglob("*.sol")):
        try:
            files[str(item)] = item.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
    return files


class Session:
    """A loaded project surface plus the passes that describe it."""

    def __init__(self, path: str, language: str = "auto",
                 allow_unscanned: tuple[str, ...] = ()) -> None:
        from .ingest import assess_coverage, detect_language

        self.path = str(path)
        self.language = detect_language(path) if language == "auto" else language
        self.blocked = False
        self.block_message = ""
        self.report: Any = None
        self.flags: tuple[Any, ...] = ()
        self.verdicts: list[Any] = []
        self.flows: list[Any] = []
        self.callgraph: Any = None

        coverage = assess_coverage(path, self.language,
                                   allow_unscanned=tuple(allow_unscanned))
        if coverage.blocked:
            self.blocked = True
            self.block_message = coverage.block_message()
            return
        if self.language not in ("solidity", "rust", "go", "vyper"):
            self.blocked = True
            self.block_message = f"no scannable source found under {path!r}"
            return
        self._load()

    def _load(self) -> None:
        from .ingest import evaluate, evaluate_go, evaluate_rust, ingest, ingest_go, ingest_rust

        if self.language == "solidity":
            self.report = ingest(self.path)
            self.flags = evaluate(self.report)
        elif self.language == "rust":
            self.report = ingest_rust(self.path)
            self.flags = evaluate_rust(self.report)
        elif self.language == "go":
            self.report = ingest_go(self.path)
            self.flags = evaluate_go(self.report)
        else:  # vyper has no unified report object here
            return

        try:
            from .interrogate import interrogate

            verdicts, _lang, _errors = interrogate(self.path, self.language)
            self.verdicts = list(verdicts)
        except Exception:  # noqa: BLE001 - exploration must not die on one pass
            self.verdicts = []

        if self.language == "solidity":
            try:
                from .dataflow import analyse_source

                self.flows = list(analyse_source(_sol_files(Path(self.path))).unprivileged)
            except Exception:  # noqa: BLE001
                self.flows = []
            try:
                from .ingest.callgraph import infer_calls

                contracts = {c.name: c for c in self.report.contracts}
                self.callgraph = infer_calls(contracts)
            except Exception:  # noqa: BLE001
                self.callgraph = None

    # -- views -------------------------------------------------------------
    def contracts(self) -> str:
        contracts = getattr(self.report, "contracts", ()) or getattr(self.report, "modules", ())
        packages = getattr(self.report, "packages", ())
        names = list(contracts) + list(packages)
        if not names:
            return "No contracts recovered."
        lines = [f"Contracts ({len(names)}):"]
        for item in names:
            kind = getattr(item, "kind", "package")
            path = getattr(item, "path", getattr(item, "root", ""))
            functions = len(getattr(item, "functions", ()) or ())
            guard = "guards" if getattr(item, "has_access_control", False) else "no-guard-vocab"
            lines.append(f"  {item.name:<24} {kind:<10} {path}  functions={functions}  {guard}")
        return "\n".join(lines)

    def functions(self, contract: Optional[str] = None) -> str:
        rows = self._function_rows(contract)
        if not rows:
            return f"No functions found{f' for {contract}' if contract else ''}."
        header = f"Functions ({len(rows)}):"
        lines = [header]
        for contract_name, func in rows:
            visibility, mutability, changing, _ = _func_meta(func)
            flag = " state-changing" if changing else ""
            lines.append(f"  {contract_name}.{func.name:<22} {visibility:<9} "
                         f"{mutability:<12} line {func.line}{flag}")
        return "\n".join(lines)

    def _function_rows(self, contract: Optional[str] = None) -> list[tuple[str, Any]]:
        rows: list[tuple[str, Any]] = []
        containers = (getattr(self.report, "contracts", ())
                      or getattr(self.report, "modules", ())
                      or getattr(self.report, "packages", ())
                      or ())
        for item in containers:
            if contract and item.name.casefold() != contract.casefold():
                continue
            for func in getattr(item, "functions", ()) or ():
                rows.append((item.name, func))
        return rows

    def explain(self, name: str) -> str:
        matches = [(c, f) for c, f in self._function_rows() if f.name == name]
        if not matches:
            folded = [(c, f) for c, f in self._function_rows() if name.lower() in f.name.lower()]
            if len(folded) == 1:
                matches = folded
            elif len(folded) > 1:
                return ("Ambiguous: " + ", ".join(f"{c}.{f.name}" for c, f in folded) +
                        "\nUse the full name.")
            else:
                return f"No function named {name!r}."
        contract_name, func = matches[0]
        key = f"{contract_name}.{func.name}"
        visibility, mutability, changing, modifiers = _func_meta(func)
        lines = [f"# {key}", ""]
        lines.append(f"- signature: `{func.signature}`")
        lines.append(f"- contract: {contract_name}")
        lines.append(f"- visibility/mutability: {visibility} / {mutability}")
        lines.append(f"- modifiers: {', '.join(modifiers) or '-'}")
        lines.append(f"- line: {func.line}")
        lines.append(f"- state-changing: {changing}")
        body = "\n".join(func.body.splitlines()[:40])
        if body.strip():
            lines += ["", "```solidity", body, "```"]

        func_leads = [f for f in self.flags if getattr(f, "function", "") == func.name]
        lines += ["", f"## Leads ({len(func_leads)})", ""]
        for lead in func_leads:
            lines.append(f"- [{getattr(lead, 'severity_hint', '')}] "
                         f"{getattr(lead, 'rule', '')}: {getattr(lead, 'evidence', '')}")

        claims = [v for v in self.verdicts
                  if func.name in getattr(v.claim, "subject", "")
                  or f":{func.line}" in getattr(v.claim, "location", "")]
        lines += ["", f"## Claims ({len(claims)})", ""]
        for verdict in claims:
            lines.append(f"- [{verdict.status}] {verdict.claim.location} — "
                         f"{verdict.claim.statement}")

        flows = [f for f in self.flows
                 if getattr(f, "function", "") == func.name]
        lines += ["", f"## Unprivileged flows ({len(flows)})", ""]
        for flow in flows:
            lines.append(f"- {flow.source} -> {flow.sink} (line {flow.line})")

        if self.callgraph is not None:
            out = [e for e in self.callgraph.edges
                   if e.caller == contract_name and e.caller_op == func.name]
            incoming = [e for e in self.callgraph.edges
                        if e.callee == contract_name and e.callee_op == func.name]
            lines += ["", "## Call edges", ""]
            for edge in out:
                lines.append(f"- out: {edge.callee}.{edge.callee_op}")
            for edge in incoming:
                lines.append(f"- in:  {edge.caller}.{edge.caller_op}")
            if not out and not incoming:
                lines.append("- none inferred")
        return "\n".join(lines)

    def leads(self, severity: Optional[str] = None) -> str:
        rows = [f for f in self.flags
                if severity is None or getattr(f, "severity_hint", "") == severity.lower()]
        if not rows:
            return "No candidate lead matched. A miss is not a proof of safety."
        lines = [f"Candidate leads ({len(rows)}):"]
        for lead in rows:
            lines.append(f"  [{getattr(lead, 'severity_hint', '')}] "
                         f"{getattr(lead, 'contract', '')}.{getattr(lead, 'function', '')}  "
                         f"{getattr(lead, 'rule', '')}  {getattr(lead, 'path', '')}:"
                         f"{getattr(lead, 'line', '')}")
        return "\n".join(lines)

    def claims(self) -> str:
        if not self.verdicts:
            return "No claims derived (interrogation not available for this language)."
        counts: dict[str, int] = {}
        for verdict in self.verdicts:
            counts[verdict.status] = counts.get(verdict.status, 0) + 1
        lines = [f"Claims ({len(self.verdicts)}): " +
                 " ".join(f"{k}={v}" for k, v in sorted(counts.items()))]
        for verdict in self.verdicts:
            lines.append(f"  [{verdict.status}] {verdict.claim.location} — {verdict.claim.statement}")
        return "\n".join(lines)

    def flows(self) -> str:
        if not self.flows:
            return "No unprivileged flow found within the model."
        lines = [f"Unprivileged flows ({len(self.flows)}):"]
        for flow in self.flows:
            lines.append(f"  {flow.contract}.{flow.function}:{flow.line}  "
                         f"{flow.source} -> {flow.sink}")
        return "\n".join(lines)

    def callgraph(self) -> str:
        if self.callgraph is None:
            return "Call graph not available for this language."
        lines = [f"Call edges ({len(self.callgraph.edges)}):"]
        for edge in self.callgraph.edges:
            lines.append(f"  {edge.caller}.{edge.caller_op} -> {edge.callee}.{edge.callee_op}")
        for gap in self.callgraph.unresolved:
            lines.append(f"  [unresolved] {gap.get('caller')}.{gap.get('caller_op')} -> "
                         f"{gap.get('receiver')}.{gap.get('callee_op')} ({gap.get('reason')})")
        return "\n".join(lines)

    def help(self) -> str:
        return _HELP.strip()

    def dispatch(self, query: str) -> str:
        parts = query.strip().split()
        if not parts:
            return ""
        command = parts[0].lower()
        arg = parts[1] if len(parts) > 1 else None
        if command in ("help", "?"):
            return self.help()
        if command == "contracts":
            return self.contracts()
        if command == "functions":
            return self.functions(arg)
        if command in ("function", "explain"):
            return self.explain(arg) if arg else "usage: function <name>"
        if command == "leads":
            return self.leads(arg)
        if command == "claims":
            return self.claims()
        if command == "flows":
            return self.flows()
        if command == "callgraph":
            return self.callgraph()
        return f"unknown command {command!r}; type 'help'"


def repl(session: Session, stdin: Optional[Iterable[str]] = None,
         stdout: Any = None) -> int:
    """Run the shell. Reads lines from ``stdin`` (testable) and writes to ``stdout``."""
    stdin = stdin if stdin is not None else sys.stdin
    stdout = stdout if stdout is not None else sys.stdout
    interactive = getattr(stdin, "isatty", lambda: False)()
    stdout.write(f"BLACKHEART explore — {session.path} ({session.language})\n"
                 "type 'help' for commands, 'quit' to leave\n")
    while True:
        if interactive:
            stdout.write("bh> ")
            stdout.flush()
        line = stdin.readline()
        if not line:
            break
        query = line.strip()
        if not query:
            continue
        if query.lower() in ("quit", "exit", ":q"):
            break
        stdout.write(session.dispatch(query) + "\n")
    return 0
