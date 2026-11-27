"""Render an ingested surface and its candidate flags.

The report is deliberately blunt about what it is: a triage sheet of *leads*,
each pointing at a real source line, that a human still has to turn into a
hypothesis and then a reproduction.
"""

from __future__ import annotations

from .flags import CandidateFlag
from .solidity import SurfaceReport

DISCLAIMER = (
    "These are leads, not findings. Each entry is a source line that matches a "
    "known weakness shape. None is a vulnerability until an attacker sequence "
    "reproduces a real impact under the mission's scope."
)


def as_dict(report: SurfaceReport, flags: tuple[CandidateFlag, ...]) -> dict:
    by_rule: dict[str, int] = {}
    for flag in flags:
        by_rule[flag.rule] = by_rule.get(flag.rule, 0) + 1
    return {
        "root": report.root,
        "files_scanned": len(report.files),
        "contracts": len(report.contracts),
        "functions": len(report.functions),
        "flags": len(flags),
        "flags_by_rule": dict(sorted(by_rule.items(), key=lambda kv: (-kv[1], kv[0]))),
        "errors": list(report.errors),
        "disclaimer": DISCLAIMER,
        "candidates": [flag.as_dict() for flag in flags],
    }


def render_markdown(report: SurfaceReport, flags: tuple[CandidateFlag, ...]) -> str:
    lines: list[str] = []
    lines.append("# Attack-surface ingestion")
    lines.append("")
    lines.append(f"Root: `{report.root}`")
    lines.append("")
    lines.append(
        f"Scanned {len(report.files)} file(s), {len(report.contracts)} contract(s), "
        f"{len(report.functions)} function(s); {len(flags)} candidate lead(s)."
    )
    lines.append("")
    lines.append(f"> {DISCLAIMER}")
    lines.append("")

    if report.errors:
        lines.append("## Ingest notes")
        lines.append("")
        for err in report.errors:
            lines.append(f"- {err}")
        lines.append("")

    if not flags:
        lines.append("No rule matched. That is not a clean bill of health: the rules "
                     "cover a fixed set of shapes, and a miss is not a proof of safety.")
        lines.append("")
        return "\n".join(lines)

    lines.append("## Leads")
    lines.append("")
    lines.append("| severity | rule | category | location | function |")
    lines.append("|---|---|---|---|---|")
    for f in flags:
        lines.append(
            f"| {f.severity_hint} | `{f.rule}` | `{f.category}` | "
            f"`{f.path}:{f.line}` | `{f.contract}.{f.function}` |"
        )
    lines.append("")

    lines.append("## Detail")
    lines.append("")
    for f in flags:
        lines.append(f"### `{f.rule}` - {f.contract}.{f.function}")
        lines.append("")
        lines.append(f"- Category: `{f.category}` (severity hint: {f.severity_hint})")
        lines.append(f"- Location: `{f.path}:{f.line}`")
        lines.append(f"- Why it fired: {f.rationale}")
        lines.append(f"- Evidence: `{f.evidence}`")
        lines.append(f"- Attacker question: {f.question}")
        lines.append("")
    return "\n".join(lines)


def synthesis_as_dict(results) -> list[dict]:
    """Serialise (SynthesisReport, certificate) pairs for the JSON surface."""
    out = []
    for srep, cert in results:
        out.append({
            "contract": srep.contract,
            "path": srep.path,
            "modelled_ops": list(srep.modelled_ops),
            "unmodelled_ops": list(srep.unmodelled_ops),
            "unmodelled_statements": list(srep.unmodelled_statements),
            "invariants": list(srep.invariants),
            "notes": list(srep.notes),
            "model_coverage": dict(getattr(srep, "model_coverage", {}) or {}),
            "broke": cert.broke,
            "verdict": cert.verdict_line(),
            "violations": cert.violations[:5],
        })
    return out


def render_synthesis(results) -> str:
    lines = ["## Synthesised model (executable)", ""]
    lines.append(
        "> The certifier ran on a model built from the contract's own functions. A "
        "violation here is a lead about the source under the modelled subset -- confirm "
        "it against the real contract before calling it a finding."
    )
    lines.append("")
    for srep, cert in results:
        lines.append(f"### `{srep.contract}` - {srep.path}")
        lines.append("")
        lines.append(f"- Modelled operations: {', '.join(srep.modelled_ops) or '(none)'}")
        if srep.unmodelled_ops:
            lines.append(f"- Unmodelled operations (not simulated): {', '.join(srep.unmodelled_ops)}")
        lines.append(f"- Derived invariants: {', '.join(srep.invariants) or '(none)'}")
        for note in srep.notes:
            lines.append(f"- Note: {note}")
        cov = getattr(srep, "model_coverage", {}) or {}
        if cov:
            summary = cov.get("summary", {})
            lines.append(
                f"- Model coverage: {'COMPLETE' if cov.get('complete') else 'INCOMPLETE'} "
                f"({summary.get('modelled_functions', 0)}/"
                f"{summary.get('reachable_functions', 0)} reachable functions, "
                f"{summary.get('unmodelled_statements', 0)} unmodelled statement(s), "
                f"{summary.get('unmodelled_call_edges', 0)} unresolved call edge(s))"
            )
            for gap in (cov.get("gaps") or [])[:5]:
                lines.append(
                    f"  - gap: {gap.get('path', '')}:{gap.get('line', '')} "
                    f"{gap.get('function', '')} - "
                    f"{gap.get('statement') or gap.get('reason', '')}"
                )
        lines.append(f"- Verdict: {cert.verdict_line()}")
        lines.append("")
        for v in cert.violations[:3]:
            seq = " -> ".join(
                f"{step.get('actor')}.{step.get('action')}({step.get('params')})"
                for step in v.get("minimal_sequence", [])
            )
            lines.append(f"  - `{v.get('invariant_id')}` broken by: {seq}")
        lines.append("")
    return "\n".join(lines)


def rust_as_dict(report, flags: tuple[CandidateFlag, ...]) -> dict:
    """The machine-readable form of a Rust surface scan."""
    by_rule: dict[str, int] = {}
    for flag in flags:
        by_rule[flag.rule] = by_rule.get(flag.rule, 0) + 1
    return {
        "language": "rust",
        "root": report.root,
        "files_scanned": len(report.files),
        "modules": len(report.modules),
        "functions": len(report.functions),
        "dispatchables": len(report.dispatchables),
        "leads": len(flags),
        "leads_by_rule": dict(sorted(by_rule.items(), key=lambda kv: (-kv[1], kv[0]))),
        "errors": list(report.errors),
        "disclaimer": DISCLAIMER,
        "surface": [
            {
                "module": module.name,
                "path": module.path,
                "storage_items": list(module.storage_items),
                "dispatchables": [
                    {
                        "name": f.name,
                        "signature": f.signature,
                        "weight": f.weight,
                        "line": f.line,
                    }
                    for f in module.dispatchables
                ],
            }
            for module in report.modules
        ],
        "candidates": [flag.as_dict() for flag in flags],
    }


def render_rust_markdown(report, flags: tuple[CandidateFlag, ...]) -> str:
    """The human-readable form of a Rust surface scan."""
    lines: list[str] = []
    lines.append("# Attack-surface ingestion (Rust / Substrate)")
    lines.append("")
    lines.append(f"- root: `{report.root}`")
    lines.append(f"- files scanned: {len(report.files)}")
    lines.append(f"- modules: {len(report.modules)}")
    lines.append(f"- dispatchables (attacker-reachable): {len(report.dispatchables)}")
    lines.append(f"- leads: {len(flags)}")
    lines.append("")

    if report.dispatchables:
        lines.append("## Dispatchables")
        lines.append("")
        lines.append("| module | dispatchable | weight | line |")
        lines.append("|---|---|---|---|")
        for module in report.modules:
            for f in module.dispatchables:
                weight = f.weight or "—"
                lines.append(f"| {module.name} | `{f.name}` | `{weight}` | {module.path}:{f.line} |")
        lines.append("")

    if flags:
        lines.append("## Candidate leads")
        lines.append("")
        lines.append("| severity | rule | category | function | location | evidence |")
        lines.append("|---|---|---|---|---|---|")
        for flag in flags:
            evidence = flag.evidence.replace("|", "\\|")
            lines.append(
                f"| {flag.severity_hint} | `{flag.rule}` | {flag.category} | "
                f"`{flag.function}` | {flag.path}:{flag.line} | `{evidence}` |"
            )
        lines.append("")
        lines.append("### The question each lead asks")
        lines.append("")
        for flag in flags:
            lines.append(f"- **{flag.rule}** ({flag.path}:{flag.line}) — {flag.question}")
        lines.append("")

    if report.errors:
        lines.append("## What this scan could not read")
        lines.append("")
        for error in report.errors:
            lines.append(f"- {error}")
        lines.append("")

    lines.append("> " + DISCLAIMER)
    lines.append("")
    return "\n".join(lines)


def go_as_dict(report, flags: tuple[CandidateFlag, ...]) -> dict:
    """The machine-readable form of a Go / Cosmos surface scan."""
    by_rule: dict[str, int] = {}
    for flag in flags:
        by_rule[flag.rule] = by_rule.get(flag.rule, 0) + 1
    from .golang_calls import GoCallGraph

    graph_summary = GoCallGraph(report).summary()
    return {
        "language": "go",
        "root": report.root,
        "files_scanned": len(report.files),
        "packages": len(report.packages),
        "functions": len(report.functions),
        "handlers": len(report.handlers),
        "consensus_entry_points": len(report.consensus),
        "stubs": len(report.stubs),
        "build_flavors": dict(report.build_flavors),
        "stub_files": list(report.stub_files),
        "full_files": list(report.full_files),
        "boundaries": [b.__dict__ for b in report.boundaries],
        "leads": len(flags),
        "leads_by_rule": dict(sorted(by_rule.items(), key=lambda kv: (-kv[1], kv[0]))),
        "errors": list(report.errors),
        "disclaimer": DISCLAIMER,
        "surface": [
            {
                "package": pkg.name,
                "path": pkg.path,
                "files": list(pkg.files),
                "types": [
                    {"name": t.name, "kind": t.kind, "line": t.line}
                    for t in pkg.types
                ],
                "handlers": [
                    {"receiver": f.receiver, "name": f.name, "line": f.line,
                     "path": f.path, "stub": f.stub, "build_flavor": f.build_flavor}
                    for f in pkg.functions if f.is_handler or f.is_consensus
                ],
            }
            for pkg in report.packages
        ],
        "call_graph": graph_summary.to_dict(),
        "candidates": [flag.as_dict() for flag in flags],
    }


def render_go_markdown(report, flags: tuple[CandidateFlag, ...]) -> str:
    """The human-readable form of a Go / Cosmos surface scan."""
    lines: list[str] = []
    lines.append("# Attack-surface ingestion (Go / Cosmos SDK)")
    lines.append("")
    lines.append(f"- root: `{report.root}`")
    lines.append(f"- files scanned: {len(report.files)}")
    lines.append(f"- packages: {len(report.packages)}")
    lines.append(f"- functions: {len(report.functions)}")
    lines.append(f"- handlers / consensus entry points: {len(report.handlers)} / {len(report.consensus)}")
    lines.append(f"- stub functions: {len(report.stubs)}")
    lines.append(f"- build flavors: {dict(report.build_flavors)}")
    lines.append(f"- leads: {len(flags)}")
    from .golang_calls import GoCallGraph

    graph_summary = GoCallGraph(report).summary()
    lines.append(f"- call edges resolved / unresolved: {graph_summary.resolved} / {graph_summary.unresolved}")
    lines.append("")

    if report.stub_files:
        lines.append("## Public-build stubs")
        lines.append("")
        lines.append(
            "These files are behind a `!full` build tag (or named `*_stub.go`). "
            "They are **not** the implementation the full build runs; a finding in "
            "them does not establish a finding on the deployed chain."
        )
        lines.append("")
        for path in report.stub_files[:80]:
            lines.append(f"- `{path}`")
        if len(report.stub_files) > 80:
            lines.append(f"- … {len(report.stub_files) - 80} more")
        lines.append("")

    if report.boundaries:
        lines.append("## Unmodelled language boundaries")
        lines.append("")
        for b in report.boundaries:
            lines.append(f"- `{b.path}:{b.line}` {b.kind}: `{b.detail}`")
        lines.append("")

    if report.consensus:
        lines.append("## Consensus and message entry points")
        lines.append("")
        lines.append("| package | receiver | function | path | build |")
        lines.append("|---|---|---|---|---|")
        for f in report.handlers + report.consensus:
            lines.append(
                f"| {f.package} | `{f.receiver or '—'}` | `{f.name}` | "
                f"`{f.path}:{f.line}` | {f.build_flavor} |"
            )
        lines.append("")

    if graph_summary.delegated_writes:
        lines.append("## Delegated state writes")
        lines.append("")
        lines.append("| handler | delegated keeper method | location |")
        lines.append("|---|---|---|")
        for handler, callee, path, line in graph_summary.delegated_writes:
            lines.append(f"| `{handler}` | `{callee}` | `{path}:{line}` |")
        lines.append("")

    if graph_summary.unresolved_dispatches:
        lines.append("## Unresolved handler dispatches")
        lines.append("")
        lines.append("These calls are not declared in the scanned tree. They are a "
                     "coverage gap, not a finding.")
        lines.append("")
        for handler, expression in graph_summary.unresolved_dispatches:
            lines.append(f"- `{handler}` -> `{expression}`")
        lines.append("")

    if flags:
        lines.append("## Candidate leads")
        lines.append("")
        lines.append("| severity | rule | category | function | location | evidence |")
        lines.append("|---|---|---|---|---|---|")
        for flag in flags:
            evidence = flag.evidence.replace("|", "\\|")
            lines.append(
                f"| {flag.severity_hint} | `{flag.rule}` | {flag.category} | "
                f"`{flag.contract}.{flag.function}` | {flag.path}:{flag.line} | `{evidence}` |"
            )
        lines.append("")
        lines.append("### The question each lead asks")
        lines.append("")
        for flag in flags:
            lines.append(f"- **{flag.rule}** ({flag.path}:{flag.line}) — {flag.question}")
        lines.append("")

    if report.errors:
        lines.append("## What this scan could not read")
        lines.append("")
        for error in report.errors:
            lines.append(f"- {error}")
        lines.append("")

    lines.append("> " + DISCLAIMER)
    lines.append("")
    return "\n".join(lines)
