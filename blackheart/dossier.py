"""Project dossier: one explorable view of a tree, for a human or an agent.

This module adds **no engine**. It calls the scanner, the rule engine, the
interrogation pass and the dataflow pass that already exist, and renders what
they already report as a single ranked view:

* the recovered surface (contracts, functions, externally callable, state-changing);
* candidate leads (from the rule engine);
* falsified claims (from ``interrogate``);
* unprivileged taint flows (from ``dataflow``, Solidity only);
* the scanner's own blind spots (unread source, unsupported constructs);
* a ranked ``next_probes`` list that merges the strongest of the above.

Every item is a **lead**, never a finding. The dossier exists so that opening an
advanced or already-audited project starts from one page of what the code says
and where it cannot be trusted, instead of a blank editor.
"""

from __future__ import annotations

import dataclasses
from pathlib import Path
from typing import Any

DISCLAIMER = (
    "A dossier is a map, not a finding. Every item is a lead; none is a "
    "vulnerability until it is reproduced under scope, and a clean scan is not "
    "a proof of safety."
)

_SEVERITY_ORDER = {"critical": 0, "high": 0, "medium": 1, "low": 2, "info": 3}


def _flag_dict(flag: Any) -> dict[str, Any]:
    """Normalise a per-language flag object to a dict without assuming its type."""
    for name in ("as_dict", "to_dict"):
        fn = getattr(flag, name, None)
        if callable(fn):
            try:
                return dict(fn())
            except Exception:  # noqa: BLE001 - a flag must never crash the dossier
                pass
    if dataclasses.is_dataclass(flag):
        try:
            return dataclasses.asdict(flag)
        except Exception:  # noqa: BLE001
            pass
    return {"value": repr(flag)}


def _severity(flag: dict[str, Any]) -> str:
    value = flag.get("severity_hint") or flag.get("severity") or "info"
    return str(value).lower()


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


def _surface(language: str, path: str) -> dict[str, Any]:
    if language == "solidity":
        from .ingest import evaluate, ingest

        report = ingest(path)
        return {
            "contracts": len(report.contracts),
            "functions": len(report.functions),
            "externally_callable": sum(1 for f in report.functions if f.externally_callable),
            "state_changing": sum(1 for f in report.functions if f.state_changing),
            "errors": list(report.errors),
            "leads": [_flag_dict(f) for f in evaluate(report)],
        }
    if language == "rust":
        from .ingest import evaluate_rust, ingest_rust

        report = ingest_rust(path)
        return {
            "contracts": len(report.modules),
            "functions": len(report.functions),
            "dispatchables": len(report.dispatchables),
            "errors": list(report.errors),
            "leads": [_flag_dict(f) for f in evaluate_rust(report)],
        }
    if language == "go":
        from .ingest import evaluate_go, ingest_go

        report = ingest_go(path)
        return {
            "contracts": len(report.packages),
            "functions": len(report.functions),
            "boundaries": len(report.boundaries),
            "errors": list(report.errors),
            "leads": [_flag_dict(f) for f in evaluate_go(report)],
        }
    if language == "vyper":
        from .ingest import evaluate_vyper, scan_vyper

        root = Path(path).expanduser()
        files = [root] if root.is_file() else sorted(root.rglob("*.vy"))
        contracts = functions = 0
        errors: list[str] = []
        leads: list[dict[str, Any]] = []
        for item in files:
            report = scan_vyper(item.read_text(encoding="utf-8", errors="replace"), str(item))
            contracts += 1
            functions += len(report.functions)
            errors.extend(report.errors)
            leads.extend(_flag_dict(f) for f in evaluate_vyper(report))
        return {"contracts": contracts, "functions": functions,
                "errors": errors, "leads": leads}
    return {"contracts": 0, "functions": 0,
            "errors": [f"no scanner for language {language!r}"], "leads": []}


def _interrogation(language: str, path: str) -> dict[str, Any]:
    if language not in ("solidity", "rust", "go"):
        return {"supported": False,
                "reason": f"interrogation supports solidity, rust and go; language is {language!r}"}
    from .interrogate import FALSIFIED, UNTESTABLE, interrogate, summarise

    verdicts, resolved, errors = interrogate(path, language)
    return {
        "supported": True,
        "language": resolved,
        "summary": summarise(verdicts),
        "errors": list(errors),
        "falsified": [v.as_dict() for v in verdicts if v.status == FALSIFIED],
        "untestable": [v.as_dict() for v in verdicts if v.status == UNTESTABLE],
    }


def _dataflow(path: str) -> dict[str, Any]:
    from .dataflow import analyse_source

    files = _sol_files(Path(path).expanduser())
    if not files:
        return {"supported": False, "reason": "no .sol files to analyse"}
    result = analyse_source(files)
    return {
        "supported": True,
        "contracts": len(result.contracts),
        "functions": result.functions,
        "flows": len(result.flows),
        "unprivileged_flows": [f.to_dict() for f in result.unprivileged],
        "unsupported": list(result.unsupported)[:20],
    }


def _rank(surface: dict[str, Any], interrogation: dict[str, Any],
          dataflow: dict[str, Any]) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for lead in surface.get("leads", []):
        items.append({
            "kind": "candidate-lead",
            "severity": _severity(lead),
            "location": lead.get("location") or lead.get("path", ""),
            "detail": lead.get("rationale") or lead.get("rule", ""),
            "question": lead.get("question", ""),
        })
    for verdict in interrogation.get("falsified", []):
        items.append({
            "kind": "falsified-claim",
            "severity": "medium",
            "location": verdict.get("location", ""),
            "detail": verdict.get("claim", ""),
            "question": verdict.get("question", ""),
        })
    for flow in dataflow.get("unprivileged_flows", []):
        items.append({
            "kind": "unprivileged-flow",
            "severity": "medium" if not flow.get("guarded") else "low",
            "location": f"{flow.get('contract', '')}:{flow.get('function', '')}:{flow.get('line', '')}",
            "detail": f"{flow.get('source', '')} -> {flow.get('sink', '')}",
            "question": "Does this unprivileged taint path reach a value or authority sink?",
        })
    items.sort(key=lambda item: _SEVERITY_ORDER.get(item["severity"], 9))
    return items[:25]


def build_dossier(path: str, language: str = "auto",
                  allow_unscanned: tuple[str, ...] = ()) -> dict[str, Any]:
    """Compose the existing passes into one dossier dict. Never executes the target."""
    from .ingest import assess_coverage, detect_language

    resolved = detect_language(path) if language == "auto" else language
    coverage = assess_coverage(path, resolved, allow_unscanned=tuple(allow_unscanned))
    if coverage.blocked:
        return {
            "target": str(path),
            "language": resolved,
            "blocked": True,
            "block_message": coverage.block_message(),
            "language_coverage": coverage.to_dict(),
            "discipline": DISCLAIMER,
        }

    surface = _surface(resolved, path)
    interrogation = _interrogation(resolved, path)
    dataflow = _dataflow(path) if resolved == "solidity" else {
        "supported": False,
        "reason": f"dataflow is Solidity-only; language is {resolved!r}",
    }
    return {
        "target": str(path),
        "language": resolved,
        "blocked": False,
        "language_coverage": coverage.to_dict(),
        "surface": surface,
        "interrogation": interrogation,
        "dataflow": dataflow,
        "next_probes": _rank(surface, interrogation, dataflow),
        "discipline": DISCLAIMER,
    }


def render_markdown(dossier: dict[str, Any]) -> str:
    if dossier.get("blocked"):
        return (f"# Dossier blocked\n\n{dossier.get('block_message', '')}\n\n"
                f"> {dossier.get('discipline', DISCLAIMER)}\n")

    surface = dossier.get("surface", {})
    interrogation = dossier.get("interrogation", {})
    dataflow = dossier.get("dataflow", {})
    lines: list[str] = ["# Project dossier", ""]
    lines.append(f"- target: `{dossier.get('target', '')}`")
    lines.append(f"- language: {dossier.get('language', '')}")
    coverage = dossier.get("language_coverage") or {}
    status = coverage.get("status") if isinstance(coverage, dict) else None
    if status:
        lines.append(f"- language coverage: {status}")
    lines.append("")

    lines.append("## Surface")
    lines.append("")
    lines.append(f"- contracts/packages: {surface.get('contracts', 0)}")
    lines.append(f"- functions: {surface.get('functions', 0)}")
    if "externally_callable" in surface:
        lines.append(f"- externally callable: {surface['externally_callable']}")
    if "state_changing" in surface:
        lines.append(f"- state-changing: {surface['state_changing']}")
    if "dispatchables" in surface:
        lines.append(f"- dispatchables: {surface['dispatchables']}")
    if "boundaries" in surface:
        lines.append(f"- cgo/FFI boundaries: {surface['boundaries']}")
    lines.append("")

    leads = surface.get("leads", [])
    lines.append(f"## Candidate leads ({len(leads)})")
    lines.append("")
    if leads:
        lines.append("| severity | category | location | question |")
        lines.append("|---|---|---|---|")
        for lead in leads:
            lines.append(
                f"| {_severity(lead)} | {lead.get('category', lead.get('rule', ''))} | "
                f"{lead.get('location', '')} | {lead.get('question', '')} |"
            )
    else:
        lines.append("No rule matched. This is not a proof of safety — see the blind spots below.")
    lines.append("")

    if interrogation.get("supported"):
        summary = interrogation.get("summary", {})
        lines.append("## Interrogation")
        lines.append("")
        lines.append(f"- claims tested: {sum(summary.values())}")
        lines.append(f"- falsified: {summary.get('FALSIFIED', 0)}")
        lines.append(f"- survived (within this check): {summary.get('SURVIVED', 0)}")
        lines.append(f"- untestable: {summary.get('UNTESTABLE', 0)}")
        lines.append("")
        for verdict in interrogation.get("falsified", []):
            lines.append(f"- **FALSIFIED** `{verdict.get('location', '')}` — "
                         f"{verdict.get('claim', '')}")
        lines.append("")

    if dataflow.get("supported"):
        flows = dataflow.get("unprivileged_flows", [])
        lines.append(f"## Unprivileged data flows ({len(flows)})")
        lines.append("")
        if flows:
            lines.append("| contract:function:line | source -> sink |")
            lines.append("|---|---|")
            for flow in flows:
                loc = f"{flow.get('contract', '')}:{flow.get('function', '')}:{flow.get('line', '')}"
                lines.append(f"| {loc} | {flow.get('source', '')} -> {flow.get('sink', '')} |")
        else:
            lines.append("No unprivileged flow found within the model.")
        lines.append("")

    lines.append("## Next probes (ranked)")
    lines.append("")
    probes = dossier.get("next_probes", [])
    if probes:
        for probe in probes:
            lines.append(f"1. [{probe['kind']}/{probe['severity']}] `{probe['location']}` — "
                         f"{probe['detail']} _({probe['question']})_")
    else:
        lines.append("Nothing ranked. The surface is empty or entirely guarded within this model.")
    lines.append("")

    errors = list(surface.get("errors", [])) + list(interrogation.get("errors", []))
    if errors:
        lines.append("## What the scanner could not read")
        lines.append("")
        for error in errors:
            lines.append(f"- {error}")
        lines.append("")

    lines.append(f"> {DISCLAIMER}")
    lines.append("")
    return "\n".join(lines)
