"""Audit coverage: what an audit touched, and what it left unread.

Adds no engine. It parses an audit report (JSON, or Markdown as a heuristic),
maps each finding onto the recovered surface, and reports the reachable
functions that no finding refers to -- the unaudited surface, ranked by the
existing rule leads. A finding is a lead, never a verdict; this is a coverage
map, not a proof that the audited code is safe or the unaudited code is broken.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

DISCLAIMER = (
    "Coverage, not a verdict. An audited function is not proven safe, and an "
    "unaudited function is not proven broken; it is where the audit did not look."
)

_LOCATION_RE = re.compile(r"([A-Za-z0-9_./\\-]+\.(?:sol|vy|rs|go))\s*[:#]\s*(\d+)")
_SEVERITY_RE = re.compile(r"\b(critical|high|medium|low|informational|info)\b", re.IGNORECASE)
_TAG_RE = re.compile(r"\[([A-Z]+-\d+)\]|\(([A-Z]+-\d+)\)")
_HEADING_RE = re.compile(r"^(#{1,6})\s+(.*)$")
_IDENT_RE = re.compile(r"`([A-Za-z_][A-Za-z0-9_]*)`")
_SKIP_HEADINGS = {
    "table of contents", "contents", "introduction", "summary", "overview",
    "scope", "methodology", "disclaimer", "appendix", "conclusion",
    "executive summary", "about", "background", "risk classification",
}

_SEVERITY_RANK = {"medium": 0, "low": 1, "info": 2}


@dataclass(frozen=True)
class AuditFinding:
    id: str
    title: str
    severity: str = ""
    file: str = ""
    line: int = 0
    function: str = ""
    status: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {"id": self.id, "title": self.title, "severity": self.severity,
                "file": self.file, "line": self.line, "function": self.function,
                "status": self.status}


def _as_int(value: Any) -> int:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return 0


def _parse_location(text: str) -> tuple[str, int]:
    match = _LOCATION_RE.search(text or "")
    if not match:
        return "", 0
    return match.group(1), _as_int(match.group(2))


def _first(entry: dict[str, Any], *keys: str) -> str:
    for key in keys:
        value = entry.get(key)
        if isinstance(value, (str, int)) and str(value).strip():
            return str(value).strip()
    return ""


def _finding_from_dict(entry: dict[str, Any]) -> AuditFinding:
    location = entry.get("location")
    file = ""
    line = 0
    function = ""
    if isinstance(location, dict):
        file = _first(location, "file", "path", "source")
        line = _as_int(location.get("line", location.get("start_line", 0)))
        function = _first(location, "function", "symbol", "method")
    elif isinstance(location, str):
        file, line = _parse_location(location)
    file = file or _first(entry, "file", "path", "source_file", "filename")
    line = line or _as_int(entry.get("line", entry.get("start_line", 0)))
    function = function or _first(entry, "function", "symbol", "method")
    finding_id = _first(entry, "id", "finding_id", "issue_id", "ref") or "(no id)"
    title = _first(entry, "title", "name", "summary", "description", "issue") or finding_id
    severity = _first(entry, "severity", "risk", "impact", "classification").lower()
    status = _first(entry, "status", "state", "resolution", "fix").lower()
    return AuditFinding(finding_id, title, severity, file, line, function, status)


def parse_json_findings(text: str) -> list[AuditFinding]:
    data = json.loads(text)
    if isinstance(data, dict):
        for key in ("findings", "issues", "results", "vulnerabilities"):
            if isinstance(data.get(key), list):
                data = data[key]
                break
        else:
            data = [data]
    if not isinstance(data, list):
        return []
    return [_finding_from_dict(item) for item in data if isinstance(item, dict)]


def parse_markdown_findings(text: str) -> tuple[list[AuditFinding], list[str]]:
    findings: list[AuditFinding] = []
    uncertainties: list[str] = []
    current: dict[str, Any] | None = None

    def flush() -> None:
        nonlocal current
        if not current:
            return
        body = "\n".join(current["body"])
        file, line = _parse_location(body)
        sev_match = _SEVERITY_RE.search(current["title"] + " " + body)
        func_match = _IDENT_RE.search(body)
        findings.append(AuditFinding(
            id=current["id"] or "(no id)",
            title=current["title"],
            severity=(sev_match.group(1).lower() if sev_match else ""),
            file=file, line=line,
            function=(func_match.group(1) if func_match else ""),
        ))
        current = None

    for raw in text.splitlines():
        heading = _HEADING_RE.match(raw)
        if heading:
            title = heading.group(2).strip()
            level = len(heading.group(1))
            # A bare level-1 heading is a document title, not a finding; a level-1
            # heading that carries an issue tag is a finding in some report styles.
            if level == 1 and not _TAG_RE.search(title):
                flush()
                continue
            if title.casefold().strip("# ").strip() in _SKIP_HEADINGS:
                flush()
                continue
            flush()
            tag = _TAG_RE.search(title)
            finding_id = (tag.group(1) or tag.group(2)) if tag else ""
            clean = _TAG_RE.sub("", title).strip(" -:") or title
            current = {"id": finding_id, "title": clean, "body": []}
        elif current is not None:
            current["body"].append(raw)
    flush()

    if not findings:
        # Fall back to a bold-led bullet list, the other common shape.
        for raw in text.splitlines():
            bullet = re.match(r"^\s*[-*]\s+\*\*(.+?)\*\*\s*[:\-]?\s*(.*)$", raw)
            if not bullet:
                continue
            title = bullet.group(1).strip()
            tag = _TAG_RE.search(title)
            finding_id = (tag.group(1) or tag.group(2)) if tag else ""
            body = _TAG_RE.sub("", title).strip(" -:") + " " + bullet.group(2)
            file, line = _parse_location(body)
            sev = _SEVERITY_RE.search(body)
            findings.append(AuditFinding(
                id=finding_id or "(no id)",
                title=_TAG_RE.sub("", title).strip(" -:") or title,
                severity=(sev.group(1).lower() if sev else ""),
                file=file, line=line,
            ))
    if not findings:
        uncertainties.append("no findings recognised in the Markdown audit report")
    return findings, uncertainties


def load_audit_findings(path: str) -> tuple[list[AuditFinding], list[str]]:
    text = Path(path).expanduser().read_text(encoding="utf-8", errors="replace")
    stripped = text.lstrip()
    if stripped[:1] in ("{", "["):
        try:
            return parse_json_findings(text), []
        except json.JSONDecodeError as exc:
            findings, uncertainties = parse_markdown_findings(text)
            uncertainties.insert(0, f"report looked like JSON but failed to parse ({exc}); "
                                    "fell back to Markdown")
            return findings, uncertainties
    return parse_markdown_findings(text)


def _same_file(a: str, b: str) -> bool:
    if not a or not b:
        return False
    na, nb = a.replace("\\", "/"), b.replace("\\", "/")
    return na == nb or na.endswith("/" + nb) or nb.endswith("/" + na) or Path(na).name == Path(nb).name


def _function_key(contract: str, name: str) -> str:
    return f"{contract}.{name}"


def map_findings(findings: list[AuditFinding], report: Any) -> tuple[
        dict[str, list[str]], list[dict[str, Any]], list[str]]:
    """Map findings to ``Contract.function`` keys. Ambiguity is reported, never guessed."""
    audited: dict[str, list[str]] = {}
    unmapped: list[dict[str, Any]] = []
    file_level: list[str] = []
    funcs = [(_function_key(c.name, f.name), c.name, f, c.path)
             for c in report.contracts for f in c.functions]

    for finding in findings:
        hit = None
        if finding.function:
            candidates = [t for t in funcs if t[2].name == finding.function]
            if finding.file:
                candidates = [t for t in candidates if _same_file(t[3], finding.file)]
            if len(candidates) == 1:
                hit = candidates[0]
            elif len(candidates) > 1:
                unmapped.append({"id": finding.id,
                                 "reason": f"function {finding.function!r} is ambiguous "
                                           f"across {len(candidates)} definitions"})
                continue
        if hit is None and finding.file and finding.line:
            same = [t for t in funcs
                    if _same_file(t[3], finding.file) and t[2].line <= finding.line]
            if same:
                hit = max(same, key=lambda t: t[2].line)
        if hit is None and finding.file:
            same = [t for t in funcs if _same_file(t[3], finding.file)]
            if same:
                for key, _, _, _ in same:
                    audited.setdefault(key, []).append(finding.id)
                file_level.append(finding.id)
                continue
        if hit is None:
            unmapped.append({"id": finding.id,
                             "reason": "no function matched the finding location"})
            continue
        audited.setdefault(hit[0], []).append(finding.id)
    return audited, unmapped, file_level


def _leads_by_function(flags: tuple[Any, ...]) -> dict[str, list[Any]]:
    out: dict[str, list[Any]] = {}
    for flag in flags:
        out.setdefault(_function_key(flag.contract, flag.function), []).append(flag)
    return out


def build_audit_coverage(path: str, audit_path: str, language: str = "auto",
                         allow_unscanned: tuple[str, ...] = ()) -> dict[str, Any]:
    from .ingest import assess_coverage, detect_language, evaluate, ingest

    resolved = detect_language(path) if language == "auto" else language
    coverage = assess_coverage(path, resolved, allow_unscanned=tuple(allow_unscanned))
    if coverage.blocked:
        return {"target": str(path), "audit": str(audit_path), "language": resolved,
                "blocked": True, "block_message": coverage.block_message(),
                "language_coverage": coverage.to_dict(), "discipline": DISCLAIMER}
    if resolved != "solidity":
        return {"target": str(path), "audit": str(audit_path), "language": resolved,
                "blocked": False, "supported": False,
                "reason": "audit coverage maps Solidity surfaces only (functions carry "
                          "file:line); other languages are not mapped here",
                "discipline": DISCLAIMER}

    report = ingest(path)
    flags = evaluate(report)
    findings, uncertainties = load_audit_findings(audit_path)
    audited, unmapped, file_level = map_findings(findings, report)
    leads = _leads_by_function(flags)

    unaudited: list[dict[str, Any]] = []
    audited_surface: list[dict[str, Any]] = []
    total = 0
    for contract in report.contracts:
        for func in contract.functions:
            if func.declaration_only or not func.externally_callable:
                continue
            total += 1
            key = _function_key(contract.name, func.name)
            location = f"{contract.path}:{func.line}"
            if key in audited:
                audited_surface.append({"function": key, "location": location,
                                        "signature": func.signature,
                                        "findings": audited[key]})
                continue
            func_leads = leads.get(key, [])
            rank = min((_SEVERITY_RANK.get(lead.severity_hint, 9) for lead in func_leads),
                       default=9)
            unaudited.append({
                "function": key,
                "location": location,
                "signature": func.signature,
                "state_changing": func.state_changing,
                "leads": [lead.rule for lead in func_leads],
                "rank": rank,
            })
    unaudited.sort(key=lambda item: (item["rank"], 0 if item["state_changing"] else 1,
                                     item["function"]))
    covered = len(audited_surface)
    return {
        "target": str(path),
        "audit": str(audit_path),
        "language": resolved,
        "blocked": False,
        "supported": True,
        "findings_total": len(findings),
        "findings_mapped": len(findings) - len(unmapped),
        "unmapped_findings": unmapped,
        "file_level_findings": file_level,
        "parse_uncertainties": uncertainties,
        "audited_functions": audited_surface,
        "unaudited_functions": unaudited,
        "coverage": {"reachable_functions": total, "audited": covered,
                     "unaudited": total - covered,
                     "pct": round(100.0 * covered / total, 1) if total else 0.0},
        "language_coverage": coverage.to_dict(),
        "discipline": DISCLAIMER,
    }


def render_markdown(payload: dict[str, Any]) -> str:
    if payload.get("blocked"):
        return f"# Audit coverage blocked\n\n{payload.get('block_message', '')}\n"
    if not payload.get("supported", True):
        return f"# Audit coverage not supported\n\n{payload.get('reason', '')}\n"

    cov = payload.get("coverage", {})
    lines = ["# Audit coverage", ""]
    lines.append(f"- target: `{payload.get('target', '')}`")
    lines.append(f"- audit: `{payload.get('audit', '')}`")
    lines.append(f"- findings parsed: {payload.get('findings_total', 0)} "
                 f"(mapped: {payload.get('findings_mapped', 0)})")
    lines.append(f"- reachable functions: {cov.get('reachable_functions', 0)} "
                 f"| audited: {cov.get('audited', 0)} "
                 f"| unaudited: {cov.get('unaudited', 0)} "
                 f"({cov.get('pct', 0.0)}% touched)")
    lines.append("")

    lines.append("## Unaudited reachable surface (ranked)")
    lines.append("")
    unaudited = payload.get("unaudited_functions", [])
    if unaudited:
        lines.append("| rank | function | location | state-changing | leads |")
        lines.append("|---|---|---|---|---|")
        for item in unaudited:
            lines.append(f"| {item['rank']} | `{item['function']}` | {item['location']} | "
                         f"{item['state_changing']} | {', '.join(item['leads']) or '-'} |")
    else:
        lines.append("Every reachable function is referenced by at least one finding. "
                     "That is coverage, not a proof of safety.")
    lines.append("")

    if payload.get("audited_functions"):
        lines.append("## Functions the audit touched")
        lines.append("")
        for item in payload["audited_functions"]:
            lines.append(f"- `{item['function']}` ({item['location']}) — {', '.join(item['findings'])}")
        lines.append("")

    if payload.get("unmapped_findings"):
        lines.append("## Findings that did not map (uncertainty)")
        lines.append("")
        for item in payload["unmapped_findings"]:
            lines.append(f"- {item['id']}: {item['reason']}")
        lines.append("")

    if payload.get("parse_uncertainties"):
        lines.append("## Parse uncertainties")
        lines.append("")
        for item in payload["parse_uncertainties"]:
            lines.append(f"- {item}")
        lines.append("")

    lines.append(f"> {DISCLAIMER}")
    lines.append("")
    return "\n".join(lines)
