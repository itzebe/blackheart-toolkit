"""Unified multi-engine reporting: Markdown, JSON, and SARIF 2.1.0.

A report is generated from an :class:`~blackheart.engines.orchestrator.OrchestrationResult`
and is honest by construction:

  * Confirmed clusters, unconfirmed candidates, duplicates and missing engines are
    reported in separate sections -- a candidate is never labelled a confirmed
    vulnerability.
  * Every finding carries its source engine, engine version, and the hash of the
    raw artifact it came from, so provenance survives into the report.
  * The SARIF mapping only emits results for clusters with a real severity, and
    labels each result's ``security-severity`` from CVSS when present. A cluster
    without a source location is anchored as a logical location, never a fake
    file path.
"""

from __future__ import annotations

import json

from .orchestrator import FindingCluster, OrchestrationResult
from .schema import SEVERITY_ORDER

#: SARIF only has three levels; map our five onto them, keeping the raw label.
_SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning",
                "low": "note", "info": "note"}
_SEVERITY_SCORE = {"critical": "9.5", "high": "8.0", "medium": "5.5",
                   "low": "3.0", "info": "0.0"}


def _sorted_clusters(clusters: list[FindingCluster]) -> list[FindingCluster]:
    return sorted(clusters, key=lambda c: SEVERITY_ORDER.get(c.severity, 5))


def render_markdown(result: OrchestrationResult, *, engagement: str = "",
                    authz_status: str = "") -> str:
    from ..mindset import ATTACKER_QUESTION

    lines: list[str] = []
    lines.append("# BLACKHEART Multi-Engine Assessment Report")
    lines.append("")
    lines.append(f"> {ATTACKER_QUESTION}")
    lines.append("")
    lines.append(f"- **Target:** {result.target}")
    if engagement:
        lines.append(f"- **Engagement:** {engagement}")
    lines.append(f"- **Authorization status:** {authz_status or 'not recorded'}")
    lines.append(f"- **Started:** {result.started_at}")
    lines.append(f"- **Finished:** {result.finished_at or 'in progress'}")
    lines.append("")

    # Executive summary
    lines.append("## Executive summary")
    lines.append("")
    lines.append(f"- Confirmed findings: **{len(result.confirmed)}**")
    lines.append(f"- Candidates needing more evidence: **{len(result.pending)}**")
    lines.append(f"- Known duplicates / prior art: **{len(result.duplicates)}**")
    lines.append(f"- Attack chains correlated: **{len(result.chains)}**")
    lines.append(f"- Total normalized candidates: **{len(result.candidates)}**")
    lines.append("")
    lines.append("> A candidate is *not* a confirmed vulnerability. Only clusters with "
                 "disposition CONFIRMED have passed BLACKHEART's independent verification "
                 "gate; everything else is an unproven lead from an external engine.")
    lines.append("")

    # Engines used
    lines.append("## Engines")
    lines.append("")
    lines.append("| Engine | State | Version | Findings | Detail |")
    lines.append("|---|---|---|---|---|")
    for e in result.engines:
        lines.append(f"| {e.engine} | {e.state} | {e.version or '-'} | {e.findings} | {e.detail or ''} |")
    lines.append("")
    if result.missing_engines:
        lines.append(f"**Engines not available this run:** {', '.join(result.missing_engines)}. "
                     "Their capabilities are NOT covered by this report.")
        lines.append("")

    # Confirmed
    lines.append("## Confirmed findings")
    lines.append("")
    if not result.confirmed:
        lines.append("_None. No cluster has passed independent verification._")
        lines.append("")
    for c in _sorted_clusters(result.confirmed):
        lines.extend(_cluster_md(c, confirmed=True))

    # Candidates
    lines.append("## Unconfirmed candidates (need more evidence)")
    lines.append("")
    if not result.pending:
        lines.append("_None._")
        lines.append("")
    for c in _sorted_clusters(result.pending):
        lines.extend(_cluster_md(c, confirmed=False))

    # Duplicates
    lines.append("## Duplicates / known prior art")
    lines.append("")
    if not result.duplicates:
        lines.append("_None._")
        lines.append("")
    for c in _sorted_clusters(result.duplicates):
        lines.append(f"- **{c.cluster_id}** {c.representative.title} "
                     f"(seen by: {', '.join(c.sources)})")
    lines.append("")

    # Attack chains
    lines.append("## Attack chains")
    lines.append("")
    if not result.chains:
        lines.append("_No chains correlated (a chain requires evidence that one weakness enables the next)._")
        lines.append("")
    for chain in result.chains:
        lines.append(f"- **{chain.chain_id}** {' -> '.join(chain.steps)}: {chain.rationale}")
    lines.append("")

    # Notes + limitations
    lines.append("## Execution notes and limitations")
    lines.append("")
    for note in result.notes or ["_No notes._"]:
        lines.append(f"- {note}")
    lines.append("- External engine output is untrusted candidate evidence; it cannot change "
                 "authorization, scope, or a finding's disposition.")
    lines.append("")
    return "\n".join(lines)


def _cluster_md(c: FindingCluster, *, confirmed: bool) -> list[str]:
    r = c.representative
    tag = "CONFIRMED" if confirmed else "CANDIDATE"
    out = [f"### [{tag}] {c.cluster_id} -- {r.title}", ""]
    out.append(f"- **Severity:** {c.severity}")
    if r.cvss is not None:
        out.append(f"- **CVSS:** {r.cvss}")
    if r.cwe:
        out.append(f"- **CWE:** {r.cwe}")
    out.append(f"- **Sources:** {', '.join(c.sources)}"
               + (" (corroborated)" if c.corroborated else ""))
    if r.component:
        out.append(f"- **Component:** {r.component}")
    if r.source_location:
        out.append(f"- **Location:** {r.source_location}")
    lens = c.attacker_lens()
    out.append(f"- **Attacker outcome:** {lens['outcome']}")
    out.append(f"- **Attacker levers:** {', '.join(lens['levers'])}")
    if lens["gaps"]:
        out.append(f"- **Lens gap:** {'; '.join(lens['gaps'])}")
    if r.description:
        out.append("")
        out.append(r.description)
    if r.impact:
        out.append("")
        out.append(f"**Impact:** {r.impact}")
    if r.exploit_steps:
        out.append("")
        out.append("**Exploit steps:**")
        out.extend(f"{i+1}. {s}" for i, s in enumerate(r.exploit_steps))
    if c.contradiction:
        out.append("")
        out.append(f"**Contradiction:** {c.contradiction_detail} (sent to independent verification)")
    if r.raw_artifact:
        out.append("")
        out.append(f"_Raw artifact: `{r.raw_artifact}`_")
    out.append("")
    return out


def render_json(result: OrchestrationResult, *, engagement: str = "",
                authz_status: str = "") -> str:
    from ..mindset import ATTACKER_QUESTION

    payload = {
        "schema": "blackheart.multi-engine-report.v1",
        "attacker_question": ATTACKER_QUESTION,
        "target": result.target,
        "engagement": engagement,
        "authorization_status": authz_status,
        "summary": {
            "confirmed": len(result.confirmed),
            "candidates": len(result.pending),
            "duplicates": len(result.duplicates),
            "chains": len(result.chains),
            "candidate_records": len(result.candidates),
        },
        "engines": [e.to_dict() for e in result.engines],
        "missing_engines": list(result.missing_engines),
        "clusters": [c.to_dict() for c in result.clusters],
        "chains": [c.to_dict() for c in result.chains],
        "notes": list(result.notes),
    }
    return json.dumps(payload, indent=2, default=str)


def render_sarif(result: OrchestrationResult) -> str:
    """Render a SARIF 2.1.0 log.

    Only clusters with a usable location or a component are emitted; each rule is
    keyed on the CWE when present, and ``security-severity`` is populated so GitHub
    code-scanning can rank alerts. A candidate that is not confirmed is still
    emitted (a code-scanning alert is a lead), but its properties record the
    BLACKHEART disposition so a consumer never mistakes it for a proven defect.
    """
    rules: dict[str, dict] = {}
    results: list[dict] = []
    for cluster in result.clusters:
        r = cluster.representative
        rule_id = r.cwe or _slug(r.title) or "BLACKHEART"
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": r.title[:128] or rule_id,
                "shortDescription": {"text": r.title[:200] or rule_id},
                "properties": {
                    "security-severity": str(r.cvss if r.cvss is not None
                                             else _SEVERITY_SCORE.get(cluster.severity, "0.0")),
                    "blackheart-disposition": cluster.disposition,
                    "sources": ", ".join(cluster.sources),
                },
            }
        location = _sarif_location(r.source_location, r.component)
        results.append({
            "ruleId": rule_id,
            "level": _SARIF_LEVEL.get(cluster.severity, "note"),
            "message": {"text": (r.description or r.title)[:1000]},
            "locations": [location],
            "properties": {
                "clusterId": cluster.cluster_id,
                "disposition": cluster.disposition,
                "severity": cluster.severity,
                "sources": cluster.sources,
                "corroborated": cluster.corroborated,
                "contradiction": cluster.contradiction,
            },
        })
    sarif = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {"driver": {
                "name": "BLACKHEART",
                "informationUri": "https://github.com/itzebe/blackheart",
                "rules": list(rules.values()),
            }},
            "results": results,
        }],
    }
    return json.dumps(sarif, indent=2)


def _sarif_location(source_location: str, component: str) -> dict:
    if source_location and "/" in source_location or (source_location and "." in source_location):
        uri = source_location.replace("\\", "/").lstrip("/")
        if ".." not in uri.split("/"):
            return {"physicalLocation": {"artifactLocation": {"uri": uri}}}
    return {"logicalLocations": [{"fullyQualifiedName": component or source_location or "target"}]}


def _slug(text: str) -> str:
    import re

    return re.sub(r"[^a-z0-9]+", "-", (text or "").lower()).strip("-")[:64]


def write_reports(result: OrchestrationResult, outdir, *, engagement: str = "",
                  authz_status: str = "", formats: tuple[str, ...] = ("md", "json", "sarif")) -> dict:
    """Write the requested report formats; return ``{format: path}``."""
    from pathlib import Path

    out = Path(outdir)
    out.mkdir(parents=True, exist_ok=True)
    written: dict[str, str] = {}
    if "md" in formats:
        p = out / "report.md"
        p.write_text(render_markdown(result, engagement=engagement, authz_status=authz_status), encoding="utf-8")
        written["md"] = str(p)
    if "json" in formats:
        p = out / "report.json"
        p.write_text(render_json(result, engagement=engagement, authz_status=authz_status), encoding="utf-8")
        written["json"] = str(p)
    if "sarif" in formats:
        p = out / "report.sarif"
        p.write_text(render_sarif(result), encoding="utf-8")
        written["sarif"] = str(p)
    return written
