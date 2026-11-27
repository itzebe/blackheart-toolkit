"""One resumable mission artifact around the source pipeline.

The engines are individually callable, but an operator should not have to
reconstruct which stage ran, what it concluded, and where the evidence lives.
This module runs the existing source pipeline and writes two artifacts:

* ``mission.json`` -- the complete :class:`PipelineResult` payload;
* ``MISSION.md`` -- a short human report with every stage's own status.

It adds no engine and upgrades nothing: a lead stays a lead, a bounded negative
stays a bounded negative, and only the pipeline's own verdict is printed.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

from .pipeline import PipelineConfig, PipelineResult, run_source_pipeline


@dataclass
class MissionArtifacts:
    result: PipelineResult
    directory: Path
    json_path: Path
    markdown_path: Path

    def to_dict(self) -> dict:
        return {
            "result": self.result.to_dict(),
            "artifacts": {
                "directory": str(self.directory),
                "json": str(self.json_path),
                "markdown": str(self.markdown_path),
            },
        }


def _slug(text: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_.-]+", "-", text.strip()).strip(".-")
    return cleaned or "mission"


def render_markdown(result: PipelineResult) -> str:
    lines = [
        f"# Mission: {result.target or result.address}",
        "",
        f"- Status: `{result.status}`",
        f"- Confirmed: `{result.confirmed}`",
        f"- Verdict: {result.verdict_line()}",
        f"- Invariant: `{result.invariant_id or 'none'}`",
        f"- Finding: `{result.finding_id or 'none'}` "
        f"(`{result.finding_status or 'none'}`)",
        "",
        "## Stages",
        "",
    ]
    for stage in result.stages:
        lines.append(f"- `{stage.stage}` — **{stage.status}** — {stage.summary}")
    if result.reasons:
        lines += ["", "## Reasons and limits", ""]
        lines += [f"- {reason}" for reason in result.reasons]
    if result.economic:
        lines += ["", "## Economic result", "", "```json",
                  json.dumps(result.economic, indent=2), "```"]
    if result.verification:
        lines += ["", "## Independent verification", "", "```json",
                  json.dumps(result.verification, indent=2), "```"]
    lines += ["", "> A local source model is not a deployment claim. A lead is not a finding."]
    return "\n".join(lines) + "\n"


def run_mission(config: PipelineConfig, *, directory: str | Path | None = None) -> MissionArtifacts:
    """Run the source pipeline and write the mission artifacts."""
    result = run_source_pipeline(config)
    root = Path(directory) if directory else (
        Path("research/private/missions") / _slug(
            config.contract_name or Path(config.source_path).stem or "mission"))
    root.mkdir(parents=True, exist_ok=True)
    json_path = root / "mission.json"
    markdown_path = root / "MISSION.md"
    json_path.write_text(json.dumps(result.to_dict(), indent=2), encoding="utf-8")
    markdown_path.write_text(render_markdown(result), encoding="utf-8")
    return MissionArtifacts(result, root, json_path, markdown_path)
