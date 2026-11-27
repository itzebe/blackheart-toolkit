"""Shannon adapter (AGPL-3.0) -- isolated, process-based.

Shannon (https://github.com/KeygraphHQ/shannon) is an autonomous AI pentester for
web applications and APIs. Its real interface is a CLI run through ``npx``:

    npx @keygraph/shannon@latest start -u <url> -r <repo> [--config f]
        [--workspace name] [--output dir] [--yes]

It requires Docker (a worker container) and Node.js 22+, and writes a workspace
under ``./workspaces/<name>/`` containing ``.shannon/deliverables/report.json``
(the structured findings), ``report.sarif`` (SARIF 2.1.0) and a surfaced
``Security-Assessment-Report.md``.

**License boundary.** Shannon is AGPL-3.0. BLACKHEART is MIT. This adapter
therefore *never* imports, copies, or links Shannon source: it invokes the
upstream CLI as a separate process (``npx``) and reads only its output files.
That keeps the AGPL work at arm's length. If Shannon is not installed, the
adapter reports MISSING and BLACKHEART's own engine remains fully usable.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

from .contract import (
    Capability,
    EngineAdapter,
    EngineState,
    EngineUnavailable,
    ExecutionMetadata,
    ExecutionResult,
    Health,
    find_json_records,
    redact_secrets,
    run_bounded,
)
from .schema import NormalizedFinding, normalize_cvss, normalize_cwe, normalize_severity
from ..models import utcnow

_VERSION_RE = re.compile(r"(\d+\.\d+\.\d+)")
#: The pinned upstream package this adapter is written against.
SHANNON_PACKAGE = "@keygraph/shannon"


class ShannonAdapter(EngineAdapter):
    name = "shannon"
    upstream_url = "https://github.com/KeygraphHQ/shannon"
    license_id = "AGPL-3.0"
    description = "Source-aware autonomous pentester (web/API, NO EXPLOIT NO FINDING)"

    _CAPABILITIES = [
        ("source_aware", "Source-code-aware attack-path & data-flow analysis"),
        ("architecture", "Application architecture & trust-boundary mapping"),
        ("authz_testing", "Authentication & authorization testing"),
        ("injection", "Injection, XSS, SSRF testing"),
        ("browser", "Browser automation for live exploitation"),
        ("exploit_validation", "Actual exploit validation (NO EXPLOIT, NO FINDING)"),
        ("poc", "Reproducible proof-of-concept evidence"),
        ("resumable", "Resumable workspaces"),
        ("json_report", "JSON + Markdown reports"),
        ("sarif", "SARIF 2.1.0 report"),
        ("ci_gate", "CI/CD-compatible security gate (report.sarif)"),
    ]

    # -- discovery --------------------------------------------------------- #
    def _npx(self) -> str | None:
        return self._which("npx")

    def _local_shannon(self) -> str | None:
        return self._which("shannon")

    def detect_installation(self) -> bool:
        # Shannon ships as an npx package; a local `shannon` shim also counts.
        return self._local_shannon() is not None or self._npx() is not None

    def _base_argv(self) -> list[str] | None:
        local = self._local_shannon()
        if local:
            return [local]
        npx = self._npx()
        if npx:
            return [npx, "-y", f"{SHANNON_PACKAGE}@latest"]
        return None

    def inspect_version(self) -> str:
        cached = getattr(self, "_version_cache", None)
        if cached is not None:
            return cached
        base = self._base_argv()
        if not base:
            self._version_cache = ""
            return ""
        try:
            out = run_bounded(base + ["--version"], cwd=self.workspace, timeout_s=120)
        except OSError:
            self._version_cache = ""
            return ""
        m = _VERSION_RE.search((out.stdout or "") + (out.stderr or ""))
        self._version_cache = m.group(1) if m else (out.stdout or out.stderr or "").strip()[:64]
        return self._version_cache

    def verify_health(self) -> Health:
        base = self._base_argv()
        if not base:
            return Health(EngineState.MISSING, detail="neither `shannon` nor `npx` is on PATH")
        docker = self._which("docker")
        if not docker:
            return Health(EngineState.UNSUPPORTED,
                          detail="shannon requires docker for its worker container; docker is unavailable")
        version = self.inspect_version()
        has_provider = any(
            os.environ.get(k)
            for k in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY", "XAI_API_KEY", "AWS_BEARER_TOKEN_BEDROCK")
        )
        detail = "shannon + docker present"
        if not has_provider:
            detail += "; no model-provider key in environment (configure before a live scan)"
        return Health(EngineState.INSTALLED, version=version, detail=detail)

    def inspect_capabilities(self) -> list[Capability]:
        installed = self.detect_installation()
        note = "" if installed else "engine not installed"
        return [Capability(k, label, installed, note) for k, label in self._CAPABILITIES]

    def validate_configuration(self) -> tuple[bool, str]:
        if not self.detect_installation():
            return False, "shannon is not installed (no `shannon` or `npx` on PATH)"
        if not self._which("docker"):
            return False, "docker is required by shannon and is not available"
        return True, "ok"

    # -- execution --------------------------------------------------------- #
    def _build_argv(self, target: str, options: dict) -> list[str]:
        base = self._base_argv() or ["npx", "-y", f"{SHANNON_PACKAGE}@latest"]
        argv = base + ["start", "-u", target]
        if options.get("repo"):
            argv += ["-r", str(options["repo"])]
        if options.get("config"):
            argv += ["--config", str(options["config"])]
        if options.get("workspace_name"):
            argv += ["--workspace", str(options["workspace_name"])]
        argv += ["--yes"]  # non-interactive: never prompt
        return argv

    def prepare_execution(self, target: str, **options: Any) -> ExecutionMetadata:
        return ExecutionMetadata(
            engine=self.name,
            version=self.inspect_version(),
            argv=self._build_argv(target, options),
            cwd=str(self.workspace),
            started_at=utcnow(),
            target=target,
        )

    def execute_scan(self, target: str, **options: Any) -> ExecutionResult:
        health = self.verify_health()
        if health.state in (EngineState.MISSING, EngineState.UNSUPPORTED):
            raise EngineUnavailable(health.detail)
        if not options.get("repo"):
            raise EngineUnavailable("shannon requires a source repository (pass repo=...)")
        meta = self.prepare_execution(target, **options)
        timeout_s = float(options.get("timeout_s", self.config.get("timeout_s", 5400)))
        env = dict(os.environ)
        env.setdefault("NO_COLOR", "1")
        env.setdefault("CI", "1")
        out = run_bounded(meta.argv, cwd=self.workspace, env=env, timeout_s=timeout_s,
                          cancel_event=options.get("cancel_event"))
        meta.finished_at = utcnow()
        meta.exit_code = out.returncode
        meta.output_sha256 = out.output_sha256
        meta.timed_out = out.timed_out
        meta.cancelled = out.cancelled
        if out.cancelled:
            meta.state = EngineState.CANCELLED
        elif out.timed_out:
            meta.state = EngineState.FAILED
            meta.note = "timeout"
        elif out.returncode == 0:
            meta.state = EngineState.COMPLETED
        else:
            meta.state = EngineState.FAILED
            meta.note = f"exit {out.returncode}"

        run_dir = self._find_workspace(options.get("workspace_name"))
        artifacts = self.collect_artifacts(run_dir) if run_dir else {}
        records = self._load_report_json(run_dir) if run_dir else []
        if meta.state == EngineState.COMPLETED and not artifacts:
            meta.state = EngineState.PARTIAL
            meta.note = "completed but no shannon deliverables found"
        return ExecutionResult(
            metadata=meta,
            raw_stdout=redact_secrets(out.stdout),
            raw_stderr=redact_secrets(out.stderr),
            artifacts=artifacts,
            raw_records=records,
        )

    # -- artifacts --------------------------------------------------------- #
    def _find_workspace(self, name: str | None) -> Path | None:
        root = self.workspace / "workspaces"
        if not root.is_dir():
            return None
        if name:
            candidate = root / str(name)
            if candidate.is_dir():
                return candidate
        dirs = [d for d in root.iterdir() if d.is_dir()]
        return max(dirs, key=lambda d: d.stat().st_mtime) if dirs else None

    def collect_artifacts(self, run_dir: Path) -> dict[str, str]:
        artifacts: dict[str, str] = {}
        if run_dir is None or not run_dir.is_dir():
            return artifacts
        candidates = [
            run_dir / ".shannon" / "deliverables" / "report.json",
            run_dir / ".shannon" / "deliverables" / "report.sarif",
            run_dir / "Security-Assessment-Report.md",
            run_dir / ".shannon" / "deliverables" / "comprehensive_security_assessment_report.md",
        ]
        for path in candidates:
            if path.is_file():
                artifacts[path.name] = str(path)
        return artifacts

    def _load_report_json(self, run_dir: Path) -> list[dict]:
        path = run_dir / ".shannon" / "deliverables" / "report.json"
        return find_json_records(path) if path.is_file() else []

    # -- normalization ----------------------------------------------------- #
    def normalize_findings(self, result: ExecutionResult) -> list[NormalizedFinding]:
        findings: list[NormalizedFinding] = []
        for rec in result.raw_records:
            finding = self._normalize_one(rec, result)
            if finding is not None:
                findings.append(finding)
        return findings

    def _normalize_one(self, rec: dict, result: ExecutionResult) -> NormalizedFinding | None:
        title = str(rec.get("title") or rec.get("name") or "").strip()
        if not title:
            return None
        code_paths = rec.get("code_paths") or []
        source_location = ""
        if isinstance(code_paths, list) and code_paths:
            source_location = str(code_paths[0])
        elif rec.get("file"):
            source_location = str(rec["file"])
        poc_steps = rec.get("exploitation_steps") or rec.get("steps") or []
        steps = [str(s) for s in poc_steps] if isinstance(poc_steps, list) else []
        finding = NormalizedFinding(
            source_engine=self.name,
            engine_version=result.metadata.version,
            target_id=result.metadata.target,
            raw_artifact=result.artifacts.get("report.json", ""),
            category=str(rec.get("category") or rec.get("vulnerability_type") or ""),
            title=title,
            description=str(rec.get("description") or ""),
            severity=normalize_severity(rec.get("severity")),
            cvss=normalize_cvss(rec.get("cvss")),
            cwe=normalize_cwe(rec.get("cwe")),
            confidence=str(rec.get("confidence") or ""),
            component=str(rec.get("endpoint") or rec.get("component") or ""),
            source_location=source_location,
            attack_vector=str(rec.get("method") or rec.get("attack_vector") or ""),
            preconditions=[str(p) for p in (rec.get("prerequisites") or []) if p],
            attacker_capabilities=[str(p) for p in (rec.get("attacker_capabilities") or []) if p],
            exploit_steps=steps,
            reproduction=str(rec.get("proof_of_concept") or rec.get("poc") or rec.get("reproduction") or ""),
            evidence_refs=[str(rec["evidence"])] if rec.get("evidence") else [],
            request_response=str(rec.get("request_response") or ""),
            execution_environment=f"shannon {result.metadata.version}",
            reproduction_status=str(rec.get("repro_status") or "reproduced"),
            impact=str(rec.get("impact") or ""),
            remediation=str(rec.get("mitigation") or rec.get("remediation") or ""),
            raw=rec,
        )
        return finding.finalize()
