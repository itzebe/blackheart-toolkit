"""Strix adapter (Apache-2.0).

Strix (https://github.com/usestrix/strix) is a Python multi-agent penetration
testing tool. Its real interface is a console script:

    strix --target <url|path> [--instruction "..."] [--non-interactive]
          [--scan-mode ...] [--max-budget-usd N] [--config file]

It writes run artifacts under ``./strix_runs/<run>/`` -- notably
``vulnerabilities.json`` (the findings list), ``run.json`` (run record) and a
``findings.sarif`` sidecar.

This adapter drives that interface directly. It never invents a flag: the argv
it builds is exactly the documented CLI. When the console script is absent it
reports MISSING; when Docker or a model provider key is absent it reports
UNSUPPORTED/CONFIGURATION_ERROR rather than pretending a scan can run.

License: Apache-2.0. Strix is invoked as an external process; no Strix source is
vendored into BLACKHEART.
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

_VERSION_RE = re.compile(r"(\d+\.\d+(?:\.\d+)?)")


class StrixAdapter(EngineAdapter):
    name = "strix"
    upstream_url = "https://github.com/usestrix/strix"
    license_id = "Apache-2.0"
    description = "Autonomous multi-agent penetration testing (web/API/source)"

    #: Capabilities Strix documents and that this adapter surfaces. Marked
    #: available only when the engine is actually present.
    _CAPABILITIES = [
        ("autonomous_recon", "Autonomous reconnaissance & attack-surface discovery"),
        ("dast", "Dynamic application security testing (live HTTP)"),
        ("sast", "Static/source analysis of a local project or repo"),
        ("authz_testing", "Authentication & authorization testing"),
        ("injection", "SQL/NoSQL injection, XSS, SSRF, XXE, SSTI, OS command injection"),
        ("business_logic", "Business-logic & IDOR testing"),
        ("poc", "Working proof-of-concept generation (Python)"),
        ("cvss_owasp", "CVSS + OWASP classification"),
        ("sarif", "SARIF 2.1.0 output"),
    ]

    # -- discovery --------------------------------------------------------- #
    def _binary(self) -> str | None:
        return self._which("strix")

    def detect_installation(self) -> bool:
        return self._binary() is not None

    def inspect_version(self) -> str:
        binary = self._binary()
        if not binary:
            return ""
        try:
            out = run_bounded([binary, "--version"], cwd=self.workspace, timeout_s=30)
        except OSError:
            return ""
        m = _VERSION_RE.search((out.stdout or "") + (out.stderr or ""))
        return m.group(1) if m else (out.stdout or out.stderr or "").strip()[:64]

    def verify_health(self) -> Health:
        binary = self._binary()
        if not binary:
            return Health(EngineState.MISSING, detail="strix console script not on PATH")
        version = self.inspect_version()
        if not version:
            return Health(EngineState.INSTALLED, detail="strix present but --version gave no version")
        docker = self._which("docker")
        has_provider_key = any(
            os.environ.get(k)
            for k in ("STRIX_LLM", "LLM_API_KEY", "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GEMINI_API_KEY")
        )
        if not docker:
            return Health(EngineState.UNSUPPORTED, version=version,
                          detail="strix installed but docker is not available (sandbox required)")
        detail = "strix + docker present"
        if not has_provider_key:
            detail += "; no model-provider key in environment (configure before a live scan)"
        return Health(EngineState.INSTALLED, version=version, detail=detail)

    def inspect_capabilities(self) -> list[Capability]:
        installed = self.detect_installation()
        caps = [Capability(k, label, installed,
                           "" if installed else "engine not installed")
                for k, label in self._CAPABILITIES]
        return caps

    def validate_configuration(self) -> tuple[bool, str]:
        if not self.detect_installation():
            return False, "strix is not installed"
        if not self._which("docker"):
            return False, "docker is required by strix and is not available"
        return True, "ok"

    # -- execution --------------------------------------------------------- #
    def _build_argv(self, target: str, options: dict) -> list[str]:
        argv = [self._binary() or "strix", "--target", target, "--non-interactive"]
        if options.get("instruction"):
            argv += ["--instruction", str(options["instruction"])]
        if options.get("scan_mode"):
            argv += ["--scan-mode", str(options["scan_mode"])]
        if options.get("max_budget_usd") is not None:
            argv += ["--max-budget-usd", str(options["max_budget_usd"])]
        if options.get("config"):
            argv += ["--config", str(options["config"])]
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
        meta = self.prepare_execution(target, **options)
        timeout_s = float(options.get("timeout_s", self.config.get("timeout_s", 3600)))
        env = dict(os.environ)
        env.setdefault("NO_COLOR", "1")
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

        run_dir = self._latest_run_dir()
        artifacts = self.collect_artifacts(run_dir) if run_dir else {}
        records = self._load_vulnerabilities(run_dir) if run_dir else []
        if meta.state == EngineState.COMPLETED and not records and not artifacts:
            # Ran but produced no parseable artifacts: honest PARTIAL, not success.
            meta.state = EngineState.PARTIAL
            meta.note = "completed but no strix_runs artifacts found"
        return ExecutionResult(
            metadata=meta,
            raw_stdout=redact_secrets(out.stdout),
            raw_stderr=redact_secrets(out.stderr),
            artifacts=artifacts,
            raw_records=records,
        )

    # -- artifacts --------------------------------------------------------- #
    def _runs_root(self) -> Path:
        return self.workspace / "strix_runs"

    def _latest_run_dir(self) -> Path | None:
        root = self._runs_root()
        if not root.is_dir():
            return None
        runs = [d for d in root.iterdir() if d.is_dir()]
        if not runs:
            return None
        return max(runs, key=lambda d: d.stat().st_mtime)

    def collect_artifacts(self, run_dir: Path) -> dict[str, str]:
        artifacts: dict[str, str] = {}
        if run_dir is None or not run_dir.is_dir():
            return artifacts
        for name in ("vulnerabilities.json", "run.json", "findings.sarif", "report.md"):
            path = run_dir / name
            if path.is_file():
                artifacts[name] = str(path)
        return artifacts

    def _load_vulnerabilities(self, run_dir: Path) -> list[dict]:
        path = run_dir / "vulnerabilities.json"
        return find_json_records(path) if path.is_file() else []

    # -- normalization ----------------------------------------------------- #
    def normalize_findings(self, result: ExecutionResult) -> list[NormalizedFinding]:
        findings: list[NormalizedFinding] = []
        version = result.metadata.version
        for rec in result.raw_records:
            finding = self._normalize_one(rec, version, result)
            if finding is not None:
                findings.append(finding)
        return findings

    def _normalize_one(self, rec: dict, version: str, result: ExecutionResult) -> NormalizedFinding | None:
        title = str(rec.get("title") or "").strip()
        if not title:
            return None
        endpoint = str(rec.get("endpoint") or rec.get("target") or "").strip()
        code_locs = rec.get("code_locations") or []
        source_location = ""
        if isinstance(code_locs, list) and code_locs:
            first = code_locs[0]
            if isinstance(first, dict):
                source_location = str(first.get("path") or first.get("file") or first.get("location") or "")
        poc = rec.get("poc_description") or ""
        poc_code = rec.get("poc_script_code") or ""
        steps = [str(s) for s in (rec.get("reproduction_steps") or []) if s]
        if not steps and poc:
            steps = [str(poc)]
        finding = NormalizedFinding(
            source_engine=self.name,
            engine_version=version,
            target_id=result.metadata.target,
            raw_artifact=result.artifacts.get("vulnerabilities.json", ""),
            category=str(rec.get("finding_class") or rec.get("category") or ""),
            title=title,
            description=str(rec.get("description") or ""),
            severity=normalize_severity(rec.get("severity")),
            cvss=normalize_cvss(rec.get("cvss")),
            cwe=normalize_cwe(rec.get("cwe")),
            confidence=str(rec.get("confidence") or ""),
            component=endpoint,
            source_location=source_location,
            attack_vector=str(rec.get("method") or ""),
            preconditions=[str(a) for a in (rec.get("assumptions") or []) if a],
            exploit_steps=steps,
            reproduction="\n".join(s for s in (poc_code, str(poc)) if s),
            evidence_refs=[str(e) for e in (rec.get("evidence") or []) if e] if isinstance(rec.get("evidence"), list) else ([str(rec["evidence"])] if rec.get("evidence") else []),
            request_response="",
            execution_environment=f"strix {version}",
            impact=str(rec.get("impact") or ""),
            remediation=str(rec.get("remediation_steps") or rec.get("remediation") or ""),
            raw=rec,
        )
        return finding.finalize()
