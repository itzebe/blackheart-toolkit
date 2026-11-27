"""PentAGI adapter (MIT core + EULA) -- isolated upstream runtime, API-based.

PentAGI (https://github.com/vxcontrol/pentagi) is a self-hosted multi-agent
penetration-testing platform. It is a Go service run with Docker Compose and
driven over HTTP:

  * REST: ``GET  {base}/api/v1/flows``            -- list flows
          ``GET  {base}/api/v1/info``             -- system info (health/version)
  * GraphQL: ``POST {base}/api/v1/graphql``       -- ``mutation createFlow(modelProvider, input)``
  * Auth: ``Authorization: Bearer <api-token>``

**License boundary.** The PentAGI source is MIT but the project ships an
additional EULA and a ``NOTICE``/``licenses`` set for bundled components, and the
commercial VXControl SDK components are not free to reuse. BLACKHEART therefore
never vendors PentAGI code: this adapter talks to a *separately deployed* PentAGI
instance over its documented HTTP API. If no instance is configured and reachable
the adapter reports MISSING/CONFIGURATION_ERROR.

Because PentAGI does not document a structured JSON findings export today (its
report is Markdown/PDF), normalization here is deliberately conservative: it
preserves the flow report artifact and only emits candidates from structured
task/subtask results when the instance actually provides them.
"""

from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request
from typing import Any

from .contract import (
    Capability,
    EngineAdapter,
    EngineState,
    EngineUnavailable,
    ExecutionMetadata,
    ExecutionResult,
    Health,
    redact_secrets,
)
from .schema import NormalizedFinding, normalize_cwe, normalize_cvss, normalize_severity
from ..models import utcnow

_VERSION_RE = re.compile(r"(\d+\.\d+(?:\.\d+)?)")
_CREATE_FLOW_MUTATION = (
    "mutation CreateFlow($provider: String!, $input: String!) {"
    " createFlow(modelProvider: $provider, input: $input) { id title status createdAt } }"
)
_FLOW_QUERY = "query Flow($id: ID!) { flow(flowId: $id) { id title status } }"


class PentAGIAdapter(EngineAdapter):
    name = "pentagi"
    upstream_url = "https://github.com/vxcontrol/pentagi"
    license_id = "MIT (core) + EULA / NOTICE"
    description = "Self-hosted multi-agent pentest platform (REST/GraphQL, isolated runtime)"

    _CAPABILITIES = [
        ("multi_agent", "Multi-agent pentest orchestration"),
        ("recon_agents", "Specialized reconnaissance agents"),
        ("attack_path", "Attack-path investigation & complex multi-step workflows"),
        ("tool_execution", "Tool execution & coordination (nmap, sqlmap, metasploit, ...)"),
        ("memory", "Agent memory & context preservation (PostgreSQL/pgvector)"),
        ("traceability", "Investigation traceability (logs, subtasks, graph)"),
        ("model_flexibility", "Model-provider flexibility (10+ providers, local models)"),
        ("observability", "Execution observability (Grafana/Prometheus)"),
        ("reporting", "Detailed vulnerability reports with exploitation guides"),
    ]

    # -- configuration ----------------------------------------------------- #
    def _base_url(self) -> str:
        return str(self.config.get("base_url") or os.environ.get("PENTAGI_BASE_URL") or "").rstrip("/")

    def _token(self) -> str:
        return str(self.config.get("api_token") or os.environ.get("PENTAGI_API_TOKEN") or "")

    def _provider(self) -> str:
        return str(self.config.get("model_provider") or "openai")

    # -- discovery --------------------------------------------------------- #
    def detect_installation(self) -> bool:
        """An isolated PentAGI instance counts as present only if it answers."""
        if not self._base_url():
            return False
        try:
            self._get("/info")
            return True
        except Exception:
            return False

    def inspect_version(self) -> str:
        try:
            data = self._get("/info")
        except Exception:
            return ""
        text = json.dumps(data)
        m = _VERSION_RE.search(text)
        return m.group(1) if m else ""

    def verify_health(self) -> Health:
        base = self._base_url()
        if not base:
            return Health(EngineState.MISSING,
                          detail="no PentAGI instance configured (set PENTAGI_BASE_URL / api_token)")
        if not self._token():
            return Health(EngineState.CONFIGURATION_ERROR,
                          detail="PentAGI base_url set but no api_token configured")
        try:
            self._get("/info")
        except urllib.error.HTTPError as e:
            return Health(EngineState.CONFIGURATION_ERROR, detail=f"/info returned HTTP {e.code}")
        except Exception as e:  # noqa: BLE001 - report the reason, do not raise
            return Health(EngineState.MISSING, detail=f"PentAGI instance unreachable: {type(e).__name__}")
        return Health(EngineState.INSTALLED, version=self.inspect_version(),
                      detail="PentAGI instance reachable")

    def inspect_capabilities(self) -> list[Capability]:
        installed = self.detect_installation()
        note = "" if installed else "instance not configured/reachable"
        return [Capability(k, label, installed, note) for k, label in self._CAPABILITIES]

    def validate_configuration(self) -> tuple[bool, str]:
        if not self._base_url():
            return False, "PENTAGI_BASE_URL is not set"
        if not self._token():
            return False, "PENTAGI_API_TOKEN is not set"
        return True, "ok"

    # -- execution --------------------------------------------------------- #
    def prepare_execution(self, target: str, **options: Any) -> ExecutionMetadata:
        return ExecutionMetadata(
            engine=self.name,
            version=self.inspect_version(),
            argv=["POST", f"{self._base_url()}/api/v1/graphql",
                  f"createFlow(provider={self._provider()}, input={target!r})"],
            cwd=str(self.workspace),
            started_at=utcnow(),
            target=target,
        )

    def execute_scan(self, target: str, **options: Any) -> ExecutionResult:
        health = self.verify_health()
        if health.state in (EngineState.MISSING, EngineState.UNSUPPORTED, EngineState.CONFIGURATION_ERROR):
            raise EngineUnavailable(health.detail)
        meta = self.prepare_execution(target, **options)
        timeout_s = float(options.get("timeout_s", self.config.get("timeout_s", 3600)))
        poll_s = float(self.config.get("poll_interval_s", 10))
        instruction = options.get("instruction") or f"Perform an authorized penetration test of {target}"
        artifacts: dict[str, str] = {}
        records: list[dict] = []
        try:
            flow = self._create_flow(instruction)
        except Exception as e:  # noqa: BLE001
            meta.finished_at = utcnow()
            meta.state = EngineState.FAILED
            meta.note = f"createFlow failed: {type(e).__name__}"
            return ExecutionResult(metadata=meta, raw_stderr=redact_secrets(str(e)))
        meta.note = f"flow {flow.get('id')}"
        status = self._await_flow(str(flow.get("id")), timeout_s, poll_s,
                                  cancel_event=options.get("cancel_event"))
        meta.finished_at = utcnow()
        meta.exit_code = 0 if status == "finished" else None
        if status == "cancelled":
            meta.state = EngineState.CANCELLED
        elif status == "finished":
            meta.state = EngineState.COMPLETED
        elif status == "timeout":
            meta.state = EngineState.FAILED
            meta.timed_out = True
        else:
            meta.state = EngineState.FAILED
            meta.note = f"flow {status}"
        snapshot = self._flow_snapshot(str(flow.get("id")))
        if snapshot is not None:
            path = self.workspace / f"pentagi-flow-{flow.get('id')}.json"
            path.write_text(json.dumps(snapshot, indent=2), encoding="utf-8")
            artifacts["flow.json"] = str(path)
            records = self._extract_candidates(snapshot)
        if meta.state == EngineState.COMPLETED and not artifacts:
            meta.state = EngineState.PARTIAL
            meta.note = "flow finished but no report artifact retrieved"
        return ExecutionResult(metadata=meta, artifacts=artifacts, raw_records=records)

    def monitor_execution(self) -> EngineState:
        return EngineState.RUNNING

    def _await_flow(self, flow_id: str, timeout_s: float, poll_s: float, cancel_event: Any = None) -> str:
        import time

        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            if cancel_event is not None and cancel_event.is_set():
                return "cancelled"
            try:
                data = self._graphql(_FLOW_QUERY, {"id": flow_id})
            except Exception:  # noqa: BLE001 - transient; keep polling until deadline
                time.sleep(poll_s)
                continue
            status = str(((data.get("data") or {}).get("flow") or {}).get("status") or "").lower()
            if status in ("finished", "failed"):
                return status
            time.sleep(poll_s)
        return "timeout"

    def _flow_snapshot(self, flow_id: str) -> dict | None:
        try:
            return self._get(f"/flows/{flow_id}")
        except Exception:  # noqa: BLE001
            return None

    def _extract_candidates(self, snapshot: dict) -> list[dict]:
        """Pull structured candidates from a flow snapshot when the API offers them.

        PentAGI's REST flow object is not a documented findings schema, so this
        looks only for an explicit findings/vulnerabilities list; it never invents
        a finding from prose.
        """
        for key in ("vulnerabilities", "findings"):
            value = snapshot.get(key)
            if isinstance(value, list):
                return [r for r in value if isinstance(r, dict)]
        return []

    def normalize_findings(self, result: ExecutionResult) -> list[NormalizedFinding]:
        findings: list[NormalizedFinding] = []
        for rec in result.raw_records:
            title = str(rec.get("title") or rec.get("name") or "").strip()
            if not title:
                continue
            finding = NormalizedFinding(
                source_engine=self.name,
                engine_version=result.metadata.version,
                target_id=result.metadata.target,
                raw_artifact=result.artifacts.get("flow.json", ""),
                category=str(rec.get("category") or ""),
                title=title,
                description=str(rec.get("description") or ""),
                severity=normalize_severity(rec.get("severity")),
                cvss=normalize_cvss(rec.get("cvss")),
                cwe=normalize_cwe(rec.get("cwe")),
                component=str(rec.get("target") or rec.get("host") or ""),
                source_location=str(rec.get("location") or ""),
                impact=str(rec.get("impact") or ""),
                remediation=str(rec.get("remediation") or ""),
                raw=rec,
            )
            findings.append(finding.finalize())
        return findings

    # -- HTTP helpers (stdlib only) ---------------------------------------- #
    def _request(self, method: str, path: str, body: dict | None = None) -> dict:
        url = f"{self._base_url()}/api/v1{path}"
        data = json.dumps(body).encode("utf-8") if body is not None else None
        req = urllib.request.Request(url, data=data, method=method)
        req.add_header("Accept", "application/json")
        if body is not None:
            req.add_header("Content-Type", "application/json")
        if self._token():
            req.add_header("Authorization", f"Bearer {self._token()}")
        with urllib.request.urlopen(req, timeout=30) as resp:
            raw = resp.read().decode("utf-8", "replace")
        return json.loads(raw) if raw.strip() else {}

    def _get(self, path: str) -> dict:
        return self._request("GET", path)

    def _graphql(self, query: str, variables: dict) -> dict:
        return self._request("POST", "/graphql", {"query": query, "variables": variables})

    def _create_flow(self, instruction: str) -> dict:
        data = self._graphql(_CREATE_FLOW_MUTATION,
                             {"provider": self._provider(), "input": instruction})
        flow = (data.get("data") or {}).get("createFlow") or {}
        if not flow.get("id"):
            raise RuntimeError("createFlow returned no flow id")
        return flow
