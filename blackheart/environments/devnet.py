"""A local compose-based devnet backend.

A Cosmos/Substrate/EVM development network is the only place an unprivileged
transaction sequence can be run for real before a testnet. This backend owns
exactly one thing: a **configured local compose file**. It never accepts an
arbitrary shell string, never reaches a remote host, and refuses every action
outside a fixed verb set.

The compose file is the boundary. ``inspect`` reads it, ``capture`` reads its
logs, and ``execute`` runs one of ``up`` / ``down`` / ``ps`` / ``logs``. An
``exec`` into a service is opt-in at construction time because it is the one
action that can run arbitrary target code; even then it takes a service name and
an argv list, never a shell.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any, Optional

from .adapter import (
    AdapterState,
    Capabilities,
    ExecutionAdapter,
    Observation,
    ProbeRequest,
    ProbeResult,
)

_SERVICE = re.compile(r"^  ([A-Za-z0-9][A-Za-z0-9_.-]*):\s*$")
_IMAGE = re.compile(r"^\s+image:\s*(\S+)\s*$")
_PORT = re.compile(r"^\s+-\s*[\"']?([0-9]+):([0-9]+)")


def compose_services(text: str) -> dict[str, dict[str, Any]]:
    """Recover the service names and images a compose file declares.

    This is intentionally a narrow reader, not a YAML parser: it only needs the
    names and the image lines, and it must never guess a service that is absent.
    """
    services: dict[str, dict[str, Any]] = {}
    in_services = False
    current = ""
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped == "services:":
            in_services = True
            continue
        if not in_services:
            continue
        if line and not line.startswith(" ") and not line.startswith("\t"):
            in_services = False
            current = ""
            continue
        match = _SERVICE.match(line)
        if match:
            current = match.group(1)
            services[current] = {"image": "", "ports": []}
            continue
        if not current:
            continue
        image = _IMAGE.match(line)
        if image:
            services[current]["image"] = image.group(1)
            continue
        port = _PORT.match(line)
        if port:
            services[current]["ports"].append(int(port.group(1)))
    return services


class DevnetAdapter(ExecutionAdapter):
    """A real local compose devnet, bounded to one compose file."""

    name = "local-devnet"

    def __init__(self, compose_file: str | Path, *, allow_exec: bool = False,
                 project: str = "") -> None:
        self._compose = Path(compose_file).expanduser().resolve()
        self._allow_exec = allow_exec
        self._project = project
        self.declared = Capabilities(
            target_types=("non-evm-chain", "container", "test-environment",
                          "protocol-implementation"),
            operations=("inspect", "execute", "capture", "reset"),
            network=True,
            state_control=True,
            transactions=False,
            snapshot_rollback=False,
            evidence_capture=True,
            evidence_tier="real-execution",
            limitations=[
                "one configured local compose file only; no remote or public network",
                "no snapshot/rollback: reset is down + up, not a state fork",
                "service exec is disabled unless allow_exec=True",
                "no transaction client: a sequence runs as an exec command or not at all",
            ],
            required_permissions=["docker daemon", "compose file"],
            safety_constraints=[
                "fixed verb set; never an arbitrary shell string",
                "exec is opt-in and takes a service name plus an argv list",
                "the compose file path is fixed at construction",
            ],
        )
        super().__init__()

    # -- readiness ----------------------------------------------------- #

    def _probe(self) -> ProbeResult:
        if not self._compose.is_file():
            return ProbeResult(
                state=AdapterState.MISSING,
                detail=f"compose file does not exist: {self._compose}",
            )
        docker = shutil.which("docker")
        if not docker:
            return ProbeResult(
                state=AdapterState.MISSING,
                detail="docker is not on PATH; a compose devnet cannot run",
            )
        try:
            proc = subprocess.run(
                [docker, "compose", "version"], capture_output=True, text=True,
                timeout=15, env=self._env(),
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return ProbeResult(
                state=AdapterState.UNSUPPORTED,
                detail=f"docker compose probe failed: {type(exc).__name__}: {exc}",
            )
        if proc.returncode != 0:
            return ProbeResult(
                state=AdapterState.UNSUPPORTED,
                detail="docker compose is unavailable: " + (proc.stderr or proc.stdout).strip(),
            )
        try:
            services = compose_services(self._compose.read_text(encoding="utf-8"))
        except OSError as exc:
            return ProbeResult(
                state=AdapterState.MISCONFIGURED,
                detail=f"cannot read compose file: {exc}",
            )
        if not services:
            return ProbeResult(
                state=AdapterState.MISCONFIGURED,
                detail="compose file declares no services",
            )
        confirmed = Capabilities(
            target_types=self.declared.target_types,
            operations=self.declared.operations,
            tools={"docker": True, "compose": True},
            network=True,
            state_control=True,
            transactions=False,
            snapshot_rollback=False,
            evidence_capture=True,
            evidence_tier="real-execution",
            limitations=list(self.declared.limitations),
            required_permissions=list(self.declared.required_permissions),
            safety_constraints=list(self.declared.safety_constraints),
        )
        if not self._allow_exec:
            confirmed.limitations.append("service exec disabled (allow_exec=False)")
        return ProbeResult(
            state=AdapterState.READY,
            detail=f"local compose devnet ready: {len(services)} service(s)",
            confirmed=confirmed,
        )

    # -- execution ----------------------------------------------------- #

    def _execute(self, request: ProbeRequest, caps: Capabilities) -> Observation:
        if request.operation == "inspect":
            return self._inspect(request, caps)
        if request.operation == "capture":
            return self._capture(request, caps)
        if request.operation == "reset":
            down = self._run(("down",), request.timeout_s)
            if not down[0]:
                return self._obs(request, caps, False, down[1], error="compose down failed")
            up = self._run(("up", "-d"), request.timeout_s)
            return self._obs(request, caps, up[0], up[1],
                             error="" if up[0] else "compose up failed",
                             facts={"reset": "down then up -d"})
        if request.operation == "execute":
            return self._execute_verb(request, caps)
        return self._obs(request, caps, False, "",
                         error=f"unsupported operation {request.operation!r}")

    def _inspect(self, request: ProbeRequest, caps: Capabilities) -> Observation:
        services = compose_services(self._compose.read_text(encoding="utf-8"))
        return self._obs(
            request, caps, True, self._compose.read_text(encoding="utf-8"),
            facts={"compose_file": str(self._compose), "services": services},
        )

    def _capture(self, request: ProbeRequest, caps: Capabilities) -> Observation:
        ok, output = self._run(("logs", "--no-color", "--tail", "200"),
                               request.timeout_s)
        return self._obs(request, caps, ok, output,
                         error="" if ok else "compose logs failed")

    def _execute_verb(self, request: ProbeRequest, caps: Capabilities) -> Observation:
        action = str(request.params.get("action", "ps")).lower()
        if action in {"up", "down", "ps", "logs"}:
            argv: tuple[str, ...]
            if action == "up":
                argv = ("up", "-d")
            elif action == "logs":
                argv = ("logs", "--no-color", "--tail",
                        str(request.params.get("tail", 200)))
            else:
                argv = (action,)
            ok, output = self._run(argv, request.timeout_s)
            return self._obs(request, caps, ok, output,
                             error="" if ok else f"compose {action} failed",
                             facts={"action": action})
        if action == "exec":
            if not self._allow_exec:
                return self._obs(request, caps, False, "",
                                 error="service exec is disabled for this adapter")
            service = str(request.params.get("service", ""))
            argv = request.params.get("argv", [])
            if not service or not isinstance(argv, list) or not argv or \
                    not all(isinstance(a, str) and a for a in argv):
                return self._obs(request, caps, False, "",
                                 error="exec needs a service and a non-empty argv list")
            services = compose_services(self._compose.read_text(encoding="utf-8"))
            if service not in services:
                return self._obs(request, caps, False, "",
                                 error=f"unknown service {service!r}")
            ok, output = self._run(("exec", "-T", service, *argv), request.timeout_s)
            return self._obs(request, caps, ok, output,
                             error="" if ok else "compose exec failed",
                             facts={"action": "exec", "service": service,
                                    "argv": list(argv)})
        return self._obs(request, caps, False, "",
                         error=f"unknown action {action!r}; use up/down/ps/logs/exec")

    # -- process boundary ---------------------------------------------- #

    def _env(self) -> dict[str, str]:
        # Docker needs its own configuration, not every secret the operator holds.
        allowed = {"PATH", "HOME", "LANG", "LC_ALL", "TZ", "TMPDIR",
                   "DOCKER_HOST", "DOCKER_CONFIG", "DOCKER_CONTEXT"}
        return {k: v for k, v in os.environ.items() if k in allowed}

    def _run(self, argv: tuple[str, ...], timeout_s: float) -> tuple[bool, str]:
        docker = shutil.which("docker")
        if not docker:
            return False, "docker is not on PATH"
        cmd = [docker, "compose", "-f", str(self._compose)]
        if self._project:
            cmd.extend(["-p", self._project])
        cmd.extend(argv)
        try:
            proc = subprocess.run(
                cmd, cwd=str(self._compose.parent), capture_output=True, text=True,
                timeout=max(1.0, min(timeout_s, 300.0)), env=self._env(),
            )
        except subprocess.TimeoutExpired:
            return False, f"compose command timed out after {timeout_s}s"
        except OSError as exc:
            return False, f"compose command failed: {type(exc).__name__}: {exc}"
        output = (proc.stdout or "") + (proc.stderr or "")
        return proc.returncode == 0, output.strip()

    def _obs(self, request: ProbeRequest, caps: Capabilities, ok: bool, raw: str,
             *, error: str = "", facts: Optional[dict] = None) -> Observation:
        return Observation(
            adapter=self.name, target=request.target, operation=request.operation,
            ok=ok, evidence_tier=caps.evidence_tier, raw=raw,
            facts=dict(facts or {}), error=error,
        )
