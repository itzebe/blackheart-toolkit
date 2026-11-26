"""A local-process execution adapter.

Runs a controlled local application as a child process and drives it over a
line-delimited JSON protocol on stdin/stdout:

  * request  ``{"op": "...", "actor": "...", "params": {...}}``
  * response ``{"status": <int>, "body": {...}}``

This is the "local application process" execution environment the mission names.
Safety is structural: the scope must explicitly set ``allow_process_exec=True``
(so a process is never spawned implicitly), the command is a fixed argv the caller
declared (never a shell string, so there is no shell-injection surface), the child
runs with a bounded wall-clock timeout, and it is always terminated on close.

The adapter is generic: it drives *any* process that speaks the tiny protocol. The
:class:`~blackheart.statespace.runtime.harness_apps` apps are also exposed through
it (see :func:`blackheart.statespace.runtime.harness_process`), so the same
application can be exercised either as an HTTP service or as a local process.
"""

from __future__ import annotations

import json
import subprocess
import sys
from typing import Any, Optional

from ..model import SystemModel
from .authz import LocalScope
from .base import BaseExecutionAdapter
from .interface import ExecRecord, ExecutionError


class ProcessExecutionAdapter(BaseExecutionAdapter):
    """Drive a local process that speaks the line-JSON operation protocol."""

    transport = "process"

    def __init__(self, argv: list[str], model: SystemModel, scope: LocalScope, *,
                 timeout: float = 10.0, budget=None, env: Optional[dict] = None) -> None:
        super().__init__(scope, budget=budget, timeout=timeout)
        self.argv = list(argv)
        self._model = model
        self.name = model.target
        self._env = env
        self._proc: Optional[subprocess.Popen] = None

    # -- lifecycle ------------------------------------------------------- #

    def load(self) -> None:
        # process execution is authorized separately from HTTP
        self._authorize(kind="process")
        if not self.argv:
            raise ExecutionError("no command supplied for the process adapter")
        try:
            self._proc = subprocess.Popen(
                self.argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, text=True, env=self._env,
            )
        except OSError as exc:
            raise ExecutionError(f"could not start process {self.argv!r}: {exc}") from exc
        self._loaded = True
        self._loaded_meta = {"argv": self.argv}

    def close(self) -> None:
        proc = self._proc
        self._proc = None
        self._loaded = False
        if proc is None:
            return
        try:
            if proc.stdin:
                proc.stdin.close()
            proc.terminate()
            proc.wait(timeout=5)
        except Exception:  # noqa: BLE001 -- cleanup must never raise
            try:
                proc.kill()
            except Exception:  # noqa: BLE001
                pass

    # -- declared model -------------------------------------------------- #

    def model(self) -> SystemModel:
        return self._model

    def identities(self) -> list[str]:
        return [a.name for a in self._model.actors]

    def operations(self) -> list[str]:
        return [o.name for o in self._model.operations]

    def invariants(self) -> list[Any]:
        return getattr(self, "_invariants", [])

    def set_invariants(self, invariants: list[Any]) -> None:
        self._invariants = invariants

    # -- request/response ------------------------------------------------ #

    def _rpc(self, payload: dict) -> dict:
        if self._proc is None or self._proc.stdin is None or self._proc.stdout is None:
            raise ExecutionError("process is not running")
        try:
            self._proc.stdin.write(json.dumps(payload) + "\n")
            self._proc.stdin.flush()
        except (BrokenPipeError, OSError) as exc:
            raise ExecutionError(f"process pipe closed: {exc}") from exc
        line = self._proc.stdout.readline()
        if not line:
            raise ExecutionError("process produced no response (crashed or exited)")
        try:
            return json.loads(line)
        except ValueError as exc:
            raise ExecutionError(f"process returned non-JSON: {line[:200]!r}") from exc

    def snapshot(self) -> dict[str, Any]:
        if not self._loaded:
            return {}
        resp = self._rpc({"op": "__state__", "actor": "", "params": {}})
        body = resp.get("body", {})
        if isinstance(body, dict) and "state" in body:
            return body["state"]
        return body if isinstance(body, dict) else {}

    def reset(self) -> None:
        self._authorize(kind="process")
        self._rpc({"op": "__reset__", "actor": "", "params": {}})

    def _dispatch(self, operation: str, actor: str, params: dict[str, Any]) -> ExecRecord:
        resp = self._rpc({"op": operation, "actor": actor, "params": dict(params)})
        status = int(resp.get("status", 0))
        body = resp.get("body", {})
        accepted = 200 <= status < 300
        partial = bool(isinstance(body, dict) and (body.get("error") or body.get("partial")))
        if accepted and partial:
            step = "partial_failure"
        elif accepted:
            step = "ok"
        else:
            step = "rejected" if status < 500 else "error"
        return ExecRecord(
            index=-1, actor=actor, operation=operation, params=dict(params),
            provenance="executed", transport=self.transport,
            status=step, accepted=accepted, http_status=status,
            error="" if accepted else str(body.get("error", "")),
            response=body if isinstance(body, dict) else {"body": body},
        )


def process_argv_for_app(app_name: str) -> list[str]:
    """The argv that runs a harness app as a local process (protocol server)."""
    return [sys.executable, "-m", "blackheart.statespace.runtime.app_process", app_name]
