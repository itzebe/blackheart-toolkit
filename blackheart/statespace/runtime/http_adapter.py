"""A loopback HTTP execution adapter.

Dispatches operations to a controlled local application over HTTP on the loopback
interface. Safety is structural, not advisory:

  * only loopback hosts are ever contacted (:mod:`blackheart.statespace.runtime.authz`);
  * **redirects are never followed** -- a 3xx is recorded as a refusal, so a
    redirect cannot move execution off the approved origin (scope escape);
  * the connection is to an explicit host/port that the scope authorized;
  * a per-request timeout bounds every call, and the base class bounds the total.

The application is the caller's own controlled target (a BLACKHEART harness app or
an operator-authorized local service). This adapter is not a scanner: it issues
exactly the operations in the target's declared model, with the declared actors.
"""

from __future__ import annotations

import json
import socket
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Optional

from ..model import SystemModel
from ...noise import NoiseGovernor
from .authz import LocalScope, is_forbidden_address, is_loopback_host
from .base import BaseExecutionAdapter
from .interface import ExecRecord, ExecutionError, ScopeError


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse to follow any redirect -- a 3xx must not become a scope escape."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401
        raise ScopeError(
            f"target attempted a redirect to {newurl!r}; refusing to follow "
            "(redirects could escape the approved loopback origin)"
        )


def _opener() -> urllib.request.OpenerDirector:
    return urllib.request.build_opener(_NoRedirect)


class HttpExecutionAdapter(BaseExecutionAdapter):
    """Drive a loopback HTTP application as an executable target."""

    transport = "http"

    def __init__(self, base_url: str, model: SystemModel, scope: LocalScope, *,
                 identities: Optional[dict[str, dict[str, str]]] = None,
                 timeout: float = 10.0, budget=None, health_path: str = "/health",
                 noise: Optional[NoiseGovernor] = None) -> None:
        super().__init__(scope, budget=budget, timeout=timeout)
        parsed = urllib.parse.urlsplit(base_url)
        if parsed.scheme not in ("http", "https"):
            raise ExecutionError(f"unsupported URL scheme {parsed.scheme!r} in {base_url!r}")
        self.host = parsed.hostname or ""
        self.port = parsed.port or (443 if parsed.scheme == "https" else 80)
        self.base_url = base_url.rstrip("/")
        self._model = model
        self.name = model.target
        self._identities = identities or {}
        self.health_path = health_path
        self._opener = _opener()
        #: Optional per-host pacer: every live request is throttled through it so a
        #: research run cannot hammer the target (the "no DoS" rule, enforced).
        self.noise = noise

    # -- lifecycle ------------------------------------------------------- #

    def load(self) -> None:
        self._authorize(host=self.host, port=self.port, kind="http")
        if is_forbidden_address(self.host):
            raise ScopeError(f"refusing to contact forbidden address {self.host!r}")
        if not is_loopback_host(self.host):
            raise ScopeError(f"refusing non-loopback host {self.host!r}")
        # confirm the target is actually up (a health probe is a real request)
        try:
            body = self._request("GET", self.health_path, actor="", params={}, op_headers={})
        except ScopeError:
            raise
        except ExecutionError:
            raise
        self._loaded = True
        self._loaded_meta = {"host": self.host, "port": self.port, "health": body}

    def close(self) -> None:
        self._loaded = False

    # -- declared model -------------------------------------------------- #

    def model(self) -> SystemModel:
        return self._model

    def identities(self) -> list[str]:
        return [a.name for a in self._model.actors]

    def operations(self) -> list[str]:
        return [o.name for o in self._model.operations]

    def invariants(self) -> list[Any]:
        # The HTTP adapter evaluates invariants through a local evaluator supplied
        # by the harness app's declared invariants (see harness apps). Until one is
        # supplied, there are none and a violation cannot be claimed.
        return getattr(self, "_invariants", [])

    def set_invariants(self, invariants: list[Any]) -> None:
        self._invariants = invariants

    # -- state ----------------------------------------------------------- #

    def snapshot(self) -> dict[str, Any]:
        """Read the application's *observed* state (not a local copy)."""
        if not self._loaded:
            return {}
        try:
            result = self._request("GET", "/state", actor="", params={}, op_headers={})
        except (ExecutionError, ScopeError):
            return {}
        body = result.get("body", {})
        if isinstance(body, dict) and "state" in body:
            return body["state"]
        return body if isinstance(body, dict) else {"state": body}

    def reset(self) -> None:
        """Return the application to its known initial state via its own endpoint."""
        self._authorize(host=self.host, port=self.port, kind="http")
        self._request("POST", "/reset", actor="", params={}, op_headers={})

    # -- dispatch -------------------------------------------------------- #

    def _headers_for(self, actor: str) -> dict[str, str]:
        if not actor:
            return {}
        return dict(self._identities.get(actor, {}))

    def _request(self, method: str, path: str, *, actor: str, params: dict[str, Any],
                 op_headers: dict[str, str]) -> Any:
        url = self.base_url + (path if path.startswith("/") else "/" + path)
        data = None
        headers = {"Accept": "application/json"}
        headers.update(self._headers_for(actor))
        headers.update(op_headers)
        if method == "GET":
            if params:
                url += "?" + urllib.parse.urlencode(params)
        else:
            data = json.dumps(params).encode("utf-8")
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(url, data=data, method=method, headers=headers)
        if self.noise is not None:
            with self.noise.acquire(self.host) as slot:
                raw, status = self._send(req)
                slot.report(status)
        else:
            raw, status = self._send(req)
        try:
            body = json.loads(raw.decode("utf-8")) if raw else {}
        except (ValueError, UnicodeDecodeError):
            body = {"_raw": raw.decode("utf-8", "replace")[:2000]}
        return {"status": status, "body": body}

    def _send(self, req: urllib.request.Request) -> tuple[bytes, int]:
        """Perform one request, returning ``(body, status)``. No pacing here."""
        try:
            with self._opener.open(req, timeout=self.timeout) as resp:
                return resp.read(), resp.status
        except urllib.error.HTTPError as exc:
            return (exc.read() if hasattr(exc, "read") else b""), exc.code
        except (socket.timeout, TimeoutError) as exc:
            raise ExecutionError(f"request timed out after {self.timeout}s: {exc}") from exc
        except urllib.error.URLError as exc:
            raise ExecutionError(f"target unreachable: {exc.reason}") from exc
        except ScopeError:
            raise
        except OSError as exc:
            raise ExecutionError(f"transport error: {exc}") from exc

    def _dispatch(self, operation: str, actor: str, params: dict[str, Any]) -> ExecRecord:
        op = self._model.operation(operation)
        if op is None:
            raise ExecutionError(f"operation {operation!r} is not in the target model")
        entry = op.entry_point or ""
        method, _, path = entry.partition(" ")
        if not path:
            method, path = "POST", f"/{operation}"
        method = (method or "POST").upper()
        result = self._request(method, path, actor=actor, params=params, op_headers={})
        status = result["status"]
        body = result["body"]
        accepted = 200 <= status < 300
        # A 2xx that carries an explicit error/partial marker is a partial failure.
        partial = bool(isinstance(body, dict) and (body.get("error") or body.get("partial")))
        if accepted and partial:
            step_status = "partial_failure"
        elif accepted:
            step_status = "ok"
        elif status in (401, 403):
            step_status = "rejected"
        elif status == 429:
            step_status = "rejected"
        else:
            step_status = "rejected" if status < 500 else "error"
        return ExecRecord(
            index=-1, actor=actor, operation=operation, params=dict(params),
            provenance="executed", transport=self.transport,
            status=step_status, accepted=accepted, http_status=status,
            error="" if accepted else str(body.get("error", body) if isinstance(body, dict) else ""),
            response=body if isinstance(body, dict) else {"body": body},
        )
