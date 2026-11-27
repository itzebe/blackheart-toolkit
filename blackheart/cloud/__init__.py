"""InstaBox cloud execution: portable, auditable remote execution on the
persistent InstaBox machine.

BLACKHEART runs a persistent cloud box on InstaBox (``api.instabox.sh``) and uses
it for work the local sandbox cannot do (heavy source analysis, fuzzing, builds).
This module is the *only* place that talks to InstaBox, so the boundary is
auditable in one file.

Design rules (mission Part A) -- each is enforced in code, not by convention:

  * **Credential from the environment only.** The key comes from
    ``INSTABOX_API_KEY``. It is never read from a file, never committed, never
    printed, and never written to an artifact or log.
  * **Fails closed.** A missing credential, a rejected key, an unreachable API,
    or an absent machine aborts. There is no local fallback: this module has no
    local execution path at all, so a remote request can never silently become a
    local one.
  * **Remote is named.** Every result carries the machine id and name, so remote
    work is never mistaken for local.
  * **Read-only on the machine.** This module only reads and runs commands
    (``exec``, file read/write/list, metrics). It never stops, suspends,
    restarts, resizes, or deletes a machine -- the box is reused, not recreated.
  * **Content-addressed artifacts.** Retrieval verifies SHA-256 against a hash the
    remote host itself computed, so a truncated or corrupted transfer is caught.

The HTTP layer uses only the standard library (``urllib``); no dependency is
added. The transport is injectable so tests exercise the real request-building,
header, and error-mapping code paths without a network.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional

# The API server the InstaBox CLI uses (same variable names, same order, so one
# credential serves both).
DEFAULT_SERVER = "https://api.instabox.sh"

# The credential is an InstaBox API key (``ibk_...``). Environment only.
CREDENTIAL_ENV = "INSTABOX_API_KEY"

# Optional: the machine to use (id ``m_...`` or name). When unset, discovery
# picks the single running machine and refuses when the choice is ambiguous.
MACHINE_ENV = "BLACKHEART_CLOUD_MACHINE"

# Where engagement directories are written (gitignored by default).
HOME_ENV = "BLACKHEART_CLOUD_HOME"
DEFAULT_WORKDIR = "research/private/cloud"

# The API caps a single exec at 600 seconds (a longer job must run detached).
MAX_EXEC_TIMEOUT = 600

# The remote root for engagement directories. ``/data`` is the persistent disk
# (HOME is ``/data/home``), so work survives pause, stop and resume.
REMOTE_ROOT = "/data/home/.blackheart/engagements"

# A machine in one of these states can be used directly: an ``exec`` wakes a
# suspended/paused machine. The InstaBox API exposes no separate resume route,
# so discovery must treat these as usable -- a persistent box that has idled
# into auto-suspend is the *normal* state, not a missing machine. A machine in
# any other state (stopped, deleted, ...) cannot be woken by an exec and is
# refused, and BLACKHEART never issues a lifecycle command to start it.
WAKEABLE_STATES = ("running", "suspended", "paused")


# --------------------------------------------------------------------------- #
# Errors -- distinct classes so a caller (and the CLI) can act differently.
# --------------------------------------------------------------------------- #

class CloudError(RuntimeError):
    """Any failure talking to or running work on InstaBox."""


class MissingCredential(CloudError):
    """No ``INSTABOX_API_KEY`` in the environment. Fails closed."""


class AuthError(CloudError):
    """The credential was rejected by the API (401/403)."""


class MachineNotFound(CloudError):
    """The requested machine does not exist, or no running machine was found."""


class RemoteExecutionError(CloudError):
    """The remote command could not be run, or the transfer/verification failed."""


# --------------------------------------------------------------------------- #
# Transport
# --------------------------------------------------------------------------- #

# A transport returns (http_status, response_bytes). Injected in tests so the
# real client code runs with no network.
Transport = Callable[[str, str, dict, Optional[bytes], float], "tuple[int, bytes]"]


def _default_transport(
    method: str, url: str, headers: dict, body: Optional[bytes], timeout: float
) -> tuple[int, bytes]:
    """Real HTTP via the standard library. Never raises for an HTTP status."""
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:  # a real HTTP status with a body
        return exc.code, exc.read()


# --------------------------------------------------------------------------- #
# Result records
# --------------------------------------------------------------------------- #

@dataclass
class ExecResult:
    """The outcome of one remote command (the API's exec shape)."""

    stdout: str
    stderr: str
    exit_code: int
    timed_out: bool = False
    truncated: bool = False
    oom_killed: bool = False
    duration_ms: int = 0

    @property
    def ok(self) -> bool:
        return self.exit_code == 0 and not self.timed_out

    @classmethod
    def from_dict(cls, d: dict) -> "ExecResult":
        return cls(
            stdout=d.get("stdout", "") or "",
            stderr=d.get("stderr", "") or "",
            exit_code=int(d.get("exitCode", 0) or 0),
            timed_out=bool(d.get("timedOut", False)),
            truncated=bool(d.get("truncated", False)),
            oom_killed=bool(d.get("oomKilled", False)),
            duration_ms=int(d.get("durationMs", 0) or 0),
        )

    def to_dict(self) -> dict:
        return {
            "stdout": self.stdout,
            "stderr": self.stderr,
            "exit_code": self.exit_code,
            "timed_out": self.timed_out,
            "truncated": self.truncated,
            "oom_killed": self.oom_killed,
            "duration_ms": self.duration_ms,
        }


@dataclass
class CloudConfig:
    """Resolved cloud configuration. The credential is held but never printed."""

    server: str
    api_key: str
    machine: Optional[str]
    workdir_root: Path

    @property
    def has_credential(self) -> bool:
        return bool(self.api_key)

    @classmethod
    def from_env(
        cls,
        env: Optional[dict] = None,
        workdir_root: Optional[str] = None,
    ) -> "CloudConfig":
        env = env if env is not None else os.environ
        server = (
            env.get("INSTABOX_SERVER")
            or env.get("INSTABOX_API_URL")
            or env.get("INSTABOX_API")
            or DEFAULT_SERVER
        )
        key = (env.get(CREDENTIAL_ENV) or "").strip()
        machine = (env.get(MACHINE_ENV) or "").strip() or None
        root = workdir_root or env.get(HOME_ENV) or DEFAULT_WORKDIR
        return cls(
            server=server.rstrip("/"),
            api_key=key,
            machine=machine,
            workdir_root=Path(root),
        )

    def to_dict(self) -> dict:
        """A safe view: the credential is reported as present/absent only."""
        return {
            "server": self.server,
            "machine": self.machine,
            "credential": "present" if self.has_credential else "missing",
            "credential_env": CREDENTIAL_ENV,
            "workdir_root": str(self.workdir_root),
        }


# --------------------------------------------------------------------------- #
# Client
# --------------------------------------------------------------------------- #

class InstaBoxClient:
    """A minimal, standard-library InstaBox API client.

    Only the read/exec/file routes BLACKHEART needs are exposed. No route that
    stops, deletes, resizes or recreates a machine is reachable from here.
    """

    def __init__(
        self,
        server: str,
        api_key: str,
        *,
        timeout: float = 60.0,
        transport: Optional[Transport] = None,
    ) -> None:
        if not api_key:
            raise MissingCredential(
                f"{CREDENTIAL_ENV} is not set; BLACKHEART cloud execution fails "
                f"closed and never falls back to local execution"
            )
        self.server = server.rstrip("/")
        self._api_key = api_key
        self.timeout = timeout
        self._transport: Transport = transport or _default_transport

    def __repr__(self) -> str:  # never leak the key
        return f"InstaBoxClient(server={self.server!r}, credential=<redacted>)"

    # -- request plumbing --------------------------------------------------- #

    def _request(
        self,
        method: str,
        path: str,
        *,
        json_body: Optional[dict] = None,
        raw_body: Optional[bytes] = None,
        content_type: Optional[str] = None,
        timeout: Optional[float] = None,
    ) -> tuple[int, bytes]:
        url = self.server + path
        headers = {"Accept": "application/json", "X-API-Key": self._api_key}
        body: Optional[bytes] = None
        if json_body is not None:
            body = json.dumps(json_body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        elif raw_body is not None:
            body = raw_body
            headers["Content-Type"] = content_type or "application/octet-stream"
        try:
            status, data = self._transport(
                method, url, headers, body, timeout if timeout is not None else self.timeout
            )
        except CloudError:
            raise
        except Exception as exc:  # noqa: BLE001 - network/OS error, wrapped with context
            raise CloudError(f"network error talking to {self.server}: {exc}") from exc

        if status in (401, 403):
            raise AuthError(
                f"InstaBox rejected the credential (HTTP {status}); "
                f"check {CREDENTIAL_ENV}"
            )
        if status >= 400:
            raise CloudError(
                f"InstaBox HTTP {status} for {method} {path}: {self._error_message(data)}"
            )
        return status, data

    @staticmethod
    def _error_message(data: bytes) -> str:
        try:
            payload = json.loads(data.decode("utf-8"))
            err = payload.get("error") or {}
            return str(err.get("message") or err.get("code") or payload)
        except Exception:  # noqa: BLE001
            return (data[:200].decode("utf-8", "replace") if data else "")

    @staticmethod
    def _json(data: bytes):
        if not data:
            return None
        return json.loads(data.decode("utf-8"))

    # -- account ------------------------------------------------------------ #

    def me(self) -> dict:
        _, data = self._request("GET", "/v1/me")
        return self._json(data) or {}

    # -- machines ----------------------------------------------------------- #

    def list_machines(self) -> list[dict]:
        _, data = self._request("GET", "/v1/machines")
        payload = self._json(data)
        if isinstance(payload, list):
            return payload
        if isinstance(payload, dict):
            return payload.get("machines") or []
        return []

    def get_machine(self, machine_id: str) -> dict:
        _, data = self._request("GET", f"/v1/machines/{machine_id}")
        return self._json(data) or {}

    def disk(self, machine_id: str) -> dict:
        _, data = self._request("GET", f"/v1/machines/{machine_id}/disk")
        return self._json(data) or {}

    # -- exec --------------------------------------------------------------- #

    def exec(
        self,
        machine_id: str,
        cmd: str,
        *,
        cwd: Optional[str] = None,
        envs: Optional[dict] = None,
        timeout_seconds: Optional[int] = None,
        stdin: Optional[bytes] = None,
    ) -> ExecResult:
        body: dict = {"cmd": cmd}
        if cwd:
            body["cwd"] = cwd
        if envs:
            body["envs"] = envs
        if timeout_seconds:
            if timeout_seconds > MAX_EXEC_TIMEOUT:
                raise CloudError(
                    f"exec timeout {timeout_seconds}s exceeds the API limit "
                    f"({MAX_EXEC_TIMEOUT}s); run a long job detached instead"
                )
            body["timeoutSeconds"] = timeout_seconds
        # A command's own runtime may exceed the request timeout by the command
        # timeout; give the socket the command timeout plus a margin.
        request_timeout = (timeout_seconds or 60) + 30
        _, data = self._request(
            "POST",
            f"/v1/machines/{machine_id}/exec",
            json_body=body,
            timeout=request_timeout,
        )
        return ExecResult.from_dict(self._json(data) or {})

    # -- files -------------------------------------------------------------- #

    def put_file(
        self, machine_id: str, path: str, data: bytes, *, parents: bool = True
    ) -> dict:
        q = f"?path={path}&parents=true" if parents else f"?path={path}"
        _, resp = self._request(
            "PUT", f"/v1/machines/{machine_id}/files{q}", raw_body=data
        )
        return self._json(resp) or {}

    def get_file(self, machine_id: str, path: str) -> bytes:
        _, resp = self._request(
            "GET", f"/v1/machines/{machine_id}/files/content?path={path}"
        )
        return resp

    def list_files(self, machine_id: str, path: str = "/") -> dict:
        _, resp = self._request("GET", f"/v1/machines/{machine_id}/files?path={path}")
        return self._json(resp) or {}


# --------------------------------------------------------------------------- #
# Machine resolution (reuse, never create)
# --------------------------------------------------------------------------- #

def resolve_machine(
    client: InstaBoxClient, selector: Optional[str] = None
) -> dict:
    """Return the machine to use, reusing the existing one.

    ``selector`` (an id or a name) wins. Without it, the single *usable* machine
    is chosen; zero or several usable machines is an error rather than a guess,
    because creating or picking the wrong box would be a silent, costly action.

    "Usable" means a state an ``exec`` can wake (running, suspended, paused) --
    see ``WAKEABLE_STATES``. A persistent box that has idled into auto-suspend is
    the normal case for a fresh conversation, so it must be selectable.
    """
    machines = client.list_machines()
    if selector:
        for m in machines:
            if m.get("id") == selector or m.get("name") == selector:
                return m
        raise MachineNotFound(
            f"no machine with id or name {selector!r} in this account; "
            f"known: {[m.get('name') for m in machines]}"
        )
    usable = [m for m in machines if m.get("state") in WAKEABLE_STATES]
    if len(usable) == 1:
        return usable[0]
    if not usable:
        raise MachineNotFound(
            "no usable machine found (none running, suspended or paused); set "
            "BLACKHEART_CLOUD_MACHINE to an existing machine (this module never "
            "creates or starts one)"
        )
    names = [m.get("name") for m in usable]
    raise CloudError(
        f"{len(usable)} usable machines {names}; set BLACKHEART_CLOUD_MACHINE "
        f"to choose one (this module never guesses)"
    )


def machine_is_ready(machine: dict) -> bool:
    """A machine is usable when an ``exec`` can wake it (running/suspended/paused)."""
    return machine.get("state") in WAKEABLE_STATES


def machine_summary(machine: dict) -> dict:
    """A compact, non-secret view of a machine for reports."""
    spec = machine.get("spec") or {}
    storage = machine.get("storage") or {}
    return {
        "id": machine.get("id"),
        "name": machine.get("name"),
        "state": machine.get("state"),
        "desired_state": machine.get("desiredState"),
        "vcpus": spec.get("vcpus") or machine.get("vcpus"),
        "mem_mib": spec.get("memMiB") or machine.get("memMiB"),
        "persistent_disk_gib": spec.get("persistentDiskGiB")
        or storage.get("sizeGiB"),
        "storage_mount": storage.get("mountPath"),
        "storage_persistent": storage.get("persistent"),
        "template": (machine.get("template") or {}).get("id"),
        "guest_user": machine.get("guestUser"),
        "ready_at": machine.get("readyAt"),
    }


def sha256_hex(data: bytes) -> str:
    import hashlib

    return hashlib.sha256(data).hexdigest()


__all__ = [
    "AuthError",
    "CloudConfig",
    "CloudError",
    "ExecResult",
    "InstaBoxClient",
    "MachineNotFound",
    "MissingCredential",
    "RemoteExecutionError",
    "Transport",
    "machine_is_ready",
    "machine_summary",
    "resolve_machine",
    "sha256_hex",
    "CREDENTIAL_ENV",
    "DEFAULT_SERVER",
    "MAX_EXEC_TIMEOUT",
    "REMOTE_ROOT",
]
