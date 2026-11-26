"""The engine adapter contract (the one interface every external engine implements).

BLACKHEART is the control plane; an external engine (Strix, Shannon, PentAGI) is
an untrusted *capability provider*. Every adapter exposes the same operations, so
the orchestrator never special-cases an engine, and every adapter is honest about
its own installation state.

Design rules enforced here, not by convention:

  * An engine is ``MISSING``/``UNSUPPORTED`` until a real interface is found; the
    adapter file existing proves nothing.
  * Execution is bounded: timeout, output cap, isolated workspace, cancellation.
  * An engine's output is *candidate evidence*. Nothing here can confirm a
    finding, change authorization, or widen scope.
  * Every invocation is described by a reproducible :class:`ExecutionMetadata`.
"""

from __future__ import annotations

import functools
import hashlib
import json
import os
import re
import shutil
import signal
import subprocess
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Optional

from ..models import utcnow
from ..toolchain.enforce import ExecutionTarget, guarded


class EngineState(str, Enum):
    """The installation/lifecycle state of an engine adapter.

    These are the *only* states an adapter may report; a caller must never infer
    "integrated" from the presence of an adapter module.
    """

    INSTALLED = "INSTALLED"                  # interface found and runnable
    MISSING = "MISSING"                      # not installed in this environment
    UNSUPPORTED = "UNSUPPORTED"              # present but cannot run here (e.g. no Docker)
    CONFIGURATION_ERROR = "CONFIGURATION_ERROR"
    READY = "READY"                          # configured and preflighted for a run
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    PARTIAL = "PARTIAL"                      # finished but output incomplete/unparseable
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"
    VERIFICATION_PENDING = "VERIFICATION_PENDING"


#: Terminal states an engine execution can end in.
TERMINAL_EXECUTION_STATES = frozenset(
    {
        EngineState.COMPLETED,
        EngineState.PARTIAL,
        EngineState.FAILED,
        EngineState.CANCELLED,
    }
)


class EngineError(RuntimeError):
    """A controlled adapter failure (never a crash the caller cannot classify)."""


class EngineUnavailable(EngineError):
    """The engine cannot run here (missing binary/image or unsupported platform)."""


class EngineTimeout(EngineError):
    """The engine exceeded its execution budget and was terminated."""


class EngineCancelled(EngineError):
    """The execution was cancelled by the caller."""


@dataclass
class Capability:
    """One capability an engine can provide, discovered rather than assumed."""

    key: str
    label: str
    available: bool
    detail: str = ""

    def to_dict(self) -> dict:
        return {"key": self.key, "label": self.label,
                "available": self.available, "detail": self.detail}


@dataclass
class Health:
    """The result of a health/version probe."""

    state: EngineState
    version: str = ""
    detail: str = ""
    checked_at: str = field(default_factory=utcnow)

    @property
    def ok(self) -> bool:
        return self.state in (EngineState.INSTALLED, EngineState.READY)

    def to_dict(self) -> dict:
        return {"state": self.state.value, "version": self.version,
                "detail": self.detail, "checked_at": self.checked_at}


@dataclass
class ExecutionMetadata:
    """Reproducible metadata for one engine invocation.

    This is what makes an engine run auditable and repeatable: the exact argv, the
    working directory, the exit status, the duration, and a hash of the captured
    output. It deliberately records the argv as a list so no shell interpolation
    can hide a command.
    """

    engine: str
    version: str
    argv: list[str]
    cwd: str
    started_at: str
    finished_at: str = ""
    exit_code: Optional[int] = None
    state: EngineState = EngineState.RUNNING
    output_sha256: str = ""
    timed_out: bool = False
    cancelled: bool = False
    target: str = ""
    note: str = ""

    def to_dict(self) -> dict:
        return {
            "engine": self.engine,
            "version": self.version,
            "argv": list(self.argv),
            "cwd": self.cwd,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "exit_code": self.exit_code,
            "state": self.state.value,
            "output_sha256": self.output_sha256,
            "timed_out": self.timed_out,
            "cancelled": self.cancelled,
            "target": self.target,
            "note": self.note,
        }


@dataclass
class ExecutionResult:
    """What an execution produced: metadata plus raw artifacts, never findings.

    Raw output is preserved verbatim (``raw_stdout``/``raw_stderr``/``artifacts``)
    so provenance survives normalization. The orchestrator, not the adapter,
    decides what a finding means.
    """

    metadata: ExecutionMetadata
    raw_stdout: str = ""
    raw_stderr: str = ""
    artifacts: dict[str, str] = field(default_factory=dict)  # name -> path
    raw_records: list[dict] = field(default_factory=list)    # parsed engine records

    @property
    def state(self) -> EngineState:
        return self.metadata.state

    def to_dict(self) -> dict:
        return {
            "metadata": self.metadata.to_dict(),
            "raw_stdout": self.raw_stdout,
            "raw_stderr": self.raw_stderr,
            "artifacts": dict(self.artifacts),
            "raw_record_count": len(self.raw_records),
        }


# --------------------------------------------------------------------------- #
# Process execution with hard bounds (shared by every adapter)
# --------------------------------------------------------------------------- #

_SECRET_PATTERNS = [
    re.compile(r"(?i)(api[_-]?key|secret|token|password|passwd|bearer)\s*[:=]\s*"
               r"[\"']?([A-Za-z0-9_\-\.]{8,})"),
    re.compile(r"\bsk-[A-Za-z0-9]{16,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bghp_[A-Za-z0-9]{20,}\b"),
    # `Authorization: Bearer <token>` (space-separated, not just `bearer:`).
    re.compile(r"(?i)\bbearer\s+[A-Za-z0-9_\-\.=]{8,}"),
    # A JWT (three base64url segments), which is what a bearer token usually is.
    re.compile(r"\beyJ[A-Za-z0-9_\-]{6,}\.[A-Za-z0-9_\-]{6,}\.[A-Za-z0-9_\-]{4,}\b"),
]


def redact_secrets(text: str) -> str:
    """Redact obvious credentials from captured output before it is stored.

    This is a defensive default: engine output can echo environment variables. It
    is deliberately conservative (may over-redact) because leaking a credential
    into an artifact is worse than losing a token of context.
    """
    if not text:
        return text
    out = text
    for pat in _SECRET_PATTERNS:
        out = pat.sub(lambda m: (m.group(1) + "=<redacted>") if m.lastindex else "<redacted>", out)
    return out


@dataclass
class ProcessOutcome:
    argv: list[str]
    returncode: Optional[int]
    stdout: str
    stderr: str
    duration_s: float
    timed_out: bool
    cancelled: bool
    output_sha256: str


def run_bounded(
    argv: list[str],
    *,
    cwd: str | Path,
    env: Optional[dict[str, str]] = None,
    timeout_s: float = 600.0,
    max_output_bytes: int = 8 * 1024 * 1024,
    cancel_event: Any = None,
) -> ProcessOutcome:
    """Run a process with a hard timeout, output cap, and cooperative cancellation.

    The argv is executed directly (``shell=False``) so no shell metacharacter can
    be injected through a target string. Output is drained by ``communicate`` so a
    child that writes more than a pipe buffer cannot deadlock. Output is capped so
    a runaway engine cannot exhaust memory. A cancellation request (a
    ``threading.Event`` or any object with ``is_set()``) terminates the process
    group from a watcher thread.
    """
    import threading

    started = time.monotonic()
    proc = subprocess.Popen(
        argv,
        cwd=str(cwd),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,  # own process group, so we can kill the whole tree
    )
    timed_out = False
    cancelled = {"value": False}

    def _watch() -> None:
        while proc.poll() is None:
            if cancel_event is not None and cancel_event.is_set():
                cancelled["value"] = True
                _terminate(proc)
                return
            time.sleep(0.05)

    watcher = threading.Thread(target=_watch, daemon=True) if cancel_event is not None else None
    if watcher is not None:
        watcher.start()
    try:
        stdout, stderr = proc.communicate(timeout=timeout_s)
    except subprocess.TimeoutExpired:
        timed_out = True
        _terminate(proc)
        stdout, stderr = proc.communicate()

    duration = time.monotonic() - started
    stdout = _cap(stdout, max_output_bytes)
    stderr = _cap(stderr, max_output_bytes)
    digest = hashlib.sha256((stdout + "\n" + stderr).encode("utf-8", "replace")).hexdigest()
    return ProcessOutcome(
        argv=list(argv),
        returncode=proc.returncode,
        stdout=stdout,
        stderr=stderr,
        duration_s=duration,
        timed_out=timed_out,
        cancelled=cancelled["value"],
        output_sha256=digest,
    )


def _terminate(proc: subprocess.Popen) -> None:
    """Terminate the process group (SIGTERM, then SIGKILL). Never leaves orphans."""
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
    except (ProcessLookupError, PermissionError):
        return
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass


def _cap(text: str, limit: int) -> str:
    if text is None:
        return ""
    data = text.encode("utf-8", "replace")
    if len(data) <= limit:
        return text
    head = data[: limit // 2].decode("utf-8", "replace")
    tail = data[-(limit // 2):].decode("utf-8", "replace")
    return f"{head}\n...[truncated {len(data) - limit} bytes]...\n{tail}"


# --------------------------------------------------------------------------- #
# The adapter contract
# --------------------------------------------------------------------------- #

class EngineAdapter:
    """The contract every engine adapter implements.

    Subclasses must override :meth:`detect_installation` and the execution
    primitives. The default implementations here are honest "unavailable"
    behaviour, so a partially-written adapter reports MISSING rather than
    pretending to work.
    """

    #: Stable engine key used in CLI, reports, and finding provenance.
    name: str = "engine"
    #: The upstream project URL (for provenance and license notices).
    upstream_url: str = ""
    #: The upstream license SPDX id.
    license_id: str = ""
    #: Human-readable one-line description.
    description: str = ""

    def __init__(self, workspace: str | Path, *, config: Optional[dict] = None):
        # Absolute: an engine is executed with ``cwd`` set to the *target*, so a
        # relative workspace would make every artifact path relative to the target
        # and the adapter would look for the report in the wrong directory.
        self.workspace = Path(workspace).resolve()
        self.config = dict(config or {})

    def __init_subclass__(cls, **kwargs: Any) -> None:
        """Wrap every adapter's ``execute_scan`` in the compatibility gate.

        The gate has to hold for adapters that do not exist yet, so it is applied
        here rather than trusted to each implementation: an adapter author cannot
        forget it, and cannot opt out by overriding the method. Execution runs
        only inside an authorised execution (an ``Orchestrator`` run that passed
        the gate) or with an explicit ``compatibility=`` record.
        """
        super().__init_subclass__(**kwargs)
        original = cls.__dict__.get("execute_scan")
        if original is None or getattr(original, "_compatibility_guarded", False):
            return

        @functools.wraps(original)
        def execute_scan(self, target, *args, **kw):
            compatibility = kw.pop("compatibility", None)
            with guarded(compatibility, ExecutionTarget(name=str(target)),
                         f"{type(self).__name__}.execute_scan"):
                return original(self, target, *args, **kw)

        execute_scan._compatibility_guarded = True
        cls.execute_scan = execute_scan

    # -- discovery --------------------------------------------------------- #
    def detect_installation(self) -> bool:
        """Return True only if the engine's real interface is present here."""
        raise NotImplementedError

    def inspect_version(self) -> str:
        """Return the engine's version string, or '' if unknown."""
        return ""

    def verify_health(self) -> Health:
        """Probe the engine and report an honest state."""
        raise NotImplementedError

    def inspect_capabilities(self) -> list[Capability]:
        """Discover capabilities rather than assuming them."""
        return []

    def validate_configuration(self) -> tuple[bool, str]:
        """Validate the adapter's configuration; return ``(ok, reason)``."""
        return True, "ok"

    # -- execution --------------------------------------------------------- #
    def prepare_execution(self, target: str, **options: Any) -> ExecutionMetadata:
        raise NotImplementedError

    def execute_scan(self, target: str, **options: Any) -> ExecutionResult:
        raise NotImplementedError

    def monitor_execution(self) -> EngineState:
        return EngineState.RUNNING

    def collect_artifacts(self, run_dir: Path) -> dict[str, str]:
        return {}

    def normalize_findings(self, result: ExecutionResult) -> list[dict]:
        """Map raw engine records into the unified finding schema (dicts)."""
        return []

    def report_execution_status(self) -> EngineState:
        return EngineState.INSTALLED

    def clean_temporary_workspace(self) -> None:
        """Remove the adapter's scratch workspace (never the caller's data)."""
        scratch = self.workspace / f".{self.name}-scratch"
        if scratch.exists():
            shutil.rmtree(scratch, ignore_errors=True)

    # -- helpers ----------------------------------------------------------- #
    def _which(self, *names: str) -> Optional[str]:
        for n in names:
            path = shutil.which(n)
            if path:
                return path
        return None

    def describe(self) -> dict:
        return {
            "name": self.name,
            "description": self.description,
            "upstream_url": self.upstream_url,
            "license": self.license_id,
        }


def find_json_records(path: Path) -> list[dict]:
    """Load a JSON array/object file as a list of dicts (best-effort, honest)."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    if isinstance(data, list):
        return [r for r in data if isinstance(r, dict)]
    if isinstance(data, dict):
        for key in ("vulnerabilities", "findings", "results", "issues"):
            value = data.get(key)
            if isinstance(value, list):
                return [r for r in value if isinstance(r, dict)]
        return [data]
    return []
