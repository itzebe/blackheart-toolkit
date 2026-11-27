"""The shared base for every tool adapter.

The contract is deliberately small and the same for every tool, because the point
is that *the engine can drive any of them and read the result back* -- a bespoke
interface per tool would just move the operator's manual work into the codebase.

The lifecycle is: authorize -> locate -> run -> capture -> parse -> record. Two of
those steps are non-negotiable and enforced here, not left to each adapter:

  * ``authorize`` runs before anything else and raises on a blocked asset.
  * ``run`` never fabricates: a missing binary, a timeout, or a non-zero exit is
    recorded as it happened.
"""

from __future__ import annotations

import shutil
import subprocess
import time
from dataclasses import dataclass, field
from typing import Any, Optional

from ...authz import assert_authorized
from ...models import AuthorizationRecord


class ToolUnavailable(RuntimeError):
    """The tool binary is not installed; the scan did not run."""


@dataclass
class ToolFinding:
    """One parsed observation from a tool's output.

    ``kind`` is the tool's own classification (its template id, vuln type, or a
    neutral ``"match"``); ``severity`` is the tool's, kept as a string because
    tools disagree on the vocabulary. ``evidence`` is the raw line/JSON the
    finding was parsed from, so the parse is auditable.
    """

    tool: str
    kind: str
    target: str
    severity: str = ""
    detail: str = ""
    evidence: str = ""
    raw: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "tool": self.tool,
            "kind": self.kind,
            "target": self.target,
            "severity": self.severity,
            "detail": self.detail,
            "evidence": self.evidence,
        }


@dataclass
class ToolRun:
    """The honest record of one tool invocation."""

    tool: str
    target: str
    asset: str
    command: str
    available: bool
    authorized: bool
    returncode: int = -1
    stdout: str = ""
    stderr: str = ""
    findings: list[ToolFinding] = field(default_factory=list)
    parse_notes: list[str] = field(default_factory=list)
    elapsed_seconds: float = 0.0
    reason: str = ""

    def to_dict(self) -> dict:
        return {
            "tool": self.tool,
            "target": self.target,
            "asset": self.asset,
            "command": self.command,
            "available": self.available,
            "authorized": self.authorized,
            "returncode": self.returncode,
            "findings": [f.to_dict() for f in self.findings],
            "finding_count": len(self.findings),
            "parse_notes": list(self.parse_notes),
            "elapsed_seconds": round(self.elapsed_seconds, 3),
            "reason": self.reason,
            "stdout_tail": "\n".join(self.stdout.splitlines()[-30:]),
            "stderr_tail": "\n".join(self.stderr.splitlines()[-30:]),
        }


def locate(binary: str) -> Optional[str]:
    """Find a tool binary on PATH or in the common install dirs."""
    found = shutil.which(binary)
    if found:
        return found
    from pathlib import Path

    for cand in (Path.home() / "go" / "bin" / binary,
                 Path.home() / ".local" / "bin" / binary,
                 Path("/usr/local/bin") / binary,
                 Path("/root/go/bin") / binary):
        try:
            if cand.exists():
                return str(cand)
        except OSError:
            continue
    return None


def run_command(cmd: list[str], *, timeout: int) -> tuple[int, str, str]:
    """Run ``cmd`` and return ``(returncode, stdout, stderr)``; never raises.

    A timeout is reported as returncode ``124`` (the conventional value) with the
    message in stderr, so a caller sees exactly what happened rather than an
    exception it might swallow.
    """
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return proc.returncode, proc.stdout or "", proc.stderr or ""
    except subprocess.TimeoutExpired as exc:
        out = exc.stdout.decode() if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        return 124, out, f"timed out after {timeout}s"
    except FileNotFoundError:
        return 127, "", f"{cmd[0]}: not found"
    except OSError as exc:  # pragma: no cover - defensive
        return 1, "", str(exc)


def authorized_run(
    *,
    tool: str,
    asset: str,
    target: str,
    record: AuthorizationRecord,
    build_cmd,
    timeout: int,
) -> ToolRun:
    """Authorize, locate, run, and capture -- the common shell of every adapter.

    ``build_cmd`` is a callable taking the resolved binary path and returning the
    argv list, so an adapter can decide its own flags while this function keeps
    the authorization and capture discipline identical across tools.
    """
    # 1. Authorization is the first thing that happens and it is fail-closed.
    assert_authorized(record, asset)
    binary = tool
    path = locate(binary)
    if path is None:
        return ToolRun(tool=tool, target=target, asset=asset,
                       command=f"{tool} (not found)", available=False,
                       authorized=True, reason=f"{tool} is not installed")

    cmd = build_cmd(path)
    start = time.monotonic()
    rc, out, err = run_command(cmd, timeout=timeout)
    elapsed = time.monotonic() - start
    run = ToolRun(
        tool=tool, target=target, asset=asset, command=" ".join(cmd),
        available=True, authorized=True, returncode=rc, stdout=out, stderr=err,
        elapsed_seconds=elapsed,
    )
    if rc == 124:
        run.reason = "timeout"
    return run
