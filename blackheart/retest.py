"""Vulnerability retest loop (adapted from ARTEX's ``retester``).

A confirmed finding can rot: the target is patched, a fork pin moves, or a
fixture changes. This module re-runs a finding's proof of concept against the
*current* state and records exactly one of three honest verdicts:

    STILL_REPRODUCIBLE  -- the PoC still fails (the bug is still there)
    FIXED               -- the PoC now passes (the bug is gone)
    CANNOT_CONFIRM      -- the PoC could not be run (missing tool, timeout, error)

The verdict is written to the finding's ``retest_result`` (section I of the
A-J record). A retest never changes the finding's *verdict*: a fixed finding is
still a valid historical finding, it is simply no longer live.

It adds no engine. It runs the operator's own reproduction command and
classifies the result. The same authorization and local/fork-only rules apply to
that command as to any other run -- the retester enforces nothing new, it just
records what happened.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Iterable, Optional, Sequence, Union


def utcnow() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


class RetestVerdict(str, Enum):
    """The three honest outcomes of a retest."""

    STILL_REPRODUCIBLE = "still-reproducible"
    FIXED = "fixed"
    CANNOT_CONFIRM = "cannot-confirm"


#: A reproduction command is either an argv list (run without a shell) or a
#: single string (run through the shell exactly as the operator wrote it).
Command = Union[str, Sequence[str]]


@dataclass
class RetestRecord:
    """One retest of one finding, with the evidence that produced the verdict."""

    finding_id: str
    verdict: RetestVerdict
    command: str
    exit_code: Optional[int] = None
    note: str = ""
    evidence_ids: list[str] = field(default_factory=list)
    timestamp: str = field(default_factory=utcnow)

    def to_dict(self) -> dict:
        return {
            "finding_id": self.finding_id,
            "verdict": self.verdict.value,
            "command": self.command,
            "exit_code": self.exit_code,
            "note": self.note,
            "evidence_ids": list(self.evidence_ids),
            "timestamp": self.timestamp,
        }


def classify(exit_code: Optional[int], *, error: str = "") -> RetestVerdict:
    """Map a reproduction command's exit status to a retest verdict.

    A clean exit (0) means the PoC no longer reproduces the bug -> FIXED.
    A non-zero exit means the PoC still detects the bug -> STILL_REPRODUCIBLE.
    No exit code (timeout, missing tool, spawn error) -> CANNOT_CONFIRM; we do
    not guess, because an unrunnable PoC is not evidence either way.
    """
    if error or exit_code is None:
        return RetestVerdict.CANNOT_CONFIRM
    return RetestVerdict.FIXED if exit_code == 0 else RetestVerdict.STILL_REPRODUCIBLE


def _as_command(command: Command) -> tuple[str, bool]:
    """Return ``(display, use_shell)`` for a command given as argv or string."""
    if isinstance(command, str):
        return command, True
    return " ".join(str(part) for part in command), False


def run_retest(
    finding_id: str,
    command: Command,
    *,
    timeout: float = 600.0,
    cwd: Optional[str] = None,
    evidence_ids: Iterable[str] = (),
) -> RetestRecord:
    """Run ``command`` and classify the result as a retest verdict.

    The command is the operator's own reproduction step (a ``forge test``, a
    ``poc run``, a script). It runs with a timeout; a timeout, a missing binary,
    or any spawn error is CANNOT_CONFIRM, never a silent success or failure.
    """
    display, use_shell = _as_command(command)
    try:
        proc = subprocess.run(
            command,
            shell=use_shell,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return RetestRecord(
            finding_id=finding_id,
            verdict=RetestVerdict.CANNOT_CONFIRM,
            command=display,
            note=f"timed out after {timeout:g}s",
            evidence_ids=list(evidence_ids),
        )
    except (OSError, ValueError) as exc:
        return RetestRecord(
            finding_id=finding_id,
            verdict=RetestVerdict.CANNOT_CONFIRM,
            command=display,
            note=f"could not run: {exc}",
            evidence_ids=list(evidence_ids),
        )
    verdict = classify(proc.returncode)
    tail = _tail(proc.stdout) or _tail(proc.stderr) or ""
    note = f"exit {proc.returncode}" + (f": {tail}" if tail else "")
    return RetestRecord(
        finding_id=finding_id,
        verdict=verdict,
        command=display,
        exit_code=proc.returncode,
        note=note,
        evidence_ids=list(evidence_ids),
    )


def _tail(text: str, limit: int = 400) -> str:
    text = (text or "").strip()
    if len(text) <= limit:
        return text
    return "..." + text[-limit:]


def apply_to_record(retest: RetestRecord, record: object) -> object:
    """Write a retest verdict onto a ``FindingRecord`` and return it.

    Only ``retest_result`` is touched (section I). The finding's ``status`` /
    verdict is deliberately left alone: a fixed bug is still a recorded finding.
    """
    value = f"{retest.verdict.value} ({retest.timestamp})"
    if retest.note:
        value += f" -- {retest.note}"
    setattr(record, "retest_result", value)
    if hasattr(record, "updated_at"):
        setattr(record, "updated_at", retest.timestamp)
    return record
