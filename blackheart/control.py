"""Resolve and run the guarded control for a differential check.

A witness is only evidence of a *bug* when the fixed twin does not exhibit it.
This module automates the two ways an operator obtains that twin:

* a verified deployment address (attested through Sourcify), or
* a patched commit fetched with a shallow ``git fetch`` and scanned locally.

The comparison replays the exact witness on both models. It reports
``CONTROL_CLEAN`` only when the vulnerable model violates and the control does
not; ``CONTROL_ALSO_VULNERABLE`` means the witness is not specific to the
target, and ``NO_VIOLATION`` means the witness did not reproduce at all.
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

from .ingest.solidity import scan_source
from .ingest.synthesize import SynthesisReport, SynthesizedTarget, synthesize
from .ingest.verified import best_contract
from .invariants.engine import run_sequence
from .models import AttackStep
from .toolchain.enforce import CompatibilityRecord

STATUSES = ("MODELLED", "UNMODELLED", "ERROR", "FETCHED", "FETCH_FAILED")

GitRunner = Callable[..., subprocess.CompletedProcess]


@dataclass
class ControlSource:
    status: str
    path: str = ""
    commit: str = ""
    reason: str = ""
    files: dict[str, str] = field(default_factory=dict, repr=False)

    def to_dict(self) -> dict:
        return {"status": self.status, "path": self.path, "commit": self.commit,
                "reason": self.reason, "files": sorted(self.files)}


@dataclass
class ControlModel:
    status: str
    contract: str = ""
    report: Optional[SynthesisReport] = None
    target: Optional[SynthesizedTarget] = field(default=None, repr=False)
    reason: str = ""

    def to_dict(self) -> dict:
        return {"status": self.status, "contract": self.contract,
                "reason": self.reason,
                "report": self.report.__dict__ if self.report is not None else None}


@dataclass
class DifferentialResult:
    status: str  # CONTROL_CLEAN | CONTROL_ALSO_VULNERABLE | NO_VIOLATION | BLOCKED
    vulnerable_violations: list[str] = field(default_factory=list)
    control_violations: list[str] = field(default_factory=list)
    reason: str = ""

    @property
    def specific(self) -> bool:
        return self.status == "CONTROL_CLEAN"

    def to_dict(self) -> dict:
        return {"status": self.status,
                "vulnerable_violations": list(self.vulnerable_violations),
                "control_violations": list(self.control_violations),
                "specific": self.specific, "reason": self.reason}


def load_source_tree(root: str | Path) -> dict[str, str]:
    """Read every ``.sol`` file under ``root``, keyed by relative path."""
    base = Path(root)
    if not base.exists():
        return {}
    skip = ("/out/", "/lib/", "/cache/", "/node_modules/", "/.git/")
    return {
        str(path.relative_to(base)): path.read_text(encoding="utf-8", errors="replace")
        for path in sorted(base.rglob("*.sol"))
        if path.is_file() and not any(part in f"/{path.as_posix()}/" for part in skip)
    }


def fetch_patched_source(
    repo_url: str,
    commit: str,
    dest: str | Path,
    *,
    timeout: int = 180,
    runner: Optional[GitRunner] = None,
) -> ControlSource:
    """Shallow-fetch one commit and return its Solidity files.

    The commit is pinned: a branch name is not a control. A failed fetch is
    ``FETCH_FAILED`` and the caller must not run a differential.
    """
    if not commit:
        return ControlSource("FETCH_FAILED", reason="a control commit is required")
    target = Path(dest)
    if target.exists():
        shutil.rmtree(target, ignore_errors=True)
    invoke = runner or subprocess.run
    try:
        for cmd in (
            ["git", "init", str(target)],
            ["git", "-C", str(target), "remote", "add", "origin", repo_url],
            ["git", "-C", str(target), "fetch", "--depth", "1", "origin", commit],
            ["git", "-C", str(target), "checkout", "FETCH_HEAD"],
        ):
            proc = invoke(cmd, capture_output=True, text=True, timeout=timeout)
            if getattr(proc, "returncode", 1) != 0:
                return ControlSource("FETCH_FAILED", str(target), commit,
                                     (getattr(proc, "stderr", "") or "")[:500])
    except (OSError, subprocess.TimeoutExpired) as exc:
        return ControlSource("FETCH_FAILED", str(target), commit, str(exc))
    files = load_source_tree(target)
    if not files:
        return ControlSource("FETCH_FAILED", str(target), commit,
                             "the fetched commit contains no Solidity source")
    return ControlSource("FETCHED", str(target), commit, files=files)


def discover_control_commit(
    repo_url: str,
    vulnerable_commit: str,
    dest: str | Path,
    *,
    paths: tuple[str, ...] = (),
    depth: int = 200,
    timeout: int = 180,
    runner: Optional[GitRunner] = None,
) -> ControlSource:
    """Find the first descendant commit touching ``paths`` and fetch its source.

    This is bounded: only ``depth`` commits are fetched, and a commit outside
    that window is a named failure, never a guessed control. The vulnerable
    commit itself is never returned.
    """
    if not vulnerable_commit:
        return ControlSource("FETCH_FAILED", reason="a vulnerable commit is required")
    target = Path(dest)
    if target.exists():
        shutil.rmtree(target, ignore_errors=True)
    invoke = runner or subprocess.run
    commands = [
        ["git", "clone", "--no-checkout", "--depth", str(depth), repo_url,
         str(target)],
        ["git", "-C", str(target), "cat-file", "-e", f"{vulnerable_commit}^{{commit}}"],
    ]
    try:
        for cmd in commands:
            proc = invoke(cmd, capture_output=True, text=True, timeout=timeout)
            if getattr(proc, "returncode", 1) != 0:
                return ControlSource("FETCH_FAILED", str(target), vulnerable_commit,
                                     (getattr(proc, "stderr", "") or "")[:500])
        log_cmd = ["git", "-C", str(target), "log", "--format=%H", "--reverse", "--all"]
        if paths:
            log_cmd += ["--", *paths]
        proc = invoke(log_cmd, capture_output=True, text=True, timeout=timeout)
        if getattr(proc, "returncode", 1) != 0:
            return ControlSource("FETCH_FAILED", str(target), vulnerable_commit,
                                 (getattr(proc, "stderr", "") or "")[:500])
        candidates = [line.strip() for line in (getattr(proc, "stdout", "") or "").splitlines()
                      if line.strip() and line.strip() != vulnerable_commit]
        for candidate in candidates:
            check = invoke(
                ["git", "-C", str(target), "merge-base", "--is-ancestor",
                 vulnerable_commit, candidate],
                capture_output=True, text=True, timeout=timeout)
            if getattr(check, "returncode", 1) != 0:
                continue
            checkout = invoke(["git", "-C", str(target), "checkout", candidate],
                              capture_output=True, text=True, timeout=timeout)
            if getattr(checkout, "returncode", 1) != 0:
                return ControlSource("FETCH_FAILED", str(target), candidate,
                                     (getattr(checkout, "stderr", "") or "")[:500])
            files = load_source_tree(target)
            if not files:
                return ControlSource("FETCH_FAILED", str(target), candidate,
                                     "the discovered commit contains no Solidity source")
            return ControlSource("FETCHED", str(target), candidate, files=files)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return ControlSource("FETCH_FAILED", str(target), vulnerable_commit, str(exc))
    return ControlSource(
        "FETCH_FAILED", str(target), vulnerable_commit,
        f"no descendant commit touching the requested paths was found within {depth} commits")


def build_control(files: dict[str, str], *, contract_name: str = "") -> ControlModel:
    """Scan, synthesize and return the control target (no certification claim)."""
    contracts = tuple(
        contract for path, source in sorted(files.items())
        for contract in scan_source(source, path)
    )
    if not contracts:
        return ControlModel("UNMODELLED", reason="no contract surface recovered")
    chosen = (next((c for c in contracts if c.name == contract_name), None)
              if contract_name else best_contract(contracts))
    if chosen is None:
        return ControlModel("UNMODELLED", reason=f"contract {contract_name!r} not found")
    try:
        target, report = synthesize(chosen)
    except Exception as exc:  # noqa: BLE001
        return ControlModel("ERROR", chosen.name, reason=str(exc))
    if not report.modelled_ops:
        return ControlModel("UNMODELLED", chosen.name, report,
                            reason="no externally callable function could be modelled")
    return ControlModel("MODELLED", chosen.name, report, target)


def compare_sequence(
    vulnerable: SynthesizedTarget,
    control: ControlModel | SynthesizedTarget,
    steps: list[AttackStep],
    *,
    compatibility: Optional[CompatibilityRecord],
    repository: str = "",
    commit: str = "",
) -> DifferentialResult:
    """Replay one witness on both models and classify the contrast."""
    control_target = control.target if isinstance(control, ControlModel) else control
    if control_target is None:
        return DifferentialResult("BLOCKED", reason="the control is not modelled")
    if compatibility is None:
        return DifferentialResult("BLOCKED",
                                  reason="no compatibility record; nothing was run")
    left = run_sequence(vulnerable, steps, compatibility,
                        repository=repository, commit=commit)
    right = run_sequence(control_target, steps, compatibility,
                         repository=repository, commit=commit)
    if left.violated and not right.violated:
        return DifferentialResult("CONTROL_CLEAN", list(left.violated),
                                  list(right.violated),
                                  "the witness reproduces on the target and not on the control")
    if left.violated and right.violated:
        return DifferentialResult("CONTROL_ALSO_VULNERABLE", list(left.violated),
                                  list(right.violated),
                                  "the same witness breaks the control; it is not specific")
    return DifferentialResult("NO_VIOLATION", list(left.violated), list(right.violated),
                              "the witness did not reproduce on the vulnerable model")
