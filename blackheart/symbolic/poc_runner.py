"""Run a generated PoC under the compatibility gate.

Rendering a test is not reproducing a bug. This module writes the generated
Solidity into a minimal Foundry project, runs ``forge test`` only when the
language-aware gate admits the target, and reports the doctrine's statuses:

* ``PASS``        -- the PoC's assertion held: the witness reproduced.
* ``FAIL``        -- the test ran but the assertion did not hold.
* ``BLOCKED``     -- the gate refused, or forge is absent. Nothing ran.
* ``INCOMPLETE``  -- the build or the output could not be interpreted.

A ``PASS`` is a reproduced witness, not a priced finding. Impact still has to be
accounted for separately.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional

from ..engines.solidity.base import resolve_tool
from ..toolchain.enforce import CompatibilityRecord, ExecutionTarget, bind

STATUSES = ("PASS", "FAIL", "BLOCKED", "INCOMPLETE")

#: ``(command, cwd, timeout) -> CompletedProcess``. Injectable so the gate and
#: the output parser can be tested on a host without forge.
Runner = Callable[[list[str], str, int], subprocess.CompletedProcess]

FOUNDRY_TOML = """\
[profile.default]
src = "src"
test = "test"
out = "out"
libs = []

[invariant]
runs = 256
depth = 64
fail_on_revert = false
"""


@dataclass(frozen=True)
class PocRunOutcome:
    status: str
    detail: str
    test_name: str
    output: str = ""
    project_dir: str = ""

    def as_dict(self) -> dict:
        return {
            "status": self.status,
            "detail": self.detail,
            "test_name": self.test_name,
            "output": self.output,
            "project_dir": self.project_dir,
            "note": "a PASS is a reproduced witness, not a priced finding",
        }


def write_poc_project(solidity: str, root: str | Path, *,
                      filename: str = "Poc.t.sol",
                      sources: Optional[dict[str, str]] = None) -> Path:
    """Write a standalone Foundry project; the PoC needs no forge-std import.

    ``sources`` writes the target's verified files under ``src/`` so a
    source-level PoC can import the real contract instead of an etched blob.
    """
    project = Path(root)
    (project / "test").mkdir(parents=True, exist_ok=True)
    src = project / "src"
    src.mkdir(parents=True, exist_ok=True)
    for path, text in (sources or {}).items():
        clean = str(path).replace("\\", "/").lstrip("/")
        # Sources are written under src/; a repository-relative key that already
        # starts with src/ would otherwise become src/src/ and break the import.
        clean = clean.removeprefix("src/")
        if ".." in clean.split("/"):
            clean = Path(clean).name
        target = src / clean
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
    (project / "foundry.toml").write_text(FOUNDRY_TOML, encoding="utf-8")
    path = project / "test" / filename
    path.write_text(solidity, encoding="utf-8")
    return path


def _entries(bucket: object) -> list[str]:
    if not isinstance(bucket, list):
        return []
    names = []
    for entry in bucket:
        if isinstance(entry, str):
            names.append(entry)
        elif isinstance(entry, dict):
            name = entry.get("name") or entry.get("test") or entry.get("signature")
            if name:
                names.append(str(name))
    return names


def _matches(name: str, test_name: str) -> bool:
    return name.split("(", 1)[0].rsplit("::", 1)[-1] == test_name


def interpret_forge_json(stdout: str, test_name: str) -> tuple[Optional[str], str]:
    """Read ``forge test --json`` and say whether ``test_name`` passed or failed."""
    text = (stdout or "").strip()
    start = text.find("{")
    if start > 0:
        text = text[start:]
    try:
        payload = json.loads(text)
    except (ValueError, TypeError):
        return None, "forge output is not JSON"
    if not isinstance(payload, dict):
        return None, "unexpected forge JSON shape"

    results: list[tuple[str, str]] = []
    for suite, data in payload.items():
        if not isinstance(data, dict):
            continue
        for bucket in ("passed", "failed", "skipped"):
            for name in _entries(data.get(bucket)):
                if _matches(name, test_name):
                    results.append((bucket, name))
        test_results = data.get("test_results")
        if isinstance(test_results, dict):
            for name, result in test_results.items():
                if not _matches(name, test_name):
                    continue
                status = str(result.get("status", "")).lower() if isinstance(result, dict) else ""
                if status == "skipped":
                    bucket = "skipped"
                elif status in ("success", "pass", "passed"):
                    bucket = "passed"
                else:
                    bucket = "failed"
                results.append((bucket, name))

    if not results:
        return None, f"test {test_name!r} was not found in the forge result"
    if any(bucket == "failed" for bucket, _ in results):
        return "FAIL", f"{test_name} ran and its assertion did not hold"
    if any(bucket == "passed" for bucket, _ in results):
        return "PASS", f"{test_name} ran and its assertion held"
    return None, f"{test_name} was skipped"


def _default_runner(command: list[str], cwd: str, timeout: int) -> subprocess.CompletedProcess:
    # The toolchain resolver searches ~/.foundry/bin explicitly; a shell PATH
    # that happens to omit it must not make an installed forge look absent.
    if command and command[0] == "forge":
        resolved = resolve_tool("forge")
        if resolved is not None:
            command = [resolved.binary, *command[1:]]
    return subprocess.run(command, cwd=cwd, capture_output=True, text=True, timeout=timeout)


def run_poc_text(solidity: str, *, test_name: str = "test_witness",
                 compatibility: Optional[CompatibilityRecord],
                 target_component: str, repository: str, commit: str = "",
                 timeout: int = 600, keep_dir: Optional[str] = None,
                 runner: Optional[Runner] = None,
                 sources: Optional[dict[str, str]] = None,
                 fork_url: str = "", fork_block: Optional[int] = None) -> PocRunOutcome:
    """Write and run one generated PoC. The gate is checked before the tool."""
    if compatibility is None:
        return PocRunOutcome("BLOCKED", "no compatibility record; nothing was run", test_name)
    decision = bind(compatibility, ExecutionTarget(
        name=target_component, repository=repository, commit=commit))
    if decision.decision != "ADMIT":
        return PocRunOutcome("BLOCKED", "gate refused: " + "; ".join(decision.reasons),
                             test_name)
    if runner is None and resolve_tool("forge") is None:
        return PocRunOutcome("BLOCKED", "forge is not installed on this host; nothing was run",
                             test_name)

    project = Path(keep_dir) if keep_dir else Path(tempfile.mkdtemp(prefix="blackheart-poc-"))
    try:
        try:
            write_poc_project(solidity, project, sources=sources)
        except OSError as exc:
            return PocRunOutcome("INCOMPLETE", f"could not write the project: {exc}",
                                 test_name, project_dir=str(project) if keep_dir else "")
        invoke = runner or _default_runner
        try:
            command = ["forge", "test", "--json", "--match-test", test_name]
            if fork_url:
                command += ["--fork-url", fork_url]
            if fork_block is not None:
                command += ["--fork-block-number", str(fork_block)]
            proc = invoke(command, str(project), timeout)
        except (OSError, subprocess.TimeoutExpired) as exc:
            return PocRunOutcome("INCOMPLETE", f"could not complete: {exc}", test_name,
                                 project_dir=str(project) if keep_dir else "")
        status, detail = interpret_forge_json(proc.stdout, test_name)
        output = (proc.stdout or proc.stderr or "")[:4000]
        if status is None:
            return PocRunOutcome("INCOMPLETE", detail, test_name, output,
                                 str(project) if keep_dir else "")
        return PocRunOutcome(status, detail, test_name, output,
                             str(project) if keep_dir else "")
    finally:
        if keep_dir is None:
            shutil.rmtree(project, ignore_errors=True)
