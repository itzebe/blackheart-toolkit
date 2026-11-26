"""Damn Vulnerable DeFi training environment integration (mission section 4).

BLACKHEART ships its own self-contained DVDF-style challenge under
``harnesses/dvdf`` so that exploit training never depends on a network clone and
never touches a live chain. This module locates that harness (or an external DVDF
checkout), runs a challenge's Foundry tests, and captures the exact command and
output as evidence.

Nothing here broadcasts a transaction. The harness is compiled and executed in
Foundry's in-process EVM against local fixtures only.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from ..evidence import EvidenceStore


# Repo-relative location of the bundled training harness.
DEFAULT_HARNESS = Path(__file__).resolve().parents[2] / "harnesses" / "dvdf"


def forge_env() -> dict:
    """The environment a forge invocation needs, with the standard install on PATH."""
    env = dict(os.environ)
    foundry = str(Path.home() / ".foundry" / "bin")
    if foundry not in env.get("PATH", ""):
        env["PATH"] = env.get("PATH", "") + os.pathsep + foundry
    return env


def clear_replay_cache(path: Path | str = DEFAULT_HARNESS) -> None:
    """Drop forge's persisted invariant counterexamples so a run really re-executes.

    forge stores a discovered counterexample under
    ``cache/invariant/failures/<contract>/`` and *replays* it on the next run. A
    replay prints only ``[FAIL: <invariant> replay failure]``: it neither re-runs
    the handler nor prints the violated assertion. Left in place the cache makes
    results order-dependent -- the same command reports a violation once and a
    bare replay afterwards. Only a derived artifact is removed, never a source or
    an evidence file.
    """
    shutil.rmtree(Path(path) / "cache" / "invariant" / "failures", ignore_errors=True)


@dataclass
class ChallengeResult:
    name: str
    command: str
    returncode: int
    stdout: str = ""
    passed: bool = False
    evidence_id: str = ""

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "command": self.command,
            "returncode": self.returncode,
            "passed": self.passed,
            "evidence_id": self.evidence_id,
        }


@dataclass
class DVDFHarness:
    """A local Damn Vulnerable DeFi training environment."""

    path: Path = field(default_factory=lambda: DEFAULT_HARNESS)
    #: Empty means resolve from the toolchain (``~/.foundry/bin`` included), so
    #: a shell PATH without Foundry does not make an installed forge invisible.
    forge_bin: str = ""
    evidence: EvidenceStore | None = None

    def available(self) -> bool:
        return (self.path / "foundry.toml").exists() and (self.path / "src").exists()

    def _env(self) -> dict:
        return forge_env()

    def build(self, timeout: int = 600) -> ChallengeResult:
        return self._run(["build"], "build", timeout=timeout, require_suite_ok=False)

    def run_challenge(self, contract: str, *, verbosity: int = 3, timeout: int = 600,
                      extra: list[str] | None = None) -> ChallengeResult:
        """Run one challenge test contract (``--match-contract <contract>``)."""
        args = ["test", "--match-contract", contract, f"-{'v' * verbosity}"]
        args += extra or []
        return self._run(args, f"challenge:{contract}", timeout=timeout)

    def run_invariant(self, contract: str, timeout: int = 900) -> ChallengeResult:
        """Run an invariant test contract (expected to FAIL when it finds a bug).

        forge persists a discovered counterexample under
        ``cache/invariant/failures/<contract>/`` and *replays* it on the next run.
        A replay prints only ``[FAIL: <invariant> replay failure]`` -- it does not
        re-execute the handler or print the violated assertion. Left in place, the
        cache makes the run order-dependent: the same command reports a violation
        the first time and a bare replay the second, so a test asserting on the
        violation message fails depending on which test ran before it.

        The cache is therefore cleared before each run. This removes only a
        derived artifact, never a source or an evidence file, so the run always
        executes the campaign and the output always says what actually happened.
        """
        clear_replay_cache(self.path)
        return self._run(
            ["test", "--match-contract", contract, "-vvv"],
            f"invariant:{contract}", timeout=timeout,
        )

    def _run(self, args: list[str], name: str, *, timeout: int,
             require_suite_ok: bool = True) -> ChallengeResult:
        forge = self.forge_bin
        if not forge:
            from ..engines.solidity.base import resolve_tool
            found = resolve_tool("forge")
            forge = found.binary if found is not None else ""
        if not forge:
            raise FileNotFoundError(
                "forge not found; run ./install.sh (or add ~/.foundry/bin to PATH)"
            )
        cmd = [forge, *args]
        proc = subprocess.run(
            cmd, cwd=self.path, capture_output=True, text=True,
            timeout=timeout, env=self._env(),
        )
        out = (proc.stdout or "") + (proc.stderr or "")
        # ``forge build`` prints no suite summary, so success is its exit code
        # alone; a test run additionally has to report a passing suite.
        passed = proc.returncode == 0 and (not require_suite_ok or "Suite result: ok" in out)
        result = ChallengeResult(
            name=name, command=" ".join(cmd), returncode=proc.returncode,
            stdout=out, passed=passed,
        )
        if self.evidence is not None:
            ev = self.evidence.put_text(
                out, kind="dvdf-run",
                description=f"DVDF {name}",
                command=" ".join(cmd),
                metadata={"returncode": proc.returncode, "passed": passed},
            )
            result.evidence_id = ev.evidence_id
        return result


__all__ = ["DVDFHarness", "ChallengeResult", "DEFAULT_HARNESS",
           "forge_env", "clear_replay_cache"]
