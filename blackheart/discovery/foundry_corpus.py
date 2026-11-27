"""Foundry integration for the historical corpus (mission 3.G).

Runs the real Foundry PoC suite in ``harnesses/historical-corpus`` and captures
the exact command and output as evidence. Nothing here broadcasts a transaction;
``forge`` executes everything in its in-process EVM.

If ``forge`` is not installed the runner reports it honestly (``available=False``)
rather than pretending the PoCs ran. This mirrors :mod:`blackheart.foundry`.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path

from ..engines.solidity.base import resolve_tool


HARNESS = Path(__file__).resolve().parents[2] / "harnesses" / "historical-corpus"
# The single source of truth for the harness's forge-std pin, shared with
# fetch.sh so a programmatic install and a manual one cannot diverge.
FORGE_STD_REPO = "https://github.com/foundry-rs/forge-std.git"
FORGE_STD_PIN = "v1.9.7"


def _forge() -> str | None:
    found = resolve_tool("forge")
    return found.binary if found is not None else None


@dataclass
class FoundryResult:
    available: bool
    command: str = ""
    returncode: int = -1
    stdout: str = ""
    passed: bool = False
    reason: str = ""

    def to_dict(self) -> dict:
        return {
            "available": self.available,
            "command": self.command,
            "returncode": self.returncode,
            "passed": self.passed,
            "reason": self.reason,
            "stdout_tail": "\n".join(self.stdout.splitlines()[-40:]),
        }


def ensure_deps() -> bool:
    """Vendor forge-std if it is absent (idempotent). Returns True if present.

    Uses a plain clone + checkout pinned to :data:`FORGE_STD_PIN` -- matching
    ``fetch.sh`` and the sibling harnesses -- so a fetch cannot silently
    substitute a different version and no git submodule is created in a
    repository that keeps these vendored deps git-ignored.
    """
    lib = HARNESS / "lib" / "forge-std"
    if lib.exists():
        return True
    try:
        lib.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(["git", "clone", "--quiet", FORGE_STD_REPO, str(lib)],
                       capture_output=True, text=True, timeout=300, check=True)
        subprocess.run(["git", "-C", str(lib), "checkout", "--quiet", FORGE_STD_PIN],
                       capture_output=True, text=True, timeout=300, check=True)
    except (subprocess.SubprocessError, OSError):
        return lib.exists()
    return lib.exists()


def run_poc_suite(*, match: str = "HistoricalCorpusPoC", timeout: int = 600) -> FoundryResult:
    """Run the corpus PoC suite and return the result with exact evidence.

    The default match is the exploit-PoC contract, whose tests are all expected to
    PASS (each exploit succeeds on the vulnerable contract and its control
    reverts on the patched one). The stateful invariant contracts are run
    separately by :func:`run_invariant_differential`, because one of them is
    *expected* to fail (it is the bug demonstration).
    """
    forge = _forge()
    if forge is None:
        return FoundryResult(available=False, reason="forge not installed")
    ensure_deps()
    cmd = [forge, "test", "-vv"]
    if match:
        cmd += ["--match-contract", match]
    try:
        proc = subprocess.run(cmd, cwd=HARNESS, capture_output=True, text=True,
                              timeout=timeout)
    except subprocess.TimeoutExpired:
        return FoundryResult(available=True, command=" ".join(cmd),
                             reason="timeout", passed=False)
    out = proc.stdout + proc.stderr
    return FoundryResult(
        available=True,
        command=" ".join(cmd),
        returncode=proc.returncode,
        stdout=out,
        passed=proc.returncode == 0,
    )


def run_invariant_differential() -> dict:
    """Run both invariant contracts and report the differential honestly.

    The vulnerable-bank invariant is *expected to fail* (it demonstrates the bug);
    the patched-bank invariant is *expected to pass*. A result is only meaningful
    if both directions hold.
    """
    vuln = run_poc_suite(match="BankInvariantTest", timeout=600)
    patched = run_poc_suite(match="SafeBankInvariantTest", timeout=600)
    # forge returns non-zero when the invariant fails, which is the expected
    # outcome for the vulnerable contract.
    vuln_fails = (not vuln.passed) and vuln.available
    patched_passes = patched.passed
    return {
        "vulnerable_invariant_failed_as_expected": vuln_fails,
        "patched_invariant_held": patched_passes,
        "differential_established": vuln_fails and patched_passes,
        "vulnerable_run": vuln.to_dict(),
        "patched_run": patched.to_dict(),
    }
