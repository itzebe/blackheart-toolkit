"""Run a caller-supplied Foundry test against an arbitrary source tree.

This is the execution backend the source model is not: a real compiler and a
real EVM run the whole project, including contracts the fixed statement subset
cannot interpret. It is deliberately a *test runner*, not a semantics engine.
The caller supplies the test; BLACKHEART supplies the verified files, the
compatibility gate, the fork flags and an honest PASS/FAIL/BLOCKED/INCOMPLETE
result.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

from ..symbolic.poc_runner import PocRunOutcome, run_poc_text
from ..toolchain.enforce import CompatibilityRecord


@dataclass(frozen=True)
class FoundryRun:
    status: str
    detail: str
    test_name: str
    output: str = ""
    project_dir: str = ""

    @property
    def passed(self) -> bool:
        return self.status == "PASS"

    def to_dict(self) -> dict:
        return {"status": self.status, "detail": self.detail,
                "test_name": self.test_name, "output": self.output,
                "project_dir": self.project_dir,
                "note": "a PASS is a reproduced test, not a priced finding"}


def run_foundry_test(
    files: dict[str, str],
    test_source: str,
    *,
    compatibility: Optional[CompatibilityRecord],
    target_component: str,
    repository: str,
    commit: str = "",
    test_name: str = "test_witness",
    fork_url: str = "",
    fork_block: Optional[int] = None,
    timeout: int = 600,
    keep_dir: Optional[str] = None,
    runner: Any = None,
) -> FoundryRun:
    """Compile and run one test with the real Foundry toolchain, gated first."""
    if not files:
        return FoundryRun("INCOMPLETE", "no source files to compile", test_name)
    if not test_source.strip():
        return FoundryRun("INCOMPLETE", "no test source supplied", test_name)
    outcome: PocRunOutcome = run_poc_text(
        test_source, test_name=test_name, compatibility=compatibility,
        target_component=target_component, repository=repository, commit=commit,
        timeout=timeout, keep_dir=keep_dir, runner=runner, sources=files,
        fork_url=fork_url, fork_block=fork_block,
    )
    return FoundryRun(outcome.status, outcome.detail, outcome.test_name,
                      outcome.output, outcome.project_dir)
