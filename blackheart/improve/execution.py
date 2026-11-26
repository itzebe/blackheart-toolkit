"""Compile a project with a real compiler, then hand its ABI to the model layer.

This is the composition the loop was missing: ``ingest --compile`` produced
artifacts but did not expose a programmatic result, and ``pocgen`` could run a
witness but needed a model first. The result is honest: a missing compiler is
``BLOCKED``, a build failure is ``INCOMPLETE``, and no artifact is invented.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from ..ingest.compile import compile_project, models_from_compiled
from ..toolchain.enforce import CompatibilityRecord


@dataclass
class CompileModel:
    status: str
    tool: str = ""
    contract: str = ""
    artifact: dict = field(default_factory=dict)
    model_operations: list[str] = field(default_factory=list)
    reason: str = ""

    @property
    def ok(self) -> bool:
        return self.status == "OK" and bool(self.artifact)

    def to_dict(self) -> dict:
        return {
            "status": self.status,
            "tool": self.tool,
            "contract": self.contract,
            "artifact": dict(self.artifact),
            "model_operations": list(self.model_operations),
            "reason": self.reason,
        }


def compile_and_model(
    root: str,
    *,
    compatibility: Optional[CompatibilityRecord],
    target_component: str,
    repository: str,
    commit: str = "",
    contract: str = "",
    timeout: int = 600,
) -> CompileModel:
    """Compile ``root`` and return the chosen contract's ABI-backed model.

    The compatibility gate is mandatory: without a record the compiler is never
    invoked, exactly as ``ingest --compile`` requires.
    """
    outcome = compile_project(
        root, compatibility=compatibility,
        target_component=target_component, repository=repository,
        commit=commit, timeout=timeout,
    )
    if not outcome.ok:
        return CompileModel(outcome.status, outcome.tool, reason=outcome.reason)
    names = sorted(outcome.artifacts)
    chosen = contract or names[0]
    artifact = outcome.artifacts.get(chosen)
    if artifact is None:
        return CompileModel(
            "INCOMPLETE", outcome.tool, reason=(
                f"contract {chosen!r} is not among the compiled artifacts: "
                + ", ".join(names)))
    models = models_from_compiled(outcome)
    model = models.get(chosen)
    operations = [op.name for op in model.operations] if model is not None else []
    return CompileModel(
        "OK", outcome.tool, chosen, artifact.to_dict(), operations,
        outcome.reason,
    )


__all__ = ["CompileModel", "compile_and_model"]
