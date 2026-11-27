"""Drive the state-space engine against a *real* running application.

This is the bridge the mission asks for: the existing ``HypothesisGenerator``,
``StateSpaceExplorer`` and ``IndependentSequenceVerifier`` are run unchanged, but
over a :class:`~blackheart.statespace.runtime.base.RuntimeTarget` that dispatches
operations to a live loopback application and evaluates invariants against the
application's *actual* observed state.

The result is a :class:`RuntimeReport` that keeps the full execution trace, the
minimised sequence, and the independent verifier's verdict -- with the provenance
of every step stated as ``"executed"``. A model-predicted violation is never
reported as a runtime finding; only an executed, independently re-executed
violation can reach ``INDEPENDENTLY_VERIFIED``.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Optional

from ...toolchain.enforce import ExecutionTarget, guarded
from ...noise import NoiseGovernor
from ..explore import ExploreConfig, ExploreReport, StateSpaceExplorer
from ..hypotheses import HypothesisGenerator
from ..verify import IndependentSequenceVerifier, VerifyConfig, VerifyResult
from .authz import LocalScope
from .base import RuntimeTarget
from .harness_apps import AppInvariant, make_app
from .harness_server import HarnessServer
from .http_adapter import HttpExecutionAdapter


def _to_invariant_specs(app_invariants: list[AppInvariant]):
    from ...invariants.engine import InvariantSpec

    return [InvariantSpec(inv.inv_id, inv.title, inv.predicate, severity_if_broken=inv.severity)
            for inv in app_invariants]


@dataclass
class RuntimeReport:
    """The outcome of executing the engine against a live application."""

    target: str
    mode: str = "runtime"                       # "runtime" | "fixture"
    executed: bool = False
    sequences_executed: int = 0
    steps_executed: int = 0
    elapsed_seconds: float = 0.0
    violations: list[dict] = field(default_factory=list)
    verdicts: list[dict] = field(default_factory=list)
    trace: list[dict] = field(default_factory=list)   # the trace of the winning sequence
    adapter: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "mode": self.mode,
            "executed": self.executed,
            "sequences_executed": self.sequences_executed,
            "steps_executed": self.steps_executed,
            "elapsed_seconds": self.elapsed_seconds,
            "violations": self.violations,
            "verdicts": self.verdicts,
            "trace": self.trace,
            "adapter": self.adapter,
        }


def _noise_from_env() -> Optional[NoiseGovernor]:
    """A governor only when the operator opts in via BLACKHEART_NOISE_PROFILE."""
    import os

    profile = os.environ.get("BLACKHEART_NOISE_PROFILE", "").strip()
    if not profile:
        return None
    try:
        return NoiseGovernor(profile=profile)
    except ValueError:
        return None


def build_http_target(app_name: str, *, scope: Optional[LocalScope] = None,
                      timeout: float = 10.0, max_operations: int = 20_000,
                      host: str = "127.0.0.1",
                      noise: Optional[NoiseGovernor] = None,
                      ) -> tuple[HarnessServer, HttpExecutionAdapter, RuntimeTarget]:
    """Start a harness app on loopback and wire an executable target to it.

    The server is returned so the caller owns its lifecycle (and always stops it).
    The scope must explicitly authorize the target; the default is a narrow
    local-harness authorization for BLACKHEART's own controlled apps.

    When ``noise`` is given (or ``BLACKHEART_NOISE_PROFILE`` is set), every live
    request is paced through it, so a run cannot hammer the target.
    """
    from .authz import local_harness_scope
    from .base import ExecutionBudget

    if noise is None:
        noise = _noise_from_env()
    app = make_app(app_name)
    server = HarnessServer(app_name, host=host).start()
    model = app.model()
    scope = scope or local_harness_scope(app_name)
    adapter = HttpExecutionAdapter(
        server.base_url, model, scope,
        identities=server.identities(),
        timeout=timeout,
        budget=ExecutionBudget(max_operations=max_operations),
        noise=noise,
    )
    adapter.set_invariants(_to_invariant_specs(server.invariants()))
    adapter.load()
    target = RuntimeTarget(adapter, model)
    return server, adapter, target


def run_runtime_discovery(app_name: str, *, cfg: Optional[ExploreConfig] = None,
                          verify: bool = True,
                          compatibility: object = None) -> RuntimeReport:
    """Run the full pipeline against a live harness app and return a report.

    Steps: start the app -> load the adapter (scope-checked) -> derive the model
    from the app's own declaration -> generate hypotheses -> explore with *real
    execution* -> minimise -> independently re-execute and verify.

    Compatibility-gated before the app is started: the gate is checked here, so an
    unauthorised run never launches the process.
    """
    with guarded(compatibility, ExecutionTarget(name=app_name),
                 "statespace.runtime.run_runtime_discovery"):
        return _run_runtime_discovery(app_name, cfg=cfg or ExploreConfig(), verify=verify)


def _run_runtime_discovery(app_name: str, *, cfg: ExploreConfig,
                           verify: bool) -> RuntimeReport:
    server, adapter, target = build_http_target(app_name)
    report = RuntimeReport(target=app_name)
    try:
        model = target.model()
        gen = HypothesisGenerator(model).generate()
        t0 = time.monotonic()
        explore = StateSpaceExplorer(target, cfg).explore(gen.hypotheses)
        report.elapsed_seconds = round(time.monotonic() - t0, 4)
        report.executed = True
        report.sequences_executed = explore.sequences_tried
        report.steps_executed = explore.steps_evaluated
        report.adapter = adapter.to_dict()
        report.violations = [v.to_dict() for v in explore.violations]

        if verify and explore.violations:
            # The control target (the secure variant) is a *different* app; the
            # verifier's control factory starts it fresh for a differential check.
            control_name = _control_name(app_name)
            control_factory = (lambda: build_http_target(control_name)[2]) if control_name else None
            vcfg = VerifyConfig(
                control_factory=control_factory,
                in_scope=True, scope_reference=adapter.scope.reference,
                authorization_gate_passed=adapter.scope.authorized,
            )
            verifier = IndependentSequenceVerifier(
                lambda: build_http_target(app_name)[2], vcfg)
            results: list[VerifyResult] = []
            for v in explore.violations:
                results.append(verifier.verify(v, model=model, preconditions_satisfiable=True))
            report.verdicts = [r.to_dict() for r in results]
        # Capture the trace of the smallest verified violation for the evidence.
        report.trace = _trace_for_smallest(explore, target)
    finally:
        server.stop()
        adapter.close()
    return report


def _control_name(app_name: str) -> Optional[str]:
    from .harness_apps import APP_PAIRS

    for vuln, guard, _inv, _cls in APP_PAIRS:
        if vuln == app_name:
            return guard
    return None


def _trace_for_smallest(explore: ExploreReport, target: RuntimeTarget) -> list[dict]:
    """Re-execute the smallest violation and return its full per-step trace."""
    if not explore.violations:
        return []
    from ..explore import run_sequence

    smallest = min(explore.violations, key=lambda v: len(v.minimal_sequence))
    target.reset()
    run_sequence(target, smallest.minimal_sequence)
    return target.execution_trace()


# --------------------------------------------------------------------------- #
# Adapter-mode discovery: a declared, auditable adapter (no auto-extraction)
# --------------------------------------------------------------------------- #

def adapter_report(app_name: str) -> dict:
    """A declarative, inspectable summary of a harness app's runtime model.

    This is the "explicit, auditable adapter declaration" the mission requires
    where automatic extraction would be unreliable: it states the operations, the
    identities and their roles, the entry points, and the invariants -- each with a
    provenance string pointing at the app's own declaration.
    """
    app = make_app(app_name)
    model = app.model()
    return {
        "target": app_name,
        "provenance": f"blackheart/statespace/runtime/harness_apps.py#{type(app).__name__}",
        "identities": {name: list(roles) for name, roles in app.roles().items()},
        "operations": [
            {
                "name": op.name,
                "roles": list(op.roles),
                "entry_point": op.entry or f"POST /{op.name}",
                "source": f"app:{app_name}",
            }
            for op in app.ops()
        ],
        "invariants": [
            {"inv_id": inv.inv_id, "statement": inv.title, "severity": inv.severity}
            for inv in app.invariants()
        ],
        "model": model.to_dict(),
    }
