"""Run the engine against external-source EVM cases and report the outcome.

This driver wires the unchanged discovery pipeline (hypothesis generation ->
model-guided exploration -> minimisation -> independent verification) to an
:class:`~blackheart.statespace.runtime.evm.EvmExecutionAdapter` so the search
executes real bytecode on a local EVM, then reports -- honestly -- what was found,
what was independently verified, and what the differential control says about each
hit.

The cases come from :mod:`evm_registry`: three independently-maintained external
applications (Damn Vulnerable DeFi v4.1.0, OpenZeppelin Ethernaut, and the Euler V1
lending protocol). The output is
a machine-readable report; the human report is built from it. Every number is
measured, not asserted: sequences tried, steps executed, wall-clock, the minimal
violating sequence, the verifier's verdict, and the control's behaviour.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Optional

from ...toolchain.enforce import ExecutionTarget, guarded
from ..explore import ExploreConfig, StateSpaceExplorer, run_sequence
from ..hypotheses import HypothesisGenerator
from ..verify import IndependentSequenceVerifier, VerifyConfig
from .base import ExecutionBudget, RuntimeTarget
from .evm import EvmExecutionAdapter
from .evm_registry import get_case, has_control, target_for
from .authz import LocalScope


def _evm_scope(name: str) -> LocalScope:
    return LocalScope(
        asset=name, authorized=True,
        reference="local-evm:blackheart/statespace/runtime/evm "
                  "(vendored DVDF v4.1.0 / OpenZeppelin Ethernaut / Euler V1)",
        allowed_hosts=("127.0.0.1", "::1"),
        notes="ephemeral local anvil node; external bytecode; no network, no real funds",
    )


def build_evm_target(name: str, *, control: bool = False,
                     max_operations: int = 200_000) -> tuple[EvmExecutionAdapter, RuntimeTarget]:
    case = get_case(name, control=control)
    adapter = EvmExecutionAdapter(
        case, _evm_scope(case.name),
        budget=ExecutionBudget(max_operations=max_operations),
    )
    adapter.load()
    return adapter, RuntimeTarget(adapter)


@dataclass
class EvmRunReport:
    case: str
    suite: str
    description: str
    executed: bool = False
    detected: bool = False
    sequences_tried: int = 0
    steps_executed: int = 0
    elapsed_seconds: float = 0.0
    minimal_sequence: list[dict] = field(default_factory=list)
    minimal_len: int = 0
    observed: dict[str, Any] = field(default_factory=dict)
    verdict: str = ""
    independently_verified: bool = False
    control_reproduced: Optional[bool] = None    # does the patched control also violate?
    invariant_ids: list[str] = field(default_factory=list)
    trace: list[dict] = field(default_factory=list)
    adapter: dict = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    ground_truth: str = ""
    target: str = ""
    repository: str = ""
    commit: str = ""

    def to_dict(self) -> dict:
        return {
            "case": self.case, "suite": self.suite, "description": self.description,
            "executed": self.executed, "detected": self.detected,
            "sequences_tried": self.sequences_tried, "steps_executed": self.steps_executed,
            "elapsed_seconds": self.elapsed_seconds,
            "minimal_sequence": self.minimal_sequence, "minimal_len": self.minimal_len,
            "observed": self.observed, "verdict": self.verdict,
            "independently_verified": self.independently_verified,
            "control_reproduced": self.control_reproduced,
            "invariant_ids": self.invariant_ids, "trace": self.trace,
            "adapter": self.adapter, "errors": self.errors,
            "ground_truth": self.ground_truth,
            "target": self.target, "repository": self.repository, "commit": self.commit,
        }


def run_evm_case(name: str, *, cfg: Optional[ExploreConfig] = None,
                 verify: bool = True, compatibility: object = None) -> EvmRunReport:
    """Run one EVM case under the compatibility gate, bound to the case's target."""
    target_info = target_for(name)
    identity = ExecutionTarget(name=name, repository=target_info.repository,
                               commit=target_info.commit)
    with guarded(compatibility, identity, "statespace.runtime.run_evm_case"):
        return _run_evm_case(name, cfg=cfg or ExploreConfig(), verify=verify)


def _run_evm_case(name: str, *, cfg: ExploreConfig, verify: bool) -> EvmRunReport:
    case = get_case(name)
    target_info = target_for(name)
    adapter, target = build_evm_target(name)
    report = EvmRunReport(case=case.name, suite=case.suite, description=case.description,
                          ground_truth=case.ground_truth,
                          target=target_info.project, repository=target_info.repository,
                          commit=target_info.commit)
    try:
        model = target.model()
        gen = HypothesisGenerator(model).generate()
        t0 = time.monotonic()
        explore = StateSpaceExplorer(target, cfg).explore(gen.hypotheses)
        report.elapsed_seconds = round(time.monotonic() - t0, 4)
        report.executed = True
        report.sequences_tried = explore.sequences_tried
        report.steps_executed = explore.steps_evaluated
        report.adapter = adapter.to_dict()
        report.invariant_ids = [i[0] for i in case.invariants]

        if explore.violations:
            report.detected = True
            best = min(explore.violations, key=lambda v: len(v.minimal_sequence))
            report.minimal_sequence = [s.to_dict() for s in best.minimal_sequence]
            report.minimal_len = len(best.minimal_sequence)
            report.observed = best.observed
            report.trace = _trace(adapter, target, best.minimal_sequence)

        if verify and explore.violations:
            control_factory = None
            if has_control(name):
                control_factory = lambda: build_evm_target(name, control=True)[1]
            vcfg = VerifyConfig(
                control_factory=control_factory,
                in_scope=True, scope_reference=adapter.scope.reference,
                authorization_gate_passed=adapter.scope.authorized,
            )
            verifier = IndependentSequenceVerifier(lambda: build_evm_target(name)[1], vcfg)
            best = min(explore.violations, key=lambda v: len(v.minimal_sequence))
            result = verifier.verify(best, model=model, preconditions_satisfiable=True)
            report.verdict = result.disposition
            report.independently_verified = result.disposition == "INDEPENDENTLY_VERIFIED"
            ci = result.checks.get("control_integrity")
            if ci is not None:
                report.control_reproduced = not ci[0]
    finally:
        adapter.close()
    return report


def _trace(adapter: EvmExecutionAdapter, target: RuntimeTarget,
           seq: list) -> list[dict]:
    target.reset()
    run_sequence(target, list(seq))
    return target.execution_trace()
