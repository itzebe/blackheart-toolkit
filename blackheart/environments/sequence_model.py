"""A simulation backend: the existing invariant-engine state machine as a target.

This is materially different from :mod:`blackheart.environments.local_source` -- it
does not touch a filesystem or a subprocess. It drives the *existing*
:class:`blackheart.invariants.engine.Target` protocol (``reset``/``ops``/
``invariants``/``step``/``snapshot``), which is the same model the explorer, the
certifier, the fuzzer, and the portfolio already use. Per the project's own rule,
no parallel target model is introduced: this adapter is a **transport** that
exposes a state machine to the universal research core through the common
contract.

Its evidence tier is ``simulation``. That is not a downgrade to apologise for -- it
is the honest label. A state machine can *develop* a hypothesis and can *reproduce*
a planted defect, but it is not the real target, so
:meth:`Observation.can_support_finding` is ``False`` and no finding may be confirmed
from it alone. The controller records it as simulation evidence, never as a real
exploit.

Because it owns the state object, this backend *does* support snapshot/rollback and
reset -- the state control a real remote service rarely offers.
"""

from __future__ import annotations

from typing import Any

from .adapter import (
    AdapterState,
    Capabilities,
    ExecutionAdapter,
    Observation,
    ProbeRequest,
    ProbeResult,
)


class SequenceModelAdapter(ExecutionAdapter):
    """Run operation sequences against an invariant-engine ``Target``."""

    name = "sequence-model"

    declared = Capabilities(
        target_types=("protocol-implementation", "backend-service", "source-repository"),
        operations=("inspect", "enumerate", "execute", "sequence", "reset",
                    "snapshot", "rollback", "capture"),
        network=False,
        state_control=True,
        transactions=False,
        snapshot_rollback=True,
        evidence_capture=True,
        evidence_tier="simulation",
        limitations=[
            "simulation, not the real target: a result develops a hypothesis and "
            "cannot independently prove real-world exploitability",
            "models only the operations and invariants the target declares",
            "no network, no deployment, no real assets",
        ],
        required_permissions=["an in-memory target instance"],
        safety_constraints=["state is bounded to the instance; nothing external is touched"],
    )

    def __init__(self, target: Any):
        self._target = target
        super().__init__()

    # -- probe --------------------------------------------------------- #

    def _probe(self) -> ProbeResult:
        target = self._target
        missing = [
            attr for attr in ("reset", "ops", "invariants", "step", "snapshot")
            if not callable(getattr(target, attr, None))
        ]
        if missing:
            return ProbeResult(
                state=AdapterState.MISCONFIGURED,
                detail=f"target is missing the Target protocol members: {', '.join(missing)}",
            )
        try:
            ops = target.ops()
            invs = target.invariants()
        except Exception as exc:
            return ProbeResult(
                state=AdapterState.MISCONFIGURED,
                detail=f"target.ops()/invariants() raised {type(exc).__name__}: {exc}",
            )
        if not ops:
            return ProbeResult(
                state=AdapterState.UNSUPPORTED,
                detail="target declares no operations; nothing to explore",
            )
        confirmed = Capabilities(
            target_types=self.declared.target_types,
            operations=self.declared.operations,
            tools={},
            network=False,
            state_control=True,
            transactions=False,
            snapshot_rollback=True,
            evidence_capture=True,
            evidence_tier="simulation",
            limitations=list(self.declared.limitations),
            required_permissions=list(self.declared.required_permissions),
            safety_constraints=list(self.declared.safety_constraints),
        )
        if not invs:
            confirmed.limitations.append("target declares no invariants: nothing to violate")
        return ProbeResult(
            state=AdapterState.READY,
            detail=f"{len(ops)} operations, {len(invs)} invariants",
            confirmed=confirmed,
        )

    # -- execute ------------------------------------------------------- #

    def _execute(self, request: ProbeRequest, caps: Capabilities) -> Observation:
        target = self._target
        if request.operation in ("inspect", "enumerate", "capture"):
            return self._inspect(request)

        state = target.reset()
        steps: list[dict[str, Any]] = []
        # A `sequence` request runs its ordered steps; an `execute` request runs a
        # single (op_name, actor, params) step from params.
        if request.operation == "sequence":
            plan = list(request.sequence)
        else:
            op_name = request.params.get("op") or request.params.get("op_name")
            if not op_name:
                return Observation(
                    adapter=self.name, target=request.target, operation=request.operation,
                    ok=False, evidence_tier=caps.evidence_tier,
                    error="execute requires params.op (an operation name)",
                )
            plan = ((op_name, {
                "actor": request.params.get("actor", ""),
                "params": request.params.get("params", {}) or {},
            }),)

        invariants = target.invariants()
        violated: list[str] = []
        for op_name, meta in plan:
            actor = meta.get("actor", "")
            params = meta.get("params", {}) or {}
            try:
                target.step(state, op_name, actor, params)
            except Exception as exc:
                steps.append({"op": op_name, "actor": actor, "error": f"{type(exc).__name__}: {exc}"})
                return Observation(
                    adapter=self.name, target=request.target, operation=request.operation,
                    ok=False, evidence_tier=caps.evidence_tier, steps=steps,
                    error=f"step '{op_name}' raised {type(exc).__name__}: {exc}",
                )
            broken = [inv.inv_id for inv in invariants if not inv.holds(state)]
            steps.append({"op": op_name, "actor": actor, "violated": broken})
            violated.extend(broken)

        snap = target.snapshot(state)
        return Observation(
            adapter=self.name, target=request.target, operation=request.operation,
            ok=True, evidence_tier=caps.evidence_tier, steps=steps,
            facts={"violated_invariants": sorted(set(violated)), "final_state": snap},
            raw=f"{len(plan)} step(s); violations: {sorted(set(violated)) or 'none'}",
        )

    def _inspect(self, request: ProbeRequest) -> Observation:
        target = self._target
        ops = target.ops()
        invs = target.invariants()
        facts = {
            "operations": [
                {"name": o.name, "actors": list(getattr(o, "actors", [])),
                 "description": getattr(o, "description", "")}
                for o in ops
            ],
            "invariants": [
                {"inv_id": i.inv_id, "title": getattr(i, "title", ""),
                 "severity": getattr(i, "severity_if_broken", "")}
                for i in invs
            ],
        }
        return Observation(
            adapter=self.name, target=request.target, operation=request.operation,
            ok=True, evidence_tier="simulation", facts=facts,
            raw=f"{len(ops)} operations, {len(invs)} invariants",
        )
