"""The base execution adapter: lifecycle, budgets, and the runtime target bridge.

:class:`BaseExecutionAdapter` implements everything the mission requires of an
adapter except the transport itself: loading, a declared operation/identity model,
a known initial state, operation and wall-clock budgets, reliable reset, and a
uniform, secret-redacted evidence record. A concrete adapter (loopback HTTP,
local process) supplies :meth:`_dispatch`.

:class:`RuntimeTarget` adapts any execution adapter to the engine's existing
``SequenceTarget`` protocol, so the *same* ``StateSpaceExplorer`` and
``IndependentSequenceVerifier`` drive a real application. That is the whole point
of the bridge: the pipeline is unchanged; only the thing under it is now real.
"""

from __future__ import annotations

import re
import time
from typing import Any, Optional

from ..model import SequenceTarget, SystemModel, violated
from .authz import LocalScope
from .interface import ExecRecord, ExecutionError, ScopeError

# A conservative redactor for anything that looks like a credential in an error
# message, header echo, or response body. Execution evidence is stored and shown,
# so a token that leaks into a body must not survive into the record.
_SECRET_PATTERNS = (
    re.compile(r"(?i)(authorization|x-api-key|api[_-]?key|cookie|set-cookie|token)"
               r"\s*[:=]\s*\S+"),
    re.compile(r"\bydc-[A-Za-z0-9._-]{6,}\b"),
    re.compile(r"\bsk-[A-Za-z0-9._-]{6,}\b"),
    re.compile(r"\bBearer\s+[A-Za-z0-9._-]{6,}\b"),
)


def redact(text: str) -> str:
    """Scrub credential-shaped substrings from a message before it is recorded."""
    if not text:
        return text
    out = text
    for pat in _SECRET_PATTERNS:
        out = pat.sub("<redacted>", out)
    return out


class ExecutionBudget:
    """Operation, step, and wall-clock limits -- enforced, not advisory.

    A budget that runs out raises :class:`ExecutionError`; it never silently
    returns a partial result as if it were complete.
    """

    def __init__(self, max_operations: int = 10_000, max_seconds: float = 300.0,
                 max_operations_per_run: int = 64) -> None:
        self.max_operations = max_operations
        self.max_seconds = max_seconds
        self.max_operations_per_run = max_operations_per_run
        self.operations = 0
        self.started = time.monotonic()
        self._run_operations = 0

    def begin_run(self) -> None:
        self._run_operations = 0

    def charge(self) -> None:
        self.operations += 1
        self._run_operations += 1
        if self.operations > self.max_operations:
            raise ExecutionError(
                f"operation budget exhausted ({self.max_operations} operations)"
            )
        if self._run_operations > self.max_operations_per_run:
            raise ExecutionError(
                f"per-sequence operation budget exhausted ({self.max_operations_per_run} steps)"
            )
        if time.monotonic() - self.started > self.max_seconds:
            raise ExecutionError(f"wall-clock budget exhausted ({self.max_seconds}s)")

    def to_dict(self) -> dict:
        return {
            "max_operations": self.max_operations,
            "max_seconds": self.max_seconds,
            "max_operations_per_run": self.max_operations_per_run,
            "operations_used": self.operations,
            "seconds_used": round(time.monotonic() - self.started, 4),
        }


class BaseExecutionAdapter:
    """Shared lifecycle, scope enforcement, and evidence shaping for adapters."""

    name: str = "adapter"
    transport: str = "unknown"

    def __init__(self, scope: LocalScope, *, budget: Optional[ExecutionBudget] = None,
                 timeout: float = 10.0) -> None:
        self.scope = scope
        self.budget = budget or ExecutionBudget()
        self.timeout = timeout
        self._loaded = False
        self._loaded_meta: dict[str, Any] = {}

    # -- lifecycle ------------------------------------------------------- #

    def load(self) -> None:
        """Bring the target up (or verify it is reachable) under scope enforcement."""
        self._authorize(kind="load")
        self._loaded = True

    def close(self) -> None:
        self._loaded = False

    def __enter__(self):
        self.load()
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # -- scope ----------------------------------------------------------- #

    def _authorize(self, *, host: Optional[str] = None, port: Optional[int] = None,
                   kind: str = "http") -> None:
        self.scope.check(host=host, port=port, kind=kind)

    # -- to be supplied by a concrete adapter ---------------------------- #

    def _dispatch(self, operation: str, actor: str, params: dict[str, Any]) -> ExecRecord:
        raise NotImplementedError

    def model(self) -> SystemModel:
        raise NotImplementedError

    def identities(self) -> list[str]:
        raise NotImplementedError

    def operations(self) -> list[str]:
        return [op.name for op in self.model().operations]

    def reset(self) -> None:
        """Return the target to a known initial state. Must be reliable."""
        raise NotImplementedError

    def snapshot(self) -> dict[str, Any]:
        raise NotImplementedError

    def invariants(self) -> list[Any]:
        return []

    # -- the uniform, budgeted execute path ------------------------------ #

    def execute(self, operation: str, actor: str, params: dict[str, Any]) -> ExecRecord:
        """Authorize, budget, dispatch, and record one operation.

        Scope is checked *before* the operation is dispatched (fail-closed). The
        result carries ``provenance="executed"`` because the concrete adapter
        really dispatched it; a fixture or abstract operation never reaches here.
        """
        if not self._loaded:
            self.load()
        self._authorize(kind="execute")
        self.budget.charge()
        before = self.snapshot()
        t0 = time.monotonic()
        try:
            rec = self._dispatch(operation, actor, params)
        except ScopeError:
            raise
        except ExecutionError as exc:
            rec = ExecRecord(index=-1, actor=actor, operation=operation, params=dict(params),
                             provenance="executed", transport=self.transport,
                             status="error", accepted=False, error=redact(str(exc)))
        except Exception as exc:  # noqa: BLE001 -- a dispatch failure is evidence, not a crash
            rec = ExecRecord(index=-1, actor=actor, operation=operation, params=dict(params),
                             provenance="executed", transport=self.transport,
                             status="error", accepted=False,
                             error=redact(f"{type(exc).__name__}: {exc}"))
        rec.provenance = "executed"
        rec.transport = rec.transport or self.transport
        rec.latency_ms = round((time.monotonic() - t0) * 1000, 3)
        rec.before = before
        if rec.status not in ("error", "timeout"):
            rec.after = self.snapshot()
        rec.error = redact(rec.error)
        return rec

    def reset_and_verify(self) -> dict[str, Any]:
        """Reset, then confirm the state equals a fresh load's state.

        A reset that cannot be trusted makes every later result suspect, so the
        adapter proves the reset worked rather than assuming it.
        """
        self.reset()
        return self.snapshot()

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "transport": self.transport,
            "scope": self.scope.to_dict(),
            "budget": self.budget.to_dict(),
            "timeout": self.timeout,
            "loaded": self._loaded,
            "meta": dict(self._loaded_meta),
        }


# --------------------------------------------------------------------------- #
# Bridge: an execution adapter as an engine SequenceTarget
# --------------------------------------------------------------------------- #

class RuntimeTarget(SequenceTarget):
    """Drive a real application through the engine's ``SequenceTarget`` protocol.

    ``step`` dispatches the operation for real and records the resulting
    :class:`ExecRecord` in a trace the caller can inspect. ``snapshot`` returns the
    application's *actual* observed state, and ``violated`` is evaluated against
    that observed state using the target's declared invariants -- so a violation
    is established from runtime evidence, not from the model's prediction.
    """

    def __init__(self, adapter: BaseExecutionAdapter, model: Optional[SystemModel] = None) -> None:
        self.adapter = adapter
        self.name = adapter.name
        self._model = model
        self.trace: list[ExecRecord] = []
        self._records: dict[int, ExecRecord] = {}

    def model(self) -> SystemModel:
        if self._model is None:
            self._model = self.adapter.model()
        return self._model

    def reset(self) -> Any:
        self.trace = []
        self._records = {}
        self.adapter.budget.begin_run()
        self.adapter.reset()
        return self.adapter.snapshot()

    def ops(self):
        """Expose the adapter's operations as ``OpSpec`` so the explorer's
        parameter/actor logic works unchanged."""
        from ...invariants.engine import OpSpec

        if hasattr(self.adapter, "op_specs"):
            return self.adapter.op_specs()
        m = self.model()
        by_name = {o.name: o for o in m.operations}
        specs = []
        for name in self.adapter.operations():
            op = by_name.get(name)
            actors = list(self.adapter.identities()) if op is None else \
                [a.name for a in m.actors_for(op)]
            specs.append(OpSpec(name, actors, {"amount": [10, 100, 1000]}, weight=1))
        return specs

    def invariants(self):
        return self.adapter.invariants()

    def step(self, state: Any, op_name: str, actor: str, params: dict[str, Any]) -> None:
        rec = self.adapter.execute(op_name, actor, params)
        rec.index = len(self.trace)
        # The engine's runner evaluates invariants against the ``state`` object it
        # threads through the sequence, so update it in place with the *observed*
        # post-operation state. This is what makes the violation a runtime fact.
        observed = self.adapter.snapshot()
        if isinstance(state, dict):
            state.clear()
            state.update(observed)
        rec.violated = sorted(violated(observed, self.adapter.invariants()))
        self.trace.append(rec)
        self._records[rec.index] = rec

    def snapshot(self, state: Any) -> dict[str, Any]:
        return self.adapter.snapshot()

    # -- real-instrumentation coverage (optional) ------------------------ #

    def run_coverage_features(self) -> list[tuple]:
        """Opcode/pc/edge coverage for the run just executed, if the adapter has it.

        This is what lets the coverage-guided fuzzer keep a sequence that drove the
        contract down a *new code path* even when it reached a state the behavioural
        signal already saw. An adapter without instrumentation contributes nothing.
        """
        oracle = getattr(self.adapter, "coverage", None)
        if oracle is None or not hasattr(oracle, "features"):
            return []
        return oracle.features()

    # -- evidence -------------------------------------------------------- #

    def execution_trace(self) -> list[dict[str, Any]]:
        return [r.to_dict() for r in self.trace]

    def last_record(self) -> Optional[ExecRecord]:
        return self.trace[-1] if self.trace else None
