"""The execution-adapter interface: abstract vs fixture vs actual operations.

The state-space engine's ``SequenceTarget`` protocol runs an operation against an
in-memory fixture. This module introduces the *execution* contract the mission
requires: a target whose operations are actually carried out against a running
application, with the results, the before/after state, and every failure recorded
as independently inspectable evidence.

Three kinds of "operation" exist and must never be conflated:

  * **abstract** -- an operation named in a :class:`SystemModel`; it is a claim
    about intended behaviour, not something that runs.
  * **fixture** -- an operation carried out against a local in-memory object.
  * **executed** -- an operation actually dispatched to a running application, and
    whose result was observed.

The mission forbids reporting an abstract or fixture operation as an executed one,
so the provenance is explicit and travels with every result (:class:`ExecRecord`
carries ``provenance``). The adapters here are *real*: they dispatch HTTP requests
to a loopback application and record what the application actually did.

Scope and isolation are enforced *before* execution, in :meth:`ExecutionAdapter.
authorize` (fail-closed), not merely at reporting time. The loopback HTTP adapter
refuses any non-loopback host, refuses to follow redirects, and refuses to reach
cloud-metadata addresses; the base class enforces operation and time budgets.

Nothing here is a network scanner: the adapters only ever talk to a target the
caller explicitly loaded and authorized.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional, Protocol

from ..model import SystemModel


# --------------------------------------------------------------------------- #
# Provenance and result vocabulary
# --------------------------------------------------------------------------- #

#: How an operation was actually carried out. Ordered weakest -> strongest.
PROVENANCE = ("abstract", "fixture", "executed")


class ExecutionError(RuntimeError):
    """A target could not be executed (unreachable, refused, or unsafe to try)."""


class ScopeError(ExecutionError):
    """Execution was refused because the target is not authorized/in scope."""


@dataclass
class ExecRecord:
    """The observed result of one executed operation -- the unit of evidence.

    ``provenance`` is one of :data:`PROVENANCE`. Only ``"executed"`` means the
    operation was really dispatched to a running application; ``"fixture"`` and
    ``"abstract"`` records are kept in the same shape so a trace is uniform, but
    they are never presented as execution.
    """

    index: int
    actor: str
    operation: str
    params: dict[str, Any] = field(default_factory=dict)
    provenance: str = "executed"          # abstract | fixture | executed
    transport: str = ""                   # "http" | "fixture" | "" ...
    # observed outcome
    status: str = ""                      # "ok" | "rejected" | "partial" | "error" | "timeout"
    accepted: Optional[bool] = None       # did the target accept the operation?
    http_status: Optional[int] = None
    error: str = ""                       # an error/exception message (redacted)
    latency_ms: float = 0.0
    before: dict[str, Any] = field(default_factory=dict)
    after: dict[str, Any] = field(default_factory=dict)
    violated: list[str] = field(default_factory=list)   # invariant ids broken by this step
    response: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "index": self.index,
            "actor": self.actor,
            "operation": self.operation,
            "params": dict(self.params),
            "provenance": self.provenance,
            "transport": self.transport,
            "status": self.status,
            "accepted": self.accepted,
            "http_status": self.http_status,
            "error": self.error,
            "latency_ms": self.latency_ms,
            "before": dict(self.before),
            "after": dict(self.after),
            "violated": list(self.violated),
            "response": dict(self.response),
        }


#: The mission's per-step outcome vocabulary.
STEP_OUTCOMES = (
    "rejected",            # the target refused the operation (e.g. 401/403/409)
    "success",             # the operation completed and was accepted
    "partial_failure",     # the operation half-completed (2xx but an error field / partial write)
    "unexpected_state",    # the operation succeeded but the state moved unexpectedly
    "invariant_violation",  # the operation left a stated invariant broken
    "unverified",          # we could not establish the outcome
)


# --------------------------------------------------------------------------- #
# The adapter protocol
# --------------------------------------------------------------------------- #

class ExecutionAdapter(Protocol):
    """A controlled, authorized executable target the engine can drive.

    Implementations must enforce scope *before* dispatching an operation and must
    record real observed evidence. They must never fabricate a result.
    """

    name: str

    def load(self) -> None: ...
    def model(self) -> SystemModel: ...
    def identities(self) -> list[str]: ...
    def operations(self) -> list[str]: ...
    def reset(self) -> None: ...
    def execute(self, operation: str, actor: str, params: dict[str, Any]) -> ExecRecord: ...
    def snapshot(self) -> dict[str, Any]: ...
    def invariants(self) -> list[Any]: ...
    def close(self) -> None: ...
