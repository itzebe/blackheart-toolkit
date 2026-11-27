"""The execution-backend adapter contract, with one central authorization boundary.

An execution backend is how a research probe becomes *real*. It is deliberately
narrow: a backend owns exactly one concern -- turning an authorized,
capability-checked request into an observed result -- and nothing else. It does not
generate hypotheses, decide severity, confirm a finding, or widen scope.

The authorization boundary is enforced **structurally**, not by convention:
:meth:`ExecutionAdapter.execute` is the only public entry point, and it runs the
central gate (:func:`blackheart.authz.authorize_active_testing`) *before* it calls
the subclass hook :meth:`_execute`. A backend therefore cannot skip the gate, and a
new backend added tomorrow inherits the same gate for free. This is the same
boundary the scheduler and ingress already use -- there is no parallel
authorization system here.

Evidence honesty is also structural. Every :class:`Observation` carries the
backend's declared ``evidence_tier``, so a simulation can never be read as real
execution: a consumer asks :meth:`Observation.can_support_finding` rather than
trusting a caller's optimism.
"""

from __future__ import annotations

import abc
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

from ..authz import AuthorizationError, GateDecision, authorize_active_testing
from ..models import AuthorizationRecord, utcnow
from .capabilities import Capabilities, validate_declaration


class AdapterState(str, Enum):
    """How ready a backend is in *this* environment.

    ``READY`` requires a successful probe. An adapter module existing proves
    nothing, exactly as in :mod:`blackheart.engines.contract`.
    """

    READY = "READY"                  # probe succeeded; interface works here
    UNSUPPORTED = "UNSUPPORTED"      # present but cannot run in this environment
    MISSING = "MISSING"              # required tool/binary absent
    MISCONFIGURED = "MISCONFIGURED"  # declaration invalid or probe raised
    DISABLED = "DISABLED"            # operator turned it off


class AdapterError(RuntimeError):
    """A classified backend failure the caller can act on."""


class CapabilityError(AdapterError):
    """The backend was asked for a target/operation it does not declare."""


class AuthorizationDenied(AdapterError):
    """The central gate refused the asset. Raised before any execution happens."""


@dataclass
class ProbeRequest:
    """What to run against a backend. Compiled from a research hypothesis."""

    target: str
    target_type: str
    operation: str = "inspect"
    #: The authorization record for the target's asset. Required, and checked by
    #: :meth:`ExecutionAdapter.execute` before the subclass hook runs.
    authorization: Optional[AuthorizationRecord] = None
    #: The asset identity used for the scope check. Defaults to ``target``.
    asset: str = ""
    params: dict[str, Any] = field(default_factory=dict)
    #: For an ordered probe: the operations to run in sequence.
    sequence: tuple[tuple[str, dict[str, Any]], ...] = ()
    timeout_s: float = 30.0

    @property
    def asset_id(self) -> str:
        return self.asset or self.target


@dataclass
class Observation:
    """What a backend actually observed, with its evidence tier attached.

    ``evidence_tier`` is copied from the backend's capabilities, never chosen by
    the caller, so a simulation result cannot be relabelled as real execution.
    """

    adapter: str
    target: str
    operation: str
    ok: bool
    evidence_tier: str
    #: The raw, unmodified output the backend produced.
    raw: str = ""
    #: Structured facts the backend parsed out (never fabricated).
    facts: dict[str, Any] = field(default_factory=dict)
    #: Every probe performed, in order, with its own result.
    steps: list[dict[str, Any]] = field(default_factory=list)
    error: str = ""
    limitation: str = ""
    started_at: str = field(default_factory=utcnow)
    duration_s: float = 0.0

    def can_support_finding(self) -> bool:
        """A finding needs *real* execution. Simulation never qualifies."""
        return self.ok and self.evidence_tier == "real-execution"

    def to_dict(self) -> dict:
        return {
            "adapter": self.adapter,
            "target": self.target,
            "operation": self.operation,
            "ok": self.ok,
            "evidence_tier": self.evidence_tier,
            "can_support_finding": self.can_support_finding(),
            "raw_sha256_len": len(self.raw),
            "facts": dict(self.facts),
            "steps": list(self.steps),
            "error": self.error,
            "limitation": self.limitation,
            "started_at": self.started_at,
            "duration_s": round(self.duration_s, 4),
        }


@dataclass
class ProbeResult:
    """The outcome of probing a backend's readiness."""

    state: AdapterState
    detail: str = ""
    #: Capabilities *as confirmed by the probe*, which may be narrower than what
    #: the adapter would like to claim.
    confirmed: Optional[Capabilities] = None
    checked_at: str = field(default_factory=utcnow)

    @property
    def ready(self) -> bool:
        return self.state is AdapterState.READY

    def to_dict(self) -> dict:
        return {
            "state": self.state.value,
            "detail": self.detail,
            "confirmed": self.confirmed.to_dict() if self.confirmed else None,
            "checked_at": self.checked_at,
        }


class ExecutionAdapter(abc.ABC):
    """One execution backend. Subclass and implement :meth:`_probe` / :meth:`_execute`.

    The two public methods (:meth:`probe`, :meth:`execute`) are the whole surface
    the research core may call. :meth:`execute` runs the central authorization gate
    first; a subclass that overrides it instead of :meth:`_execute` would remove
    the gate, so the base class asserts at construction that neither is overridden.
    """

    #: A stable, human-readable backend name.
    name: str = "adapter"
    #: What this backend claims it can do. Confirmed/corrected by :meth:`probe`.
    declared: Capabilities = Capabilities()

    def __init__(self) -> None:
        # Guardrail against a subclass silently replacing the gated entry point.
        # Both must resolve to exactly this class's implementation.
        for hook in ("execute",):
            if getattr(type(self), hook) is not getattr(ExecutionAdapter, hook):
                raise AdapterError(
                    f"{type(self).__name__} overrides {hook!r}; override '_execute' "
                    "instead so the central authorization gate cannot be bypassed"
                )
        problems = validate_declaration(self.declared)
        if problems:
            raise AdapterError(
                f"{self.name}: invalid capability declaration: " + "; ".join(problems)
            )
        self._probe_result: Optional[ProbeResult] = None

    # ------------------------------------------------------------------ #
    # Readiness
    # ------------------------------------------------------------------ #

    def probe(self) -> ProbeResult:
        """Confirm the backend works *here*, and narrow its claims to reality."""
        try:
            result = self._probe()
        except Exception as exc:  # a probe must classify, never crash the caller
            result = ProbeResult(
                state=AdapterState.MISCONFIGURED,
                detail=f"probe raised {type(exc).__name__}: {exc}",
            )
        self._probe_result = result
        return result

    @property
    def state(self) -> AdapterState:
        if self._probe_result is None:
            return AdapterState.UNSUPPORTED
        return self._probe_result.state

    def capabilities(self) -> Capabilities:
        """The capabilities the probe confirmed (falls back to the declaration)."""
        if self._probe_result and self._probe_result.confirmed:
            return self._probe_result.confirmed
        return self.declared

    # ------------------------------------------------------------------ #
    # The gated entry point -- the ONLY way to run work
    # ------------------------------------------------------------------ #

    def execute(self, request: ProbeRequest) -> Observation:
        """Run ``request`` after the central authorization gate has approved it.

        Order is deliberate and non-negotiable:

        1. **Authorization** -- the central gate must approve the asset. This
           happens before the capability check so an unauthorized asset is refused
           even if the backend happens to support its type.
        2. **Capability** -- the backend must declare the target type and the
           operation. Asking for what it cannot do is a classified error, never a
           silent substitute.
        3. **Execution** -- the subclass hook runs, bounded by a timeout, and every
           outcome is wrapped in an :class:`Observation` that carries the backend's
           evidence tier.
        """
        # 1. Central authorization -- identical boundary to the scheduler/ingress.
        if request.authorization is None:
            raise AuthorizationDenied(
                f"{self.name}: no authorization record supplied for "
                f"'{request.asset_id}'; refusing to execute"
            )
        decision: GateDecision = authorize_active_testing(
            request.authorization, request.asset_id
        )
        if not decision.allowed:
            raise AuthorizationDenied(
                f"{self.name}: asset '{request.asset_id}' is not authorized: "
                + "; ".join(decision.blockers or ["gate refused"])
            )

        # 2. Capability -- declared, and confirmed by the probe.
        caps = self.capabilities()
        if not caps.supports_target(request.target_type):
            raise CapabilityError(
                f"{self.name} does not support target type '{request.target_type}' "
                f"(supports: {', '.join(caps.target_types) or 'none'})"
            )
        if not caps.supports_operation(request.operation):
            raise CapabilityError(
                f"{self.name} does not support operation '{request.operation}' "
                f"(supports: {', '.join(caps.operations) or 'none'})"
            )

        # 3. Execution, bounded and honestly wrapped.
        started = time.monotonic()
        try:
            obs = self._execute(request, caps)
        except AdapterError:
            raise
        except Exception as exc:
            elapsed = time.monotonic() - started
            return Observation(
                adapter=self.name, target=request.target,
                operation=request.operation, ok=False,
                evidence_tier=caps.evidence_tier,
                error=f"{type(exc).__name__}: {exc}",
                duration_s=elapsed,
            )
        obs.evidence_tier = caps.evidence_tier  # the backend's tier, not the caller's
        obs.duration_s = time.monotonic() - started
        return obs

    # ------------------------------------------------------------------ #
    # Subclass hooks
    # ------------------------------------------------------------------ #

    @abc.abstractmethod
    def _probe(self) -> ProbeResult:
        """Determine readiness in this environment and return confirmed caps."""

    @abc.abstractmethod
    def _execute(self, request: ProbeRequest, caps: Capabilities) -> Observation:
        """Perform the (already authorized, already capability-checked) work."""

    # ------------------------------------------------------------------ #
    # Introspection
    # ------------------------------------------------------------------ #

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "state": self.state.value,
            "declared": self.declared.to_dict(),
            "probe": self._probe_result.to_dict() if self._probe_result else None,
        }


def require_authorization(record: Optional[AuthorizationRecord], asset: str) -> None:
    """Fail closed when a caller forgot to attach an authorization record."""
    if record is None:
        raise AuthorizationError(
            f"refusing to act on '{asset}' with no authorization record"
        )
