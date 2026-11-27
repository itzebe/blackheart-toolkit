"""The backend registry: how the research core reaches *an* environment, not one.

The core never imports a concrete backend. It asks
:class:`EnvironmentRegistry` for a backend that declares the target type and the
operation a probe needs, and the registry returns a *ready* backend -- one whose
probe succeeded -- or an explicit refusal naming why nothing could serve the probe.

This is what makes the absence of one sandbox non-fatal. Removing the local-source
backend does not break an HTTP workflow, and removing the HTTP backend does not
break a local one; each probe is routed to whatever backend can actually do it. When
*no* backend can, the probe is reported ``UNROUTABLE`` with the reason -- never
silently simulated into a false result.

Selection is deterministic (registration order) so a run is reproducible, and a
backend marked ``DISABLED`` or un-probed is never selected.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .adapter import AdapterError, AdapterState, ExecutionAdapter, ProbeResult


class Unroutable(AdapterError):
    """No ready backend can serve a probe. Raised so the caller records a gap."""


@dataclass
class RouteDecision:
    """Why a probe was (or was not) routed to a backend."""

    target_type: str
    operation: str
    required_tool: str = ""
    chosen: str = ""
    reason: str = ""
    #: Every backend considered, and why it was rejected when it was.
    considered: list[dict] = field(default_factory=list)

    @property
    def routed(self) -> bool:
        return bool(self.chosen)

    def to_dict(self) -> dict:
        return {
            "target_type": self.target_type, "operation": self.operation,
            "required_tool": self.required_tool,
            "chosen": self.chosen, "routed": self.routed, "reason": self.reason,
            "considered": list(self.considered),
        }


class EnvironmentRegistry:
    """An ordered set of execution backends, selectable by capability."""

    def __init__(self) -> None:
        self._adapters: list[ExecutionAdapter] = []
        self._disabled: set[str] = set()

    # -- registration -------------------------------------------------- #

    def register(self, adapter: ExecutionAdapter, *, enabled: bool = True) -> None:
        self._adapters.append(adapter)
        if not enabled:
            self._disabled.add(adapter.name)

    def disable(self, name: str) -> None:
        """Turn a backend off without deleting it (proves others keep working)."""
        self._disabled.add(name)

    def adapters(self) -> list[ExecutionAdapter]:
        return list(self._adapters)

    def ready_adapters(self) -> list[ExecutionAdapter]:
        return [a for a in self._adapters
                if a.name not in self._disabled and a.state is AdapterState.READY]

    def probe_all(self) -> list[ProbeResult]:
        return [a.probe() for a in self._adapters]

    # -- routing ------------------------------------------------------- #

    def route(self, target_type: str, operation: str, *,
              required_tool: str = "") -> RouteDecision:
        """Decide which backend should serve a probe, deterministically.

        ``required_tool`` is the caller's declared dependency (for example
        ``go``). A backend that did not confirm it on this host is rejected, so
        a route cannot promise an execution the host cannot perform.
        """
        decision = RouteDecision(target_type=target_type, operation=operation,
                                 required_tool=required_tool)
        for adapter in self._adapters:
            if adapter.name in self._disabled:
                decision.considered.append(
                    {"adapter": adapter.name, "rejected": "disabled"}
                )
                continue
            if adapter.state is not AdapterState.READY:
                decision.considered.append(
                    {"adapter": adapter.name, "rejected": f"state={adapter.state.value}"}
                )
                continue
            caps = adapter.capabilities()
            if not caps.supports_target(target_type):
                decision.considered.append(
                    {"adapter": adapter.name, "rejected": f"no target type '{target_type}'"}
                )
                continue
            if not caps.supports_operation(operation):
                decision.considered.append(
                    {"adapter": adapter.name, "rejected": f"no operation '{operation}'"}
                )
                continue
            if required_tool and not caps.tools.get(required_tool):
                decision.considered.append(
                    {"adapter": adapter.name,
                     "rejected": f"required tool '{required_tool}' not confirmed"}
                )
                continue
            decision.chosen = adapter.name
            decision.reason = (
                f"{adapter.name} declares '{target_type}' + '{operation}' "
                f"(evidence tier: {caps.evidence_tier})"
            )
            return decision
        decision.reason = (
            f"no ready backend declares '{target_type}' + '{operation}'"
        )
        return decision

    def resolve(self, target_type: str, operation: str, *,
                required_tool: str = "") -> ExecutionAdapter:
        """Return the chosen backend or raise :class:`Unroutable` with the reason."""
        decision = self.route(target_type, operation, required_tool=required_tool)
        if not decision.routed:
            reachable = sorted(a.name for a in self.ready_adapters())
            raise Unroutable(
                f"{decision.reason}; ready backends: {', '.join(reachable) or 'none'}"
            )
        return self._by_name(decision.chosen)

    def _by_name(self, name: str) -> ExecutionAdapter:
        for adapter in self._adapters:
            if adapter.name == name:
                return adapter
        raise Unroutable(f"unknown backend '{name}'")

    # -- introspection ------------------------------------------------- #

    def capability_matrix(self) -> dict:
        """Every backend's state and confirmed capabilities, for the operator."""
        return {
            a.name: {
                "state": a.state.value,
                "enabled": a.name not in self._disabled,
                "capabilities": a.capabilities().to_dict(),
            }
            for a in self._adapters
        }

    def can_prove_real_execution(self) -> bool:
        """True when at least one ready backend can prove real execution."""
        return any(a.capabilities().can_prove_real_execution()
                   for a in self.ready_adapters())


def default_registry(root: str = "", *, allow_hosts: tuple[str, ...] = (),
                     devnet_compose: str = "") -> EnvironmentRegistry:
    """Build a registry of the real backends available without configuration.

    A source backend is registered only when a readable repository path is given;
    the HTTP backend is always registered (it needs no path). Neither is *probed*
    here -- the caller probes, so readiness reflects this host at run time.
    """
    from .devnet import DevnetAdapter
    from .http_service import HttpServiceAdapter
    from .local_source import LocalSourceAdapter

    reg = EnvironmentRegistry()
    if root:
        reg.register(LocalSourceAdapter(root))
    if devnet_compose:
        reg.register(DevnetAdapter(devnet_compose))
    reg.register(HttpServiceAdapter(allow_hosts=allow_hosts))
    return reg
