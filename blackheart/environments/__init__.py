"""Environment-agnostic execution: the backend adapter architecture.

BLACKHEART's research core must not assume one sandbox, chain, framework, RPC
provider, repository layout, or deployment environment. This package makes the
execution environment a **pluggable backend** behind a stable contract:

  * :mod:`~blackheart.environments.capabilities` -- explicit capability
    declarations (target types, operations, tools, evidence tier, limitations),
    validated against a fixed vocabulary.
  * :mod:`~blackheart.environments.adapter` -- the :class:`ExecutionAdapter`
    contract whose *only* public execution entry point runs the **central
    authorization gate** before any subclass hook, so no adapter can widen scope or
    silently substitute a simulation for real execution.
  * :mod:`~blackheart.environments.registry` -- capability-based routing, so the
    absence of one backend does not break a workflow another backend can serve.
  * Backends: :class:`~blackheart.environments.local_source.LocalSourceAdapter`
    (a real local repository), :class:`~blackheart.environments.http_service.HttpServiceAdapter`
    (a real read-only HTTP endpoint), and
    :class:`~blackheart.environments.sequence_model.SequenceModelAdapter`
    (a simulation over the existing invariant-engine state machine).

Support is claimed only where a backend is *probed ready* in this environment; a
capability with no ready backend is an explicit :class:`~blackheart.environments.registry.Unroutable`
limitation, never a fabricated result.
"""

from __future__ import annotations

from .adapter import (
    AdapterError,
    AdapterState,
    AuthorizationDenied,
    CapabilityError,
    ExecutionAdapter,
    Observation,
    ProbeRequest,
    ProbeResult,
)
from .capabilities import (
    EVIDENCE_TIERS,
    OPERATIONS,
    TARGET_TYPES,
    Capabilities,
    validate_declaration,
)
from .devnet import DevnetAdapter
from .http_service import HttpServiceAdapter
from .local_source import LocalSourceAdapter
from .registry import (
    EnvironmentRegistry,
    RouteDecision,
    Unroutable,
    default_registry,
)
from .sequence_model import SequenceModelAdapter

__all__ = [
    "AdapterError",
    "AdapterState",
    "AuthorizationDenied",
    "Capabilities",
    "CapabilityError",
    "DevnetAdapter",
    "EnvironmentRegistry",
    "EVIDENCE_TIERS",
    "ExecutionAdapter",
    "HttpServiceAdapter",
    "LocalSourceAdapter",
    "Observation",
    "OPERATIONS",
    "ProbeRequest",
    "ProbeResult",
    "RouteDecision",
    "SequenceModelAdapter",
    "TARGET_TYPES",
    "Unroutable",
    "default_registry",
    "validate_declaration",
]
