"""Executable-target adapters for the state-space engine.

The engine's core pipeline (``SystemModel`` -> ``HypothesisGenerator`` ->
``StateSpaceExplorer`` -> ``IndependentSequenceVerifier``) runs unchanged over a
real application through these adapters. The distinction the mission requires is
explicit and travels with every result:

  * **abstract** -- an operation named in a ``SystemModel``; a claim, not a run.
  * **fixture**  -- an operation carried out against a local in-memory object.
  * **executed** -- an operation actually dispatched to a running application and
    observed (:class:`~blackheart.statespace.runtime.interface.ExecRecord`).

Scope is enforced before execution, fail-closed, by
:class:`~blackheart.statespace.runtime.authz.LocalScope`; the loopback HTTP
adapter refuses non-loopback hosts and never follows a redirect.
"""

from __future__ import annotations

from .authz import LocalScope, from_authorization_record, local_harness_scope
from .base import BaseExecutionAdapter, ExecutionBudget, RuntimeTarget, redact
from .execute import (
    RuntimeReport,
    adapter_report,
    build_http_target,
    run_runtime_discovery,
)
from .harness_apps import APP_PAIRS, DEVELOPMENT_APPS, HELDOUT_APPS, app_names, make_app
from .harness_server import HarnessServer, serve
from .http_adapter import HttpExecutionAdapter
from .research import (
    RESEARCH_STATUS,
    ResearchNote,
    research_finding,
    research_findings,
)
from .interface import (
    PROVENANCE,
    STEP_OUTCOMES,
    ExecRecord,
    ExecutionAdapter,
    ExecutionError,
    ScopeError,
)

__all__ = [
    # interface
    "ExecRecord", "ExecutionAdapter", "ExecutionError", "ScopeError",
    "PROVENANCE", "STEP_OUTCOMES",
    # authz
    "LocalScope", "local_harness_scope", "from_authorization_record",
    # base
    "BaseExecutionAdapter", "ExecutionBudget", "RuntimeTarget", "redact",
    # http
    "HttpExecutionAdapter",
    # harness
    "HarnessServer", "serve", "APP_PAIRS", "DEVELOPMENT_APPS", "HELDOUT_APPS",
    "app_names", "make_app",
    # execute
    "RuntimeReport", "run_runtime_discovery", "build_http_target", "adapter_report",
    # research
    "ResearchNote", "research_finding", "research_findings", "RESEARCH_STATUS",
]
