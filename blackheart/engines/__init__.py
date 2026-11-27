"""The engine integration layer: adapters for external offensive engines.

BLACKHEART is the control plane. This package lets it *drive* three external
engines (Strix, Shannon, PentAGI) as capability providers without ever letting
them bypass BLACKHEART's authorization, scope, or verification gates.

Layout:

  * :mod:`blackheart.engines.contract` -- the adapter contract, the bounded
    process runner, and the honest :class:`~blackheart.engines.contract.EngineState`
    vocabulary shared by every adapter.
  * :mod:`blackheart.engines.schema` -- the unified, engine-independent finding
    schema every adapter normalises into.
  * :mod:`blackheart.engines.strix` / ``shannon`` / ``pentagi`` -- the adapters.
  * :mod:`blackheart.engines.orchestrator` -- cross-engine coordination
    (deduplication, corroboration, contradiction, attack-chain correlation) and
    the BLACKHEART final verdict.

A core principle: **an engine's output is untrusted candidate evidence.** No
adapter can confirm a finding, change authorization, widen scope, submit a
report, or broadcast a transaction. Those remain BLACKHEART's alone.
"""

from __future__ import annotations

from .contract import (
    Capability,
    EngineAdapter,
    EngineCancelled,
    EngineError,
    EngineState,
    EngineTimeout,
    EngineUnavailable,
    ExecutionMetadata,
    ExecutionResult,
    Health,
    run_bounded,
    redact_secrets,
)
from .schema import NormalizedFinding, normalize_severity, normalize_cwe, normalize_cvss

__all__ = [
    "Capability",
    "EngineAdapter",
    "EngineCancelled",
    "EngineError",
    "EngineState",
    "EngineTimeout",
    "EngineUnavailable",
    "ExecutionMetadata",
    "ExecutionResult",
    "Health",
    "run_bounded",
    "redact_secrets",
    "NormalizedFinding",
    "normalize_severity",
    "normalize_cwe",
    "normalize_cvss",
    "ENGINE_ADAPTERS",
    "SOLIDITY_ENGINES",
    "get_adapter",
    "list_engines",
]


# The adapters, imported lazily in get_adapter so importing the package never
# requires any optional engine dependency.
ENGINE_ADAPTERS: dict[str, str] = {
    "strix": "blackheart.engines.strix:StrixAdapter",
    "shannon": "blackheart.engines.shannon:ShannonAdapter",
    "pentagi": "blackheart.engines.pentagi:PentAGIAdapter",
    # Local Solidity analysis engines. They implement the same contract, so the
    # orchestrator's dedup / corroboration / no-self-promotion gates apply to
    # them unchanged.
    "slither": "blackheart.engines.solidity.slither:SlitherAdapter",
    "wake": "blackheart.engines.solidity.wake:WakeAdapter",
    "halmos": "blackheart.engines.solidity.halmos:HalmosAdapter",
    "echidna": "blackheart.engines.solidity.echidna:EchidnaAdapter",
    "medusa": "blackheart.engines.solidity.medusa:MedusaAdapter",
}

#: Engines that analyse Solidity source locally, in the doctrine's order.
SOLIDITY_ENGINES: tuple[str, ...] = ("slither", "wake", "halmos", "echidna", "medusa")


def get_adapter(name: str, workspace, *, config=None) -> EngineAdapter:
    """Construct the adapter for ``name`` (``KeyError`` for an unknown engine)."""
    import importlib

    target = ENGINE_ADAPTERS.get(name.lower())
    if target is None:
        raise KeyError(f"unknown engine: {name!r} (known: {', '.join(ENGINE_ADAPTERS)})")
    module_name, cls_name = target.split(":")
    cls = getattr(importlib.import_module(module_name), cls_name)
    return cls(workspace, config=config)


def list_engines() -> list[str]:
    return list(ENGINE_ADAPTERS)
