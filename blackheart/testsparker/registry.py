"""Adapter registry: one place that knows which TestSparker adapters exist.

Kept tiny on purpose. A registry that imports every adapter eagerly would couple
the evaluator to an adapter's dependencies (a live-RPC adapter would drag its
client in). Instead each entry is a lazy factory, so asking for the adapter list
costs nothing and asking for one adapter costs only that adapter.
"""

from __future__ import annotations

from typing import Callable

__all__ = ["adapter_names", "get_adapter"]

_FACTORIES: dict[str, Callable[[], object]] = {}


def _register() -> None:
    if _FACTORIES:
        return
    from .dispatch import DispatchSparker

    _FACTORIES["dispatch"] = DispatchSparker


def adapter_names() -> list[str]:
    """Every registered adapter name, sorted for stable CLI output."""
    _register()
    return sorted(_FACTORIES)


def get_adapter(name: str):
    """Return a fresh adapter instance, or raise ``KeyError`` naming the choices."""
    _register()
    try:
        factory = _FACTORIES[name]
    except KeyError:
        raise KeyError(
            f"unknown TestSparker adapter {name!r}; available: {', '.join(adapter_names())}"
        ) from None
    return factory()
