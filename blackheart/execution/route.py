"""Execution routing: real anvil first, the local EVM as the labelled fallback.

The local interpreter (:mod:`blackheart.evmworld`) is fast and deterministic but
it is not a chain. When Foundry's ``anvil`` is installed, the same bytecode and
message can be executed on a real EVM through ``eth_call``. This module makes
that choice explicit and carries the engine name with the result, so a report
never presents a local-model run as a chain run.

``revm`` has no stable command-line contract; it is detected and reported, but
not executed. A missing real engine is a named fallback, never a silent one.
"""

from __future__ import annotations

import shutil
from dataclasses import dataclass, field
from typing import Any, Optional

from ..evmdiff import DifferentialCase, _run_anvil, anvil_available
from ..evm_fuzz import run_bytecode
from ..statespace.runtime.evm import AnvilNode


def revm_available() -> bool:
    return shutil.which("revm") is not None


def select_engine(prefer: str = "auto") -> tuple[str, str]:
    """Return ``(engine, reason)``. ``engine`` is ``anvil`` or ``local-evm``."""
    prefer = (prefer or "auto").lower()
    if prefer == "local":
        return "local-evm", "local engine requested"
    if prefer == "revm":
        if revm_available():
            return "local-evm", "revm detected but no stable CLI adapter; local EVM used"
        return "local-evm", "revm is not installed; local EVM used"
    if anvil_available():
        return "anvil", "anvil detected; real EVM via eth_call"
    return "local-evm", "anvil is not installed; local EVM used"


@dataclass
class RoutedExecution:
    engine: str
    requested: str
    reason: str
    result: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {"engine": self.engine, "requested": self.requested,
                "reason": self.reason, "result": dict(self.result)}


class RoutedExecutor:
    """Run bytecode on the selected engine, reusing one anvil node when possible."""

    def __init__(self, prefer: str = "auto") -> None:
        self.requested = prefer or "auto"
        self.engine, self.reason = select_engine(self.requested)
        self._node: Optional[AnvilNode] = None

    def _start_anvil(self) -> bool:
        try:
            self._node = AnvilNode()
            self._node.start()
            return True
        except Exception as exc:  # noqa: BLE001 -- a missing binary is a fallback
            self._node = None
            self.engine = "local-evm"
            self.reason = f"anvil could not start ({type(exc).__name__}: {exc}); local EVM used"
            return False

    def __enter__(self) -> "RoutedExecutor":
        if self.engine == "anvil":
            self._start_anvil()
        return self

    def __exit__(self, *exc) -> None:
        if self._node is not None:
            self._node.stop()
            self._node = None

    def run(self, code: bytes, calldata: bytes = b"", *, address: int = 0xC0DE,
            caller: int = 0xA11CE, value: int = 0,
            storage: Optional[dict[int, int]] = None,
            env: Optional[dict[str, int]] = None) -> RoutedExecution:
        if self.engine == "anvil" and self._node is None:
            self._start_anvil()
        if self.engine == "anvil":
            case = DifferentialCase(
                name="routed-exec", code=bytes(code), calldata=bytes(calldata),
                caller=caller, to=address, value=value,
                env=dict(env or {}),
                accounts={address: (b"", dict(storage or {}), 0)},
            )
            try:
                result = _run_anvil(case, self._node)
            except Exception as exc:  # noqa: BLE001 -- transport failure, not a verdict
                self.engine = "local-evm"
                self.reason = f"anvil execution failed ({type(exc).__name__}: {exc}); local EVM used"
            else:
                return RoutedExecution("anvil", self.requested, self.reason, result)
        result = run_bytecode(bytes(code), bytes(calldata), address=address,
                              caller=caller, value=value, storage=storage, env=env)
        payload = {
            "succeeded": result.succeeded,
            "halt": str(result.halt),
            "return_data": "0x" + result.return_data.hex(),
            "state_diff": list(result.state_diff),
            "gas_used": getattr(result.frame, "gas_used", None),
        }
        return RoutedExecution("local-evm", self.requested, self.reason, payload)


def run_routed(code: bytes, calldata: bytes = b"", *, prefer: str = "auto",
               **kwargs: Any) -> RoutedExecution:
    with RoutedExecutor(prefer) as executor:
        return executor.run(code, calldata, **kwargs)


__all__ = [
    "RoutedExecution", "RoutedExecutor", "run_routed", "select_engine",
    "anvil_available", "revm_available",
]
