"""Prove a symbolic witness against runtime bytecode, not just the model.

The symbolic explorer works on bytecode already, but a witness is only useful
when the concrete EVM reaches the same terminal state. This module replays the
witness in :mod:`blackheart.evmworld` and compares the halt status and any
declared storage expectations. It is deliberately small: it proves reachability
of the recorded outcome, not the source-level cause.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from .evmworld import Account, World, execute_message
from .symbolic.poc import calldata_from_witness

TARGET = 0xB1AC
CALLER = 0xA11CE
STATUSES = ("VERIFIED", "DIVERGED", "INCOMPLETE")


@dataclass
class BytecodeWitness:
    status: str
    calldata: str = ""
    expected_revert: bool = False
    observed_revert: bool = False
    storage_ok: bool = True
    halt: str = ""
    state_diff: list[dict] = field(default_factory=list)
    reason: str = ""

    @property
    def verified(self) -> bool:
        return self.status == "VERIFIED"

    def to_dict(self) -> dict:
        return {
            "status": self.status,
            "calldata": self.calldata,
            "expected_revert": self.expected_revert,
            "observed_revert": self.observed_revert,
            "storage_ok": self.storage_ok,
            "halt": self.halt,
            "state_diff": list(self.state_diff),
            "reason": self.reason,
        }


def verify_runtime_witness(
    runtime_code: bytes,
    witness: dict[str, Any],
    *,
    expect_revert: Optional[bool] = None,
    expected_storage: Optional[dict[int, int]] = None,
    caller: int = CALLER,
    target: int = TARGET,
    value: int = 0,
    gas: int = 1_000_000,
) -> BytecodeWitness:
    """Replay a witness on ``runtime_code`` and compare the terminal outcome."""
    code = bytes(runtime_code)
    if not code:
        return BytecodeWitness("INCOMPLETE", reason="no runtime bytecode")
    calldata = calldata_from_witness(witness)
    if expect_revert is None:
        expect_revert = witness.get("_halt") == "revert"
    world = World({target: Account(code=code)})
    try:
        tx = execute_message(world, caller=caller, to=target, calldata=calldata,
                             value=value, gas=gas)
    except Exception as exc:  # noqa: BLE001 -- an executor failure is not a proof
        return BytecodeWitness("INCOMPLETE", "0x" + calldata.hex(),
                               bool(expect_revert), reason=str(exc))
    observed_revert = not tx.succeeded
    storage_ok = True
    if expected_storage:
        storage_ok = all(world.get_storage(target, key) == val
                         for key, val in expected_storage.items())
    status = "VERIFIED" if observed_revert == expect_revert and storage_ok else "DIVERGED"
    reason = ("the concrete EVM reached the recorded outcome"
              if status == "VERIFIED" else
              "the concrete EVM did not match the witness's halt or storage")
    return BytecodeWitness(status, "0x" + calldata.hex(), bool(expect_revert),
                           observed_revert, storage_ok, str(tx.halt),
                           list(tx.state_diff), reason)


def verify_runtime_hex(runtime_hex: str, witness: dict[str, Any], **kwargs: Any) -> BytecodeWitness:
    """Convenience for a hex runtime string (``0x`` optional)."""
    text = runtime_hex[2:] if runtime_hex.startswith(("0x", "0X")) else runtime_hex
    try:
        code = bytes.fromhex(text)
    except ValueError as exc:
        return BytecodeWitness("INCOMPLETE", reason=f"invalid runtime hex: {exc}")
    return verify_runtime_witness(code, witness, **kwargs)
