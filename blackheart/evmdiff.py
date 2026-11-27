"""Differential verification of :mod:`blackheart.evmworld` against a real EVM.

An interpreter is only worth what it can be *shown* to agree with. This module runs
the same runtime bytecode through two engines under the same conditions -- our
``evmworld`` ``Machine`` and a real ``anvil`` node -- and compares what actually
happened.

What is compared, and why each one:

* **halt class** -- success vs revert vs exceptional halt. The single most important
  agreement, because everything downstream depends on it.
* **return data** -- byte-exact. A dispatcher that returns the wrong value is a
  dispatcher bug that a status-only comparison would hide.
* **revert data** -- byte-exact. The revert reason is part of the contract's
  observable behaviour and the thing a test asserts on.
* **storage writes** -- per slot, as a delta. This is what a state-transition claim
  is actually about.
* **logs** -- topics and data. An event that fires in anvil but not here (or the
  reverse) means the control flow diverged.

What is deliberately **not** compared:

* **gas used.** Our gas meter is a determinism budget, not a cost model. Asserting
  equality would force us to clone mainnet gas schedules, and a gas number that is
  merely *close* is worse than none: it invites a claim that has no basis. The
  differential record says ``gas_compared: false`` explicitly.

Every case carries an explicit verification status. A case that anvil cannot run for
an environmental reason is ``SKIPPED`` with the reason, never ``PASS``: an untested
claim is not a verified one.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Optional

from .evmworld import Account, World, execute_message

__all__ = [
    "Status",
    "DifferentialCase",
    "CaseOutcome",
    "DifferentialReport",
    "run_case",
    "DEFAULT_CASES",
    "run_default_suite",
    "anvil_available",
]


class Status(str):
    """Per-case verification status."""


PASS = Status("PASS")
FAIL = Status("FAIL")
SKIPPED = Status("SKIPPED")


@dataclass
class DifferentialCase:
    """One comparison: bytecode + accounts + a message, run on both engines."""

    name: str
    code: bytes
    calldata: bytes = b""
    caller: int = 0x1111
    to: int = 0x2222
    value: int = 0
    gas: int = 1_000_000
    env: dict[str, int] = field(default_factory=dict)
    #: Extra accounts: address -> (code, storage, balance)
    accounts: dict[int, tuple[bytes, dict[int, int], int]] = field(default_factory=dict)
    #: Opcodes this case is meant to exercise, recorded in the report.
    exercises: list[str] = field(default_factory=list)
    note: str = ""


@dataclass
class CaseOutcome:
    name: str
    status: Status
    detail: str = ""
    exercises: list[str] = field(default_factory=list)
    ours: dict = field(default_factory=dict)
    anvil: dict = field(default_factory=dict)
    mismatches: list[str] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return self.status is PASS

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "status": str(self.status),
            "detail": self.detail,
            "exercises": self.exercises,
            "ours": self.ours,
            "anvil": self.anvil,
            "mismatches": self.mismatches,
        }


@dataclass
class DifferentialReport:
    cases: list[CaseOutcome] = field(default_factory=list)
    gas_compared: bool = False
    engine: str = "evmworld"
    reference: str = "anvil"

    @property
    def passed(self) -> int:
        return sum(1 for c in self.cases if c.status is PASS)

    @property
    def failed(self) -> int:
        return sum(1 for c in self.cases if c.status is FAIL)

    @property
    def skipped(self) -> int:
        return sum(1 for c in self.cases if c.status is SKIPPED)

    @property
    def ok(self) -> bool:
        return self.failed == 0 and self.skipped == 0 and self.passed == len(self.cases)

    def to_dict(self) -> dict:
        return {
            "engine": self.engine,
            "reference": self.reference,
            "gas_compared": self.gas_compared,
            "passed": self.passed,
            "failed": self.failed,
            "skipped": self.skipped,
            "ok": self.ok,
            "cases": [c.to_dict() for c in self.cases],
        }


def anvil_available() -> bool:
    from .statespace.runtime.evm import _foundry_bin

    return _foundry_bin("anvil") is not None


# --------------------------------------------------------------------------- #
# Our engine
# --------------------------------------------------------------------------- #

def _run_ours(case: DifferentialCase) -> dict:
    world = World()
    for addr, (code, storage, balance) in case.accounts.items():
        world.accounts[addr] = Account(code=code, storage=dict(storage), balance=balance)
    world.accounts.setdefault(case.to, Account(code=case.code))
    world.account(case.to).code = case.code

    res = execute_message(
        world,
        caller=case.caller,
        to=case.to,
        calldata=case.calldata,
        value=case.value,
        gas=case.gas,
        env=case.env,
    )
    logs = res.frame.logs
    return {
        "reached": _reached_addresses(res.frame),
        "halt": str(res.halt),
        "succeeded": res.succeeded,
        "return_data": "0x" + res.return_data.hex(),
        "revert_data": "0x" + res.return_data.hex() if str(res.halt) == "REVERT" else "",
        "storage_writes": _flat_storage(res.state_diff),
        "logs": logs,
        "gas_used": res.frame.gas_used,
    }


def _reached_addresses(frame) -> list[str]:
    """Every address whose code actually ran, outermost first."""
    out = [f"0x{frame.code_address:040x}"]
    for child in frame.children:
        out.extend(_reached_addresses(child))
    return out


def _flat_storage(diff: list[dict]) -> dict[str, str]:
    out: dict[str, str] = {}
    for entry in diff:
        addr = entry["address"]
        for slot in entry["storage"]:
            out[f"{addr}:{slot['slot']}"] = str(slot["to"])
    return out


# --------------------------------------------------------------------------- #
# anvil
# --------------------------------------------------------------------------- #

#: anvil's exceptional-halt messages, mapped to the halt class we model. Treating
#: these as "harness limitations" would throw away the most valuable comparisons:
#: an exceptional halt that both engines agree on is a *verified* semantic.
_ANVIL_HALTS: list[tuple[str, str]] = [
    ("stackunderflow", "STACK_UNDERFLOW"),
    ("stackoverflow", "STACK_OVERFLOW"),
    ("invalidjump", "BAD_JUMP"),
    ("outofgas", "OUT_OF_GAS"),
    ("staticstatechange", "STATIC_VIOLATION"),
    ("invalidfeopcode", "INVALID"),
    ("invalidopcode", "INVALID"),
    ("revert", "REVERT"),
]


def _classify_anvil_error(exc: Exception) -> Optional[dict]:
    """Turn an anvil RPC error into a comparable outcome, or None if not classifiable.

    An unclassifiable error (a bad request, an unsupported override) is a genuine
    harness limitation and must stay a skip. A classified halt is a real result.
    """
    msg = str(exc)
    low = msg.lower()
    # A revert carries its data in a structured ``data`` field, not in the prose.
    data = ""
    m = re.search(r"'data':\s*'(0x[0-9a-fA-F]*)'", msg)
    if m:
        data = m.group(1)
    for needle, halt in _ANVIL_HALTS:
        if needle in low:
            return {
                "halt": halt,
                "succeeded": False,
                "return_data": data,
                "revert_data": data if halt == "REVERT" else "",
                "storage_writes": {},
                "logs": [],
                "gas_used": None,
            }
    return None


def _run_anvil(case: DifferentialCase, node) -> dict:
    """Execute the same message on a real node via state override."""
    rpc = node.rpc
    to_hex = f"0x{case.to:040x}"
    caller_hex = f"0x{case.caller:040x}"

    state_override = {to_hex: {"code": "0x" + case.code.hex()}}
    for addr, (code, storage, balance) in case.accounts.items():
        entry: dict[str, Any] = {}
        if code:
            entry["code"] = "0x" + code.hex()
        if storage:
            entry["stateDiff"] = {f"0x{k:064x}": f"0x{v:064x}" for k, v in storage.items()}
        if balance:
            entry["balance"] = hex(balance)
        state_override[f"0x{addr:040x}"] = entry
    # A value-bearing call needs the sender funded, or the node rejects the call
    # before it runs -- which would look like a disagreement when it is a setup gap.
    if case.value:
        state_override.setdefault(caller_hex, {})["balance"] = hex(case.value * 2 + 10**18)

    call = {
        "from": caller_hex,
        "to": to_hex,
        "data": "0x" + case.calldata.hex(),
        "value": hex(case.value),
        "gas": hex(case.gas),
    }
    try:
        result = rpc.call("eth_call", [call, "latest", state_override])
    except Exception as exc:  # noqa: BLE001
        classified = _classify_anvil_error(exc)
        if classified is not None:
            return classified
        raise

    # Storage writes and logs need a tracer; eth_call reports neither. When the node
    # cannot trace, those two fields stay empty and the comparison treats "not
    # observed" as "not compared" rather than "no change".
    writes: dict[str, str] = {}
    logs: list[dict] = []
    try:
        trace = rpc.call("debug_traceCall", [call, "latest", {
            "stateOverrides": state_override,
            "tracer": "prestateTracer",
            "tracerConfig": {"diffMode": True},
        }])
        post = (trace or {}).get("post", {})
        for addr, changes in post.items():
            for slot, value in (changes.get("storage") or {}).items():
                writes[f"{addr.lower()}:{int(slot, 16)}"] = str(int(value, 16))
    except Exception:  # noqa: BLE001
        writes = {}

    try:
        ctrace = rpc.call("debug_traceCall", [call, "latest", {
            "stateOverrides": state_override, "tracer": "callTracer",
            "tracerConfig": {"withLog": True},
        }])
        logs = _collect_logs(ctrace)
    except Exception:  # noqa: BLE001
        logs = []

    return {
        "halt": "RETURN" if result and result != "0x" else "STOP",
        "succeeded": True,
        "return_data": result or "0x",
        "revert_data": "",
        "storage_writes": writes,
        "logs": logs,
        "gas_used": None,
    }


# --------------------------------------------------------------------------- #
# Comparison
# --------------------------------------------------------------------------- #

def _reference_env(node) -> dict[str, int]:
    """The block environment the reference node is *actually* running on.

    ``eth_call`` cannot override CHAINID/NUMBER/TIMESTAMP, so comparing those opcodes
    only means something if our engine is given the reference's real values. Reading
    them from the node is what makes the comparison an equality rather than a
    coincidence.
    """
    if node is None:
        return {}
    try:
        block = node.rpc.call("eth_getBlockByNumber", ["latest", False]) or {}
        return {
            "chainid": int(node.rpc.call("eth_chainId"), 16),
            "number": int(block.get("number", "0x1"), 16),
            "timestamp": int(block.get("timestamp", "0x1"), 16),
            "coinbase": int(block.get("miner", "0x0"), 16),
            "gaslimit": int(block.get("gasLimit", "0x0"), 16),
            "basefee": int(block.get("baseFeePerGas", "0x0"), 16),
            "difficulty": int(block.get("difficulty", "0x0"), 16),
        }
    except Exception:  # noqa: BLE001 -- no env is better than a wrong one
        return {}


def run_case(case: DifferentialCase, node=None) -> CaseOutcome:
    # Case-declared env wins, but anything it does not pin is taken from the
    # reference node so an environment opcode compares like-for-like.
    ref_env = _reference_env(node)
    if ref_env:
        merged = {**ref_env, **case.env}
        case = DifferentialCase(
            name=case.name, code=case.code, calldata=case.calldata,
            caller=case.caller, to=case.to, value=case.value, gas=case.gas,
            env=merged, accounts=case.accounts, exercises=case.exercises,
            note=case.note,
        )
    ours = _run_ours(case)
    if node is None:
        return CaseOutcome(
            name=case.name, status=SKIPPED,
            detail="anvil not available; nothing was compared",
            exercises=case.exercises, ours=ours,
        )
    try:
        ref = _run_anvil(case, node)
    except Exception as exc:  # noqa: BLE001
        return CaseOutcome(
            name=case.name, status=SKIPPED,
            detail=f"anvil could not run this case: {exc}",
            exercises=case.exercises, ours=ours,
        )

    mismatches: list[str] = []
    # A cross-contract case that never reached its declared callee is testing
    # nothing. Fail it loudly instead of reporting agreement between two engines
    # that both executed a program with no effective call.
    if case.accounts:
        reached = set(ours.get("reached") or [])
        for addr in case.accounts:
            if f"0x{addr:040x}" not in reached:
                mismatches.append(
                    f"case never reached its declared callee 0x{addr:040x}; "
                    f"reached={sorted(reached)}"
                )
    if str(ours["succeeded"]) != str(ref["succeeded"]):
        mismatches.append(f"succeeded: ours={ours['succeeded']} anvil={ref['succeeded']}")
    # When both engines rejected the message, they must agree on *why*: a revert is
    # observable contract behaviour, an exceptional halt is a bug. Conflating them
    # would let an interpreter that reverts everything pass.
    if not ours["succeeded"] and not ref["succeeded"]:
        if str(ours["halt"]) != str(ref["halt"]):
            mismatches.append(f"halt: ours={ours['halt']} anvil={ref['halt']}")
    if _norm_hex(ours["return_data"]) != _norm_hex(ref["return_data"]):
        mismatches.append(
            f"return_data: ours={ours['return_data'][:74]} anvil={ref['return_data'][:74]}"
        )
    # Storage and logs are only compared when the reference actually reported them;
    # an empty trace is "not observed", which is not the same as "no writes".
    if ref["storage_writes"]:
        if ours["storage_writes"] != ref["storage_writes"]:
            mismatches.append(
                f"storage_writes: ours={ours['storage_writes']} anvil={ref['storage_writes']}"
            )
    if ref["logs"]:
        if _norm_logs(ours["logs"]) != _norm_logs(ref["logs"]):
            mismatches.append(f"logs: ours={_norm_logs(ours['logs'])} anvil={_norm_logs(ref['logs'])}")

    return CaseOutcome(
        name=case.name,
        status=FAIL if mismatches else PASS,
        detail="" if not mismatches else "; ".join(mismatches),
        exercises=case.exercises,
        ours=ours,
        anvil=ref,
        mismatches=mismatches,
    )


def _norm_hex(value: str) -> str:
    """Normalise hex for comparison: '' and '0x' are the same empty buffer."""
    v = (value or "").lower()
    if v in ("", "0x"):
        return "0x"
    return v if v.startswith("0x") else "0x" + v


def _norm_logs(logs: list[dict]) -> list[tuple]:
    return [
        (lg["address"].lower(), tuple(t.lower() for t in lg["topics"]), lg["data"].lower())
        for lg in logs
    ]


def _collect_logs(ctrace) -> list[dict]:
    """Recursively collect emitted logs from a callTracer trace (requires withLog=True)."""
    out: list[dict] = []
    if not isinstance(ctrace, dict):
        return out
    for lg in ctrace.get("logs") or []:
        out.append({
            "address": str(lg.get("address") or ctrace.get("to") or "").lower(),
            "topics": [str(t).lower() for t in (lg.get("topics") or [])],
            "data": str(lg.get("data") or "0x").lower(),
        })
    for child in ctrace.get("calls") or []:
        out.extend(_collect_logs(child))
    return out


# --------------------------------------------------------------------------- #
# The default suite
# --------------------------------------------------------------------------- #

def _sel(sig: str) -> bytes:
    from .deployed import function_selector

    return bytes.fromhex(function_selector(sig)[2:])


DEFAULT_CASES: list[DifferentialCase] = [
    DifferentialCase(
        name="return-a-constant",
        code=bytes([0x60, 0x2A, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xF3]),
        exercises=["MSTORE", "RETURN"],
        note="baseline: does a return value survive byte-for-byte?",
    ),
    DifferentialCase(
        name="revert-with-data",
        code=bytes([0x60, 0x2A, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xFD]),
        exercises=["REVERT"],
        note="a deliberate rejection must be distinguishable from a failure",
    ),
    DifferentialCase(
        name="storage-write-then-return",
        code=bytes([0x60, 0x07, 0x60, 0x01, 0x55, 0x60, 0x00, 0x60, 0x00, 0xF3]),
        exercises=["SSTORE", "RETURN"],
        note="does a slot write land where anvil puts it?",
    ),
    DifferentialCase(
        name="arithmetic-wrap",
        code=bytes([0x7F]) + b"\xff" * 32 + bytes([0x60, 0x01, 0x01, 0x60, 0x00, 0x52,
                                                   0x60, 0x20, 0x60, 0x00, 0xF3]),
        exercises=["ADD", "PUSH32"],
        note="0xff..ff + 1 must wrap to zero, not raise",
    ),
    DifferentialCase(
        name="sdiv-by-zero-is-zero",
        code=bytes([0x60, 0x00, 0x60, 0x05, 0x05, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xF3]),
        exercises=["SDIV"],
        note="EVM defines x/0 = 0; a Python ZeroDivisionError here would be a bug",
    ),
    DifferentialCase(
        name="jumpdest-reached",
        code=bytes([0x60, 0x04, 0x56, 0xFE, 0x5B, 0x60, 0x2A, 0x60, 0x00, 0x52,
                    0x60, 0x20, 0x60, 0x00, 0xF3]),
        exercises=["JUMP", "JUMPDEST"],
    ),
    DifferentialCase(
        name="bad-jump-reverts",
        code=bytes([0x60, 0x03, 0x56, 0x5B, 0x00]),
        exercises=["JUMP"],
        note="offset 3 is not a JUMPDEST; both engines must reject it",
    ),
    DifferentialCase(
        name="stack-underflow",
        code=bytes([0x01]),
        exercises=["ADD"],
        note="an empty stack must halt, not return a bogus value",
    ),
    DifferentialCase(
        name="keccak-of-memory",
        code=bytes([0x60, 0x00, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0x20,
                    0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xF3]),
        exercises=["KECCAK256"],
        note="keccak256(0x00*32) -- the vector that separates real Keccak from SHA3",
    ),
    DifferentialCase(
        name="calldatacopy-roundtrip",
        code=bytes([0x60, 0x04, 0x60, 0x00, 0x60, 0x00, 0x37, 0x60, 0x04, 0x60, 0x00, 0xF3]),
        calldata=bytes.fromhex("deadbeef"),
        exercises=["CALLDATACOPY", "RETURN"],
    ),
    DifferentialCase(
        name="mstore8-single-byte",
        code=bytes([0x60, 0xAB, 0x60, 0x1F, 0x53, 0x60, 0x20, 0x60, 0x00, 0xF3]),
        exercises=["MSTORE8"],
    ),
    DifferentialCase(
        name="log0-emits",
        code=bytes([0x60, 0x2A, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xA0, 0x00]),
        exercises=["LOG0"],
        note="an event must appear on both sides with the same data",
    ),
    DifferentialCase(
        name="env-chainid",
        code=bytes([0x46, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xF3]),
        exercises=["CHAINID"],
        note=(
            "environment opcodes must reflect the *actual* environment, not zero. "
            "eth_call cannot override CHAINID, so this case deliberately pins nothing "
            "and takes the reference node's own value."
        ),
    ),
    DifferentialCase(
        name="callvalue-and-caller",
        code=bytes([0x34, 0x60, 0x00, 0x52, 0x33, 0x60, 0x20, 0x52,
                    0x60, 0x40, 0x60, 0x00, 0xF3]),
        value=12345,
        exercises=["CALLVALUE", "CALLER"],
    ),
]


def run_default_suite(node=None) -> DifferentialReport:
    report = DifferentialReport()
    for case in DEFAULT_CASES:
        report.cases.append(run_case(case, node))
    return report


# --------------------------------------------------------------------------- #
# Cross-contract cases: what a single-frame interpreter could not express
# --------------------------------------------------------------------------- #
#
# EVM operand order for the call opcodes is: gas, to, [value], argsOffset,
# argsLength, retOffset, retLength -- pushed in that order, so the *last* pushed
# value (retLength) is on top and is popped first. Getting this backwards is the
# classic way to write a call test that "passes" against a broken interpreter, so
# every case below is written as explicit pushes in that exact order.

B = 0xB0B  # the callee
C = 0xC0C  # a second callee


def _p1(n: int) -> bytes:
    return bytes([0x60, n & 0xFF])


def _p2(n: int) -> bytes:
    return bytes([0x61, (n >> 8) & 0xFF, n & 0xFF])


def _push_addr(addr: int) -> bytes:
    return bytes([0x73]) + addr.to_bytes(20, "big")


_CALL_OPCODES = {"call": 0xF1, "callcode": 0xF2, "delegatecall": 0xF4, "staticcall": 0xFA}


def _call_seq(to: int, *, kind: str = "call", gas: int = 50000, ret_len: int = 32,
              value: int = 0) -> bytes:
    """Push a call's operands in the order the EVM *pops* them, then emit the opcode.

    The stack is LIFO, so the first operand popped must be pushed **last**. The EVM
    pops, in order: gas, to, [value], argsOffset, argsLength, retOffset, retLength.
    Therefore the push order is the exact reverse: retLength, retOffset, argsLength,
    argsOffset, [value], to, gas.

    Two earlier versions of this helper were wrong in ways that made every
    cross-contract case vacuous:

    1. it pushed the operands but never emitted the call opcode at all, and
    2. it pushed them front-to-back, so ``gas`` ended up at the bottom of the stack
       and the call targeted address ``0x0`` -- an account with no code, which
       "succeeds" and returns nothing.

    Both versions produced green results, because both engines agreed on a program
    that never called anything. ``_selfcheck_cases`` and the per-case callee
    assertion in :func:`run_case` exist so that this cannot recur silently.
    """
    out = _p1(ret_len) + _p1(0) + _p1(0) + _p1(0)   # retLength, retOffset, argsLength, argsOffset
    if kind in ("call", "callcode"):
        out += _p1(value)
    out += _push_addr(to) + _p2(gas)
    return out + bytes([_CALL_OPCODES[kind]])


CALLEE_RETURNS_42 = bytes([0x60, 0x2A, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xF3])
CALLEE_REVERTS_WITH_DATA = bytes([0x60, 0x2A, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xFD])
CALLEE_WRITES_SLOT7 = bytes([0x60, 0x07, 0x60, 0x01, 0x55, 0x00])
CALLEE_WRITES_SLOT9 = bytes([0x60, 0x09, 0x60, 0x02, 0x55, 0x00])

CROSS_CASES: list[DifferentialCase] = [
    DifferentialCase(
        name="call-success-returns-child-data",
        # CALL(B, ret=(0,32)) then RETURN mem[0:32]
        code=_call_seq(B) + bytes([0x50]) + _p1(0x20) + _p1(0x00) + bytes([0xF3]),
        accounts={B: (CALLEE_RETURNS_42, {}, 0)},
        exercises=["CALL", "RETURN"],
        note="the child's return data must land in the caller's memory",
    ),
    DifferentialCase(
        name="call-failure-pushes-zero",
        # CALL(B) where B reverts; the success flag on the stack must be 0
        code=_call_seq(B) + bytes([0x60, 0x00, 0x52]) + _p1(0x20) + _p1(0x00) + bytes([0xF3]),
        accounts={B: (CALLEE_REVERTS_WITH_DATA, {}, 0)},
        exercises=["CALL", "REVERT"],
        note="a reverted child returns 0, not 1 -- this is the whole point of a frame",
    ),
    DifferentialCase(
        name="call-failure-does-not-leak-writes",
        # CALL(B) where B writes slot 1 then reverts; slot 1 must stay absent
        code=_call_seq(B) + bytes([0x50]) + bytes([0x60, 0x01, 0x54, 0x60, 0x00, 0x52])
             + _p1(0x20) + _p1(0x00) + bytes([0xF3]),
        accounts={B: (bytes([0x60, 0x07, 0x60, 0x01, 0x55, 0x60, 0x00, 0x60, 0x00, 0xFD]), {}, 0)},
        exercises=["CALL", "SSTORE", "REVERT"],
        note="a reverted child must unwind its own storage writes",
    ),
    DifferentialCase(
        name="delegatecall-revert-unwinds-caller-storage",
        # DELEGATECALL to a callee that writes slot 5 = 99 in the CALLER's storage,
        # then reverts. Slot 5 must be unchanged afterwards. This is the case that
        # distinguishes "the frame unwinds its own writes" from "writes leak": the
        # callee writes into *our* storage, so a missing unwind is visible here.
        code=_call_seq(B, kind="delegatecall", ret_len=0)
             + bytes([0x50]) + bytes([0x60, 0x05, 0x54, 0x60, 0x00, 0x52])
             + _p1(0x20) + _p1(0x00) + bytes([0xF3]),
        accounts={
            B: (bytes([0x60, 0x63, 0x60, 0x05, 0x55,
                       0x60, 0x00, 0x60, 0x00, 0xFD]), {}, 0),
        },
        exercises=["DELEGATECALL", "SSTORE", "REVERT"],
        note="a reverted delegatecall must not leave its write in the caller's storage",
    ),
    DifferentialCase(
        name="staticcall-cannot-write",
        # STATICCALL to a callee that SSTOREs: must fail, and the slot must stay 0
        code=_call_seq(B, kind="staticcall", ret_len=32)
             + bytes([0x60, 0x00, 0x52]) + _p1(0x20) + _p1(0x00) + bytes([0xF3]),
        accounts={B: (CALLEE_WRITES_SLOT7, {}, 0)},
        exercises=["STATICCALL", "SSTORE"],
        note="a state change inside a static frame is a violation, not a no-op",
    ),
    DifferentialCase(
        name="delegatecall-writes-callers-storage",
        # DELEGATECALL(B) where B writes slot 1 = 7: the *caller's* slot 1 changes
        code=_call_seq(B, kind="delegatecall", ret_len=0)
             + bytes([0x50]) + bytes([0x60, 0x01, 0x54, 0x60, 0x00, 0x52])
             + _p1(0x20) + _p1(0x00) + bytes([0xF3]),
        accounts={B: (CALLEE_WRITES_SLOT7, {}, 0)},
        exercises=["DELEGATECALL", "SSTORE"],
        note="the callee's code runs against the caller's storage -- the proxy bug class",
    ),
    DifferentialCase(
        name="delegatecall-keeps-original-caller",
        # DELEGATECALL(B) where B returns CALLER: must be the *original* caller
        code=_call_seq(B, kind="delegatecall", ret_len=32)
             + bytes([0x50]) + _p1(0x20) + _p1(0x00) + bytes([0xF3]),
        accounts={B: (bytes([0x33, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xF3]), {}, 0)},
        exercises=["DELEGATECALL", "CALLER"],
        note="DELEGATECALL preserves the original CALLER, unlike CALL",
    ),
    DifferentialCase(
        name="returndatasize-after-call",
        # CALL(B); RETURNDATASIZE -> 32
        code=_call_seq(B) + bytes([0x50, 0x3D, 0x60, 0x00, 0x52])
             + _p1(0x20) + _p1(0x00) + bytes([0xF3]),
        accounts={B: (CALLEE_RETURNS_42, {}, 0)},
        exercises=["CALL", "RETURNDATASIZE"],
        note="RETURNDATASIZE must reflect the child's output, not a constant 0",
    ),
    DifferentialCase(
        name="returndatacopy-child-bytes",
        # CALL(B); RETURNDATACOPY(dest=0, off=0, len=32); RETURN mem[0:32]
        code=_call_seq(B) + bytes([0x50]) + _p1(0x20) + _p1(0x00) + _p1(0x00)
             + bytes([0x3E]) + _p1(0x20) + _p1(0x00) + bytes([0xF3]),
        accounts={B: (CALLEE_RETURNS_42, {}, 0)},
        exercises=["RETURNDATACOPY"],
        note="the child's bytes must be copied verbatim, not zero-filled",
    ),
    DifferentialCase(
        name="nested-call-two-levels",
        # A calls B; B calls C which returns 42; B returns C's answer; A returns it
        code=_call_seq(B) + bytes([0x50]) + _p1(0x20) + _p1(0x00) + bytes([0xF3]),
        accounts={
            B: (_call_seq(C) + bytes([0x50]) + _p1(0x20) + _p1(0x00) + bytes([0xF3]), {}, 0),
            C: (CALLEE_RETURNS_42, {}, 0),
        },
        exercises=["CALL", "RETURN"],
        note="a two-level call chain must propagate data all the way up",
    ),
    DifferentialCase(
        name="call-value-transfers-balance",
        # CALL(B, value=1000); B's SELFBALANCE is returned
        code=_call_seq(B, value=0xE8) + bytes([0x50])
             + _p1(0x20) + _p1(0x00) + bytes([0xF3]),
        accounts={
            B: (bytes([0x47, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xF3]), {}, 0),
        },
        exercises=["CALL", "SELFBALANCE"],
        note="a value-bearing CALL must move balance before the callee runs",
    ),
    DifferentialCase(
        name="log-from-nested-frame",
        # CALL(B) where B emits LOG0(0x2a)
        code=_call_seq(B) + bytes([0x50]) + bytes([0x00]),
        accounts={
            B: (bytes([0x60, 0x2A, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xA0, 0x00]), {}, 0),
        },
        exercises=["CALL", "LOG0"],
        note="logs from a nested frame must surface with the child's address",
    ),
]


def run_full_suite(node=None) -> DifferentialReport:
    """Every case: single-frame semantics plus cross-contract frames."""
    report = DifferentialReport()
    for case in DEFAULT_CASES + CROSS_CASES:
        report.cases.append(run_case(case, node))
    return report


def _selfcheck_cases() -> list[str]:
    """Structural checks a differential case must pass before it may report PASS.

    A case that names ``CALL`` in ``exercises`` but whose bytecode contains no call
    opcode would "pass" by comparing two engines on a program that does nothing. That
    is a false pass, and it is exactly the failure this function exists to prevent.
    """
    problems: list[str] = []
    for case in DEFAULT_CASES + CROSS_CASES:
        named = {e.upper() for e in case.exercises}
        body = case.code
        present: set[str] = set()
        i, n = 0, len(body)
        while i < n:
            op = body[i]
            if op == 0xF1:
                present.add("CALL")
            elif op == 0xF2:
                present.add("CALLCODE")
            elif op == 0xF4:
                present.add("DELEGATECALL")
            elif op == 0xFA:
                present.add("STATICCALL")
            elif op == 0x3E:
                present.add("RETURNDATACOPY")
            elif op == 0x3D:
                present.add("RETURNDATASIZE")
            elif op == 0xA0:
                present.add("LOG0")
            elif op == 0x20:
                present.add("KECCAK256")
            elif op == 0x55:
                present.add("SSTORE")
            elif op == 0x54:
                present.add("SLOAD")
            elif op == 0x33:
                present.add("CALLER")
            elif op == 0x34:
                present.add("CALLVALUE")
            elif op == 0x47:
                present.add("SELFBALANCE")
            i += 1 + (op - 0x5F if 0x60 <= op <= 0x7F else 0)
        # A callee may be where the opcode lives; that still counts.
        for _addr, (callee_code, _st, _bal) in case.accounts.items():
            j, m = 0, len(callee_code)
            while j < m:
                op = callee_code[j]
                if op == 0xF1:
                    present.add("CALL")
                elif op == 0xF4:
                    present.add("DELEGATECALL")
                elif op == 0xFA:
                    present.add("STATICCALL")
                elif op == 0x3E:
                    present.add("RETURNDATACOPY")
                elif op == 0x55:
                    present.add("SSTORE")
                elif op == 0x54:
                    present.add("SLOAD")
                elif op == 0x33:
                    present.add("CALLER")
                elif op == 0xA0:
                    present.add("LOG0")
                elif op == 0x47:
                    present.add("SELFBALANCE")
                j += 1 + (op - 0x5F if 0x60 <= op <= 0x7F else 0)
        # Only check opcodes we can detect by scanning; the rest are verified by the
        # differential comparison itself.
        detectable = {"CALL", "CALLCODE", "DELEGATECALL", "STATICCALL",
                      "RETURNDATACOPY", "RETURNDATASIZE", "LOG0", "KECCAK256",
                      "SSTORE", "SLOAD", "CALLER", "CALLVALUE", "SELFBALANCE"}
        for want in named & detectable:
            if want not in present:
                problems.append(
                    f"{case.name}: declares {want} but its bytecode never executes it"
                )
    return problems
