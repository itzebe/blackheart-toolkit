"""A multi-frame EVM: accounts, external calls, contract creation.

Mission 07 shipped ``blackheart/evm.py`` as a *single-frame* interpreter, enough to
decide "does selector S reach a body?" but not enough to model a contract that calls
another contract -- which is most of them. This module adds the missing half without
replacing it: ``evm.py`` remains the fast single-frame interpreter the dispatcher
adapter uses, and this module is the multi-frame one the research lifecycle uses when
it needs a real cross-contract sequence.

Design choices that matter:

* **Frames, not recursion into a new interpreter.** A frame has its own code, pc,
  stack, memory and gas. ``CALL`` pushes a frame; the parent resumes with exactly one
  stack value (success) and a populated return-data buffer. That is the real
  semantics, and getting it wrong is how an interpreter reports success for a call
  that reverted.
* **``STATICCALL`` writes are fatal, not ignored.** A state change inside a static
  frame halts the whole transaction with ``STATIC_VIOLATION``. Silently dropping the
  write would make a reentrancy/read-only test pass for the wrong reason.
* **``DELEGATECALL`` runs the callee's code in the *caller's* storage and address**
  while preserving the original ``CALLER``/``CALLVALUE``. That distinction is the
  entire basis of proxy bugs, so it is modelled explicitly rather than approximated.
* **A revert unwinds the frame's writes.** Each frame records the storage it touched
  and restores the prior values on revert, so a parent that continues after a failed
  call sees the pre-call state. Without this, a "guard reverted" test would still see
  the attacker's write.
* **Gas is a determinism budget, not a cost estimate.** ``gas_used`` is never claimed
  to be mainnet-accurate. What *is* enforced is that it never goes negative, that a
  memory expansion past the cap halts, and that exhaustion is an honest
  ``OUT_OF_GAS`` rather than an exception escaping to the caller.
* **Unsupported opcodes halt as ``INVALID``.** They are never treated as a no-op,
  because a no-op is indistinguishable from success.

Stdlib only. Pure: the caller supplies accounts and gets back final state. No RPC.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from .deployed import keccak256 as _keccak256

__all__ = [
    "Halt",
    "Account",
    "World",
    "FrameResult",
    "TxResult",
    "Machine",
    "execute_message",
    "UINT256_MAX",
    "STOP",
    "RETURN",
    "REVERT",
    "INVALID",
    "OUT_OF_GAS",
    "BAD_JUMP",
    "STACK_UNDERFLOW",
    "STACK_OVERFLOW",
    "STATIC_VIOLATION",
    "CALL_DEPTH_EXCEEDED",
]

UINT256_MAX = (1 << 256) - 1
_MASK = UINT256_MAX

#: Hard cap on modelled memory *per frame*. A hostile offset must halt, not allocate.
_MEMORY_LIMIT = 32 * 1024 * 1024

#: The EVM's own call-depth limit.
_MAX_DEPTH = 1024


class Halt(str):
    """Why a frame stopped. A string subclass so it serialises directly."""


STOP = Halt("STOP")
RETURN = Halt("RETURN")
REVERT = Halt("REVERT")
INVALID = Halt("INVALID")
OUT_OF_GAS = Halt("OUT_OF_GAS")
BAD_JUMP = Halt("BAD_JUMP")
STACK_UNDERFLOW = Halt("STACK_UNDERFLOW")
STACK_OVERFLOW = Halt("STACK_OVERFLOW")
STATIC_VIOLATION = Halt("STATIC_VIOLATION")
CALL_DEPTH_EXCEEDED = Halt("CALL_DEPTH_EXCEEDED")


def _signed(x: int) -> int:
    return x - (1 << 256) if x >> 255 else x


def _valid_jumpdests(code: bytes) -> frozenset[int]:
    """Offsets holding a real ``JUMPDEST``, skipping PUSH payloads.

    A ``0x5b`` inside a ``PUSH32`` constant is *not* a legal destination. Sharing the
    walk with the disassembler is what keeps the interpreter and the static analysis
    from disagreeing about the same bytecode.
    """
    out: set[int] = set()
    i, n = 0, len(code)
    while i < n:
        op = code[i]
        if op == 0x5B:
            out.add(i)
        size = op - 0x5F if 0x60 <= op <= 0x7F else 0
        i += 1 + size
    return frozenset(out)


# --------------------------------------------------------------------------- #
# World state
# --------------------------------------------------------------------------- #

@dataclass
class Account:
    """One account: code, storage, balance, nonce.

    ``code`` empty is a plain value-bearing account, which is the common case for a
    token holder. ``storage`` is a sparse dict; an absent key reads as zero.
    """

    code: bytes = b""
    storage: dict[int, int] = field(default_factory=dict)
    balance: int = 0
    nonce: int = 0

    def to_dict(self) -> dict:
        return {
            "code_hash": "0x" + _keccak256(self.code).hex(),
            "code_size": len(self.code),
            "balance": self.balance,
            "nonce": self.nonce,
            "storage": {str(k): v for k, v in sorted(self.storage.items()) if v},
        }


class World:
    """The set of accounts a message executes against.

    A ``World`` is deliberately explicit: every address the run can touch is declared
    up front. There is no implicit "fetch the code from the network" path, because a
    research run must be reproducible from its preserved evidence alone.
    """

    def __init__(self, accounts: Optional[dict[int, Account]] = None) -> None:
        self.accounts: dict[int, Account] = dict(accounts or {})
        #: Monotonic per-run counter so ``CREATE`` addresses are deterministic.
        self._create_nonce = 0
        #: EIP-1153 transient storage. It is per-transaction, so it is cleared at
        #: the start of every top-level message and is deliberately absent from
        #: ``snapshot``/``restore``/``diff`` (which describe persistent state).
        self.transient: dict[int, dict[int, int]] = {}

    def account(self, address: int) -> Account:
        acct = self.accounts.get(address)
        if acct is None:
            acct = Account()
            self.accounts[address] = acct
        return acct

    def get_storage(self, address: int, key: int) -> int:
        return self.account(address).storage.get(key, 0)

    def set_storage(self, address: int, key: int, value: int) -> None:
        self.account(address).storage[key] = value & _MASK

    def get_transient(self, address: int, key: int) -> int:
        return self.transient.get(address, {}).get(key, 0)

    def set_transient(self, address: int, key: int, value: int) -> None:
        self.transient.setdefault(address, {})[key] = value & _MASK

    def clear_transient(self) -> None:
        self.transient.clear()

    def snapshot(self) -> dict[int, dict[str, Any]]:
        return {
            addr: {
                "storage": dict(acct.storage),
                "balance": acct.balance,
                "nonce": acct.nonce,
                "code": acct.code,
            }
            for addr, acct in self.accounts.items()
        }

    def restore(self, snap: dict[int, dict[str, Any]]) -> None:
        for addr, st in snap.items():
            acct = self.account(addr)
            acct.storage = dict(st["storage"])
            acct.balance = st["balance"]
            acct.nonce = st["nonce"]
            acct.code = st["code"]

    def diff(self, before: dict[int, dict[str, Any]]) -> list[dict]:
        """Storage/balance changes between a snapshot and now, address by address."""
        out: list[dict] = []
        for addr in sorted(set(before) | set(self.accounts)):
            prev = before.get(addr, {"storage": {}, "balance": 0, "nonce": 0, "code": b""})
            acct = self.account(addr)
            slots: list[dict] = []
            for key in sorted(set(prev["storage"]) | set(acct.storage)):
                old = prev["storage"].get(key, 0)
                new = acct.storage.get(key, 0)
                if old != new:
                    slots.append({"slot": str(key), "from": old, "to": new})
            if slots or prev["balance"] != acct.balance:
                out.append({
                    "address": f"0x{addr:040x}",
                    "storage": slots,
                    "balance_from": prev["balance"],
                    "balance_to": acct.balance,
                })
        return out


@dataclass
class FrameResult:
    halt: Halt
    return_data: bytes = b""
    gas_used: int = 0
    steps: int = 0
    depth: int = 0
    error: str = ""
    #: Addresses this frame actually wrote, so a caller can attribute state change.
    writes: list[dict] = field(default_factory=list)
    #: LOG0..LOG4 emissions, in order.
    logs: list[dict] = field(default_factory=list)
    #: Executed program counters, when ``Machine(collect_pcs=True)`` asked for them.
    pcs: list[int] = field(default_factory=list)
    #: Nested frames in call order, for an execution trace.
    children: list["FrameResult"] = field(default_factory=list)
    #: Address whose code ran (differs from ``storage_address`` under DELEGATECALL).
    code_address: int = 0
    storage_address: int = 0
    static: bool = False

    @property
    def succeeded(self) -> bool:
        return self.halt in (STOP, RETURN)

    def to_dict(self) -> dict:
        return {
            "halt": str(self.halt),
            "succeeded": self.succeeded,
            "return_data": "0x" + self.return_data.hex(),
            "gas_used": self.gas_used,
            "steps": self.steps,
            "depth": self.depth,
            "error": self.error,
            "static": self.static,
            "code_address": f"0x{self.code_address:040x}",
            "storage_address": f"0x{self.storage_address:040x}",
            "writes": self.writes,
            "logs": self.logs,
            "pcs": list(self.pcs),
            "children": [c.to_dict() for c in self.children],
        }


@dataclass
class TxResult:
    """The top-level outcome, plus the state change it caused."""

    frame: FrameResult
    state_diff: list[dict] = field(default_factory=list)
    world: Optional[World] = None

    @property
    def succeeded(self) -> bool:
        return self.frame.succeeded

    @property
    def halt(self) -> Halt:
        return self.frame.halt

    @property
    def return_data(self) -> bytes:
        return self.frame.return_data

    def to_dict(self) -> dict:
        return {
            "halt": str(self.frame.halt),
            "succeeded": self.succeeded,
            "return_data": "0x" + self.return_data.hex(),
            "gas_used": self.frame.gas_used,
            "steps": self.frame.steps,
            "state_diff": self.state_diff,
            "frame": self.frame.to_dict(),
        }


# --------------------------------------------------------------------------- #
# Machine
# --------------------------------------------------------------------------- #

class _Halt(Exception):
    def __init__(self, halt: Halt, detail: str) -> None:
        super().__init__(detail)
        self.halt = halt
        self.detail = detail


class Machine:
    """Execute messages against a :class:`World`, with real call frames.

    ``env`` supplies the block environment. Values that a contract can read
    (``TIMESTAMP``, ``NUMBER``, ``CHAINID`` …) come from it rather than being fixed at
    zero, so a differential comparison against anvil is possible at all: you set the
    same environment on both sides.
    """

    def __init__(
        self,
        world: World,
        *,
        env: Optional[dict[str, int]] = None,
        max_steps_per_frame: int = 200_000,
        collect_pcs: bool = False,
    ) -> None:
        self.world = world
        #: Off by default: a research run does not pay for a trace it will not read.
        self.collect_pcs = collect_pcs
        self.env = {
            "chainid": 1,
            "number": 1,
            "timestamp": 1,
            "coinbase": 0,
            "gaslimit": 30_000_000,
            "basefee": 0,
            "difficulty": 0,
            "origin": 0,
            "gasprice": 0,
            **(env or {}),
        }
        self.max_steps_per_frame = max_steps_per_frame
        #: Every frame result, flat, in completion order.
        self.trace: list[FrameResult] = []

    # -- public API -------------------------------------------------------- #
    def message_call(
        self,
        *,
        caller: int,
        to: int,
        calldata: bytes = b"",
        value: int = 0,
        gas: int = 1_000_000,
        static: bool = False,
    ) -> TxResult:
        """A top-level transaction. Reverting unwinds every write it made."""
        before = self.world.snapshot()
        # EIP-1153: transient storage lives for exactly one transaction.
        self.world.clear_transient()
        self.env["origin"] = caller
        self.trace = []
        result = self._call(
            caller=caller,
            code_address=to,
            storage_address=to,
            calldata=bytes(calldata),
            value=value,
            gas=gas,
            depth=0,
            static=static,
        )
        if not result.succeeded:
            self.world.restore(before)
            return TxResult(frame=result, state_diff=[], world=self.world)
        return TxResult(frame=result, state_diff=self.world.diff(before), world=self.world)

    # -- frames ------------------------------------------------------------ #
    def _call(
        self,
        *,
        caller: int,
        code_address: int,
        storage_address: int,
        calldata: bytes,
        value: int,
        gas: int,
        depth: int,
        static: bool,
    ) -> FrameResult:
        if depth > _MAX_DEPTH:
            return FrameResult(
                halt=CALL_DEPTH_EXCEEDED,
                depth=depth,
                error=f"call depth {depth} exceeds {_MAX_DEPTH}",
                code_address=code_address,
                storage_address=storage_address,
                static=static,
            )
        code = self.world.account(code_address).code
        if not code:
            # A call to a codeless account succeeds and returns nothing. This is real
            # EVM behaviour and matters: a token that "transfers" to an EOA must not
            # look like a failed call.
            res = FrameResult(
                halt=STOP,
                depth=depth,
                code_address=code_address,
                storage_address=storage_address,
                static=static,
            )
            self.trace.append(res)
            return res
        return _Frame(
            machine=self,
            code=code,
            calldata=calldata,
            caller=caller,
            code_address=code_address,
            storage_address=storage_address,
            value=value,
            gas=gas,
            depth=depth,
            static=static,
        ).run()

    def _create(
        self,
        *,
        caller: int,
        storage_address: int,
        init_code: bytes,
        value: int,
        gas: int,
        depth: int,
        static: bool,
        salt: Optional[int],
    ) -> tuple[Optional[int], FrameResult]:
        """Deploy ``init_code`` and run its constructor.

        The address is derived deterministically. Real ``CREATE2`` uses
        ``keccak(0xff ++ sender ++ salt ++ keccak(init_code))``; real ``CREATE`` uses
        ``keccak(rlp(sender, nonce))``. We use the real ``CREATE2`` formula (we have a
        real Keccak) and a documented deterministic stand-in for ``CREATE``, because
        reproducing RLP + the exact sender nonce buys nothing a research run needs.
        """
        if static:
            raise _Halt(STATIC_VIOLATION, "CREATE inside a static frame")
        if depth > _MAX_DEPTH:
            return None, FrameResult(halt=CALL_DEPTH_EXCEEDED, depth=depth,
                                     error="call depth exceeded")
        if salt is not None:
            preimage = b"\xff" + storage_address.to_bytes(20, "big") + salt.to_bytes(32, "big") + _keccak256(init_code)
            new_addr = int.from_bytes(_keccak256(preimage), "big") & ((1 << 160) - 1)
        else:
            self.world._create_nonce += 1
            preimage = storage_address.to_bytes(20, "big") + self.world._create_nonce.to_bytes(8, "big") + _keccak256(init_code)
            new_addr = int.from_bytes(_keccak256(preimage), "big") & ((1 << 160) - 1)

        acct = self.world.account(new_addr)
        acct.nonce = 1
        if value:
            self.world.account(storage_address).balance -= value
            acct.balance += value

        ctor = self._call(
            caller=caller,
            code_address=new_addr,
            storage_address=new_addr,
            calldata=b"",
            value=value,
            gas=gas,
            depth=depth + 1,
            static=False,
        )
        ctor.code_address = new_addr
        ctor.storage_address = new_addr
        if not ctor.succeeded:
            return None, ctor
        # The constructor's RETURN data is the deployed runtime code.
        acct.code = ctor.return_data
        return new_addr, ctor


class _Frame:
    """One execution frame. Constructed by :meth:`Machine._call`."""

    def __init__(
        self,
        *,
        machine: Machine,
        code: bytes,
        calldata: bytes,
        caller: int,
        code_address: int,
        storage_address: int,
        value: int,
        gas: int,
        depth: int,
        static: bool,
    ) -> None:
        self.m = machine
        self.code = bytes(code)
        self.calldata = bytes(calldata)
        self.caller = caller
        self.code_address = code_address
        self.storage_address = storage_address
        self.value = value
        self.gas = gas
        self.depth = depth
        self.static = static

        self._jumpdests = _valid_jumpdests(self.code)
        self._stack: list[int] = []
        self._memory = bytearray()
        self._pc = 0
        self._gas_used = 0
        self._steps = 0
        self._returndata = b""
        self._children: list[FrameResult] = []
        #: storage writes made by this frame, replayed/reverted as a unit
        self._write_log: list[tuple[int, int, int]] = []  # (addr, key, prior)
        self._writes: list[dict] = []
        self._logs: list[dict] = []
        self._pcs: list[int] = []

    # -- stack / memory / gas ---------------------------------------------- #
    def _pop(self) -> int:
        if not self._stack:
            raise _Halt(STACK_UNDERFLOW, "stack underflow")
        return self._stack.pop()

    def _push(self, v: int) -> None:
        if len(self._stack) >= 1024:
            raise _Halt(STACK_OVERFLOW, "stack overflow")
        self._stack.append(v & _MASK)

    def _expand(self, end: int) -> None:
        if end <= len(self._memory):
            return
        if end > _MEMORY_LIMIT:
            raise _Halt(OUT_OF_GAS, f"memory expansion to {end} exceeds {_MEMORY_LIMIT}-byte cap")
        words = (end + 31) // 32
        self._charge(3 * words + words * words // 512)
        self._memory.extend(b"\x00" * (end - len(self._memory)))

    def _mem_read(self, offset: int, size: int) -> bytes:
        if size == 0:
            return b""
        if offset > _MEMORY_LIMIT or size > _MEMORY_LIMIT:
            raise _Halt(OUT_OF_GAS, f"memory read offset={offset} size={size} exceeds cap")
        end = offset + size
        self._expand(end)
        return bytes(self._memory[offset:end])

    def _mem_write(self, offset: int, data: bytes) -> None:
        if offset > _MEMORY_LIMIT:
            raise _Halt(OUT_OF_GAS, f"memory write offset={offset} exceeds cap")
        end = offset + len(data)
        self._expand(end)
        self._memory[offset:end] = data

    def _charge(self, amount: int) -> None:
        # A negative charge would make gas_used decrease, which is the one thing a
        # determinism budget must never do.
        self._gas_used += max(0, amount)
        if self._gas_used > self.gas:
            raise _Halt(OUT_OF_GAS, f"out of gas after {self._gas_used}")

    def _sstore(self, key: int, value: int) -> None:
        if self.static:
            raise _Halt(STATIC_VIOLATION, f"SSTORE in a static frame (slot {key})")
        prior = self.m.world.get_storage(self.storage_address, key)
        if prior == value:
            return
        self._write_log.append((self.storage_address, key, prior))
        self.m.world.set_storage(self.storage_address, key, value)
        self._writes.append({
            "address": f"0x{self.storage_address:040x}",
            "slot": str(key),
            "from": prior,
            "to": value,
        })

    # -- run --------------------------------------------------------------- #
    def run(self) -> FrameResult:
        snapshot = self.m.world.snapshot()
        try:
            res = self._run()
        except _Halt as h:
            res = self._result(h.halt, error=h.detail)
        if not res.succeeded:
            # A failed frame must not leave its writes behind, or a parent that
            # continues after a reverted call would observe the attacker's state.
            self.m.world.restore(snapshot)
            res.writes = []
        res.children = self._children
        self.m.trace.append(res)
        return res

    def _result(self, halt: Halt, data: bytes = b"", error: str = "") -> FrameResult:
        return FrameResult(
            halt=halt,
            return_data=data,
            gas_used=self._gas_used,
            steps=self._steps,
            depth=self.depth,
            error=error,
            writes=list(self._writes),
            logs=list(self._logs),
            pcs=list(self._pcs),
            code_address=self.code_address,
            storage_address=self.storage_address,
            static=self.static,
        )

    def _run(self) -> FrameResult:
        code, n = self.code, len(self.code)
        while self._pc < n:
            self._steps += 1
            if self._steps > self.m.max_steps_per_frame:
                raise _Halt(OUT_OF_GAS, f"step budget exceeded ({self.m.max_steps_per_frame})")
            self._charge(3)
            pc = self._pc
            if self.m.collect_pcs:
                self._pcs.append(pc)
            op = code[self._pc]
            self._pc += 1

            if 0x60 <= op <= 0x7F:  # PUSH1..PUSH32
                width = op - 0x5F
                if self._pc + width > n:
                    raise _Halt(INVALID, f"truncated PUSH{width} at {self._pc - 1}")
                self._push(int.from_bytes(code[self._pc : self._pc + width], "big"))
                self._pc += width
                continue

            if 0x80 <= op <= 0x8F:  # DUP1..DUP16
                d = op - 0x7F
                if len(self._stack) < d:
                    raise _Halt(STACK_UNDERFLOW, f"DUP{d} on depth {len(self._stack)}")
                self._push(self._stack[-d])
                continue

            if 0x90 <= op <= 0x9F:  # SWAP1..SWAP16
                d = op - 0x8F
                if len(self._stack) < d + 1:
                    raise _Halt(STACK_UNDERFLOW, f"SWAP{d} on depth {len(self._stack)}")
                self._stack[-1], self._stack[-1 - d] = self._stack[-1 - d], self._stack[-1]
                continue

            if 0xA0 <= op <= 0xA4:  # LOG0..LOG4
                count = op - 0xA0
                offset, size = self._pop(), self._pop()
                topics = [self._pop() for _ in range(count)]
                if self.static:
                    raise _Halt(STATIC_VIOLATION, "LOG inside a static frame")
                data = self._mem_read(offset, size)
                self._charge(375 + 375 * count + 8 * size)
                self._logs.append({
                    "address": f"0x{self.storage_address:040x}",
                    "topics": [f"0x{t:064x}" for t in topics],
                    "data": "0x" + data.hex(),
                })
                continue

            if op == 0x5F:  # PUSH0
                self._push(0)
                continue
            if op == 0x00:  # STOP
                return self._result(STOP)
            if op == 0x01:
                self._push(self._pop() + self._pop())
            elif op == 0x02:
                self._push(self._pop() * self._pop())
            elif op == 0x03:
                a, b = self._pop(), self._pop()
                self._push(a - b)
            elif op == 0x04:
                a, b = self._pop(), self._pop()
                self._push(0 if b == 0 else a // b)
            elif op == 0x05:
                a, b = _signed(self._pop()), _signed(self._pop())
                if b == 0:
                    self._push(0)
                else:
                    q = abs(a) // abs(b)
                    self._push(-q if (a < 0) != (b < 0) else q)
            elif op == 0x06:
                a, b = self._pop(), self._pop()
                self._push(0 if b == 0 else a % b)
            elif op == 0x07:
                a, b = _signed(self._pop()), _signed(self._pop())
                if b == 0:
                    self._push(0)
                else:
                    r = abs(a) % abs(b)
                    self._push(-r if a < 0 else r)
            elif op == 0x08:
                a, b, m = self._pop(), self._pop(), self._pop()
                self._push(0 if m == 0 else (a + b) % m)
            elif op == 0x09:
                a, b, m = self._pop(), self._pop(), self._pop()
                self._push(0 if m == 0 else (a * b) % m)
            elif op == 0x0A:
                a, b = self._pop(), self._pop()
                self._charge(max(0, b.bit_length()) * 50)
                self._push(pow(a, b, 1 << 256))
            elif op == 0x0B:
                b, x = self._pop(), self._pop()
                if b < 31:
                    bit = 8 * (b + 1) - 1
                    mask = (1 << bit) - 1
                    x = x | (_MASK ^ mask) if (x >> bit) & 1 else x & mask
                self._push(x)
            elif op == 0x10:
                a, b = self._pop(), self._pop()
                self._push(1 if a < b else 0)
            elif op == 0x11:
                a, b = self._pop(), self._pop()
                self._push(1 if a > b else 0)
            elif op == 0x12:
                a, b = _signed(self._pop()), _signed(self._pop())
                self._push(1 if a < b else 0)
            elif op == 0x13:
                a, b = _signed(self._pop()), _signed(self._pop())
                self._push(1 if a > b else 0)
            elif op == 0x14:
                self._push(1 if self._pop() == self._pop() else 0)
            elif op == 0x15:
                self._push(1 if self._pop() == 0 else 0)
            elif op == 0x16:
                self._push(self._pop() & self._pop())
            elif op == 0x17:
                self._push(self._pop() | self._pop())
            elif op == 0x18:
                self._push(self._pop() ^ self._pop())
            elif op == 0x19:
                self._push(~self._pop())
            elif op == 0x1A:
                i, x = self._pop(), self._pop()
                self._push(0 if i >= 32 else (x >> (8 * (31 - i))) & 0xFF)
            elif op == 0x1B:
                shift, x = self._pop(), self._pop()
                self._push(0 if shift >= 256 else x << shift)
            elif op == 0x1C:
                shift, x = self._pop(), self._pop()
                self._push(0 if shift >= 256 else x >> shift)
            elif op == 0x1D:
                shift, x = self._pop(), _signed(self._pop())
                if shift >= 256:
                    self._push(_MASK if x < 0 else 0)
                else:
                    self._push(x >> shift)
            elif op == 0x20:  # KECCAK256 -- real Keccak-256, shared with deployed.py
                offset, size = self._pop(), self._pop()
                data = self._mem_read(offset, size)
                self._charge(30 + 6 * ((size + 31) // 32))
                self._push(int.from_bytes(_keccak256(data), "big"))
            elif op == 0x30:  # ADDRESS -- the *storage* address, correct under DELEGATECALL
                self._push(self.storage_address)
            elif op == 0x31:  # BALANCE
                addr = self._pop()
                self._charge(100)
                self._push(self.m.world.account(addr).balance)
            elif op == 0x32:  # ORIGIN
                self._push(self.m.env["origin"])
            elif op == 0x33:  # CALLER
                self._push(self.caller)
            elif op == 0x34:  # CALLVALUE
                self._push(self.value)
            elif op == 0x35:  # CALLDATALOAD
                self._push(int.from_bytes(self._cd_slice(self._pop(), 32), "big"))
            elif op == 0x36:
                self._push(len(self.calldata))
            elif op == 0x37:  # CALLDATACOPY(dest, offset, size)
                dest, offset, size = self._pop(), self._pop(), self._pop()
                self._charge(3 + 3 * ((size + 31) // 32))
                self._mem_write(dest, self._cd_slice(offset, size))
            elif op == 0x38:
                self._push(len(self.code))
            elif op == 0x39:  # CODECOPY(dest, offset, size)
                dest, offset, size = self._pop(), self._pop(), self._pop()
                self._charge(3 + 3 * ((size + 31) // 32))
                self._mem_write(dest, self._code_slice(offset, size))
            elif op == 0x3A:  # GASPRICE
                self._push(self.m.env["gasprice"])
            elif op == 0x3B:  # EXTCODESIZE
                addr = self._pop()
                self._charge(100)
                self._push(len(self.m.world.account(addr).code))
            elif op == 0x3C:  # EXTCODECOPY(dest, addr, offset, size)
                dest, addr, offset, size = self._pop(), self._pop(), self._pop(), self._pop()
                self._charge(100 + 3 * ((size + 31) // 32))
                ext = self.m.world.account(addr).code
                chunk = ext[offset : offset + size] if offset < len(ext) else b""
                self._mem_write(dest, chunk + b"\x00" * (size - len(chunk)))
            elif op == 0x3D:  # RETURNDATASIZE
                self._push(len(self._returndata))
            elif op == 0x3E:  # RETURNDATACOPY(dest, offset, size)
                dest, offset, size = self._pop(), self._pop(), self._pop()
                if offset + size > len(self._returndata):
                    raise _Halt(INVALID, f"RETURNDATACOPY past end: {offset}+{size} > {len(self._returndata)}")
                self._charge(3 + 3 * ((size + 31) // 32))
                self._mem_write(dest, self._returndata[offset : offset + size])
            elif op == 0x3F:  # EXTCODEHASH
                addr = self._pop()
                self._charge(100)
                acct = self.m.world.account(addr)
                self._push(0 if not acct.code else int.from_bytes(_keccak256(acct.code), "big"))
            elif op == 0x40:  # BLOCKHASH
                self._pop()
                self._push(0)
            elif op == 0x41:
                self._push(self.m.env["coinbase"])
            elif op == 0x42:
                self._push(self.m.env["timestamp"])
            elif op == 0x43:
                self._push(self.m.env["number"])
            elif op == 0x44:
                self._push(self.m.env["difficulty"])
            elif op == 0x45:
                self._push(self.m.env["gaslimit"])
            elif op == 0x46:
                self._push(self.m.env["chainid"])
            elif op == 0x47:  # SELFBALANCE
                self._push(self.m.world.account(self.storage_address).balance)
            elif op == 0x48:
                self._push(self.m.env["basefee"])
            elif op == 0x49:  # BLOBHASH(index) -- EIP-4844
                idx = self._pop()
                blobs = self.m.env.get("blobhashes") or []
                self._push(blobs[idx] if isinstance(blobs, (list, tuple)) and 0 <= idx < len(blobs) else 0)
            elif op == 0x4A:  # BLOBBASEFEE -- EIP-7516
                self._push(self.m.env.get("blobbasefee", 0))
            elif op == 0x50:
                self._pop()
            elif op == 0x51:
                self._push(int.from_bytes(self._mem_read(self._pop(), 32), "big"))
            elif op == 0x52:
                offset, value = self._pop(), self._pop()
                self._mem_write(offset, value.to_bytes(32, "big"))
            elif op == 0x53:
                offset, value = self._pop(), self._pop()
                self._mem_write(offset, bytes([value & 0xFF]))
            elif op == 0x54:
                self._push(self.m.world.get_storage(self.storage_address, self._pop()))
            elif op == 0x55:
                key, value = self._pop(), self._pop()
                self._charge(100)
                self._sstore(key, value)
            elif op == 0x56:
                self._jump(self._pop())
            elif op == 0x57:
                dest, cond = self._pop(), self._pop()
                if cond != 0:
                    self._jump(dest)
            elif op == 0x58:
                self._push(self._pc - 1)
            elif op == 0x59:
                self._push(len(self._memory))
            elif op == 0x5A:
                self._push(max(0, self.gas - self._gas_used))
            elif op == 0x5B:
                pass
            elif op == 0x5C:  # TLOAD(key) -- EIP-1153 transient storage
                self._push(self.m.world.get_transient(self.storage_address, self._pop()))
            elif op == 0x5D:  # TSTORE(key, value) -- EIP-1153
                if self.static:
                    raise _Halt(STATIC_VIOLATION, "TSTORE in a static frame")
                key, value = self._pop(), self._pop()
                self.m.world.set_transient(self.storage_address, key, value)
            elif op == 0x5E:  # MCOPY(dest, src, size) -- EIP-5656
                dest, src, size = self._pop(), self._pop(), self._pop()
                if size:
                    data = self._mem_read(src, size)
                    self._charge(3 + 3 * ((size + 31) // 32))
                    self._mem_write(dest, data)
            elif op == 0xF0:  # CREATE(value, offset, size)
                self._op_create(salt=None)
            elif op == 0xF5:  # CREATE2(value, offset, size, salt)
                self._op_create(salt=True)
            elif op == 0xF1:  # CALL
                self._op_call(kind="call")
            elif op == 0xF2:  # CALLCODE
                self._op_call(kind="callcode")
            elif op == 0xF4:  # DELEGATECALL
                self._op_call(kind="delegatecall")
            elif op == 0xFA:  # STATICCALL
                self._op_call(kind="staticcall")
            elif op == 0xF3:  # RETURN
                offset, size = self._pop(), self._pop()
                return self._result(RETURN, self._mem_read(offset, size))
            elif op == 0xFD:  # REVERT
                offset, size = self._pop(), self._pop()
                return self._result(REVERT, self._mem_read(offset, size))
            elif op == 0xFE:
                raise _Halt(INVALID, "INVALID opcode")
            elif op == 0xFF:  # SELFDESTRUCT
                if self.static:
                    raise _Halt(STATIC_VIOLATION, "SELFDESTRUCT in a static frame")
                beneficiary = self._pop()
                bal = self.m.world.account(self.storage_address).balance
                if bal:
                    self.m.world.account(beneficiary).balance += bal
                    self.m.world.account(self.storage_address).balance = 0
                return self._result(STOP)
            else:
                raise _Halt(INVALID, f"unsupported opcode 0x{op:02x} at {self._pc - 1}")
        return self._result(STOP)

    # -- call / create opcodes --------------------------------------------- #
    def _op_create(self, *, salt: Optional[int]) -> None:
        if salt is not None:
            value, offset, size, salt_val = self._pop(), self._pop(), self._pop(), self._pop()
            init = self._mem_read(offset, size)
            new_addr, child = self.m._create(
                caller=self.storage_address, storage_address=self.storage_address,
                init_code=init, value=value, gas=max(0, self.gas - self._gas_used),
                depth=self.depth + 1, static=self.static, salt=salt_val,
            )
        else:
            value, offset, size = self._pop(), self._pop(), self._pop()
            init = self._mem_read(offset, size)
            new_addr, child = self.m._create(
                caller=self.storage_address, storage_address=self.storage_address,
                init_code=init, value=value, gas=max(0, self.gas - self._gas_used),
                depth=self.depth + 1, static=self.static, salt=None,
            )
        self._children.append(child)
        if child.succeeded:
            self._logs.extend(child.logs)
        self._returndata = child.return_data
        self._push(0 if new_addr is None else new_addr)

    def _op_call(self, *, kind: str) -> None:
        gas_req, to = self._pop(), self._pop()
        if kind in ("call", "callcode"):
            value, args_off, args_len, ret_off, ret_len = (
                self._pop(), self._pop(), self._pop(), self._pop(), self._pop()
            )
        else:  # delegatecall / staticcall carry no value
            value = 0
            args_off, args_len, ret_off, ret_len = (
                self._pop(), self._pop(), self._pop(), self._pop()
            )
        args = self._mem_read(args_off, args_len)
        available = max(0, self.gas - self._gas_used)
        child_gas = min(gas_req, available)

        if kind == "call":
            world = self.m.world
            if value and self.static:
                raise _Halt(STATIC_VIOLATION, "value transfer inside a static frame")
            if value and world.account(self.storage_address).balance < value:
                child = FrameResult(halt=REVERT, depth=self.depth + 1,
                                    code_address=to, storage_address=to)
            else:
                if value:
                    world.account(self.storage_address).balance -= value
                    world.account(to).balance += value
                child = self.m._call(
                    caller=self.storage_address, code_address=to, storage_address=to,
                    calldata=args, value=value, gas=child_gas,
                    depth=self.depth + 1, static=self.static,
                )
                if value and not child.succeeded:
                    world.account(to).balance -= value
                    world.account(self.storage_address).balance += value
        elif kind == "staticcall":
            child = self.m._call(
                caller=self.storage_address, code_address=to, storage_address=to,
                calldata=args, value=0, gas=child_gas,
                depth=self.depth + 1, static=True,
            )
        elif kind == "delegatecall":
            # Callee's code, *caller's* storage and address; original caller/value kept.
            child = self.m._call(
                caller=self.caller, code_address=to, storage_address=self.storage_address,
                calldata=args, value=self.value, gas=child_gas,
                depth=self.depth + 1, static=self.static,
            )
        else:  # callcode: own storage, but callee's code, caller preserved
            child = self.m._call(
                caller=self.storage_address, code_address=to, storage_address=self.storage_address,
                calldata=args, value=value, gas=child_gas,
                depth=self.depth + 1, static=self.static,
            )

        self._children.append(child)
        if child.succeeded:
            self._logs.extend(child.logs)
        self._returndata = child.return_data
        if ret_len:
            self._mem_write(ret_off, child.return_data[:ret_len].ljust(ret_len, b"\x00"))
        self._push(1 if child.succeeded else 0)

    # -- helpers ----------------------------------------------------------- #
    def _cd_slice(self, offset: int, size: int) -> bytes:
        if offset >= len(self.calldata):
            return b"\x00" * size
        chunk = self.calldata[offset : offset + size]
        return chunk + b"\x00" * (size - len(chunk))

    def _code_slice(self, offset: int, size: int) -> bytes:
        if offset >= len(self.code):
            return b"\x00" * size
        chunk = self.code[offset : offset + size]
        return chunk + b"\x00" * (size - len(chunk))

    def _jump(self, dest: int) -> None:
        if dest not in self._jumpdests:
            raise _Halt(BAD_JUMP, f"jump to {dest}, not a JUMPDEST in this code")
        self._pc = dest


def execute_message(
    world: World,
    *,
    caller: int,
    to: int,
    calldata: bytes = b"",
    value: int = 0,
    gas: int = 1_000_000,
    env: Optional[dict[str, int]] = None,
    collect_pcs: bool = False,
) -> TxResult:
    """Convenience: one top-level message against ``world``."""
    return Machine(world, env=env, collect_pcs=collect_pcs).message_call(
        caller=caller, to=to, calldata=calldata, value=value, gas=gas
    )
