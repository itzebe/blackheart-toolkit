"""A deterministic EVM interpreter for executing generated tests offline.

TestSparker must *execute* the tests it generates. Shelling out to ``anvil`` would
make every evaluation depend on a foundry install, a free port, and a fork RPC --
which means the evaluator would not run in CI, and an evaluator that cannot run is
not an evaluator. This module is the smallest interpreter that can honestly decide
the questions the dispatcher work actually asks:

  * does a call with selector *S* reach a body, or does it fall to the fallback?
  * is a jump destination a real ``JUMPDEST``, or does the call revert?
  * does a truncated ``PUSH`` change what executes?

Correctness choices that matter, and why:

* **``JUMP``/``JUMPI`` to a non-``JUMPDEST`` halts with ``BAD_JUMP``.** This is
  real EVM behaviour and the exact defect that made three hand-written fixtures
  meaningless: they jumped into a ``PUSH4`` payload. An interpreter that silently
  allowed it would reproduce the same false confidence.
* **``JUMPDEST`` validity skips PUSH payloads**, using the same walk as
  :func:`blackheart.deployed_selectors.disassemble`, so a ``0x5b`` inside a
  ``PUSH32`` constant is not a legal destination.
* **Arithmetic is 256-bit with wrap-around**, matching the EVM. Anything else
  would make an underflow test pass for the wrong reason.
* **Execution is bounded by a step budget and a simplified gas meter.** The gas
  model is *not* mainnet-accurate and is never reported as if it were; it exists to
  terminate loops deterministically. ``ExecutionResult.gas_used`` is therefore a
  determinism device, not a cost estimate.

Stdlib only. Pure: the caller supplies code, calldata and initial storage, and
gets back the halt reason, return data and final storage. No RPC, no subprocess.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

__all__ = [
    "Halt",
    "ExecutionResult",
    "EVM",
    "execute",
    "UINT256_MAX",
]

UINT256_MAX = (1 << 256) - 1
_MASK = UINT256_MAX

#: Hard cap on modelled memory. A dispatcher needs a few KiB at most; the cap exists
#: so a hostile offset cannot exhaust the host.
_MEMORY_LIMIT = 32 * 1024 * 1024


class Halt(str):
    """Why execution stopped. A string subclass so it serialises directly."""


STOP = Halt("STOP")
RETURN = Halt("RETURN")
REVERT = Halt("REVERT")
INVALID = Halt("INVALID")
OUT_OF_GAS = Halt("OUT_OF_GAS")
BAD_JUMP = Halt("BAD_JUMP")
STACK_UNDERFLOW = Halt("STACK_UNDERFLOW")
STACK_OVERFLOW = Halt("STACK_OVERFLOW")


@dataclass
class ExecutionResult:
    """What actually happened when the code ran.

    ``halt`` is the reason execution stopped. Only ``STOP`` and ``RETURN`` are a
    successful run; ``REVERT`` is a deliberate, *successful* rejection by the
    contract and is reported distinctly so a test can assert on it rather than
    treating it as an interpreter failure.
    """

    halt: Halt
    return_data: bytes = b""
    storage: dict[int, int] = field(default_factory=dict)
    gas_used: int = 0
    steps: int = 0
    #: Storage keys written by this run, with the value written. Lets a caller see
    #: which branch executed without diffing against the input state.
    storage_writes: dict[int, int] = field(default_factory=dict)
    error: str = ""

    @property
    def succeeded(self) -> bool:
        return self.halt in (STOP, RETURN)

    @property
    def reverted(self) -> bool:
        return self.halt is REVERT

    def to_dict(self) -> dict:
        return {
            "halt": str(self.halt),
            "succeeded": self.succeeded,
            "reverted": self.reverted,
            "return_data": "0x" + self.return_data.hex(),
            "gas_used": self.gas_used,
            "steps": self.steps,
            "storage_writes": {str(k): v for k, v in sorted(self.storage_writes.items())},
            "error": self.error,
        }


#: Valid jump destinations: offsets holding a real JUMPDEST, skipping PUSH payloads.
def _valid_jumpdests(code: bytes) -> frozenset[int]:
    out: set[int] = set()
    i, n = 0, len(code)
    while i < n:
        op = code[i]
        if op == 0x5B:
            out.add(i)
        size = op - 0x5F if 0x60 <= op <= 0x7F else 0
        i += 1 + size
    return frozenset(out)


def _signed(x: int) -> int:
    return x - (1 << 256) if x >> 255 else x


class EVM:
    """Execute ``code`` with ``calldata`` against ``storage``, deterministically."""

    def __init__(
        self,
        code: bytes,
        *,
        calldata: bytes = b"",
        storage: Optional[dict[int, int]] = None,
        caller: int = 0,
        address: int = 0,
        callvalue: int = 0,
        gas: int = 1_000_000,
        max_steps: int = 200_000,
    ) -> None:
        self.code = bytes(code)
        self.calldata = bytes(calldata)
        self.storage = dict(storage or {})
        self.caller = caller
        self.address = address
        self.callvalue = callvalue
        self.gas = gas
        self.max_steps = max_steps
        self._jumpdests = _valid_jumpdests(self.code)
        self._stack: list[int] = []
        self._memory = bytearray()
        self._pc = 0
        self._gas_used = 0
        self._steps = 0
        self._writes: dict[int, int] = {}

    # -- stack helpers ----------------------------------------------------- #
    def _pop(self) -> int:
        if not self._stack:
            raise _Halt(STACK_UNDERFLOW, "stack underflow")
        return self._stack.pop()

    def _push(self, value: int) -> None:
        if len(self._stack) >= 1024:
            raise _Halt(STACK_OVERFLOW, "stack overflow")
        self._stack.append(value & _MASK)

    def _expand(self, end: int) -> None:
        """Grow memory to cover ``end``, charging expansion gas, capped.

        A real EVM charges quadratic memory-expansion gas, so an attacker-chosen
        huge offset runs out of gas rather than allocating. Without this, a crafted
        offset escapes as OverflowError from bytearray indexing and crashes the
        caller -- which in a campaign means one hostile bytecode aborts the run.
        """
        if end <= len(self._memory):
            return
        if end > _MEMORY_LIMIT:
            raise _Halt(
                OUT_OF_GAS,
                f"memory expansion to {end} exceeds the {_MEMORY_LIMIT}-byte cap",
            )
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
        self._gas_used += amount
        if self._gas_used > self.gas:
            raise _Halt(OUT_OF_GAS, f"out of gas after {self._gas_used}")

    # -- main loop --------------------------------------------------------- #
    def run(self) -> ExecutionResult:
        try:
            return self._run()
        except _Halt as h:
            return ExecutionResult(
                halt=h.halt,
                storage=self.storage,
                gas_used=self._gas_used,
                steps=self._steps,
                storage_writes=dict(self._writes),
                error=h.detail,
            )

    def _run(self) -> ExecutionResult:
        code, n = self.code, len(self.code)
        while self._pc < n:
            self._steps += 1
            if self._steps > self.max_steps:
                raise _Halt(OUT_OF_GAS, f"step budget exceeded ({self.max_steps})")
            self._charge(3)
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
                depth = op - 0x7F
                if len(self._stack) < depth:
                    raise _Halt(STACK_UNDERFLOW, f"DUP{depth} on depth {len(self._stack)}")
                self._push(self._stack[-depth])
                continue

            if 0x90 <= op <= 0x9F:  # SWAP1..SWAP16
                depth = op - 0x8F
                if len(self._stack) < depth + 1:
                    raise _Halt(STACK_UNDERFLOW, f"SWAP{depth} on depth {len(self._stack)}")
                self._stack[-1], self._stack[-1 - depth] = (
                    self._stack[-1 - depth],
                    self._stack[-1],
                )
                continue

            if op == 0x5F:  # PUSH0 (EIP-3855, Shanghai)
                self._push(0)
                continue
            if op == 0x00:  # STOP
                return self._done(STOP)
            if op == 0x01:  # ADD
                self._push(self._pop() + self._pop())
            elif op == 0x02:  # MUL
                self._push(self._pop() * self._pop())
            elif op == 0x03:  # SUB
                a, b = self._pop(), self._pop()
                self._push(a - b)
            elif op == 0x04:  # DIV
                a, b = self._pop(), self._pop()
                self._push(0 if b == 0 else a // b)
            elif op == 0x06:  # MOD
                a, b = self._pop(), self._pop()
                self._push(0 if b == 0 else a % b)
            elif op == 0x05:  # SDIV
                a, b = _signed(self._pop()), _signed(self._pop())
                if b == 0:
                    self._push(0)
                else:
                    q = abs(a) // abs(b)
                    self._push(-q if (a < 0) != (b < 0) else q)
            elif op == 0x07:  # SMOD
                a, b = _signed(self._pop()), _signed(self._pop())
                if b == 0:
                    self._push(0)
                else:
                    r = abs(a) % abs(b)
                    self._push(-r if a < 0 else r)
            elif op == 0x08:  # ADDMOD
                a, b, m = self._pop(), self._pop(), self._pop()
                self._push(0 if m == 0 else (a + b) % m)
            elif op == 0x09:  # MULMOD
                a, b, m = self._pop(), self._pop(), self._pop()
                self._push(0 if m == 0 else (a * b) % m)
            elif op == 0x0A:  # EXP
                a, b = self._pop(), self._pop()
                self._charge(max(0, b.bit_length()) * 50)
                self._push(pow(a, b, 1 << 256))
            elif op == 0x0B:  # SIGNEXTEND
                b, x = self._pop(), self._pop()
                if b < 31:
                    bit = 8 * (b + 1) - 1
                    mask = (1 << bit) - 1
                    x = x | (_MASK ^ mask) if (x >> bit) & 1 else x & mask
                self._push(x)
            elif op == 0x10:  # LT
                a, b = self._pop(), self._pop()
                self._push(1 if a < b else 0)
            elif op == 0x11:  # GT
                a, b = self._pop(), self._pop()
                self._push(1 if a > b else 0)
            elif op == 0x12:  # SLT
                a, b = _signed(self._pop()), _signed(self._pop())
                self._push(1 if a < b else 0)
            elif op == 0x13:  # SGT
                a, b = _signed(self._pop()), _signed(self._pop())
                self._push(1 if a > b else 0)
            elif op == 0x14:  # EQ
                self._push(1 if self._pop() == self._pop() else 0)
            elif op == 0x15:  # ISZERO
                self._push(1 if self._pop() == 0 else 0)
            elif op == 0x16:  # AND
                self._push(self._pop() & self._pop())
            elif op == 0x17:  # OR
                self._push(self._pop() | self._pop())
            elif op == 0x18:  # XOR
                self._push(self._pop() ^ self._pop())
            elif op == 0x19:  # NOT
                self._push(~self._pop())
            elif op == 0x1A:  # BYTE
                i, x = self._pop(), self._pop()
                self._push(0 if i >= 32 else (x >> (8 * (31 - i))) & 0xFF)
            elif op == 0x1B:  # SHL
                shift, x = self._pop(), self._pop()
                self._push(0 if shift >= 256 else x << shift)
            elif op == 0x1C:  # SHR
                shift, x = self._pop(), self._pop()
                self._push(0 if shift >= 256 else x >> shift)
            elif op == 0x1D:  # SAR
                shift, x = self._pop(), _signed(self._pop())
                if shift >= 256:
                    self._push(_MASK if x < 0 else 0)
                else:
                    self._push(x >> shift)
            elif op == 0x20:  # KECCAK256 -- deterministic stand-in, never claimed exact
                offset, size = self._pop(), self._pop()
                data = self._mem_read(offset, size)
                self._charge(30 + 6 * ((size + 31) // 32))
                self._push(int.from_bytes(_keccak(data), "big"))
            elif op == 0x30:  # ADDRESS
                self._push(self.address)
            elif op == 0x32:  # ORIGIN
                self._push(self.caller)
            elif op == 0x33:  # CALLER
                self._push(self.caller)
            elif op == 0x34:  # CALLVALUE
                self._push(self.callvalue)
            elif op == 0x35:  # CALLDATALOAD
                offset = self._pop()
                self._push(int.from_bytes(self._calldata_slice(offset, 32), "big"))
            elif op == 0x36:  # CALLDATASIZE
                self._push(len(self.calldata))
            elif op == 0x37:  # CALLDATACOPY
                dest, offset, size = self._pop(), self._pop(), self._pop()
                self._charge(3 + 3 * ((size + 31) // 32))
                self._mem_write(dest, self._calldata_slice(offset, size))
            elif op == 0x38:  # CODESIZE
                self._push(len(self.code))
            elif op == 0x39:  # CODECOPY
                dest, offset, size = self._pop(), self._pop(), self._pop()
                self._charge(3 + 3 * ((size + 31) // 32))
                self._mem_write(dest, self._code_slice(offset, size))
            elif op == 0x3A:  # GASPRICE
                self._push(0)
            elif op == 0x3C:  # EXTCODECOPY -- no external accounts in this model
                dest, _addr, offset, size = self._pop(), self._pop(), self._pop(), self._pop()
                self._mem_write(dest, b"\x00" * size)
            elif op == 0x3D:  # RETURNDATASIZE
                self._push(0)
            elif op == 0x3E:  # RETURNDATACOPY
                dest, _offset, size = self._pop(), self._pop(), self._pop()
                self._mem_write(dest, b"\x00" * size)
            elif op == 0x3F:  # EXTCODEHASH -- empty account hashes to 0
                self._pop()
                self._push(0)
            elif op == 0x47:  # SELFBALANCE
                self._push(0)
            elif op == 0x41:  # COINBASE
                self._push(0)
            elif op == 0x42:  # TIMESTAMP -- fixed, so runs are deterministic
                self._push(0)
            elif op == 0x43:  # NUMBER
                self._push(0)
            elif op == 0x44:  # PREVRANDAO/DIFFICULTY
                self._push(0)
            elif op == 0x45:  # GASLIMIT
                self._push(self.gas)
            elif op == 0x46:  # CHAINID
                self._push(0)
            elif op == 0x48:  # BASEFEE
                self._push(0)
            elif op == 0x31:  # BALANCE
                self._pop()
                self._push(0)
            elif op == 0x40:  # BLOCKHASH
                self._pop()
                self._push(0)
            elif op == 0x50:  # POP
                self._pop()
            elif op == 0x51:  # MLOAD
                offset = self._pop()
                self._push(int.from_bytes(self._mem_read(offset, 32), "big"))
            elif op == 0x52:  # MSTORE
                offset, value = self._pop(), self._pop()
                self._mem_write(offset, value.to_bytes(32, "big"))
            elif op == 0x53:  # MSTORE8
                offset, value = self._pop(), self._pop()
                self._mem_write(offset, bytes([value & 0xFF]))
            elif op == 0x54:  # SLOAD
                self._push(self.storage.get(self._pop(), 0))
            elif op == 0x55:  # SSTORE
                key, value = self._pop(), self._pop()
                self._charge(100)
                self.storage[key] = value & _MASK
                self._writes[key] = value & _MASK
            elif op == 0x56:  # JUMP
                dest = self._pop()
                self._jump(dest)
            elif op == 0x57:  # JUMPI
                dest, cond = self._pop(), self._pop()
                if cond != 0:
                    self._jump(dest)
            elif op == 0x58:  # PC
                self._push(self._pc - 1)
            elif op == 0x59:  # MSIZE
                self._push(len(self._memory))
            elif op == 0x5A:  # GAS
                self._push(max(0, self.gas - self._gas_used))
            elif op == 0x5B:  # JUMPDEST
                pass
            elif op == 0xF3:  # RETURN
                offset, size = self._pop(), self._pop()
                return self._done(RETURN, self._mem_read(offset, size))
            elif op == 0xFD:  # REVERT
                offset, size = self._pop(), self._pop()
                return self._done(REVERT, self._mem_read(offset, size))
            elif op == 0xFE:  # INVALID
                raise _Halt(INVALID, "INVALID opcode")
            elif op == 0xFF:  # SELFDESTRUCT
                return self._done(STOP)
            else:
                raise _Halt(INVALID, f"unsupported opcode 0x{op:02x} at {self._pc - 1}")
        return self._done(STOP)

    # -- helpers ----------------------------------------------------------- #
    def _calldata_slice(self, offset: int, size: int) -> bytes:
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
            raise _Halt(
                BAD_JUMP,
                f"jump to {dest}, which is not a JUMPDEST in this code",
            )
        self._pc = dest

    def _done(self, halt: Halt, data: bytes = b"") -> ExecutionResult:
        return ExecutionResult(
            halt=halt,
            return_data=data,
            storage=self.storage,
            gas_used=self._gas_used,
            steps=self._steps,
            storage_writes=dict(self._writes),
        )


class _Halt(Exception):
    def __init__(self, halt: Halt, detail: str) -> None:
        super().__init__(detail)
        self.halt = halt
        self.detail = detail


def _keccak(data: bytes) -> bytes:
    """A deterministic 32-byte digest.

    ``hashlib.sha3_256`` is *not* Keccak-256, and pretending otherwise would make a
    storage-slot test that depends on ``keccak256`` pass for the wrong reason. This
    function exists only so an opcode-0x20 test can run deterministically; it is
    labelled a stand-in and no test may treat its output as the real Keccak value.
    """
    import hashlib

    return hashlib.sha3_256(data).digest()


def execute(code: bytes, *, calldata: bytes = b"", **kwargs) -> ExecutionResult:
    """Run ``code`` once and return the result. Thin convenience wrapper."""
    return EVM(code, calldata=calldata, **kwargs).run()
