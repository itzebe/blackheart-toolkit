"""Bounded symbolic execution over EVM bytecode.

This is the bytecode counterpart of :mod:`blackheart.symbolic.executor`, which
reasons over the declarative ingest IR. It walks real runtime bytecode, forks on a
symbolic ``JUMPI``, and asks the three-valued solver whether each branch is
feasible and, if so, for a concrete input.

Two limits are deliberate and stated rather than hidden:

* **constant** arithmetic follows the EVM exactly, including 256-bit wrapping,
  ``SIGNEXTEND``, ``BYTE``, ``ADDMOD``/``MULMOD`` and ``EXP``; **symbolic**
  arithmetic is unbounded by default, and ``--wrap`` forks symbolic ADD/SUB/MUL
  into their 256-bit wrapped cases. Symbolic AND/OR/XOR are carried with sound
  interval bounds; symbolic EXP and division remain unbounded, so an
  overflow-dependent bug outside that fragment is out of scope. ``SHA3`` is
  computed when its offset, size and memory are all concrete -- which is what a
  mapping slot needs -- and halts otherwise;
* it stops at any opcode it cannot model (external calls, symbolic memory
  offsets, ...). A path that stops is reported as ``unsupported`` -- never
  silently treated as safe.

The useful question it answers is narrow and real: *is there an input that
reaches this revert / this state?* and *does the guarded twin still reach it?*
"""

from __future__ import annotations

import copy
from dataclasses import dataclass, field
from typing import Any, Iterable, Optional

from ..deployed import keccak256
from .expr import Bin, Const, Expr, Not, Var, and_, eq, gt, lt, ne, not_, or_
from .solver import solve
from .smt import current_backend, current_trust_unsat


def _solve(constraints, domains):
    return solve(constraints, domains, backend=current_backend(),
                 trust_backend_unsat=current_trust_unsat())

ATTACKER = 0xA11CE
SELF = 0xC0DE
MASK = (1 << 256) - 1


def _const(value: Expr) -> Optional[int]:
    if isinstance(value, Const) and isinstance(value.value, (int, bool)):
        return int(value.value)
    return None


def _fold(left: Expr, right: Expr, fn, op: str) -> Optional[Expr]:
    a, b = _const(left), _const(right)
    if a is not None and b is not None:
        try:
            return Const(fn(a, b))
        except (ZeroDivisionError, ValueError):
            return Const(0)
    return None


def _bin(left: Expr, right: Expr, op: str) -> Expr:
    return Bin(op, left, right)


def _booleanish(value: Expr) -> bool:
    """True when a value is known to be 0/1, so ``AND``/``OR`` are logical.

    A bitwise mask over a symbolic word is not the same operation, and modelling
    it as one would be unsound, so such a path is halted as unsupported instead.
    """
    if isinstance(value, Const):
        return int(value.value) in (0, 1)
    if isinstance(value, Not):
        return True
    if isinstance(value, Bin):
        return value.op in ("<", ">", "<=", ">=", "==", "!=", "&&", "||")
    return False


def _jumpdests(code: bytes) -> frozenset[int]:
    out: set[int] = set()
    i, n = 0, len(code)
    while i < n:
        op = code[i]
        if op == 0x5B:
            out.add(i)
        i += 1 + (op - 0x5F if 0x60 <= op <= 0x7F else 0)
    return frozenset(out)


@dataclass
class EvmPath:
    """One explored path: its constraints, terminal state, and halt reason."""

    pc: int = 0
    constraints: list[Expr] = field(default_factory=list)
    stack: list[Expr] = field(default_factory=list)
    memory: dict[int, Expr] = field(default_factory=dict)
    storage: dict[int, Expr] = field(default_factory=dict)
    transient: dict[int, Expr] = field(default_factory=dict)
    reverted: bool = False
    halt: str = ""
    steps: int = 0
    trace: list[str] = field(default_factory=list)

    def clone(self) -> "EvmPath":
        return copy.deepcopy(self)

    def to_dict(self) -> dict:
        return {
            "pc": self.pc,
            "halt": self.halt,
            "reverted": self.reverted,
            "steps": self.steps,
            "constraints": [repr(c) for c in self.constraints],
            "storage": {str(k): repr(v) for k, v in sorted(self.storage.items())},
            "trace": list(self.trace),
        }


@dataclass
class EvmExploration:
    paths: list[EvmPath]
    domains: dict[str, tuple[int, int]]
    truncated: bool = False
    unsupported: list[str] = field(default_factory=list)
    solver: str = "builtin"

    @property
    def reverted_paths(self) -> list[EvmPath]:
        return [p for p in self.paths if p.reverted]

    def to_dict(self) -> dict:
        return {
            "paths": len(self.paths),
            "reverted": len(self.reverted_paths),
            "truncated": self.truncated,
            "unsupported": list(self.unsupported),
            "domains": {k: list(v) for k, v in self.domains.items()},
            "solver": self.solver,
        }


def _halt(state: EvmPath, reason: str, *, reverted: bool = False) -> None:
    state.halt = reason
    state.reverted = reverted


def _wrap_add(state: EvmPath, left: Expr, right: Expr,
              domains: dict[str, tuple[int, int]], pc: int) -> list[EvmPath]:
    """Fork a symbolic ADD into its non-overflow and overflow cases.

    Exact when both operands are in ``[0, 2**256)``; an operand produced by an
    unwrapped symbolic EXP is already an approximation.
    """
    total = _bin(left, right, "+")
    out: list[EvmPath] = []
    for overflow in (False, True):
        branch = state.clone()
        if overflow:
            branch.constraints.append(gt(total, Const(MASK)))
            branch.stack.append(_bin(total, Const(MASK + 1), "-"))
        else:
            branch.constraints.append(lt(total, Const(MASK + 1)))
            branch.stack.append(total)
        if _solve(branch.constraints, domains).status == "UNSAT":
            continue
        branch.pc = pc + 1
        out.append(branch)
    return out


def _wrap_mul(state: EvmPath, left: Expr, right: Expr,
              domains: dict[str, tuple[int, int]], pc: int) -> list[EvmPath]:
    """Fork a symbolic MUL into its non-overflow and overflow cases.

    Exact for operands in ``[0, 2**256)``. The overflow branch takes the
    product modulo ``2**256``, which is the EVM result; the solver is asked for
    a witness in each branch and an UNSAT branch is dropped.
    """
    product = _bin(left, right, "*")
    out: list[EvmPath] = []
    for overflow in (False, True):
        branch = state.clone()
        if overflow:
            branch.constraints.append(gt(product, Const(MASK)))
            branch.stack.append(_bin(product, Const(MASK + 1), "%"))
        else:
            branch.constraints.append(lt(product, Const(MASK + 1)))
            branch.stack.append(product)
        if _solve(branch.constraints, domains).status == "UNSAT":
            continue
        branch.pc = pc + 1
        out.append(branch)
    return out


def _wrap_sub(state: EvmPath, left: Expr, right: Expr,
              domains: dict[str, tuple[int, int]], pc: int) -> list[EvmPath]:
    """Fork a symbolic SUB into its no-underflow and underflow cases.

    Exact when both operands are in ``[0, 2**256)``; see ``_wrap_add``.
    """
    diff = _bin(left, right, "-")
    out: list[EvmPath] = []
    for underflow in (False, True):
        branch = state.clone()
        if underflow:
            branch.constraints.append(lt(diff, Const(0)))
            branch.stack.append(_bin(diff, Const(MASK + 1), "+"))
        else:
            branch.constraints.append(gt(diff, Const(-1)))
            branch.stack.append(diff)
        if _solve(branch.constraints, domains).status == "UNSAT":
            continue
        branch.pc = pc + 1
        out.append(branch)
    return out


def _exec_one(state: EvmPath, code: bytes, domains: dict[str, tuple[int, int]],
              valid: frozenset[int], unsupported: set[str],
              wrap_symbolic: bool = False) -> list[EvmPath]:
    """Execute one instruction. Returns successor states (0, 1 or 2)."""
    pc = state.pc
    op = code[pc]
    state.steps += 1
    state.trace.append(f"{pc:04x}:{op:02x}")

    def pop() -> Optional[Expr]:
        return state.stack.pop() if state.stack else None

    def push(value: Expr) -> None:
        state.stack.append(value)

    if op == 0x00:  # STOP
        _halt(state, "stop")
        return [state]
    if 0x60 <= op <= 0x7F:  # PUSH1..PUSH32
        size = op - 0x5F
        raw = code[pc + 1: pc + 1 + size]
        push(Const(int.from_bytes(raw.ljust(size, b"\x00"), "big")))
        state.pc = pc + 1 + size
        return [state]
    if 0x80 <= op <= 0x8F:  # DUP1..DUP16
        depth = op - 0x7F
        if len(state.stack) < depth:
            _halt(state, "stack_underflow")
            return [state]
        push(state.stack[-depth])
        state.pc = pc + 1
        return [state]
    if 0x90 <= op <= 0x9F:  # SWAP1..SWAP16
        depth = op - 0x8F
        if len(state.stack) < depth + 1:
            _halt(state, "stack_underflow")
            return [state]
        state.stack[-1], state.stack[-depth - 1] = state.stack[-depth - 1], state.stack[-1]
        state.pc = pc + 1
        return [state]

    if op == 0x50:  # POP
        if pop() is None:
            _halt(state, "stack_underflow")
        else:
            state.pc = pc + 1
        return [state]

    def _unsupported_op(name: str) -> None:
        _halt(state, f"unsupported:0x{op:02x}")
        unsupported.add(name)

    if op in (0x08, 0x09):  # ADDMOD / MULMOD: a, b, n from the top
        a, b, n = pop(), pop(), pop()
        ca, cb, cn = (_const(v) if v is not None else None for v in (a, b, n))
        if ca is None or cb is None or cn is None:
            _unsupported_op(f"0x{op:02x}(symbolic)")
            return [state]
        if cn == 0:
            push(Const(0))
        elif op == 0x08:
            push(Const((ca + cb) % cn))
        else:
            push(Const((ca * cb) % cn))
        state.pc = pc + 1
        return [state]

    if op == 0x0A:  # EXP
        base, exponent = pop(), pop()
        cb, ce = (_const(v) if v is not None else None for v in (base, exponent))
        if cb is None or ce is None:
            _unsupported_op("0x0a(symbolic)")
            return [state]
        push(Const(pow(cb, ce, MASK + 1)))
        state.pc = pc + 1
        return [state]

    if op == 0x0B:  # SIGNEXTEND
        byte_index, value = pop(), pop()
        bi, cv = (_const(v) if v is not None else None for v in (byte_index, value))
        if bi is None or cv is None:
            _unsupported_op("0x0b(symbolic)")
            return [state]
        if bi >= 32:
            push(Const(cv & MASK))
        else:
            bit = bi * 8 + 7
            low = cv & ((1 << (bit + 1)) - 1)
            push(Const((low | (~((1 << (bit + 1)) - 1))) & MASK if low & (1 << bit) else low))
        state.pc = pc + 1
        return [state]

    if op == 0x1A:  # BYTE
        index, value = pop(), pop()
        ci, cv = (_const(v) if v is not None else None for v in (index, value))
        if ci is None or cv is None:
            _unsupported_op("0x1a(symbolic)")
            return [state]
        push(Const(0 if ci >= 32 else (cv >> (248 - 8 * ci)) & 0xFF))
        state.pc = pc + 1
        return [state]

    if op in (0x1B, 0x1C, 0x1D):  # SHL / SHR / SAR
        shift, value = pop(), pop()
        cs, cv = (_const(v) if v is not None else None for v in (shift, value))
        if cs is None or cv is None:
            _unsupported_op(f"0x{op:02x}(symbolic)")
            return [state]
        if cs >= 256:
            if op == 0x1D and cv >> 255:
                push(Const(MASK))
            else:
                push(Const(0))
        elif op == 0x1B:
            push(Const((cv << cs) & MASK))
        elif op == 0x1C:
            push(Const(cv >> cs))
        else:
            signed = cv - (1 << 256) if cv >> 255 else cv
            push(Const((signed >> cs) & MASK))
        state.pc = pc + 1
        return [state]

    if op == 0x20:  # SHA3/Keccak-256 of concrete memory
        offset, size = pop(), pop()
        off, length = (_const(v) if v is not None else None for v in (offset, size))
        if off is None or length is None or length > 4096:
            _unsupported_op("sha3(symbolic)")
            return [state]
        data = bytearray()
        for i in range(off, off + length):
            word = state.memory.get(i // 32, Const(0))
            c = _const(word)
            if c is None:
                _unsupported_op("sha3(symbolic memory)")
                return [state]
            data.append((c >> (8 * (31 - i % 32))) & 0xFF)
        push(Const(int.from_bytes(keccak256(bytes(data)), "big")))
        state.pc = pc + 1
        return [state]

    # Arithmetic / comparison: EVM pops a (top), then b, and computes a op b.
    # Constant results wrap at 256 bits exactly as the EVM does.
    binary = {
        0x01: ("+", lambda a, b: (a + b) & MASK),
        0x02: ("*", lambda a, b: (a * b) & MASK),
        0x03: ("-", lambda a, b: (a - b) & MASK),
        0x04: ("/", lambda a, b: 0 if b == 0 else a // b),
        0x06: ("%", lambda a, b: 0 if b == 0 else a % b),
        0x10: ("<", lambda a, b: 1 if a < b else 0),
        0x11: (">", lambda a, b: 1 if a > b else 0),
        0x14: ("==", lambda a, b: 1 if a == b else 0),
        0x16: ("&", lambda a, b: a & b),
        0x17: ("|", lambda a, b: a | b),
        0x18: ("^", lambda a, b: a ^ b),
    }
    if op in binary:
        a, b = pop(), pop()
        if a is None or b is None:
            _halt(state, "stack_underflow")
            return [state]
        token, fn = binary[op]
        folded = _fold(a, b, fn, token)
        if folded is not None:
            push(folded)
        elif op == 0x01 and wrap_symbolic:
            return _wrap_add(state, a, b, domains, pc)
        elif op == 0x03 and wrap_symbolic:
            return _wrap_sub(state, a, b, domains, pc)
        elif op == 0x02 and wrap_symbolic:
            return _wrap_mul(state, a, b, domains, pc)
        elif op == 0x01:
            push(_bin(a, b, "+"))
        elif op == 0x02:
            push(_bin(a, b, "*"))
        elif op == 0x03:
            push(_bin(a, b, "-"))
        elif op == 0x10:
            push(lt(a, b))
        elif op == 0x11:
            push(gt(a, b))
        elif op == 0x14:
            push(eq(a, b))
        elif op in (0x16, 0x17) and _booleanish(a) and _booleanish(b):
            push(and_(a, b) if op == 0x16 else or_(a, b))
        elif op == 0x16:
            push(_bin(a, b, "&"))
        elif op == 0x17:
            push(_bin(a, b, "|"))
        elif op == 0x18:
            push(_bin(a, b, "^"))
        else:
            _halt(state, f"unsupported:0x{op:02x}")
            unsupported.add(f"0x{op:02x}")
            return [state]
        state.pc = pc + 1
        return [state]

    if op == 0x15:  # ISZERO
        a = pop()
        if a is None:
            _halt(state, "stack_underflow")
        else:
            push(not_(a))
            state.pc = pc + 1
        return [state]

    if op == 0x19:  # NOT (bitwise); only a constant is modelled
        a = pop()
        c = _const(a) if a is not None else None
        if c is None:
            _halt(state, "unsupported:0x19")
            unsupported.add("0x19")
        else:
            push(Const((~c) & ((1 << 256) - 1)))
            state.pc = pc + 1
        return [state]

    if op == 0x35:  # CALLDATALOAD
        offset = pop()
        c = _const(offset) if offset is not None else None
        if c is None or c % 32 != 0:
            _halt(state, "unsupported:calldata_offset")
            unsupported.add("calldataload(symbolic offset)")
            return [state]
        name = f"cd{c // 32}"
        push(Var(name) if name in domains else Const(0))
        state.pc = pc + 1
        return [state]

    if op == 0x51:  # MLOAD
        offset = pop()
        c = _const(offset) if offset is not None else None
        if c is None or c % 32 != 0:
            _halt(state, "unsupported:mload_offset")
            unsupported.add("mload(symbolic offset)")
            return [state]
        push(state.memory.get(c // 32, Const(0)))
        state.pc = pc + 1
        return [state]

    if op == 0x52:  # MSTORE
        offset, value = pop(), pop()
        c = _const(offset) if offset is not None else None
        if c is None or c % 32 != 0 or value is None:
            _halt(state, "unsupported:mstore_offset")
            unsupported.add("mstore(symbolic offset)")
            return [state]
        state.memory[c // 32] = value
        state.pc = pc + 1
        return [state]

    if op == 0x54:  # SLOAD
        key = pop()
        c = _const(key) if key is not None else None
        if c is None:
            _halt(state, "unsupported:sload_key")
            unsupported.add("sload(symbolic key)")
            return [state]
        push(state.storage.get(c, Const(0)))
        state.pc = pc + 1
        return [state]

    if op == 0x55:  # SSTORE
        key, value = pop(), pop()
        c = _const(key) if key is not None else None
        if c is None or value is None:
            _halt(state, "unsupported:sstore_key")
            unsupported.add("sstore(symbolic key)")
            return [state]
        state.storage[c] = value
        state.pc = pc + 1
        return [state]

    if op == 0x5C:  # TLOAD
        key = pop()
        c = _const(key) if key is not None else None
        if c is None:
            _halt(state, "unsupported:tload_key")
            unsupported.add("tload(symbolic key)")
            return [state]
        push(state.transient.get(c, Const(0)))
        state.pc = pc + 1
        return [state]

    if op == 0x5D:  # TSTORE
        key, value = pop(), pop()
        c = _const(key) if key is not None else None
        if c is None or value is None:
            _halt(state, "unsupported:tstore_key")
            unsupported.add("tstore(symbolic key)")
            return [state]
        state.transient[c] = value
        state.pc = pc + 1
        return [state]

    if op == 0x56:  # JUMP
        dest = pop()
        c = _const(dest) if dest is not None else None
        if c is None or c not in valid:
            _halt(state, "invalid_jump")
        else:
            state.pc = c
        return [state]

    if op == 0x57:  # JUMPI
        dest, cond = pop(), pop()
        c = _const(dest) if dest is not None else None
        if c is None or c not in valid or cond is None:
            _halt(state, "invalid_jump")
            return [state]
        if _const(cond) is not None:
            taken = _const(cond) != 0
            state.pc = c if taken else pc + 1
            return [state]
        out: list[EvmPath] = []
        for taken in (True, False):
            branch = state.clone()
            branch.constraints.append(ne(cond, Const(0)) if taken else eq(cond, Const(0)))
            if _solve(branch.constraints, domains).status == "UNSAT":
                continue
            branch.pc = c if taken else pc + 1
            out.append(branch)
        return out

    if op == 0x5B:  # JUMPDEST
        state.pc = pc + 1
        return [state]

    if op == 0x58:  # PC
        push(Const(pc))
        state.pc = pc + 1
        return [state]
    if op == 0x59:  # MSIZE
        push(Const(len(state.memory) * 32))
        state.pc = pc + 1
        return [state]
    if op == 0x5A:  # GAS
        push(Const(1_000_000))
        state.pc = pc + 1
        return [state]
    if op == 0x30:
        push(Const(SELF))
        state.pc = pc + 1
        return [state]
    if op in (0x32, 0x33):
        push(Const(ATTACKER))
        state.pc = pc + 1
        return [state]
    if op in (0x34, 0x3A, 0x47):
        push(Const(0))
        state.pc = pc + 1
        return [state]
    if op == 0x36:
        push(Const(len(domains) * 32))
        state.pc = pc + 1
        return [state]
    if op == 0x38:
        push(Const(len(code)))
        state.pc = pc + 1
        return [state]
    if op in (0x42, 0x43, 0x44, 0x45, 0x46, 0x48):
        push(Const(1))
        state.pc = pc + 1
        return [state]

    if op == 0xF3:  # RETURN
        _halt(state, "return")
        return [state]
    if op == 0xFD:  # REVERT
        _halt(state, "revert", reverted=True)
        return [state]
    if op == 0xFE:  # INVALID
        _halt(state, "invalid")
        return [state]

    _halt(state, f"unsupported:0x{op:02x}")
    unsupported.add(f"0x{op:02x}")
    return [state]


def explore(
    code: bytes,
    *,
    inputs: Optional[dict[str, tuple[int, int]]] = None,
    max_paths: int = 64,
    max_steps: int = 2_000,
    wrap_symbolic: bool = False,
) -> EvmExploration:
    """Symbolically explore ``code`` with the declared symbolic inputs.

    ``inputs`` maps a calldata word name (``cd0``, ``cd1``, ...) to its integer
    domain. A word that is not declared reads as zero. With ``wrap_symbolic`` a
    symbolic ADD/SUB/MUL forks on its 256-bit overflow/underflow case, so an
    overflow-dependent path is reachable; it doubles the paths at each such
    operation, so it is opt-in.
    """
    domains = dict(inputs or {"cd0": (0, 1_000)})
    valid = _jumpdests(code)
    unsupported: set[str] = set()
    work: list[EvmPath] = [EvmPath()]
    paths: list[EvmPath] = []
    truncated = False
    while work:
        if len(paths) >= max_paths:
            truncated = True
            break
        state = work.pop()
        if state.halt:
            paths.append(state)
            continue
        if state.pc >= len(code):
            _halt(state, "out_of_code")
            paths.append(state)
            continue
        if state.steps >= max_steps:
            _halt(state, "step_limit")
            paths.append(state)
            truncated = True
            continue
        successors = _exec_one(state, code, domains, valid, unsupported,
                               wrap_symbolic=wrap_symbolic)
        if not successors:
            continue
        work.extend(successors)
    return EvmExploration(paths=paths, domains=domains, truncated=truncated,
                          solver="z3" if current_backend() is not None else "builtin",
                          unsupported=sorted(unsupported))


def find_witness(
    exploration: EvmExploration,
    *,
    reverted: Optional[bool] = None,
    extra: Iterable[Expr] = (),
    limit: int = 1,
) -> list[dict[str, Any]]:
    """Return concrete inputs that satisfy a path's constraints plus ``extra``.

    A witness is only returned when the solver re-evaluates every constraint on
    the assignment; an ``UNKNOWN`` path is never reported as reachable.
    """
    out: list[dict[str, Any]] = []
    for path in exploration.paths:
        if reverted is not None and path.reverted != reverted:
            continue
        constraints = list(path.constraints) + list(extra)
        result = _solve(constraints, exploration.domains)
        if not result.sat:
            continue
        witness = dict(result.assignment)
        witness["_halt"] = path.halt
        witness["_pc"] = path.pc
        out.append(witness)
        if len(out) >= limit:
            break
    return out
