"""Which selectors are actually dispatch-reachable, not merely present as data.

``selector_present`` answers a weaker question than the one that matters. A
4-byte value appears in runtime bytecode for two very different reasons:

  1. it is compared against ``calldataload(0)`` in a dispatcher, so a call with
     that selector reaches code; or
  2. it is ordinary data -- an error string, a constant, an ABI table entry, the
     payload of a ``PUSH4`` used in arithmetic -- and no call with it ever lands
     anywhere.

Treating (2) as evidence of a callable entry point manufactures false leads, and
a false lead is worse than a gap: it spends the budget of a real investigation on
a function that does not exist.

This module recovers the real structure with a linear scan over the EVM opcodes,
which is enough for the shapes a Solidity dispatcher actually takes:

  * the classic ``DUP1 PUSH4 <sel> EQ PUSH2 <dest> JUMPI`` chain;
  * the same comparison with the selector pushed *before* the calldata load;
  * ``PUSH4 <sel>`` followed by ``EQ`` and a jump, where the calldata value was
    already on the stack.

The scan is deliberately conservative. A selector is reported as reachable only
when it is the operand of a ``PUSH4`` that is *consumed by a comparison whose
result feeds a conditional jump*. Anything it cannot prove is reported as
present-but-not-proven-reachable, which is the honest answer and the one the
doctrine demands: presence is a fingerprint, reachability needs a dispatch.

Pure logic, stdlib only, no RPC. The caller supplies the bytecode.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

__all__ = [
    "REACHABLE",
    "PRESENT_ONLY",
    "AMBIGUOUS",
    "DispatchSelector",
    "SelectorDispatchReport",
    "analyse_selectors",
    "opcode_operand_size",
    "disassemble",
]

#: A selector whose PUSH4 operand feeds a comparison that guards a jump.
REACHABLE = "REACHABLE"
#: A selector that occurs in the bytecode but whose use could not be tied to a
#: conditional-jump dispatch. Never to be reported as a callable entry point.
PRESENT_ONLY = "PRESENT_ONLY"
#: A selector whose constant reaches control flow without a comparison the scan
#: can resolve. Distinct from plain data: the truth is *unknown*, not "not
#: dispatched". It is never promoted to REACHABLE; the marker exists so a
#: consumer can tell "we proved this is not an entry point" from "we could not
#: decide", instead of reading an unresolved shape as a settled negative.
AMBIGUOUS = "AMBIGUOUS"

# Operand byte-length for every opcode that carries immediate data. Anything not
# listed here has no operand; the table is only used to *skip* immediates so that
# bytes inside a PUSH payload are never mistaken for opcodes.
_OPERAND_SIZE: dict[int, int] = {0x60 + i: i + 1 for i in range(32)}  # PUSH1..PUSH32


def opcode_operand_size(op: int) -> int:
    """Immediate operand bytes for ``op``, or 0 when it takes none."""
    return _OPERAND_SIZE.get(op, 0)


def disassemble(code: bytes) -> list[tuple[int, int, Optional[bytes]]]:
    """Yield ``(offset, opcode, operand)`` for each real instruction.

    ``operand`` is the raw immediate for a PUSH, else ``None``. The walk skips
    push payloads, so a byte inside a PUSH4 constant is never read as an opcode --
    the bug that makes naive scanners report phantom instructions.
    """
    out: list[tuple[int, int, Optional[bytes]]] = []
    i, n = 0, len(code)
    while i < n:
        op = code[i]
        size = opcode_operand_size(op)
        operand = code[i + 1 : i + 1 + size] if size else None
        # A truncated trailing PUSH cannot be interpreted; stop rather than
        # invent the missing bytes.
        if size and len(operand or b"") < size:
            break
        out.append((i, op, operand))
        i += 1 + size
    return out


# Opcodes that consume two stack items and leave a comparison result.
_EQ = 0x14
# ``SUB`` is the other way solc spells an equality test. The via-IR pipeline emits
# ``PUSH4 <sel> SUB PUSH2 <dest> JUMPI``: ``a - b`` is zero exactly when ``a == b``,
# and JUMPI treats non-zero as taken, so the branch *falls through* on equality and
# the body is reached by the jump that follows. Only this exact shape is accepted:
# a SUB whose result is tested for zero by a JUMPI (optionally through ISZERO).
_SUB = 0x03
_ISZERO = 0x15
# Conditional jumps: JUMPI consumes (dest, condition).
_JUMPI = 0x57
# The only instruction allowed between the comparison and its jump: ``DUP1``.
#
# The set is deliberately this narrow. Every opcode omitted here would let a
# comparison be counted as guarding a jump it does not guard:
#   * POP (0x50) discards the result, so the jump uses something else;
#   * SWAPn (0x90..0x9F) moves another value to the top;
#   * DUP2..DUP16 push a copy of a *lower* slot, not the result;
#   * JUMPDEST (0x5B) is a second entry point, so the stack on arrival is not
#     necessarily the one this comparison produced.
# A false "reachable" is a false lead, which is the defect this module exists to
# prevent, so ambiguity must resolve to "not proven".
_STACK_NEUTRAL_BETWEEN = frozenset({0x80})  # DUP1

#: ``JUMPDEST`` -- the only byte a ``JUMP``/``JUMPI`` may legally land on.
_JUMPDEST = 0x5B


def _valid_jumpdests(raw: bytes) -> frozenset[int]:
    """Offsets that hold a real ``JUMPDEST`` (not a byte inside a PUSH payload)."""
    return frozenset(off for off, op, _ in disassemble(raw) if op == _JUMPDEST)


def _decode_code(code: str | bytes) -> bytes:
    """Turn ``code`` into raw bytes, rejecting malformed input explicitly.

    ``eth_getCode`` returns lower-case ``0x``-prefixed hex, but a caller can pass
    an upper-case prefix or an odd number of nibbles; ``bytes.fromhex`` raises a
    bare ``ValueError`` for both, which surfaces as an unhandled crash rather than
    a clear message. The prefix is case-insensitive here and an odd length is a
    malformed payload, so it is named as such.
    """
    if isinstance(code, (bytes, bytearray)):
        return bytes(code)
    if not isinstance(code, str):
        raise TypeError(f"code must be hex str or bytes, not {type(code).__name__}")
    body = code[2:] if code[:2].lower() == "0x" else code
    if len(body) % 2:
        raise ValueError(f"hex bytecode has an odd number of nibbles ({len(body)})")
    try:
        return bytes.fromhex(body)
    except ValueError as exc:
        raise ValueError(f"hex bytecode is not valid hex: {exc}") from exc


#: Text keys solc actually emits in its metadata map.
_METADATA_KEYS = frozenset({"ipfs", "bzzr0", "bzzr1", "solc", "experimental"})
#: The shortest plausible solc metadata map; anything smaller is a coincidence.
_METADATA_MIN_BYTES = 24


def _cbor_item_end(buf: bytes, i: int) -> int:
    """End offset of one CBOR data item starting at ``i``, or -1 if malformed.

    Only the subset solc emits is supported: unsigned ints, byte strings, text
    strings, and definite-length maps. That is enough to validate a metadata
    trailer without a CBOR dependency, and anything outside it is rejected rather
    than guessed at.
    """
    if i >= len(buf):
        return -1
    major, info = buf[i] >> 5, buf[i] & 0x1F
    i += 1
    if info < 24:
        arg = info
    elif info in (24, 25, 26, 27):
        width = 1 << (info - 24)
        if i + width > len(buf):
            return -1
        arg = int.from_bytes(buf[i : i + width], "big")
        i += width
    else:
        return -1
    if major == 0:
        return i
    if major in (2, 3):
        return i + arg if i + arg <= len(buf) else -1
    if major == 5:
        for _ in range(arg):
            i = _cbor_item_end(buf, i)
            if i < 0:
                return -1
            i = _cbor_item_end(buf, i)
            if i < 0:
                return -1
        return i
    return -1


def _is_solc_metadata(buf: bytes) -> bool:
    """True if ``buf`` is a complete solc metadata map and nothing else.

    A length word at the end of arbitrary code can point at a stray ``0xa2``; that
    is why a single-byte check is not enough. The map must parse to exactly its
    own length and every key must be one solc writes.
    """
    if len(buf) < _METADATA_MIN_BYTES or not buf or buf[0] not in (0xA1, 0xA2):
        return False
    if _cbor_item_end(buf, 0) != len(buf):
        return False
    pairs = buf[0] & 0x1F
    i = 1
    for _ in range(pairs):
        if i >= len(buf) or buf[i] >> 5 != 3:  # key must be a text string
            return False
        length = buf[i] & 0x1F
        i += 1
        if length >= 24 or i + length > len(buf):
            return False
        if buf[i : i + length].decode("ascii", "replace") not in _METADATA_KEYS:
            return False
        i += length
        i = _cbor_item_end(buf, i)
        if i < 0:
            return False
    return i == len(buf)


def _strip_metadata(raw: bytes) -> tuple[bytes, bool]:
    """Split off solc's CBOR metadata trailer, returning ``(code, stripped)``.

    solc appends a CBOR map (``a2 64 "ipfs" ... 64 "solc" ...``) whose length is
    the big-endian value of the final two bytes. It is data, not instructions, so
    walking into it reads a PUSH payload as code and reports a "truncated PUSH" on
    essentially every real contract -- a warning that would then never carry
    information. The trailer is only removed when the declared region parses as a
    complete solc metadata map; a stray length word pointing at an incidental
    ``0xa2`` inside real code is rejected, so the walk proceeds and any genuine
    truncation is still surfaced.
    """
    if len(raw) < _METADATA_MIN_BYTES + 2:
        return raw, False
    declared = int.from_bytes(raw[-2:], "big")
    start = len(raw) - 2 - declared
    if declared >= _METADATA_MIN_BYTES and 0 < start and _is_solc_metadata(raw[start:-2]):
        return raw[:start], True
    return raw, False


@dataclass
class DispatchSelector:
    """One 4-byte value found in the bytecode, with the evidence for its role."""

    selector: str
    status: str
    #: Byte offsets of the PUSH4 instructions that carry this value.
    push4_offsets: list[int] = field(default_factory=list)
    #: Offsets where the value is compared and that comparison guards a JUMPI.
    dispatch_offsets: list[int] = field(default_factory=list)
    #: Human-readable justification, so a reviewer can audit the verdict.
    evidence: str = ""
    #: True when the shape was unresolved. Such a selector is reported
    #: ``PRESENT_ONLY`` (presence is never promoted) but is not a settled
    #: negative, and ``SelectorDispatchReport.ambiguous`` surfaces it.
    ambiguous: bool = False

    @property
    def reachable(self) -> bool:
        return self.status == REACHABLE

    def to_dict(self) -> dict:
        return {
            "selector": self.selector,
            "status": self.status,
            "push4_offsets": self.push4_offsets,
            "dispatch_offsets": self.dispatch_offsets,
            "evidence": self.evidence,
            "ambiguous": self.ambiguous,
        }


@dataclass
class SelectorDispatchReport:
    """Every 4-byte value in a contract, split by proven reachability."""

    code_size: int
    selectors: list[DispatchSelector] = field(default_factory=list)
    #: Set when the bytecode could not be walked (e.g. truncated PUSH).
    incomplete_reason: str = ""
    #: True when solc's CBOR metadata trailer was recognised and excluded.
    metadata_stripped: bool = False

    @property
    def reachable(self) -> list[DispatchSelector]:
        return [s for s in self.selectors if s.reachable]

    @property
    def present_only(self) -> list[DispatchSelector]:
        """Selectors that are not proven reachable -- includes the ambiguous ones.

        ``present_only`` is deliberately left as "not reachable" so existing
        counts do not move; :attr:`ambiguous` is the subset that is *undecided*
        rather than settled data.
        """
        return [s for s in self.selectors if not s.reachable]

    @property
    def ambiguous(self) -> list[DispatchSelector]:
        """Selectors whose dispatcher shape could not be resolved either way."""
        return [s for s in self.selectors if s.ambiguous]

    @property
    def complete(self) -> bool:
        """True only when the whole bytecode was walked without ambiguity."""
        return not self.incomplete_reason

    def by_selector(self) -> dict[str, DispatchSelector]:
        return {s.selector: s for s in self.selectors}

    def to_dict(self) -> dict:
        return {
            "code_size": self.code_size,
            "complete": self.complete,
            "metadata_stripped": self.metadata_stripped,
            "incomplete_reason": self.incomplete_reason,
            "reachable": [s.to_dict() for s in self.reachable],
            "present_only": [s.to_dict() for s in self.present_only],
            "ambiguous": [s.to_dict() for s in self.ambiguous],
        }


def _guards_a_jump(
    instrs: list[tuple[int, int, Optional[bytes]]],
    idx: int,
    jumpdests: frozenset[int],
) -> bool:
    """True if the comparison at ``idx`` produces the condition of a nearby JUMPI.

    Scans forward over stack-neutral instructions only. The first instruction
    that is not neutral decides: a JUMPI means the comparison guards a jump; a
    PUSH2 (the destination push that precedes JUMPI in the classic shape) is
    skipped *past* to the JUMPI; anything else means the value was consumed by
    something other than a dispatch.

    A ``SUB`` comparison is zero on equality. A JUMPI takes non-zero, so the body
    is reached on the *fall-through*, not the jump; an intervening ``ISZERO``
    flips that back. Both are accepted because both appear in real solc output,
    but a destination that is not a real ``JUMPDEST`` is rejected: the branch
    cannot land there, so the comparison does not select a reachable body.
    """
    j = idx + 1
    n = len(instrs)
    # Skip the destination push that sits between the comparison and its JUMPI.
    while j < n and instrs[j][1] in _STACK_NEUTRAL_BETWEEN:
        j += 1
    # ISZERO only re-tests the same comparison result; it cannot select another.
    if j < n and instrs[j][1] == _ISZERO:
        j += 1
        while j < n and instrs[j][1] in _STACK_NEUTRAL_BETWEEN:
            j += 1
    if j < n and instrs[j][1] == _JUMPI:
        return True
    # PUSH2 <dest> JUMPI -- the destination push does not clobber the condition.
    if j < n and 0x60 <= instrs[j][1] <= 0x7F:
        dest_instr = instrs[j]
        k = j + 1
        while k < n and instrs[k][1] in _STACK_NEUTRAL_BETWEEN:
            k += 1
        if k < n and instrs[k][1] == _JUMPI:
            # A destination push that is not a JUMPDEST cannot be jumped to, so
            # this comparison guards nothing. Checked for every push width, not
            # just PUSH2: a PUSH1/PUSH3 destination is unusual but equally
            # un-jumpable when it misses, and skipping the check would let those
            # shapes read as reachable.
            operand = dest_instr[2] or b""
            if operand and int.from_bytes(operand, "big") not in jumpdests:
                return False
            return True
    return False


def analyse_selectors(code: str | bytes) -> SelectorDispatchReport:
    """Split the 4-byte values in ``code`` into dispatch-reachable and data-only.

    ``code`` may be a ``0x``-prefixed hex string (as ``eth_getCode`` returns) or
    raw bytes.
    """
    raw = _decode_code(code)

    # Walk only the executable prefix; the CBOR trailer is data. The reported
    # code_size stays the true runtime length so an auditor can still check it.
    body, metadata_stripped = _strip_metadata(raw)
    instrs = disassemble(body)
    report = SelectorDispatchReport(
        code_size=len(raw), metadata_stripped=metadata_stripped
    )
    jumpdests = _valid_jumpdests(body)

    # A truncated trailing PUSH means the walk stopped early: say so, and never
    # claim the reachable set is complete.
    walked = sum(1 + opcode_operand_size(op) for _, op, _ in instrs)
    if walked < len(body):
        report.incomplete_reason = (
            f"disassembly stopped at byte {walked} of {len(body)}: truncated PUSH operand"
        )

    # Index PUSH4 instructions by their 4-byte value.
    pushes: dict[str, list[int]] = {}
    for offset, op, operand in instrs:
        if op == 0x63 and operand is not None and len(operand) == 4:  # PUSH4
            pushes.setdefault(operand.hex(), []).append(offset)

    index_of = {off: i for i, (off, _, _) in enumerate(instrs)}

    for sel, offsets in sorted(pushes.items()):
        dispatch_offsets: list[int] = []
        ambiguous = False
        for off in offsets:
            idx = index_of.get(off)
            if idx is None:
                continue
            # The comparison must follow the PUSH4 within the same basic block for
            # the classic shape (DUP1 PUSH4 <sel> EQ ...). Skip only DUP/SWAP noise.
            j = idx + 1
            n = len(instrs)
            while j < n and instrs[j][1] in _STACK_NEUTRAL_BETWEEN:
                j += 1
            if j >= n:
                continue
            op = instrs[j][1]
            if op == _EQ:
                if _guards_a_jump(instrs, j, jumpdests):
                    dispatch_offsets.append(off)
            elif op == _SUB:
                # via-IR equality: a - b tested for zero selects the body.
                if _guards_a_jump(instrs, j, jumpdests):
                    dispatch_offsets.append(off)
            elif op in (_JUMPI, 0x56):
                # The constant reaches control flow without a recognisable
                # comparison; that is an unresolved dispatcher shape, not proof.
                ambiguous = True

        if dispatch_offsets:
            entry = DispatchSelector(
                selector=sel,
                status=REACHABLE,
                push4_offsets=offsets,
                dispatch_offsets=dispatch_offsets,
                evidence=(
                    "PUSH4 operand is compared (EQ or SUB-for-zero) and the "
                    "comparison guards a JUMPI whose destination is a real "
                    "JUMPDEST, so a call with this selector reaches code"
                ),
            )
        else:
            evidence = (
                "PUSH4 operand occurs but no EQ/SUB comparison guards a JUMPI; it "
                "is data, not a proven callable entry point"
            )
            if ambiguous:
                evidence += (
                    " (the constant reaches control flow without a recognised "
                    "comparison: dispatcher shape unresolved, not proven either way)"
                )
            entry = DispatchSelector(
                selector=sel,
                status=PRESENT_ONLY,
                push4_offsets=offsets,
                evidence=evidence,
                ambiguous=ambiguous,
            )
        report.selectors.append(entry)

    return report
