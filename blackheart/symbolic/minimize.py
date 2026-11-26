"""Shrink a reproducer without losing the property that made it interesting.

A 4 KB fuzz input is a poor report. This is deterministic delta debugging over
32-byte calldata words: zero a word, halve a value, clear a bit, drop a word, and
keep every change that still satisfies the caller's predicate. It returns a
*smaller* reproducer, not a proven minimal one -- the predicate is arbitrary and
the search is bounded.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

WORD = 32


@dataclass(frozen=True)
class MinimizeResult:
    original: bytes
    minimized: bytes
    attempts: int
    accepted: int
    rounds: int

    @property
    def reduced(self) -> bool:
        return self.minimized != self.original

    def to_dict(self) -> dict:
        return {
            "original": "0x" + bytes(self.original).hex(),
            "minimized": "0x" + bytes(self.minimized).hex(),
            "original_bytes": len(self.original),
            "minimized_bytes": len(self.minimized),
            "attempts": self.attempts,
            "accepted": self.accepted,
            "rounds": self.rounds,
            "reduced": self.reduced,
        }


def _words(data: bytes) -> list[bytes]:
    return [data[i:i + WORD] for i in range(0, len(data), WORD)]


def _join(words: list[bytes]) -> bytes:
    return b"".join(words)


def _candidate_values(value: int) -> tuple[int, ...]:
    """Smaller values to try, cheapest and most general first."""
    out = []
    for candidate in (value // 2, value - 1, value & (value - 1)):
        if 0 <= candidate < value and candidate not in out:
            out.append(candidate)
    return tuple(out)


def minimize_calldata(calldata: bytes, predicate: Callable[[bytes], bool], *,
                      max_rounds: int = 6,
                      max_attempts: int = 2_000) -> MinimizeResult:
    """Return a smaller calldata that still satisfies ``predicate``.

    ``predicate`` must be deterministic; it is called once per attempt and its
    cost is the whole cost of the search. Trailing zero words are trimmed first,
    then each word is zeroed, shrunk, and finally dropped while the predicate
    keeps holding.
    """
    original = bytes(calldata)
    current = _words(original)
    attempts = accepted = 0

    def attempt(candidate: list[bytes]) -> bool:
        nonlocal attempts, accepted
        if attempts >= max_attempts:
            return False
        attempts += 1
        try:
            holds = predicate(_join(candidate))
        except Exception:
            holds = False
        if holds:
            accepted += 1
            return True
        return False

    while len(current) > 1 and not any(current[-1]):
        if not attempt(current[:-1]):
            break
        current = current[:-1]

    changed = True
    rounds = 0
    while changed and rounds < max_rounds and attempts < max_attempts:
        changed = False
        rounds += 1

        for i, word in enumerate(current):
            if not any(word):
                continue
            candidate = current[:i] + [b"\x00" * len(word)] + current[i + 1:]
            if attempt(candidate):
                current = candidate
                changed = True

        for i, word in enumerate(current):
            value = int.from_bytes(word, "big")
            width = len(word)
            for smaller in _candidate_values(value):
                if smaller >= (1 << (8 * width)):
                    continue
                candidate = list(current)
                candidate[i] = smaller.to_bytes(width, "big")
                if attempt(candidate):
                    current = candidate
                    changed = True
                    break

        for i in range(len(current)):
            candidate = current[:i] + current[i + 1:]
            if attempt(candidate):
                current = candidate
                changed = True
                break

    return MinimizeResult(original, _join(current), attempts, accepted, rounds)
