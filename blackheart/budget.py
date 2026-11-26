"""Task budget ledger (adapted from ARTEX's task/intent budgets).

A research run can spend real money on model tokens and can loop on a turn
count. This module is the honest accountant for that: it caps a whole task by
tokens and by turns, keeps a *wrap-up reserve* so the task can still summarise
what it found instead of dying mid-thought, and refuses to start a worker the
remaining budget cannot cover.

It is deterministic and side-effect free -- it never calls a model. The caller
charges it; the caller asks it whether it may continue. That keeps it testable
and keeps the budget out of the research logic.
"""

from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass
class Budget:
    """A token/turn budget for one task, with a wrap-up reserve.

    ``max_tokens`` / ``max_turns`` of ``None`` mean "uncapped on that axis".
    The reserve is the slice of the cap held back for the wrap-up; once spend
    crosses ``cap - reserve`` the task is *wrapped up* -- it may finish the
    current thought and summarise, but must not start new work.
    """

    max_tokens: int | None = None
    max_turns: int | None = None
    reserve_tokens: int = 0
    reserve_turns: int = 0
    used_tokens: int = 0
    used_turns: int = 0

    # -- charging -------------------------------------------------------- #
    def charge_tokens(self, n: int) -> None:
        if n < 0:
            raise ValueError("cannot charge a negative token amount")
        self.used_tokens += n

    def charge_turn(self) -> None:
        self.used_turns += 1

    # -- remaining ------------------------------------------------------- #
    @property
    def remaining_tokens(self) -> int | None:
        if self.max_tokens is None:
            return None
        return max(0, self.max_tokens - self.used_tokens)

    @property
    def remaining_turns(self) -> int | None:
        if self.max_turns is None:
            return None
        return max(0, self.max_turns - self.used_turns)

    # -- wrap-up state --------------------------------------------------- #
    @property
    def wrapped_up(self) -> bool:
        """True once spend has reached the point where new work must stop.

        The reserve is what is left after this point; crossing into it means a
        new worker/turn could not complete, so the task should wrap up instead.
        """
        if self.max_tokens is not None and self.remaining_tokens is not None:
            if self.remaining_tokens <= self.reserve_tokens:
                return True
        if self.max_turns is not None and self.remaining_turns is not None:
            if self.remaining_turns <= self.reserve_turns:
                return True
        return False

    @property
    def exhausted(self) -> bool:
        """True once the hard cap is spent (nothing left at all)."""
        if self.max_tokens is not None and self.used_tokens >= self.max_tokens:
            return True
        if self.max_turns is not None and self.used_turns >= self.max_turns:
            return True
        return False

    # -- admission ------------------------------------------------------- #
    def can_start(self, *, tokens: int = 0, turns: int = 1) -> bool:
        """Whether a worker costing ``tokens``/``turns`` may start now.

        A worker is refused if it would push spend past the wrap-up point, so we
        never begin work we cannot finish. An uncapped axis never blocks.
        """
        if self.max_tokens is not None and self.remaining_tokens is not None:
            if tokens > self.remaining_tokens - self.reserve_tokens:
                return False
        if self.max_turns is not None and self.remaining_turns is not None:
            if turns > self.remaining_turns - self.reserve_turns:
                return False
        return True

    # -- reporting ------------------------------------------------------- #
    def to_dict(self) -> dict:
        return {
            "max_tokens": self.max_tokens,
            "max_turns": self.max_turns,
            "reserve_tokens": self.reserve_tokens,
            "reserve_turns": self.reserve_turns,
            "used_tokens": self.used_tokens,
            "used_turns": self.used_turns,
            "remaining_tokens": self.remaining_tokens,
            "remaining_turns": self.remaining_turns,
            "wrapped_up": self.wrapped_up,
            "exhausted": self.exhausted,
        }


def budget_from_env(environ: dict | None = None) -> Budget | None:
    """Build a research :class:`Budget` from the environment, or ``None``.

    Reads ``BLACKHEART_BUDGET_TOKENS`` and ``BLACKHEART_BUDGET_TURNS``. When
    neither is set the budget is unbounded (``None``) -- the default. The wrap-up
    reserve defaults to a tenth of each cap (at least one unit), so a task can
    still summarise what it found instead of dying mid-thought.
    """
    env = environ if environ is not None else os.environ

    def _int(name: str) -> int | None:
        raw = env.get(name, "").strip()
        if not raw:
            return None
        try:
            value = int(raw)
        except ValueError:
            return None
        return value if value >= 0 else None

    tokens = _int("BLACKHEART_BUDGET_TOKENS")
    turns = _int("BLACKHEART_BUDGET_TURNS")
    if tokens is None and turns is None:
        return None
    reserve_tokens = max(1, tokens // 10) if tokens else 0
    reserve_turns = max(1, turns // 10) if turns else 0
    return Budget(
        max_tokens=tokens,
        max_turns=turns,
        reserve_tokens=reserve_tokens,
        reserve_turns=reserve_turns,
    )
