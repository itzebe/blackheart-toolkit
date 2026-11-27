"""Explicit outcomes for modelled calls.

A modelled call is not a boolean. It can return, revert, or fall outside the
statement subset. The third case must abort the path and name the gap; treating
it as success is how a model invents a witness for a call that never happened.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

RETURNED = "RETURNED"
REVERTED = "REVERTED"
UNMODELLED = "UNMODELLED"


@dataclass(frozen=True)
class CallResult:
    """The outcome of one external call in the executable model."""

    status: str
    values: tuple[Any, ...] = ()
    reason: str = ""

    @property
    def returned(self) -> bool:
        return self.status == RETURNED

    @property
    def reverted(self) -> bool:
        return self.status == REVERTED

    @property
    def unmodelled(self) -> bool:
        return self.status == UNMODELLED

    def to_dict(self) -> dict:
        return {"status": self.status, "values": list(self.values),
                "reason": self.reason}


def returned(*values: Any) -> CallResult:
    return CallResult(RETURNED, tuple(values))


def reverted(reason: str = "") -> CallResult:
    return CallResult(REVERTED, reason=reason)


def unmodelled(reason: str) -> CallResult:
    return CallResult(UNMODELLED, reason=reason)
