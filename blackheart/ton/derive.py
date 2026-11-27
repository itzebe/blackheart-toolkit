"""Derive a TON model from a recovered Tact surface.

The surface (:mod:`blackheart.ton.tact`) says which ``receive`` handlers a
contract exposes and whether each checks ``sender()`` against an owner/admin. This
module maps the handlers it recognises onto the reference model's operations, so a
*specific* contract can be certified against the model instead of a generic one.

It is deliberately conservative. A surface cannot show accounting semantics, so
this derived model:

* enables only the reference operations the contract actually exposes;
* takes **authorization** from the source: a privileged handler (``mint`` /
  ``change_admin``) the source leaves unguarded is modelled as reachable by
  anyone, so ``ton:admin-only-mint`` can break -- a *lead* to review;
* does **not** apply the reference model's deliberate bugs (double-credit
  transfer, unadvanced seqno), because those are not derivable from a surface;
* lists every handler it could not map as ``unmodelled_handlers``.

A broken invariant here is a lead about the contract's authorization shape, never
a finding.
"""

from __future__ import annotations

import re

from .model import TONTarget
from .tact import TonSurface

#: Recovered handler name (normalised) -> reference operation.
_ALIASES: dict[str, str] = {
    "mint": "mint",
    "transfer": "transfer",
    "burn": "burn",
    "changeadmin": "change_admin",
    "changeowner": "change_admin",
    "send": "wallet_send",
    "walletsend": "wallet_send",
}

_PRIVILEGED: frozenset[str] = frozenset({"mint", "change_admin"})


def _normalise(name: str) -> str:
    return re.sub(r"[^a-z0-9]", "", name.lower())


class DerivedTONTarget(TONTarget):
    """A TON model derived from a Tact surface.

    Only the exposed operations are enabled, and a privileged op the source leaves
    unguarded bypasses the admin check. The reference model's deliberate bugs are
    not applied -- this target claims only what the surface supports.
    """

    def __init__(self, *, enabled_ops, derived_unguarded, unmodelled_handlers=()):
        super().__init__(vulnerable=False, name="ton-derived")
        self.enabled_ops = frozenset(enabled_ops)
        self.derived_unguarded = frozenset(derived_unguarded)
        self.unmodelled_handlers = tuple(unmodelled_handlers)

    def _admin_bypass(self, op_name: str) -> bool:
        return op_name in self.derived_unguarded

    def ops(self):
        return [op for op in super().ops() if op.name in self.enabled_ops]


def derive_target(surface: TonSurface) -> DerivedTONTarget:
    """Map a recovered Tact surface onto a :class:`DerivedTONTarget`."""
    enabled: set[str] = set()
    unguarded: set[str] = set()
    unmodelled: list[str] = []
    for handler in surface.handlers:
        op = _ALIASES.get(_normalise(handler.name))
        if op is None:
            unmodelled.append(handler.name)
            continue
        enabled.add(op)
        if not handler.guarded and op in _PRIVILEGED:
            unguarded.add(op)
    return DerivedTONTarget(enabled_ops=enabled, derived_unguarded=unguarded,
                            unmodelled_handlers=unmodelled)
