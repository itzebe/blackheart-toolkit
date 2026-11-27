"""Universal program intelligence.

Programs publish scope, severity, payout, and restriction rules in incompatible
formats. This package normalizes them into one internal shape **without discarding
a program's specific rules**, preserves provenance and integrity, and makes the
policy version-aware so a change can trigger reassessment.

  * :mod:`~blackheart.program_intel.policy` -- :class:`NormalizedPolicy`,
    :class:`ScopeEntry`, :class:`ClassRule`, and the version-aware
    :class:`PolicyVersionLog`. The minimum payable band is derived from *this
    program's* policy, never a universal threshold.
  * :mod:`~blackheart.program_intel.normalize` -- a conservative, format-tolerant
    parser that records what it could not establish as an *uncertainty* rather than
    inventing it.
  * :mod:`~blackheart.program_intel.eligibility` -- the bridge that feeds a
    program's class rules into the coverage engine as an eligibility predicate,
    passing "unknown" through as unknown.

This complements, and does not replace, :mod:`blackheart.bounty` (the existing
payability evaluator that works on a single finding). The two share the same
principles: four separate axes, provenance first, no universal severity threshold.
"""

from __future__ import annotations

from .eligibility import PolicyEligibility
from .normalize import PolicyNormalizer
from .policy import (
    AssetClass,
    Band,
    ClassRule,
    NormalizedPolicy,
    PolicyChange,
    PolicyVersionLog,
    ScopeEntry,
    coerce_band,
)

__all__ = [
    "AssetClass",
    "Band",
    "ClassRule",
    "NormalizedPolicy",
    "PolicyChange",
    "PolicyEligibility",
    "PolicyNormalizer",
    "PolicyVersionLog",
    "ScopeEntry",
    "coerce_band",
]
