"""Attack-class model coverage: which objective categories the engine can *break*.

The invariant engine can only find a bug in a class it has an **executable model**
for -- a vulnerable target and its guarded control. An objective category with no
model is invisible to *every* search strategy (random, adaptive, coverage-guided,
and even the bounded-exhaustive certifier), because there is no state, no
operation, and no invariant to explore. That is the deepest way a hunter misses a
bug: not a weak search, but no target at all.

This module is the single, machine-checkable map from an objective category to the
executable model that covers it, so the gap can never be *silent*. It is honest by
construction:

  * a category is ``MODELLED`` only when the registry actually holds a
    vulnerable/guarded pair of the declared kind -- the claim is resolved against
    :data:`blackheart.invariants.registry.TARGET_SPECS`, not asserted by hand;
  * a category with no model is ``UNMODELLED`` and reported as a gap, never
    quietly omitted;
  * a model is a **representative** of its class, not exhaustive coverage: one
    vulnerable/guarded pair proves the engine can break the class, not that every
    instance of it is caught. The ledger says so rather than implying a guarantee.

``blackheart coverage`` renders it; ``coverage_report()`` is the machine form. The
companion doctrine (:data:`blackheart.mindset.MODEL_DOCTRINE`) carries the rule to
every agent and every mission.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from ..objectives import available_categories
from .registry import TARGET_SPECS

# Objective category -> the registry *kind* whose vulnerable/guarded pair covers
# it. Kept here as the single source of truth; the targets themselves are resolved
# from the registry so a removed or renamed target shows up as a gap.
CATEGORY_KIND: dict[str, str] = {
    "asset-theft": "erc4626",
    "accounting-manipulation": "erc4626",
    "unbacked-debt": "oracle",
    "oracle-manipulation": "oracle",
    "replay-forgery": "permit",
    "signature-bypass": "permit",
    "auth-bypass": "proxy",
    "privilege-escalation": "proxy",
    "state-inconsistency": "reentrancy",
    "callback-reentrancy": "reentrancy",
    "cross-contract": "cross-contract",
    "access-control": "access-control",
    "rounding-precision": "rounding",
    "ordering-timing": "timing",
    "info-disclosure": "info",
    "liquidation-bypass": "portfolio-margin",
    "cross-protocol-trust": "cross-protocol",
    "cross-chain-replay": "cross-chain",
    "slippage-manipulation": "amm",
    "silent-transfer-failure": "silent-transfer",
    "governance-manipulation": "governance",
    "denial-of-service": "griefing",
    "reward-manipulation": "reward",
    "storage-collision": "storage-collision",
    "decimals-mismatch": "decimals",
    # MCP-server classes. Two are executable; three need a live tenant + token
    # and are recorded as PROSE_ONLY below rather than faked.
    "cors-credential-leak": "mcp-cors",
    "token-audience-confusion": "mcp-audience",
}

# A representative note per kind: what the model actually demonstrates. This keeps
# the ledger from implying that one pair exhausts the class.
KIND_NOTE: dict[str, str] = {
    "erc4626": "share-accounting / first-depositor inflation",
    "wrapper": "wrapper-share vs rebasing-underlying divergence",
    "oracle": "borrow priced by a manipulable spot oracle",
    "permit": "single-use signed authorization",
    "proxy": "re-callable initializer / upgrade path",
    "reentrancy": "callback-before-effects (checks-effects-interactions)",
    "cross-contract": "consumer trusts a second contract's report across a trust boundary",
    "cross-protocol": "consumer prices off a second contract's self-reported holdings",
    "access-control": "ungated privileged state write",
    "rounding": "share issuance that rounds in the user's favour",
    "timing": "an operation accepted after its deadline (expiry race)",
    "info": "object read gated on authentication, not ownership (IDOR)",
    "portfolio-margin": "cross-margin solvency / liquidation LTV",
    "outcome": "prediction-market merge accounting",
    "cross-chain": "replay / wrong-domain execution of a bridge message",
    "amm": "swap output that ignores the input, decreasing k = rx*ry",
    "silent-transfer": "credit issued although the token transfer moved nothing",
    "governance": "flash-loaned voting power against a live (un-snapshotted) balance",
    "griefing": "one actor's state blocks a shared critical path",
    "reward": "reward claimed without a stake-time debt checkpoint",
    "storage-collision": "implementation logic overwriting a reserved proxy slot",
    "decimals": "amounts scaled by a hard-coded (wrong) decimals value",
    "mcp-cors": "a protected resource reflecting Origin with allow-credentials",
    "mcp-audience": "a token verifier that checks signature but not audience/tenant",
}

# Categories that deliberately have **no** executable model, with the reason. The
# slot is explicit so a future category is a recorded decision, never a silent
# omission. A test asserts every category is either MODELLED or listed here.
PROSE_ONLY: dict[str, str] = {
    "mcp-cross-tenant-disclosure": (
        "needs a live tenant, a real token and a consent grant: a model would be "
        "theatre. Tested as a hypothesis (cloudId substitution) on an owned instance."
    ),
    "mcp-scope-overreach": (
        "the defect is whether a tool honours the source-of-truth permission behind "
        "a scope; only observable against real Atlassian permission data."
    ),
    "mcp-consent-bypass": (
        "depends on the consent screen and redirect/client binding of a live "
        "authorization server; not representable without the real flow."
    ),
}


class Coverage(str, Enum):
    MODELLED = "modelled"          # a vulnerable/guarded pair exists
    UNMODELLED = "unmodelled"      # no pair -- a gap every search is blind to
    PROSE_ONLY = "prose-only"      # deliberately described, not executed


@dataclass
class CategoryCoverage:
    category: str
    coverage: Coverage
    kind: str = ""
    targets: list[str] = field(default_factory=list)      # registered target names
    representative: str = ""                              # what the model demonstrates
    reason: str = ""                                      # why, when not modelled

    def to_dict(self) -> dict:
        return {
            "category": self.category,
            "coverage": self.coverage.value,
            "kind": self.kind,
            "targets": list(self.targets),
            "representative": self.representative,
            "reason": self.reason,
        }


def _targets_of_kind(kind: str) -> list[str]:
    return [s.name for s in TARGET_SPECS if s.kind == kind]


def _coverage_for(category: str) -> CategoryCoverage:
    if category in PROSE_ONLY:
        return CategoryCoverage(
            category=category, coverage=Coverage.PROSE_ONLY,
            reason=PROSE_ONLY[category],
        )
    kind = CATEGORY_KIND.get(category, "")
    targets = _targets_of_kind(kind) if kind else []
    has_pair = any(not s.guarded for s in TARGET_SPECS if s.kind == kind) and \
        any(s.guarded for s in TARGET_SPECS if s.kind == kind)
    if kind and has_pair:
        return CategoryCoverage(
            category=category, coverage=Coverage.MODELLED, kind=kind,
            targets=targets, representative=KIND_NOTE.get(kind, ""),
        )
    return CategoryCoverage(
        category=category, coverage=Coverage.UNMODELLED, kind=kind, targets=targets,
        reason=(
            f"no vulnerable/guarded model of kind '{kind}' is registered"
            if kind else "no executable model is declared for this category"
        ),
    )


def coverage_report() -> list[CategoryCoverage]:
    """One :class:`CategoryCoverage` per objective category, sorted by category."""
    return [_coverage_for(c) for c in available_categories()]


def unmodelled_categories() -> list[str]:
    """Categories every search is blind to (no executable model)."""
    return [c.category for c in coverage_report()
            if c.coverage is Coverage.UNMODELLED]


def modelled_categories() -> list[str]:
    return [c.category for c in coverage_report()
            if c.coverage is Coverage.MODELLED]


def coverage_summary() -> dict:
    report = coverage_report()
    modelled = [c for c in report if c.coverage is Coverage.MODELLED]
    prose = [c for c in report if c.coverage is Coverage.PROSE_ONLY]
    unmodelled = [c for c in report if c.coverage is Coverage.UNMODELLED]
    return {
        "categories": len(report),
        "modelled": len(modelled),
        "prose_only": len(prose),
        "unmodelled": len(unmodelled),
        "unmodelled_categories": [c.category for c in unmodelled],
        "prose_only_categories": [c.category for c in prose],
        # Honest framing: the ledger proves *class coverage* (an executable model
        # exists), never that the class is exhausted.
        "note": (
            "each modelled category has at least one executable vulnerable/guarded "
            "pair -- a representative the engine can break, not exhaustive coverage "
            "of the class"
        ),
    }
