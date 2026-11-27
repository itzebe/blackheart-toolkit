"""Universal program intelligence: normalize any program's policy without losing its rules.

Programs publish scope, severity, payout, and restriction rules in wildly different
formats. Normalizing them into one internal shape is necessary for the engine to
reason uniformly -- but normalization is exactly where a program's specific rule
gets lost, and a lost rule is how a report is wrongly promised or wrongly refused.

This module normalizes *while preserving provenance and program-specific detail*:

  * :class:`ScopeEntry` keeps each asset with its *original* text, classification,
    severity notes and any asset-specific condition -- nothing is collapsed into a
    boolean.
  * :class:`NormalizedPolicy` keeps the raw source text and its hash beside the
    normalized fields, so a reviewer can always re-derive the normalization.
  * An unreadable field is recorded in ``uncertainties`` -- never filled in with a
    plausible default, never silently dropped (mission rule 3.1).
  * :class:`PolicyVersionLog` makes policies *version-aware*: a new version is
    appended, the old one preserved, and a change to a class/asset can trigger
    reassessment of affected research.

The lowest payable class is derived from *this program's* policy
(:meth:`NormalizedPolicy.minimum_eligible_band`), never a universal threshold.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from ..models import utcnow


class Band(str, Enum):
    """Severity bands as programs commonly publish them."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    UNKNOWN = "unknown"


_BAND_ORDER = {
    Band.INFO: 0, Band.LOW: 1, Band.MEDIUM: 2, Band.HIGH: 3, Band.CRITICAL: 4,
    Band.UNKNOWN: -1,
}

#: Common synonyms programs use for each band.
_BAND_SYNONYMS = {
    "critical": Band.CRITICAL, "sev0": Band.CRITICAL, "s0": Band.CRITICAL,
    "p0": Band.CRITICAL, "blocker": Band.CRITICAL,
    "high": Band.HIGH, "sev1": Band.HIGH, "s1": Band.HIGH, "p1": Band.HIGH,
    "major": Band.HIGH,
    "medium": Band.MEDIUM, "moderate": Band.MEDIUM, "sev2": Band.MEDIUM,
    "s2": Band.MEDIUM, "p2": Band.MEDIUM,
    "low": Band.LOW, "sev3": Band.LOW, "s3": Band.LOW, "p3": Band.LOW, "minor": Band.LOW,
    "info": Band.INFO, "informational": Band.INFO, "insight": Band.INFO,
    "none": Band.INFO, "note": Band.INFO, "trivial": Band.INFO,
}


def coerce_band(text: str) -> Band:
    """Map a program's severity word to a band, or ``UNKNOWN`` -- never guess."""
    t = (text or "").strip().lower()
    if not t:
        return Band.UNKNOWN
    if t in _BAND_SYNONYMS:
        return _BAND_SYNONYMS[t]
    for word, band in _BAND_SYNONYMS.items():
        if word in t:
            return band
    return Band.UNKNOWN


class AssetClass(str, Enum):
    """How an asset is classified for testing/authorization."""

    IN_SCOPE = "in_scope"
    OUT_OF_SCOPE = "out_of_scope"
    UNKNOWN = "unknown"


@dataclass
class ScopeEntry:
    """One asset, preserving its original description and per-asset conditions."""

    asset: str
    original_text: str = ""
    classification: AssetClass = AssetClass.UNKNOWN
    severity_notes: str = ""
    #: Asset-specific conditions (e.g. "testnet only", "exclude staking contract").
    conditions: list[str] = field(default_factory=list)
    poc_required: Optional[bool] = None
    #: Temporal scope, preserved exactly as published. Empty means not stated.
    effective_from: str = ""
    excluded_until: str = ""
    #: active | under_remediation | staged | not_public | unknown
    component_status: str = "unknown"

    def to_dict(self) -> dict:
        return {
            "asset": self.asset, "original_text": self.original_text,
            "classification": self.classification.value,
            "severity_notes": self.severity_notes,
            "conditions": list(self.conditions), "poc_required": self.poc_required,
            "effective_from": self.effective_from,
            "excluded_until": self.excluded_until,
            "component_status": self.component_status,
        }


@dataclass
class ClassRule:
    """A program's rule for one vulnerability class (eligible, excluded, band)."""

    class_key: str
    eligible: Optional[bool] = None       # None == not stated (unknown)
    band: Band = Band.UNKNOWN
    original_text: str = ""
    conditions: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "class_key": self.class_key, "eligible": self.eligible,
            "band": self.band.value, "original_text": self.original_text,
            "conditions": list(self.conditions),
        }


@dataclass
class NormalizedPolicy:
    """A program's policy in one internal shape, with provenance and uncertainties.

    ``source_text`` and ``source_sha256`` are kept so normalization is auditable.
    ``uncertainties`` names every field that could not be established; a caller must
    surface them, not ignore them.
    """

    program: str
    program_id: str = ""
    source_url: str = ""
    source_text: str = ""
    retrieved_at: str = field(default_factory=utcnow)
    version: str = ""
    scope: list[ScopeEntry] = field(default_factory=list)
    class_rules: list[ClassRule] = field(default_factory=list)
    severity_definitions: dict[str, str] = field(default_factory=dict)
    payouts: dict[str, str] = field(default_factory=dict)
    minimum_severity: Band = Band.UNKNOWN
    testing_restrictions: list[str] = field(default_factory=list)
    rate_limits: list[str] = field(default_factory=list)
    poc_standard: str = ""
    known_issues: list[str] = field(default_factory=list)
    special_conditions: list[str] = field(default_factory=list)
    #: Scope that begins later in the season, preserved as published.
    scope_effective_from: str = ""
    staged_components: list[str] = field(default_factory=list)
    uncertainties: list[str] = field(default_factory=list)

    # -- provenance ----------------------------------------------------- #

    @property
    def source_sha256(self) -> str:
        return hashlib.sha256(self.source_text.encode("utf-8")).hexdigest()

    def is_verified(self) -> bool:
        """A policy is verified only when its provenance and hash are present."""
        return bool(self.source_url and self.retrieved_at and self.source_text
                    and self.source_sha256)

    # -- queries -------------------------------------------------------- #

    def asset_class(self, asset: str) -> AssetClass:
        for e in self.scope:
            if e.asset == asset:
                return e.classification
        return AssetClass.UNKNOWN

    def in_scope_assets(self) -> list[str]:
        return [e.asset for e in self.scope if e.classification is AssetClass.IN_SCOPE]

    def out_of_scope_assets(self) -> list[str]:
        return [e.asset for e in self.scope if e.classification is AssetClass.OUT_OF_SCOPE]

    def class_eligible(self, class_key: str) -> Optional[bool]:
        """True / False / None (unknown) for a class under *this* program."""
        for r in self.class_rules:
            if r.class_key == class_key:
                return r.eligible
        return None

    def minimum_eligible_band(self) -> Band:
        """The lowest band that is *payable under this program*.

        Derived from the program's own statements: its explicit minimum severity if
        given, else the lowest band that appears in a class rule marked eligible.
        ``UNKNOWN`` when the program does not establish one -- never a universal
        default.
        """
        if self.minimum_severity is not Band.UNKNOWN:
            return self.minimum_severity
        eligible_bands = [
            r.band for r in self.class_rules
            if r.eligible and r.band is not Band.UNKNOWN
        ]
        if not eligible_bands:
            return Band.UNKNOWN
        return min(eligible_bands, key=lambda b: _BAND_ORDER[b])

    def is_band_eligible(self, band: Band) -> Optional[bool]:
        """Whether ``band`` clears the program's floor. None when the floor is unknown."""
        floor = self.minimum_eligible_band()
        if floor is Band.UNKNOWN:
            return None
        return _BAND_ORDER[band] >= _BAND_ORDER[floor]

    # -- serialisation --------------------------------------------------- #

    def to_dict(self) -> dict:
        return {
            "program": self.program, "program_id": self.program_id,
            "source_url": self.source_url, "retrieved_at": self.retrieved_at,
            "version": self.version, "source_sha256": self.source_sha256,
            "scope": [e.to_dict() for e in self.scope],
            "class_rules": [r.to_dict() for r in self.class_rules],
            "severity_definitions": dict(self.severity_definitions),
            "payouts": dict(self.payouts),
            "minimum_severity": self.minimum_severity.value,
            "testing_restrictions": list(self.testing_restrictions),
            "rate_limits": list(self.rate_limits),
            "poc_standard": self.poc_standard,
            "known_issues": list(self.known_issues),
            "special_conditions": list(self.special_conditions),
            "scope_effective_from": self.scope_effective_from,
            "staged_components": list(self.staged_components),
            "uncertainties": list(self.uncertainties),
            "verified": self.is_verified(),
        }


# --------------------------------------------------------------------------- #
# Version-aware policy log
# --------------------------------------------------------------------------- #

@dataclass
class PolicyChange:
    """One difference between two policy versions, and what it affects."""

    kind: str            # "asset-added" | "asset-removed" | "class-eligible" | ...
    detail: str
    affected_classes: list[str] = field(default_factory=list)
    affected_assets: list[str] = field(default_factory=list)
    #: True when the change alters eligibility for every class (e.g. the program's
    #: minimum severity), so research on classes the change does not name must also
    #: be reassessed.
    program_wide: bool = False

    def to_dict(self) -> dict:
        return {"kind": self.kind, "detail": self.detail,
                "affected_classes": list(self.affected_classes),
                "affected_assets": list(self.affected_assets),
                "program_wide": self.program_wide}


class PolicyVersionLog:
    """An append-only, version-aware history of one program's policy.

    Never rewrites history: :meth:`add` appends a new version and returns the
    changes from the prior version. A change to a class's eligibility or an asset's
    scope is reported with what it *affects*, so research built on the old version
    can be re-assessed rather than silently invalidated.
    """

    def __init__(self, program: str) -> None:
        self.program = program
        self.versions: list[NormalizedPolicy] = []

    def add(self, policy: NormalizedPolicy) -> list[PolicyChange]:
        prior = self.versions[-1] if self.versions else None
        self.versions.append(policy)
        if prior is None:
            return []
        return self._diff(prior, policy)

    def current(self) -> Optional[NormalizedPolicy]:
        return self.versions[-1] if self.versions else None

    def _diff(self, old: NormalizedPolicy, new: NormalizedPolicy) -> list[PolicyChange]:
        changes: list[PolicyChange] = []
        old_assets = {e.asset: e.classification for e in old.scope}
        new_assets = {e.asset: e.classification for e in new.scope}
        for asset, cls in new_assets.items():
            if asset not in old_assets:
                changes.append(PolicyChange("asset-added", f"asset '{asset}' added",
                                            affected_assets=[asset]))
            elif old_assets[asset] is not cls:
                changes.append(PolicyChange(
                    "asset-classification", f"asset '{asset}': "
                    f"{old_assets[asset].value} -> {cls.value}", affected_assets=[asset]))
        for asset in old_assets:
            if asset not in new_assets:
                changes.append(PolicyChange("asset-removed", f"asset '{asset}' removed",
                                            affected_assets=[asset]))
        old_rules = {r.class_key: r for r in old.class_rules}
        new_rules = {r.class_key: r for r in new.class_rules}
        for key, rule in new_rules.items():
            prior = old_rules.get(key)
            if prior is None:
                changes.append(PolicyChange("class-added", f"class '{key}' added",
                                            affected_classes=[key]))
            elif prior.eligible != rule.eligible:
                changes.append(PolicyChange(
                    "class-eligible", f"class '{key}': eligible "
                    f"{prior.eligible} -> {rule.eligible}", affected_classes=[key]))
            elif prior.band is not rule.band:
                changes.append(PolicyChange(
                    "class-band", f"class '{key}': band {prior.band.value} -> "
                    f"{rule.band.value}", affected_classes=[key]))
        for key in old_rules:
            if key not in new_rules:
                changes.append(PolicyChange("class-removed", f"class '{key}' removed",
                                            affected_classes=[key]))
        if old.minimum_severity is not new.minimum_severity:
            changes.append(PolicyChange(
                "minimum-severity",
                f"minimum severity {old.minimum_severity.value} -> "
                f"{new.minimum_severity.value}",
                affected_classes=[r.class_key for r in new.class_rules],
                # The floor applies to the whole program: a lowered floor makes
                # findings of every class newly eligible, so the change is
                # program-wide rather than limited to the classes it names.
                program_wide=True))
        return changes

    def affected_research(self, changes: list[PolicyChange]) -> dict:
        """Summarise which classes/assets a set of changes touches."""
        classes: set[str] = set()
        assets: set[str] = set()
        for c in changes:
            classes.update(c.affected_classes)
            assets.update(c.affected_assets)
        program_wide = any(c.program_wide for c in changes)
        return {"classes": sorted(classes), "assets": sorted(assets),
                "reassessment_required": bool(classes or assets or program_wide)}
