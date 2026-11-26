"""Authorization gate (mission section 5).

The gate is the single choke point that decides whether any *active* testing may
run against an asset. It fails closed: an asset is only promoted to
``AUTHORIZED`` when every required verification is affirmatively recorded.

Design rules:
  * Pure logic lives here and is unit-testable without network or I/O.
  * ``AuthorizationRecord`` is the durable, dated artefact.
  * ``authorize_active_testing`` raises ``AuthorizationError`` unless the asset
    is AUTHORIZED *and* the program-level checks all pass.

Nothing here infers authorization from a public repository, a deployed app, or a
third-party tracker -- those are explicitly rejected inputs.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Optional

from ..models import AssetStatus, AuthorizationRecord, utcnow

# Authorization evidence goes stale. A record whose dated verification is older
# than this window must be re-verified before it can authorize active testing
# (mission section 5: "Retrieve its current official scope" before every
# campaign). The daily monitoring job re-checks the live scope and refreshes the
# record, so a healthy pipeline never trips this gate.
MAX_EVIDENCE_AGE = timedelta(days=7)


class AuthorizationError(RuntimeError):
    """Raised when active testing is attempted without verified authorization."""


# Asset kinds that may NEVER be treated as authorized purely because the owning
# company also owns an in-scope asset. Ownership != permission.
NON_INFERABLE_SOURCES = frozenset(
    {
        "public-repository",
        "deployed-application",
        "third-party-tracker",
        "company-ownership",
        "assumption",
    }
)

# Program-level checks that must all be True before ANY active testing.
REQUIRED_PROGRAM_CHECKS = (
    "program_active",
    "safe_harbor",
    "zero_cost",
)


@dataclass
class GateDecision:
    allowed: bool
    asset: str
    status: AssetStatus
    reasons: list[str] = field(default_factory=list)
    blockers: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "allowed": self.allowed,
            "asset": self.asset,
            "status": self.status.value,
            "reasons": self.reasons,
            "blockers": self.blockers,
        }


def classify_asset(record: AuthorizationRecord, asset: str) -> AssetStatus:
    """Return the recorded status of ``asset``, defaulting to UNKNOWN.

    A status that is not explicitly present is UNKNOWN -- never AUTHORIZED.
    The structured ``asset_classes`` map takes precedence over the legacy
    ``assets`` map when both are present.
    """
    raw = record.asset_classes.get(asset, record.assets.get(asset))
    if raw is None:
        return AssetStatus.UNKNOWN
    try:
        return AssetStatus(raw)
    except ValueError:
        return AssetStatus.UNKNOWN


def asset_classification_report(record: AuthorizationRecord) -> dict[str, str]:
    """Return every recorded asset with its classification, for audit output.

    Any asset named in either map is reported; the value is normalised to a
    valid ``AssetStatus`` (an unparsable value becomes UNKNOWN).
    """
    names = set(record.assets) | set(record.asset_classes)
    return {name: classify_asset(record, name).value for name in sorted(names)}


def classify_asset_by_pattern(record: AuthorizationRecord, asset: str):
    """Classify ``asset`` against the record's scope *patterns*.

    Returns a :class:`~blackheart.authz.scope_matcher.ScopeDecision` when the
    record carries patterns, else ``None`` (nothing to match against). This is
    the deterministic pattern path; :func:`classify_asset` (exact map) remains
    the primary and is consulted first by :func:`authorize_active_testing`.

    Fails closed: an unparsable URL or a dangerous pattern is OUT_OF_SCOPE /
    raises, never silently in scope.
    """
    patterns = list(getattr(record, "scope_patterns", []) or [])
    exclusions = list(getattr(record, "scope_exclusions", []) or [])
    if not patterns:
        return None
    from .scope_matcher import ScopeMatcher

    matcher = ScopeMatcher(allow=patterns, exclude=exclusions)
    return matcher.explain(asset)


def evidence_age(record: AuthorizationRecord, now: Optional[datetime] = None) -> Optional[timedelta]:
    """Return how old the record's dated verification is, or ``None`` if unusable.

    An unparsable or missing ``checked_at`` returns ``None`` so callers treat the
    evidence as unusable rather than assuming it is fresh.
    """
    if not record.checked_at:
        return None
    try:
        checked = datetime.fromisoformat(record.checked_at)
    except ValueError:
        return None
    if checked.tzinfo is None:
        checked = checked.replace(tzinfo=timezone.utc)
    now = now or datetime.now(timezone.utc)
    return now - checked


def program_checks_pass(record: AuthorizationRecord) -> tuple[bool, list[str]]:
    """Verify the program-level conditions required for active testing."""
    blockers: list[str] = []
    for name in REQUIRED_PROGRAM_CHECKS:
        value = getattr(record, name, None)
        if value is not True:
            blockers.append(f"program check failed: {name}={value!r} (must be True)")
    if record.nigerian_eligible is not True:
        blockers.append(
            f"researcher eligibility not established: nigerian_eligible={record.nigerian_eligible!r}"
        )
    if record.payout_feasible is not True:
        blockers.append(
            f"payout feasibility not established: payout_feasible={record.payout_feasible!r}"
        )
    if not record.verified:
        blockers.append("authorization record is not marked verified")
    if not record.evidence:
        blockers.append("no dated authorization evidence recorded")
    if not record.scope_url:
        blockers.append("no official scope URL recorded")
    age = evidence_age(record)
    if age is None:
        blockers.append("authorization evidence has no parsable checked_at timestamp")
    elif age > MAX_EVIDENCE_AGE:
        blockers.append(
            f"authorization evidence is stale ({age.days} days old > "
            f"{MAX_EVIDENCE_AGE.days}-day limit); re-verify the current official scope"
        )
    return (not blockers), blockers


def authorize_active_testing(record: AuthorizationRecord, asset: str) -> GateDecision:
    """Decide whether *active* testing may proceed against ``asset``.

    Active testing requires:
      1. the asset is explicitly AUTHORIZED (not inferred), and
      2. every program-level check passes.

    Classification order: the explicit ``asset_classes``/``assets`` map first; if
    the asset is not listed there and the record carries scope *patterns*, the
    deterministic matcher decides (a pattern match authorizes; anything
    unlisted/unmatched is OUT_OF_SCOPE). Only an AUTHORIZED result -- from either
    path -- can pass.
    """
    status = classify_asset(record, asset)
    reasons: list[str] = [f"asset '{asset}' classified {status.value}"]

    if status == AssetStatus.UNKNOWN:
        decision = classify_asset_by_pattern(record, asset)
        if decision is not None:
            status = decision.status
            reasons.append(f"scope pattern: {decision.reason}")
            if decision.matched_rule:
                reasons.append(f"matched rule: {decision.matched_rule}")

    blockers: list[str] = []

    if status != AssetStatus.AUTHORIZED:
        blockers.append(
            f"asset '{asset}' is {status.value}; only AUTHORIZED assets may be actively tested"
        )
        return GateDecision(False, asset, status, reasons, blockers)

    ok, program_blockers = program_checks_pass(record)
    blockers.extend(program_blockers)
    if ok:
        reasons.append("all program checks passed")
    return GateDecision(ok, asset, status, reasons, blockers)


def assert_authorized(record: AuthorizationRecord, asset: str) -> None:
    """Raise ``AuthorizationError`` unless active testing is permitted."""
    decision = authorize_active_testing(record, asset)
    if not decision.allowed:
        raise AuthorizationError(
            f"active testing blocked for '{asset}': " + "; ".join(decision.blockers)
        )


def reject_inferred_authorization(source: str, asset: str) -> None:
    """Guard against inferring authorization from non-authorizing sources.

    Called by discovery code whenever it is tempted to treat an asset as in-scope
    because it *looks* related to an authorized program.
    """
    if source in NON_INFERABLE_SOURCES:
        raise AuthorizationError(
            f"cannot infer authorization for '{asset}' from source '{source}'; "
            "authorization must be recorded from the official program scope"
        )


def new_record(
    program: str,
    platform: str,
    target_url: str,
    scope_url: str,
    **checks: Optional[bool],
) -> AuthorizationRecord:
    """Build an (initially unverified) authorization record.

    ``checks`` accepts the program-level booleans by keyword; anything omitted
    stays ``None`` and therefore blocks active testing.
    """
    rec = AuthorizationRecord(
        program=program,
        platform=platform,
        target_url=target_url,
        scope_url=scope_url,
        checked_at=utcnow(),
    )
    for name in (
        "program_active",
        "safe_harbor",
        "poc_required",
        "nigerian_eligible",
        "payout_feasible",
        "zero_cost",
    ):
        if name in checks:
            setattr(rec, name, checks[name])
    return rec
