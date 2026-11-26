"""Shared data model for the attack lifecycle.

Every artefact the engine produces is a typed record so that it can be stored,
hashed, diffed, and independently re-checked. Records serialise to plain JSON
via ``to_dict`` / ``from_dict`` so the evidence store and ledger can persist them.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import MISSING, asdict, dataclass, field, fields
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def canonical_json(obj: Any) -> str:
    """Deterministic JSON used for content hashing."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


def sha256_of(obj: Any) -> str:
    return hashlib.sha256(canonical_json(obj).encode("utf-8")).hexdigest()


# --------------------------------------------------------------------------- #
# Enumerations
# --------------------------------------------------------------------------- #

class AssetStatus(str, Enum):
    """Result of the authorization gate for a single asset."""

    AUTHORIZED = "AUTHORIZED"
    PASSIVE_ONLY = "PASSIVE_ONLY"
    UNKNOWN = "UNKNOWN"
    OUT_OF_SCOPE = "OUT_OF_SCOPE"


class Classification(str, Enum):
    """Finding quality-gate outcome (see mission section 8)."""

    CONFIRMED = "CONFIRMED"
    NEEDS_MORE_EVIDENCE = "NEEDS_MORE_EVIDENCE"
    INFORMATIONAL = "INFORMATIONAL"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    OUT_OF_SCOPE = "OUT_OF_SCOPE"
    DUPLICATE_OR_KNOWN = "DUPLICATE_OR_KNOWN"
    BLOCKED = "BLOCKED"


class GateStatus(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    UNKNOWN = "UNKNOWN"


class ReviewIndependence(str, Enum):
    """How the adversarial review of a finding was performed.

    Gate 6 asks whether the finding was reviewed. *Who* reviewed it -- a
    separately authenticated model or the same model in a fresh adversarial
    context -- is a distinct fact that must be recorded rather than assumed. A
    same-model review is a real review, but it is **not** an independently
    authenticated second model, and no consumer may read it as one.
    """

    #: A separately configured, independently authenticated model reviewed it.
    INDEPENDENT_MODEL = "INDEPENDENT_MODEL"
    #: The same model reviewed it in a fresh adversarial context. Weaker: shared
    #: blind spots are not excluded, so this is never labelled independent.
    SAME_MODEL = "SAME_MODEL"
    #: The review happened but the reviewer's model independence was not recorded.
    UNRECORDED = "UNRECORDED"

    @classmethod
    def coerce(cls, value) -> "ReviewIndependence":
        """Coerce a value (enum, string, or ``None``) to a provenance, failing closed.

        An unrecognised value becomes ``SAME_MODEL`` rather than raising or passing
        as independent: an unreadable provenance must never be read as independent
        verification, and a typo must never silently promote a review.
        """
        if isinstance(value, cls):
            return value
        try:
            return cls(value)
        except ValueError:
            return cls.SAME_MODEL


#: The canonical gate-6 detail for each reviewer provenance. The wording is the
#: contract: a consumer reading a stored finding must be able to tell, from the
#: gate alone, whether an independent model or the same model reviewed it. It
#: lives beside :class:`ReviewIndependence` so the verifier and every consumer of
#: a stored finding share one definition instead of restating the rule.
GATE6_DETAIL: dict["ReviewIndependence", "tuple[GateStatus, str]"] = {
    ReviewIndependence.INDEPENDENT_MODEL: (
        GateStatus.PASS,
        "adversarial review completed by an independently authenticated model",
    ),
    ReviewIndependence.SAME_MODEL: (
        GateStatus.FAIL,
        "same-model adversarial review (fresh context) only: NOT an independent "
        "second model, so shared blind spots are not excluded",
    ),
    ReviewIndependence.UNRECORDED: (
        GateStatus.PASS,
        "verified by the deterministic verifier; no model reviewer provenance "
        "recorded, so this is not an independent-model review",
    ),
}


def gate6_detail(independence) -> "tuple[GateStatus, str]":
    """The canonical gate-6 status and detail for a reviewer provenance."""
    return GATE6_DETAIL[ReviewIndependence.coerce(independence)]


#: Every gate-6 detail string that names a provenance. A detail outside this set
#: is legacy free text that claims nothing.
CANONICAL_GATE6_DETAILS = frozenset(detail for _, detail in GATE6_DETAIL.values())


def evidenced_review_independence(finding) -> "tuple[ReviewIndependence, str]":
    """The provenance a finding's *own* gate-6 record supports, and why not.

    Provenance is a claim; the gate-6 result is the record of what happened, so
    the claim is only honoured when the record agrees with it. Returns
    ``(provenance, "")`` when they agree, and ``(SAME_MODEL, reason)`` when they
    do not -- ``SAME_MODEL`` rather than the claim because a contradiction is not
    evidence of independence, and ``SAME_MODEL`` is the only provenance that
    cannot be read as independent.

    A legacy free-text detail carries no provenance claim, so it is honoured for
    every provenance *except* ``INDEPENDENT_MODEL``: a detail that names no
    provenance cannot prove one, and only a separately authenticated model writes
    that claim (always with the canonical detail beside it). This is the one rule
    the report layer and the findings repository both apply, so neither can be
    the weaker path.
    """
    value = ReviewIndependence.coerce(getattr(finding, "review_independence", None))
    gate6 = next((g for g in getattr(finding, "gates", ()) if g.gate == 6), None)
    if gate6 is None:
        return value, ""  # nothing recorded to contradict the claim
    if gate6.detail in CANONICAL_GATE6_DETAILS:
        if gate6.detail == gate6_detail(value)[1]:
            return value, ""
        return ReviewIndependence.SAME_MODEL, (
            "the recorded gate-6 result contradicts the claimed provenance"
        )
    if value == ReviewIndependence.INDEPENDENT_MODEL:
        return ReviewIndependence.SAME_MODEL, (
            "the recorded gate-6 result names no provenance to prove independence"
        )
    return value, ""


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ToolStatus(str, Enum):
    """Distinguishes the states the mission requires us to keep separate."""

    INSTALLED = "installed"            # binary present, not yet run
    VERSION_VERIFIED = "version_verified"  # --version ran and returned a version
    FUNCTIONAL = "functional"          # actually produced a correct result
    MISSING = "missing"
    UNSUPPORTED = "unsupported"        # cannot run in this environment


class InvestigationStatus(str, Enum):
    """Lifecycle of one research investigation in the persistent memory.

    These four buckets are kept strictly separate so an unverified idea can never
    be read back as attack knowledge:

      * CONFIRMED  -- reproduced and independently verified.
      * UNCONFIRMED -- a live hypothesis that has not yet been proven.
      * DISPROVEN  -- actively falsified (do not re-run without new evidence).
      * INCOMPLETE -- investigation started but not finished.
    """

    CONFIRMED = "CONFIRMED"
    UNCONFIRMED = "UNCONFIRMED"
    DISPROVEN = "DISPROVEN"
    INCOMPLETE = "INCOMPLETE"


# Statuses that may never be treated as "confirmed attack knowledge".
_UNVERIFIED_STATUSES = frozenset(
    {
        InvestigationStatus.UNCONFIRMED.value,
        InvestigationStatus.DISPROVEN.value,
        InvestigationStatus.INCOMPLETE.value,
    }
)


# --------------------------------------------------------------------------- #
# Authorization
# --------------------------------------------------------------------------- #

@dataclass
class AuthorizationRecord:
    """Dated evidence that a target was verified authorized before testing."""

    program: str
    platform: str
    target_url: str
    scope_url: str
    checked_at: str = field(default_factory=utcnow)
    program_active: Optional[bool] = None
    safe_harbor: Optional[bool] = None
    poc_required: Optional[bool] = None
    nigerian_eligible: Optional[bool] = None
    payout_feasible: Optional[bool] = None
    zero_cost: Optional[bool] = None
    assets: dict[str, str] = field(default_factory=dict)  # asset -> AssetStatus
    # Asset -> AssetStatus classification (AUTHORIZED / PASSIVE_ONLY / UNKNOWN /
    # OUT_OF_SCOPE). Kept as an explicit map so a reviewer can see *why* each
    # asset is or is not testable. ``assets`` is the legacy field; this is the
    # structured form and takes precedence when both are present.
    asset_classes: dict[str, str] = field(default_factory=dict)
    # Scope *patterns* from the official program page (e.g. "*.target.com",
    # "10.0.0.0/24"). When present, an asset that is not listed exactly can still
    # be classified by deterministic pattern match (blackheart.authz.scope_matcher).
    scope_patterns: list[str] = field(default_factory=list)
    # Patterns that are explicitly out of scope even if an allow pattern matches.
    scope_exclusions: list[str] = field(default_factory=list)
    # The scope text as retrieved from the official program page, preserved
    # verbatim so a later reviewer can audit the authorization decision against
    # the exact words that were read (mission section 5: "retrieve its current
    # official scope").
    retrieved_scope: dict[str, Any] = field(default_factory=dict)
    evidence: list[str] = field(default_factory=list)
    notes: str = ""
    verified: bool = False

    def to_dict(self) -> dict:
        d = asdict(self)
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "AuthorizationRecord":
        return cls(**d)


# --------------------------------------------------------------------------- #
# Attacker objectives
# --------------------------------------------------------------------------- #

@dataclass
class Objective:
    """An attacker goal generated before any function-level review."""

    obj_id: str
    title: str
    category: str                 # e.g. "asset-theft", "auth-bypass"
    description: str
    attacker_capabilities: list[str] = field(default_factory=list)
    preconditions: list[str] = field(default_factory=list)
    assets_at_risk: list[str] = field(default_factory=list)
    entry_points: list[str] = field(default_factory=list)
    trust_boundaries: list[str] = field(default_factory=list)
    expected_invariant: str = ""
    attack_sequence: list[str] = field(default_factory=list)
    safe_environment: str = ""
    priority: int = 0             # higher = attack first
    rationale: str = ""
    # The attacker lens this objective answers (blackheart.mindset): the outcome
    # it targets and the attacker-controlled levers it uses. Recorded per objective
    # so the question is answered at the point the objective is created, not only
    # at report time.
    attacker_outcome: str = ""
    attacker_levers: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "Objective":
        return cls(**d)


@dataclass
class AttackStep:
    """A single operation in an attack chain."""

    index: int
    actor: str                    # e.g. "attacker", "victim", "keeper"
    action: str                   # e.g. "deposit", "borrow", "transfer"
    params: dict[str, Any] = field(default_factory=dict)
    target_contract: str = ""
    expected_effect: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class AttackChain:
    """A multi-operation hypothesis combining several weaknesses or states."""

    chain_id: str
    title: str
    objective_id: str
    steps: list[AttackStep] = field(default_factory=list)
    invariants_targeted: list[str] = field(default_factory=list)
    contracts_involved: list[str] = field(default_factory=list)
    actors: list[str] = field(default_factory=list)
    hypothesis: str = ""
    priority: int = 0

    def to_dict(self) -> dict:
        d = asdict(self)
        d["steps"] = [s.to_dict() for s in self.steps]
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "AttackChain":
        d = dict(d)
        d["steps"] = [AttackStep(**s) for s in d.get("steps", [])]
        return cls(**d)


# --------------------------------------------------------------------------- #
# Invariants
# --------------------------------------------------------------------------- #

@dataclass
class Invariant:
    """A property that must hold across arbitrary operation sequences."""

    inv_id: str
    title: str
    statement: str                # human-readable invariant
    predicate: str = ""           # machine-checkable expression / callable name
    category: str = "accounting"
    severity_if_broken: str = Severity.HIGH.value

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class InvariantFailure:
    """A counterexample produced by the stateful fuzzer."""

    inv_id: str
    seed: int
    sequence: list[AttackStep]
    actor_roles: list[str] = field(default_factory=list)
    observed: dict[str, Any] = field(default_factory=dict)
    minimized: bool = False
    minimal_sequence: list[AttackStep] = field(default_factory=list)
    reproduction_command: str = ""
    reproducible: Optional[bool] = None
    reachable_by_attacker: Optional[bool] = None

    def to_dict(self) -> dict:
        d = asdict(self)
        d["sequence"] = [s.to_dict() for s in self.sequence]
        d["minimal_sequence"] = [s.to_dict() for s in self.minimal_sequence]
        return d


# --------------------------------------------------------------------------- #
# Findings
# --------------------------------------------------------------------------- #

@dataclass
class GateResult:
    gate: int                     # 1..7
    name: str
    status: GateStatus
    detail: str = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        d["status"] = self.status.value
        return d


@dataclass
class Finding:
    """A candidate vulnerability and its evidence trail."""

    finding_id: str
    title: str
    target: str
    component: str = ""
    scope_reference: str = ""
    classification: Classification = Classification.NEEDS_MORE_EVIDENCE
    severity: str = Severity.INFO.value
    category: str = ""
    prerequisites: list[str] = field(default_factory=list)
    root_cause: str = ""
    reproduction_steps: list[str] = field(default_factory=list)
    poc_path: str = ""
    expected_behavior: str = ""
    actual_behavior: str = ""
    impact: str = ""
    commands: list[str] = field(default_factory=list)
    evidence_ids: list[str] = field(default_factory=list)
    gates: list[GateResult] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    verification_notes: str = ""
    # Evidence tags actually established (see blackheart.verify.triage.Evidence).
    # When non-empty, the deterministic triage gate is consulted before a report
    # is considered submission-ready; an empty list leaves existing behaviour
    # unchanged.
    evidence_tags: list[str] = field(default_factory=list)
    #: The priced economic account for this finding's sequence, produced by the
    #: universal value engine (:mod:`blackheart.value`): attacker profit, victim
    #: loss, protocol loss, conservation residual, repeatability, max extraction.
    #: ``None`` means "not priced" -- never "no impact". Carried on every finding
    #: so the accounting travels with it through the campaign, discovery, engine
    #: and report layers instead of being re-derived (or forgotten) per pipeline.
    economic: Optional[dict] = None
    created_at: str = field(default_factory=utcnow)
    #: How the adversarial review was performed (see :class:`ReviewIndependence`).
    #: Carried on the finding so the record and the report can state whether an
    #: independent model reviewed it or only the same model in a fresh context.
    #: Declared last so it can never shift an existing positional field.
    review_independence: ReviewIndependence = ReviewIndependence.UNRECORDED

    def to_dict(self) -> dict:
        d = asdict(self)
        d["classification"] = self.classification.value
        d["review_independence"] = ReviewIndependence.coerce(
            self.review_independence
        ).value
        d["gates"] = [g.to_dict() for g in self.gates]
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "Finding":
        # A finding file is external input: reject what cannot be understood
        # instead of crashing on it or silently dropping a field.
        if not isinstance(d, dict):
            raise ValueError(f"a finding must be a JSON object, not {type(d).__name__}")
        d = dict(d)
        known = {f.name for f in fields(cls)}
        unknown = sorted(set(d) - known)
        if unknown:
            raise ValueError(f"unknown finding field(s): {', '.join(unknown)}")
        missing = sorted(
            f.name for f in fields(cls)
            if f.name not in d and f.default is MISSING
            and f.default_factory is MISSING
        )
        if missing:
            raise ValueError(f"missing required finding field(s): {', '.join(missing)}")
        d["classification"] = Classification(d.get("classification", "NEEDS_MORE_EVIDENCE"))
        d["gates"] = [GateResult(**{**g, "status": GateStatus(g["status"])}) for g in d.get("gates", [])]
        if "review_independence" in d and d["review_independence"] is not None:
            d["review_independence"] = ReviewIndependence.coerce(
                d["review_independence"]
            )
        else:
            d["review_independence"] = ReviewIndependence.UNRECORDED
        return cls(**d)

    def gates_pass(self) -> bool:
        """All seven gates must PASS for CONFIRMED."""
        return len(self.gates) == 7 and all(g.status == GateStatus.PASS for g in self.gates)


# --------------------------------------------------------------------------- #
# Evidence
# --------------------------------------------------------------------------- #

@dataclass
class Evidence:
    """A single immutable artefact backing a claim."""

    evidence_id: str
    kind: str                     # "command-output", "screenshot", "log", "file"
    description: str
    sha256: str = ""
    path: str = ""
    command: str = ""
    created_at: str = field(default_factory=utcnow)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


# --------------------------------------------------------------------------- #
# Tool registry
# --------------------------------------------------------------------------- #

@dataclass
class ToolRecord:
    name: str
    status: str = ToolStatus.MISSING.value
    version: str = ""
    path: str = ""
    category: str = ""
    verify_command: str = ""
    functional_test: str = ""
    functional_evidence: str = ""
    notes: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


# --------------------------------------------------------------------------- #
# Persistent research memory
# --------------------------------------------------------------------------- #

@dataclass
class ResearchRecord:
    """A machine-readable record of one investigation (mission Part 2).

    Every investigation -- confirmed, unconfirmed, disproven, or incomplete --
    produces exactly one of these. The record is the unit of the persistent,
    searchable research memory: it captures what was tried, with what tooling and
    configuration, what actually happened, and what was learned, so a later
    investigation can retrieve the relevant lesson instead of repeating it.

    The record never *asserts* a vulnerability. ``status`` is the only thing that
    classifies it, and ``promote()`` refuses to move a record to CONFIRMED unless
    it is independently verified and carries an evidence reference.
    """

    record_id: str
    target: str
    target_revision: str = ""              # exact commit/tag/deployment tested
    authorization_ref: str = ""            # scope record id / official scope URL
    scope_reference: str = ""              # asset string as it appears in scope
    vulnerability_class: str = ""          # e.g. "rounding-precision", "oracle-manipulation"
    hypothesis: str = ""                   # the initial idea
    attack_strategy: str = ""              # the approach taken
    tools: list[str] = field(default_factory=list)         # tools used
    tool_configs: dict[str, Any] = field(default_factory=dict)  # tool -> config/args
    commands: list[str] = field(default_factory=list)      # reproducibility
    expected_outcome: str = ""
    actual_outcome: str = ""
    evidence_hashes: list[str] = field(default_factory=list)  # sha256 of evidence bytes
    exploitability_verdict: str = ""       # human verdict: reachable / not / unknown
    impact: str = ""                       # economic or security impact
    false_positive_reason: str = ""        # why it was disproven, if it was
    lessons: list[str] = field(default_factory=list)       # reusable knowledge
    confidence: str = "low"                # low | medium | high
    independently_verified: bool = False
    verification_ref: str = ""             # evidence id of the verification result
    status: str = InvestigationStatus.INCOMPLETE.value
    related: list[str] = field(default_factory=list)       # other record ids
    created_at: str = field(default_factory=utcnow)
    updated_at: str = field(default_factory=utcnow)

    # -- serialisation ---------------------------------------------------- #
    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "ResearchRecord":
        known = {f for f in cls.__dataclass_fields__}  # type: ignore[attr-defined]
        return cls(**{k: v for k, v in d.items() if k in known})

    # -- invariants ------------------------------------------------------- #
    def is_confirmed(self) -> bool:
        return self.status == InvestigationStatus.CONFIRMED.value

    def is_unverified(self) -> bool:
        return self.status in _UNVERIFIED_STATUSES

    def may_be_read_as_attack_knowledge(self) -> bool:
        """Only a CONFIRMED record may inform 'this is a real vulnerability'.

        Everything else is a lead, a negative result, or unfinished work -- useful
        for steering the search, never a claim of a live vulnerability.
        """
        return self.is_confirmed()

    def promote(self, status: InvestigationStatus | str, *, note: str = "") -> "ResearchRecord":
        """Move the record to ``status``, enforcing the confirmation gate.

        A record may only become CONFIRMED when it is independently verified and
        references verification evidence. An attempt to promote without those is
        refused (returns the record unchanged) rather than silently upgraded.
        """
        value = status.value if isinstance(status, InvestigationStatus) else status
        if value == InvestigationStatus.CONFIRMED.value:
            if not (self.independently_verified and (self.verification_ref or self.evidence_hashes)):
                return self
        self.status = value
        if note:
            self.lessons.append(note)
        self.updated_at = utcnow()
        return self


# --------------------------------------------------------------------------- #
# Pre-submission novelty (mission Phase 2/3)
# --------------------------------------------------------------------------- #

class NoveltyClass(str, Enum):
    """How a candidate relates to what is already publicly known.

    The default is deliberately NOT "novel": a candidate starts LIKELY_DUPLICATE
    until a documented search says otherwise. Absence of a public result is
    recorded as INSUFFICIENT_EVIDENCE, never as proof of novelty.
    """

    LIKELY_NEW = "LIKELY_NEW"
    POSSIBLE_VARIANT = "POSSIBLE_VARIANT"
    LIKELY_DUPLICATE = "LIKELY_DUPLICATE"
    ALREADY_FIXED = "ALREADY_FIXED"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"


# Statuses that must not be promoted to a submission.
_NON_SUBMITTABLE_NOVELTY = frozenset(
    {
        NoveltyClass.LIKELY_DUPLICATE.value,
        NoveltyClass.ALREADY_FIXED.value,
        NoveltyClass.INSUFFICIENT_EVIDENCE.value,
    }
)


@dataclass
class PublicDisclosure:
    """One public artefact compared against a candidate (Phase 3 evidence).

    Each field is stored so a reviewer can re-derive the comparison rather than
    trust a one-word verdict.
    """

    source: str = ""              # CVE / GHSA / advisory / issue / PR / commit
    identifier: str = ""          # e.g. CVE-2024-1234, GHSA-xxxx, issue #123
    url: str = ""
    summary: str = ""
    root_cause: str = ""
    affected_component: str = ""
    trust_boundary: str = ""
    exploit_path: str = ""
    impact: str = ""
    remediation: str = ""         # fix / patch / mitigation already applied
    retrieved_at: str = field(default_factory=utcnow)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class NoveltyReview:
    """A documented, auditable novelty review of one candidate finding.

    A strong PoC does not establish originality, and a new exploit technique does
    not establish a new vulnerability. This record is the gate that must be
    satisfied *before* a finding is treated as submission-ready.
    """

    finding_id: str
    target: str = ""
    target_revision: str = ""
    vulnerability_class: str = ""
    # The candidate's own characteristics, used for the comparison.
    root_cause: str = ""
    affected_component: str = ""
    trust_boundary: str = ""
    exploit_path: str = ""
    impact: str = ""
    prerequisites: list[str] = field(default_factory=list)
    technique: str = ""           # the exploit technique (novelty of *technique*
                                  # does NOT imply novelty of *vulnerability*)
    # The public search.
    queries: list[str] = field(default_factory=list)
    databases_searched: list[str] = field(default_factory=list)
    # Independent origins (registrable domains) actually seen in the results.
    # Provider count is NOT a substitute for this: four pages from one publisher
    # are one origin. When empty, the gate falls back to ``databases_searched``
    # so a hand-recorded review keeps its previous meaning.
    independent_sources: list[str] = field(default_factory=list)
    disclosures: list[PublicDisclosure] = field(default_factory=list)
    search_limitations: list[str] = field(default_factory=list)
    classification: str = NoveltyClass.INSUFFICIENT_EVIDENCE.value
    classification_reason: str = ""
    reviewed_at: str = field(default_factory=utcnow)
    reviewer: str = ""

    def to_dict(self) -> dict:
        return {
            **{k: v for k, v in asdict(self).items() if k != "disclosures"},
            "disclosures": [d.to_dict() for d in self.disclosures],
        }

    @classmethod
    def from_dict(cls, d: dict) -> "NoveltyReview":
        known = {f for f in cls.__dataclass_fields__}  # type: ignore[attr-defined]
        data = {k: v for k, v in d.items() if k in known}
        data["disclosures"] = [PublicDisclosure(**x) for x in d.get("disclosures", [])]
        return cls(**data)

    def is_submittable(self) -> bool:
        """Only a LIKELY_NEW or POSSIBLE_VARIANT finding may be submitted.

        Everything else -- a duplicate, an already-fixed issue, or a search too
        thin to support a claim -- is blocked from submission.
        """
        return self.classification not in _NON_SUBMITTABLE_NOVELTY

    def blocking_reason(self) -> str:
        if self.is_submittable():
            return ""
        return (
            f"novelty classification is {self.classification}: "
            f"{self.classification_reason or 'no reason recorded'}"
        )
