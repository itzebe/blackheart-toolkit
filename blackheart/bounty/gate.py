"""The mandatory official-policy eligibility gate for every candidate.

GOVERNING RULE
--------------
The official, program-specific bug bounty policy is the **sole authority** on
whether a vulnerability is eligible for submission. It decides the eligible
assets, the exclusions, the qualifying classes, the required impact, the
severity, the attacker prerequisites, the evidence bar, the duplicate treatment,
the disclosure rules and the reward conditions.

No internal score, no generic numeric threshold and no universal
severity-to-payout assumption may decide eligibility. ``research_score`` exists
on :class:`CandidateRecord` for research *prioritisation* only; :func:`gate`
never reads it, and a regression test asserts that changing it cannot change a
disposition. A valid Low or Medium finding stays eligible whenever the program's
own rules say it is.

The gate is deliberately a separate step from :func:`blackheart.bounty.evaluate`:
``evaluate`` reads a *structured* ``ProgramPolicy`` and produces one of ten
outcomes; this gate records the **seven mandatory gates** an operator must pass
(:data:`blackheart.doctrine.BOUNTY_GATES` -- deployment, eligibility,
reachability, security violation, impact, novelty, reportability) and refuses to
call anything submission-ready without traceable policy evidence.

The gates are independent and non-compensating, and no invented numeric
threshold may stand in for them (``doctrine.BOUNTY_NO_THRESHOLD_RULE``). The
classification a candidate is reported under is one of five
(:data:`CLASSIFICATIONS`); the six dispositions below are the process states that
map onto them.

If the official policy cannot be retrieved or verified, the answer is
``BLOCKED — OFFICIAL BOUNTY POLICY NOT VERIFIED``, never an invented decision.
A technical finding may stay documented while its bounty eligibility is blocked.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from ..doctrine import BOUNTY_GATES, BOUNTY_POLICY_UNVERIFIED
from ..ingest.truth import validate_deployment_truth
from . import Severity, sha256_text

__all__ = [
    "Disposition",
    "CLASSIFICATIONS",
    "MANDATORY_GATES",
    "classification_for",
    "POLICY_UNVERIFIED_BLOCKER",
    "CandidateRecord",
    "GateOutcome",
    "gate",
    "assert_submission_ready",
    "disposition_for",
    "SUBMISSION_READY_REQUIRES",
]


#: The exact string required when the official policy is unavailable. Defined
#: once in :mod:`blackheart.doctrine` so the doctrine and the gate cannot drift.
POLICY_UNVERIFIED_BLOCKER = BOUNTY_POLICY_UNVERIFIED


class Disposition:
    """The six evidence-supported dispositions (Gate D).

    These are *not* severity classes. A valid Low stays a valid Low whatever its
    disposition; a disposition only says whether the official program rules make
    it submittable, and why not when they do not.
    """

    SUBMISSION_READY = "A_SUBMISSION_READY"
    POTENTIALLY_PAYABLE = "B_POTENTIALLY_PAYABLE"
    VALID_NOT_PAYABLE = "C_VALID_NOT_PAYABLE"
    INVALID = "D_INVALID_OR_DISPROVEN"
    INFORMATIONAL = "E_INFORMATIONAL"
    NOT_ASSESSED = "F_NOT_ASSESSED"

    ORDER = (
        SUBMISSION_READY, POTENTIALLY_PAYABLE, VALID_NOT_PAYABLE,
        INVALID, INFORMATIONAL, NOT_ASSESSED,
    )

    LABELS = {
        SUBMISSION_READY: "A — submission-ready: meets verified technical and "
                          "program eligibility requirements",
        POTENTIALLY_PAYABLE: "B — potentially payable: plausible qualifying "
                             "vulnerability with outstanding validation",
        VALID_NOT_PAYABLE: "C — valid but not payable: technically valid, but "
                           "excluded or otherwise ineligible under the program rules",
        INVALID: "D — invalid or disproven",
        INFORMATIONAL: "E — informational: demonstrable observation without an "
                       "established qualifying impact",
        NOT_ASSESSED: "F — not assessed: insufficient evidence to reach a conclusion",
    }


#: The seven mandatory gates, re-exported so a caller does not need to reach into
#: the doctrine to enumerate them.
MANDATORY_GATES = BOUNTY_GATES

#: The five classifications a candidate is reported under. ``E`` is deliberately
#: absent: an informational observation fails Gate 5 (impact) and is class ``C``.
CLASSIFICATIONS = ("A", "B", "C", "D", "F")

#: Disposition -> classification. A disposition says what the process concluded;
#: a classification says what the candidate is. They are different axes, and this
#: is the only bridge between them.
_CLASSIFICATION_BY_DISPOSITION = {
    Disposition.SUBMISSION_READY: "A",
    Disposition.POTENTIALLY_PAYABLE: "B",
    Disposition.VALID_NOT_PAYABLE: "C",
    Disposition.INVALID: "D",
    Disposition.INFORMATIONAL: "C",
    Disposition.NOT_ASSESSED: "F",
}


def classification_for(disposition: str) -> str:
    """Map a gate disposition to one of :data:`CLASSIFICATIONS`.

    ``A`` is reachable only from ``SUBMISSION_READY``, so no candidate can be
    reported payable without having passed every mandatory gate.
    """
    try:
        return _CLASSIFICATION_BY_DISPOSITION[disposition]
    except KeyError:
        raise ValueError(f"unknown disposition: {disposition!r}") from None


#: What a submission-ready disposition requires, stated once so no workflow can
#: quietly relax it.
SUBMISSION_READY_REQUIRES = (
    "a verified official policy snapshot (URL, retrieval date, matching SHA-256)",
    "the affected asset verified in scope",
    "no applicable exclusion, known issue or duplicate",
    "a reproduced technical finding with attached evidence",
    "a demonstrated impact inside a published severity definition",
    "the affected deployment verified (or the policy covers undeployed source)",
    "a program-recognised severity",
    "a reward actually available for that severity",
    "the exact policy sections cited",
)

_REPRODUCED = "CONFIRMED"
_DISPROVEN = frozenset({"FALSE_POSITIVE", "DISPROVEN"})
_INFORMATIONAL = "INFORMATIONAL"

#: The four payment determinations a reassessment must return. The six
#: dispositions above are the gate's internal vocabulary; these are the words a
#: reassessment is reported in, and this mapping is the only bridge between them.
PAYMENT_DETERMINATIONS = (
    "PAYABLE",
    "POTENTIALLY PAYABLE",
    "NOT PAYABLE",
    "UNRESOLVED",
)

_DETERMINATION_BY_DISPOSITION = {
    Disposition.SUBMISSION_READY: "PAYABLE",
    Disposition.POTENTIALLY_PAYABLE: "POTENTIALLY PAYABLE",
    Disposition.VALID_NOT_PAYABLE: "NOT PAYABLE",
    Disposition.INVALID: "NOT PAYABLE",
    Disposition.INFORMATIONAL: "NOT PAYABLE",
    Disposition.NOT_ASSESSED: "UNRESOLVED",
}


def payment_determination(disposition: str) -> str:
    """Map a gate disposition to one of :data:`PAYMENT_DETERMINATIONS`.

    ``PAYABLE`` is reachable only from ``A_SUBMISSION_READY``, so no candidate can
    be reported as payable without having passed every documented requirement.
    """
    try:
        return _DETERMINATION_BY_DISPOSITION[disposition]
    except KeyError:
        raise ValueError(f"unknown disposition: {disposition!r}") from None


@dataclass
class CandidateRecord:
    """One candidate, with every field the register must state.

    The field groups follow the four gates. Anything not established is left
    empty/``None`` and is treated as *unverified* downstream -- never filled with
    a plausible default.
    """

    candidate_id: str
    target: str
    component: str = ""
    # ---- Gate A: official policy verification ----
    program: str = ""
    policy_url: str = ""
    policy_verified_at: str = ""
    policy_revision: str = ""
    policy_sha256: str = ""
    policy_text: str = ""
    in_scope_assets: list[str] = field(default_factory=list)
    out_of_scope_assets: list[str] = field(default_factory=list)
    exclusions: list[str] = field(default_factory=list)
    severity_criteria: dict[str, str] = field(default_factory=dict)
    required_impact: str = ""
    reward_conditions: str = ""
    # ---- Gate B: technical validation ----
    demonstrated_impact: str = ""
    attacker_prerequisites: list[str] = field(default_factory=list)
    reproduction_status: str = ""
    evidence_refs: list[str] = field(default_factory=list)
    root_cause: str = ""
    affected_deployment: str = ""
    deployment_verified: Optional[bool] = None
    #: A runtime-bound deployment-truth record. Required when
    #: ``deployment_verified`` is True, so a boolean cannot stand in for proof.
    deployment_truth: dict = field(default_factory=dict)
    # ---- Gate C: eligibility assessment ----
    asset_scope: str = ""            # "in_scope" | "out_of_scope" | "" (unknown)
    #: Temporal / staged scope, copied from the normalized policy.
    scope_effective_from: str = ""
    scope_effective_verified: Optional[bool] = None
    component_status: str = ""      # active | staged | under_remediation | not_public
    vulnerability_class: str = ""
    program_severity: str = ""
    impact_meets_policy: Optional[bool] = None
    known_or_fixed: Optional[bool] = None
    duplicate_check: str = ""
    remediation_check: str = ""
    reward_available: Optional[bool] = None
    expected_payout: str = ""
    policy_sections: list[str] = field(default_factory=list)
    # ---- Gate D: disposition ----
    disposition: str = ""
    blockers: list[str] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)
    submission_recommendation: str = ""
    # ---- Prioritisation metadata: never an eligibility input ----
    research_score: Optional[float] = None
    score_note: str = (
        "research prioritisation metadata only; this value is never read by the "
        "eligibility gate and cannot make a finding eligible or ineligible"
    )

    def to_dict(self) -> dict:
        return dict(self.__dict__)

    @classmethod
    def from_dict(cls, d: dict) -> "CandidateRecord":
        known = {f for f in cls.__dataclass_fields__}  # type: ignore[attr-defined]
        return cls(**{k: v for k, v in d.items() if k in known})

    # -- Gate A helpers -----------------------------------------------------
    def policy_verified(self) -> bool:
        """True only when a source, a date and a matching text hash are present."""
        if not (self.policy_url and self.policy_verified_at and self.policy_sha256):
            return False
        if self.policy_text:
            return sha256_text(self.policy_text) == self.policy_sha256
        return False

    def policy_evidence(self) -> dict:
        """The provenance a reviewer needs to re-verify the policy."""
        return {
            "program": self.program,
            "url": self.policy_url,
            "retrieved_at": self.policy_verified_at,
            "revision": self.policy_revision,
            "sha256": self.policy_sha256,
        }


@dataclass
class GateOutcome:
    """The gate's decision, with the reasoning and the policy evidence attached."""

    candidate_id: str
    disposition: str
    blockers: list[str] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)
    policy_verified: bool = False
    policy_evidence: dict = field(default_factory=dict)

    @property
    def submission_ready(self) -> bool:
        return self.disposition == Disposition.SUBMISSION_READY

    @property
    def determination(self) -> str:
        """The payment determination a reassessment reports."""
        return payment_determination(self.disposition)

    @property
    def label(self) -> str:
        return Disposition.LABELS.get(self.disposition, self.disposition)

    @property
    def classification(self) -> str:
        """The reported class: one of A, B, C, D, F."""
        return classification_for(self.disposition)

    def to_dict(self) -> dict:
        return {
            "candidate_id": self.candidate_id,
            "disposition": self.disposition,
            "determination": self.determination,
            "classification": self.classification,
            "label": self.label,
            "submission_ready": self.submission_ready,
            "policy_verified": self.policy_verified,
            "policy_evidence": dict(self.policy_evidence),
            "blockers": list(self.blockers),
            "reasons": list(self.reasons),
        }


def _class_excluded(record: CandidateRecord) -> Optional[str]:
    """Whole-token match of the candidate's class against the policy exclusions.

    Substring matching would let ``rce`` match ``resource-exhaustion``; the same
    token rule as :mod:`blackheart.bounty` is used so both paths agree.
    """
    from . import _phrase_in, _tokens

    hay = _tokens(f"{record.vulnerability_class} {record.component}")
    for cls in record.exclusions:
        if cls and _phrase_in(_tokens(cls), hay):
            return cls
    return None


def gate(record: CandidateRecord) -> GateOutcome:
    """Run Gates A-D and return one disposition. Deterministic; score-blind.

    The order is deliberate: policy provenance outranks everything (nothing
    downstream may be asserted without it), then validity, then an impact that
    provably cannot qualify, then reproduction completeness, then scope,
    exclusions and the reward question. ``record.research_score`` is never
    consulted -- that is the whole point of this gate.
    """
    out = GateOutcome(
        candidate_id=record.candidate_id, disposition=Disposition.NOT_ASSESSED,
        policy_verified=record.policy_verified(),
        policy_evidence=record.policy_evidence(),
    )

    # -- Gate A: the official policy must be verified before anything else. ----
    if not out.policy_verified:
        out.blockers.append(POLICY_UNVERIFIED_BLOCKER)
        out.blockers.append(
            "official policy needs a source URL, a retrieval date and a SHA-256 "
            "that matches the captured text"
        )
        return out
    out.reasons.append(f"official policy verified: {record.program or 'unnamed'}")

    # -- Gate B: is this a real, reproduced finding? -------------------------
    status = (record.reproduction_status or "").strip().upper()
    if status in _DISPROVEN:
        out.disposition = Disposition.INVALID
        out.reasons.append("reproduction disproved the claim")
        return out
    if status == _INFORMATIONAL:
        out.disposition = Disposition.INFORMATIONAL
        out.reasons.append("informational observation without a qualifying impact")
        return out

    # An impact that provably cannot qualify under the published rules disqualifies
    # the candidate before any further reproduction effort is spent on it.
    if record.impact_meets_policy is False:
        out.disposition = Disposition.VALID_NOT_PAYABLE
        out.blockers.append(
            "demonstrated impact does not meet the published requirement"
            + (f": {record.required_impact}" if record.required_impact else "")
        )
        if status != _REPRODUCED:
            out.reasons.append(
                f"reproduction status {record.reproduction_status!r} is moot: the "
                "impact cannot qualify under this program's rules"
            )
        return out

    if status != _REPRODUCED:
        if not record.evidence_refs:
            out.disposition = Disposition.NOT_ASSESSED
            out.blockers.append(
                f"reproduction status {record.reproduction_status!r} with no evidence "
                "attached: nothing can be assessed"
            )
        else:
            out.disposition = Disposition.POTENTIALLY_PAYABLE
            out.blockers.append(
                f"reproduction status {record.reproduction_status!r} is not "
                f"{_REPRODUCED}; independent reproduction is outstanding"
            )
        return out
    if not record.evidence_refs:
        out.disposition = Disposition.NOT_ASSESSED
        out.blockers.append("CONFIRMED claim with no evidence references attached")
        return out
    out.reasons.append(f"reproduced with {len(record.evidence_refs)} evidence reference(s)")

    # -- Gate C: eligibility, against the program's own rules. ---------------
    scope = (record.asset_scope or "").strip().lower()
    if scope == "out_of_scope":
        out.disposition = Disposition.VALID_NOT_PAYABLE
        out.blockers.append(f"asset {record.target!r} is out of scope for {record.program}")
        return out
    if scope != "in_scope":
        out.disposition = Disposition.POTENTIALLY_PAYABLE
        out.blockers.append(f"asset {record.target!r} scope not verified")
        return out
    out.reasons.append(f"asset {record.target!r} verified in scope")

    component_status = (record.component_status or "").strip().lower()
    if component_status in ("staged", "under_remediation", "not_public", "excluded"):
        out.disposition = Disposition.VALID_NOT_PAYABLE
        out.blockers.append(
            f"component {record.component or record.target!r} is {component_status} "
            "under the official policy: not assessable in this season"
        )
        return out
    if record.scope_effective_from and record.scope_effective_verified is not True:
        out.disposition = Disposition.POTENTIALLY_PAYABLE
        out.blockers.append(
            f"scope effective from {record.scope_effective_from!r} is not verified "
            "for the report date"
        )
        return out

    excluded = _class_excluded(record)
    if excluded:
        out.disposition = Disposition.VALID_NOT_PAYABLE
        out.blockers.append(f"vulnerability class excluded by policy: {excluded!r}")
        return out

    if record.known_or_fixed:
        out.disposition = Disposition.VALID_NOT_PAYABLE
        out.blockers.append(
            "already known, fixed or disclosed: "
            f"{record.duplicate_check or record.remediation_check or 'established'}"
        )
        return out

    if record.deployment_verified is not True:
        if record.deployment_verified is False:
            out.disposition = Disposition.VALID_NOT_PAYABLE
            out.blockers.append(
                "no affected deployment verified; a source-level defect alone is not "
                "a live vulnerability under a policy that covers deployed assets"
            )
        else:
            out.disposition = Disposition.POTENTIALLY_PAYABLE
            out.blockers.append(
                "affected deployment not verified: source-level defect only so far"
            )
        return out
    truth_ok, truth_reason = validate_deployment_truth(record.deployment_truth)
    if not truth_ok:
        out.disposition = Disposition.POTENTIALLY_PAYABLE
        out.blockers.append(
            "deployment_verified is not backed by a runtime-bound deployment "
            f"truth record: {truth_reason}"
        )
        return out
    out.reasons.append(
        f"affected deployment verified: {record.affected_deployment or 'stated'}; "
        f"deployment truth: {truth_reason}"
    )

    severity = Severity.coerce(record.program_severity)
    if not severity:
        out.disposition = Disposition.POTENTIALLY_PAYABLE
        out.blockers.append(
            f"program severity not established for {record.vulnerability_class!r}"
        )
        return out
    out.reasons.append(f"program severity: {severity}")

    if record.reward_available is False:
        out.disposition = Disposition.VALID_NOT_PAYABLE
        out.blockers.append(
            f"program pays no reward for severity {severity!r}"
            + (f" ({record.expected_payout})" if record.expected_payout else "")
        )
        return out
    if record.reward_available is None:
        out.disposition = Disposition.POTENTIALLY_PAYABLE
        out.blockers.append(f"reward availability for severity {severity!r} not established")
        return out

    if record.expected_payout and record.reward_available is not True:
        out.disposition = Disposition.POTENTIALLY_PAYABLE
        out.blockers.append("payout stated but reward eligibility not established")
        return out

    if not record.policy_sections:
        out.disposition = Disposition.POTENTIALLY_PAYABLE
        out.blockers.append(
            "no policy section cited: a submission-ready record must point at the "
            "exact official clauses it relies on"
        )
        return out
    out.reasons.append(
        f"cites {len(record.policy_sections)} official policy section(s)"
    )

    # -- Gate D: every requirement met. --------------------------------------
    out.disposition = Disposition.SUBMISSION_READY
    out.reasons.append("meets every verified technical and program requirement")
    return out


def assert_submission_ready(record: CandidateRecord) -> GateOutcome:
    """Return the gate outcome, or raise unless it is submission-ready.

    The single enforcement point: any workflow that wants to mark a candidate
    submission-ready must call this, so a high internal score cannot stand in for
    policy evidence.
    """
    out = gate(record)
    if not out.submission_ready:
        raise ValueError(
            f"candidate {record.candidate_id!r} is not submission-ready "
            f"({out.disposition}): " + "; ".join(out.blockers)
        )
    return out


def disposition_for(outcome: str, *, informational: bool = False) -> str:
    """Map a :class:`blackheart.bounty.Outcome` onto a Gate D disposition.

    ``informational=True`` is passed by callers that know the finding's
    classification is INFORMATIONAL, because the outcome vocabulary folds it into
    ``INVALID`` and an informational observation is *not* a disproven one.
    """
    from . import Outcome

    if informational:
        return Disposition.INFORMATIONAL
    mapping = {
        Outcome.VALID_AND_PAYABLE: Disposition.SUBMISSION_READY,
        Outcome.VALID_WITH_UNVERIFIED_ELIGIBILITY: Disposition.POTENTIALLY_PAYABLE,
        Outcome.VALID_BUT_NOT_PAYABLE: Disposition.VALID_NOT_PAYABLE,
        Outcome.OUT_OF_SCOPE: Disposition.VALID_NOT_PAYABLE,
        Outcome.EXCLUDED_BY_POLICY: Disposition.VALID_NOT_PAYABLE,
        Outcome.DUPLICATE_OR_KNOWN: Disposition.VALID_NOT_PAYABLE,
        Outcome.INVALID: Disposition.INVALID,
        Outcome.INSUFFICIENT_EVIDENCE: Disposition.NOT_ASSESSED,
        Outcome.REPRODUCTION_REQUIRED: Disposition.NOT_ASSESSED,
        Outcome.POLICY_UNVERIFIED: Disposition.NOT_ASSESSED,
    }
    return mapping.get(outcome, Disposition.NOT_ASSESSED)
