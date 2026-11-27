"""Program-specific bounty intelligence: is a valid finding actually payable?

A technically valid finding is not a payable one. A program pays only for what its
*own* policy says it pays for: an in-scope asset, a vulnerability class it does not
exclude, at a severity it recognises, not already known. This module answers that
question from the program's official policy, with the provenance attached, and
refuses to answer it from a guess.

The design keeps four axes **separate**, because collapsing them is how real
reports get wrongly rejected or wrongly promised:

  * **Technical validity** -- does the finding hold up (classification, evidence)?
  * **Severity** -- how bad is it *under this program's* definitions, not a global
    CVSS number?
  * **Scope eligibility** -- is the asset in scope and not excluded?
  * **Payout eligibility** -- does the program pay for this class at this severity?

A finding can be valid and non-payable (a real bug in an out-of-scope class); it
can be invalid and in-scope; it can be payable at Low or Medium. No axis is
allowed to overwrite another, and a generic "confidence score" never decides
eligibility -- :func:`evaluate` has no numeric confidence input at all.

Provenance is first class. A :class:`PolicySnapshot` records the exact source URL,
retrieval date, a SHA-256 of the retrieved text, and a revision id. A snapshot is
immutable once stored; when the official policy changes, a new snapshot is added,
the old one is preserved, and findings are **re-evaluated against the new one
without rewriting the old evaluation** -- the prior decision and the policy it was
made under stay in the ledger.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from ..chainedlog import ChainedLog
from ..integrity import IntegrityKey
from ..models import Finding, utcnow

__all__ = [
    "Outcome",
    "Severity",
    "PolicySnapshot",
    "ProgramPolicy",
    "Evaluation",
    "BountyLedger",
    "evaluate",
    "severity_for",
    "prepare_submission",
    "reevaluate",
    "sha256_text",
    "Disposition",
    "CLASSIFICATIONS",
    "MANDATORY_GATES",
    "classification_for",
    "CandidateRecord",
    "GateOutcome",
    "POLICY_UNVERIFIED_BLOCKER",
    "SUBMISSION_READY_REQUIRES",
    "gate_candidate",
    "assert_submission_ready",
    "disposition_for",
    "PAYMENT_DETERMINATIONS",
    "payment_determination",
]


class Outcome:
    """The ten required outcome states. A finding gets exactly one.

    They are deliberately not a single scale: ``VALID_BUT_NOT_PAYABLE`` and
    ``INVALID`` are different, and ``POLICY_UNVERIFIED`` is a statement about our
    knowledge, not about the finding. Keeping them distinct is what stops a valid
    Low finding being silently dropped and a non-payable one being called invalid.
    """

    VALID_AND_PAYABLE = "VALID_AND_PAYABLE"
    VALID_BUT_NOT_PAYABLE = "VALID_BUT_NOT_PAYABLE"
    VALID_WITH_UNVERIFIED_ELIGIBILITY = "VALID_WITH_UNVERIFIED_ELIGIBILITY"
    INVALID = "INVALID"
    OUT_OF_SCOPE = "OUT_OF_SCOPE"
    EXCLUDED_BY_POLICY = "EXCLUDED_BY_POLICY"
    DUPLICATE_OR_KNOWN = "DUPLICATE_OR_KNOWN"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
    REPRODUCTION_REQUIRED = "REPRODUCTION_REQUIRED"
    POLICY_UNVERIFIED = "POLICY_UNVERIFIED"


#: Outcomes that assert the finding is real. Used to keep "invalid" separate from
#: "not payable" -- a caller must never read a non-payable outcome as "not a bug".
VALID_OUTCOMES = frozenset({
    Outcome.VALID_AND_PAYABLE, Outcome.VALID_BUT_NOT_PAYABLE,
    Outcome.VALID_WITH_UNVERIFIED_ELIGIBILITY,
})


class Severity:
    """The four bounty severity classes, ordered. Info is not a bounty severity."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    ORDER = (LOW, MEDIUM, HIGH, CRITICAL)

    @classmethod
    def rank(cls, value: str) -> int:
        try:
            return cls.ORDER.index(value)
        except ValueError:
            return -1

    @classmethod
    def coerce(cls, value: str) -> str:
        v = (value or "").strip().lower()
        return v if v in cls.ORDER else ""


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


#: The fields a `bounty capture` file always carries. A capture is a bare snapshot,
#: so these four together identify one without confusing it with a policy object.
_SNAPSHOT_FIELDS = ("program", "source_url", "retrieved_at", "sha256")


# --------------------------------------------------------------------------- #
# Policy: an immutable, provenance-carrying snapshot
# --------------------------------------------------------------------------- #

@dataclass
class PolicySnapshot:
    """One captured version of a program's official policy.

    ``sha256`` is the digest of the *retrieved text*. It is what makes the snapshot
    auditable: a reviewer can re-fetch the URL, hash it, and see whether the policy
    we evaluated against is the policy that is there now. An empty or mismatched
    hash is what :func:`verify_snapshot` reports as unverified -- never assumed.
    """

    program: str
    source_url: str
    retrieved_at: str
    sha256: str
    revision: str = ""
    captured_text: str = ""
    notes: str = ""

    def to_dict(self) -> dict:
        return {
            "program": self.program, "source_url": self.source_url,
            "retrieved_at": self.retrieved_at, "sha256": self.sha256,
            "revision": self.revision, "captured_text": self.captured_text,
            "notes": self.notes,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "PolicySnapshot":
        known = {f for f in cls.__dataclass_fields__}  # type: ignore[attr-defined]
        return cls(**{k: v for k, v in d.items() if k in known})

    def is_verified(self) -> bool:
        """A snapshot is verified only if it has a source, a date, and a matching
        hash of the text it captured. Anything less is unverified, not "probably
        fine"."""
        if not (self.source_url and self.retrieved_at and self.sha256):
            return False
        if self.captured_text:
            return sha256_text(self.captured_text) == self.sha256
        return False


@dataclass
class ProgramPolicy:
    """A program's structured rules, as read from one official snapshot.

    Every field here is something a program actually publishes. A field that could
    not be established is left empty and is treated as *unverified* downstream --
    it is never filled in with a plausible default.
    """

    program: str
    snapshot: PolicySnapshot
    #: Asset -> "in_scope" | "out_of_scope". An asset absent from this map is
    #: treated as unknown scope, not as in scope.
    assets: dict[str, str] = field(default_factory=dict)
    #: Vulnerability classes the program excludes (e.g. "self-xss", "known-issues").
    excluded_classes: list[str] = field(default_factory=list)
    #: The program's severity definitions: class/impact -> severity.
    severity_definitions: dict[str, str] = field(default_factory=dict)
    #: Payout by severity, as published. Absent severity -> not stated.
    payouts: dict[str, str] = field(default_factory=dict)
    #: The minimum payable severity, if the program states one (e.g. "low").
    minimum_severity: str = ""
    #: Known issues / duplicates the program documents.
    known_issues: list[str] = field(default_factory=list)
    poc_required: bool = True
    #: Free-form notes on submission and disclosure requirements.
    submission_requirements: list[str] = field(default_factory=list)
    #: Asset/impact entries that could not be read -- surfaced, never guessed.
    unverified_fields: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = {k: v for k, v in self.__dict__.items() if k != "snapshot"}
        d["snapshot"] = self.snapshot.to_dict()
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "ProgramPolicy":
        data = dict(d)
        raw = data.get("snapshot")
        if raw is None:
            # `bounty capture` writes a bare snapshot, so a capture can be passed
            # straight to `bounty evaluate`. Recognise it by the fields a capture
            # always carries rather than by the absence of a key, so a policy that
            # simply forgot its snapshot is not silently read as one.
            if all(data.get(k) for k in _SNAPSHOT_FIELDS):
                raw = data
        if not isinstance(raw, dict) or not raw:
            raise ValueError(
                "policy has no snapshot: pass the file written by "
                "`blackheart bounty capture`, or a policy object with a 'snapshot' key"
            )
        try:
            data["snapshot"] = PolicySnapshot.from_dict(raw)
        except TypeError as exc:
            raise ValueError(f"policy snapshot is incomplete: {exc}") from exc
        known = {f for f in cls.__dataclass_fields__}  # type: ignore[attr-defined]
        return cls(**{k: v for k, v in data.items() if k in known})


# --------------------------------------------------------------------------- #
# Finding intake: the repository's record and the report's model
# --------------------------------------------------------------------------- #

#: A findings-repository record keeps the ten mission sections (A–J); the bounty
#: layer evaluates the report model. The verdicts map onto the report's
#: classifications, and a verdict that is not a confirmation never becomes one.
_RECORD_VERDICT_CLASSIFICATION = {
    "CONFIRMED": "CONFIRMED",
    "STRONGLY_SUPPORTED": "NEEDS_MORE_EVIDENCE",
    "UNCONFIRMED": "NEEDS_MORE_EVIDENCE",
    "NOT_REPRODUCIBLE": "NEEDS_MORE_EVIDENCE",
    "INFORMATIONAL": "INFORMATIONAL",
    "FALSE_POSITIVE": "FALSE_POSITIVE",
    "OUT_OF_SCOPE": "OUT_OF_SCOPE",
}


def _as_list(value) -> list[str]:
    """Coerce a record field to the list the report model expects."""
    if isinstance(value, (list, tuple)):
        return [str(v).strip() for v in value if str(v).strip()]
    text = str(value or "").strip()
    return [part.strip() for part in text.split(",") if part.strip()] if text else []


def _joined(*parts) -> str:
    return " — ".join(str(p).strip() for p in parts if str(p).strip())


def is_finding_record(d: dict) -> bool:
    """True for a findings-repository record rather than a report-model finding.

    The record carries the A–J sections, so it names fields the report model does
    not have. Detecting it lets `bounty evaluate` accept either shape instead of
    rejecting the record with fifty-eight unknown fields.
    """
    return isinstance(d, dict) and "root_cause_location" in d


def finding_payload_from_record(record: dict) -> dict:
    """Translate a findings-repository record into the report model's fields.

    Nothing is invented. A field the record does not carry stays empty, and a
    verdict that is not `CONFIRMED` maps to `NEEDS_MORE_EVIDENCE`: passing through
    this adapter must never promote a strong hypothesis to a confirmed finding.
    """
    verdict = str(record.get("status") or record.get("verdict") or "").strip().upper()
    classification = _RECORD_VERDICT_CLASSIFICATION.get(verdict, "NEEDS_MORE_EVIDENCE")
    severity = str(record.get("severity") or "").strip().lower()
    economic = record.get("economic")
    return {
        "finding_id": str(record.get("finding_id") or ""),
        "title": str(record.get("title") or ""),
        "target": str(record.get("target") or ""),
        "component": str(record.get("component") or ""),
        "scope_reference": str(record.get("reporting_channel") or ""),
        "classification": classification,
        "severity": severity if severity in Severity.ORDER else "info",
        "category": str(record.get("category") or ""),
        "prerequisites": _as_list(record.get("attack_prerequisites")),
        "root_cause": _joined(
            record.get("root_cause_file"), record.get("root_cause_location"),
            record.get("vulnerable_implementation"),
        ),
        "reproduction_steps": _as_list(record.get("repro_steps")),
        "poc_path": str(record.get("poc_code") or ""),
        "expected_behavior": str(record.get("expected_behavior") or ""),
        "actual_behavior": str(record.get("observed_behavior") or ""),
        "impact": str(record.get("consequences") or ""),
        "commands": _as_list(record.get("repro_commands")),
        "evidence_ids": _as_list(record.get("evidence_ids")),
        "gates": [],
        "limitations": _as_list(record.get("remaining_uncertainty")),
        "verification_notes": str(record.get("verification_result") or ""),
        "evidence_tags": [],
        "economic": economic if isinstance(economic, dict) else None,
        "created_at": str(record.get("discovery_date") or ""),
        # The record names a reviewer but not the reviewer's model provenance, so
        # this is UNRECORDED -- never read as an independent review.
        "review_independence": "UNRECORDED",
    }


@dataclass
class Evaluation:
    """The program-specific judgement of one finding, with all reasoning attached."""

    finding_id: str
    program: str
    outcome: str
    # The four axes, kept separate and explicit.
    technically_valid: bool = False
    severity: str = ""               # program-specific severity, "" if not determined
    in_scope: Optional[bool] = None  # None = unknown
    payable: Optional[bool] = None   # None = unknown
    # Reasoning.
    reasons: list[str] = field(default_factory=list)
    blockers: list[str] = field(default_factory=list)
    exclusions: list[str] = field(default_factory=list)
    # Provenance of the policy used.
    policy_sha256: str = ""
    policy_source: str = ""
    policy_retrieved_at: str = ""
    policy_revision: str = ""
    # Re-evaluation chain: the finding this one supersedes, if any.
    supersedes: str = ""
    evaluated_at: str = field(default_factory=utcnow)

    def to_dict(self) -> dict:
        return dict(self.__dict__)

    @classmethod
    def from_dict(cls, d: dict) -> "Evaluation":
        known = {f for f in cls.__dataclass_fields__}  # type: ignore[attr-defined]
        return cls(**{k: v for k, v in d.items() if k in known})

    def is_valid(self) -> bool:
        return self.outcome in VALID_OUTCOMES


# --------------------------------------------------------------------------- #
# Evaluation engine
# --------------------------------------------------------------------------- #

def severity_for(policy: ProgramPolicy, finding: Finding) -> tuple[str, str]:
    """Resolve a finding's severity under *this program's* definitions.

    Precedence: an explicit program severity definition for the finding's category
    or impact wins; otherwise the finding's own severity, but only if the program
    recognises it (it appears in its payout or definition table). Returns
    ``(severity, reason)``; ``("", reason)`` means the program did not define it,
    which is unverified, not "info".
    """
    defined = {str(k).lower(): str(v).lower() for k, v in policy.severity_definitions.items()}
    for key in (finding.category, finding.impact):
        if key and key.lower() in defined:
            sev = Severity.coerce(defined[key.lower()])
            if sev:
                return sev, f"program severity definition: {key!r} -> {sev}"

    recognised = {Severity.coerce(k) for k in policy.payouts if Severity.coerce(k)}
    recognised |= {Severity.coerce(v) for v in defined.values() if Severity.coerce(v)}
    own = Severity.coerce(finding.severity)
    if own and (not recognised or own in recognised):
        return own, f"finding severity {own!r} accepted by program"

    return "", "program defines no severity for this finding"


def _tokens(text: str) -> list[str]:
    """Split text into lowercase alphanumeric tokens.

    Substring matching is wrong for exclusions: the class ``rce`` must not match
    ``resource-exhaustion``, and ``dos`` must not match ``dosimetry``. Comparing
    whole tokens makes an exclusion match a class phrase, not a random fragment.
    """
    return [t for t in re.split(r"[^a-z0-9]+", text.lower()) if t]


def _phrase_in(phrase_tokens: list[str], hay_tokens: list[str]) -> bool:
    """True if ``phrase_tokens`` occurs as a contiguous run inside ``hay_tokens``."""
    if not phrase_tokens:
        return False
    n = len(phrase_tokens)
    return any(hay_tokens[i:i + n] == phrase_tokens
               for i in range(len(hay_tokens) - n + 1))


def _is_known(policy: ProgramPolicy, finding: Finding) -> Optional[str]:
    """Return the matching known issue, or None.

    Matched on whole tokens, like exclusions: a known issue must be a class phrase
    present in the finding, not a substring of an unrelated word.
    """
    hay = _tokens(f"{finding.title} {finding.category} {finding.impact}")
    for issue in policy.known_issues:
        if issue and _phrase_in(_tokens(issue), hay):
            return issue
    return None


def _is_excluded(policy: ProgramPolicy, finding: Finding) -> Optional[str]:
    hay = _tokens(f"{finding.title} {finding.category}")
    for cls in policy.excluded_classes:
        if cls and _phrase_in(_tokens(cls), hay):
            return cls
    return None


def _evidence_complete(finding: Finding) -> tuple[bool, str]:
    """Is there enough evidence to stand behind the finding at all?

    A finding with no evidence id and no reproduction steps cannot be confirmed,
    whatever its classification claims. This checks *presence*, not quality -- the
    quality gates live in :mod:`blackheart.report` and are not re-implemented here.
    """
    if not finding.evidence_ids:
        return False, "no evidence artefacts attached"
    return True, ""


def evaluate(finding: Finding, policy: ProgramPolicy) -> Evaluation:
    """Decide a finding's program-specific outcome. Deterministic, no confidence score.

    The order is deliberate: the cheapest disqualifiers (invalid, out of scope,
    excluded, known) run before the payout question, and a *valid* finding that
    fails a non-validity test is reported as non-payable, never as invalid.
    """
    ev = Evaluation(
        finding_id=finding.finding_id, program=policy.program, outcome="",
        policy_sha256=policy.snapshot.sha256,
        policy_source=policy.snapshot.source_url,
        policy_retrieved_at=policy.snapshot.retrieved_at,
        policy_revision=policy.snapshot.revision,
    )

    # 0. Policy provenance. If the policy itself is unverified, nothing downstream
    #    can be asserted -- this outcome outranks all others.
    if not policy.snapshot.is_verified():
        ev.outcome = Outcome.POLICY_UNVERIFIED
        ev.blockers.append("policy snapshot is not verified (source/date/hash incomplete)")
        return ev

    # 1. Technical validity: is this even a real finding?
    from ..models import Classification
    if finding.classification in (Classification.FALSE_POSITIVE,
                                  Classification.INFORMATIONAL):
        ev.outcome = Outcome.INVALID
        ev.blockers.append(f"classification is {finding.classification.value}")
        return ev
    if finding.classification != Classification.CONFIRMED:
        # Not (yet) a confirmed bug. If evidence is missing it is INSUFFICIENT;
        # if evidence exists but the claim is unconfirmed it needs reproduction.
        ok, why = _evidence_complete(finding)
        if not ok:
            ev.outcome = Outcome.INSUFFICIENT_EVIDENCE
            ev.blockers.append(why)
        else:
            ev.outcome = Outcome.REPRODUCTION_REQUIRED
            ev.blockers.append(
                f"classification {finding.classification.value} is not CONFIRMED; "
                "independent reproduction required"
            )
        return ev

    ev.technically_valid = True
    ev.reasons.append("classification is CONFIRMED")

    # 2. Scope eligibility.
    scope = policy.assets.get(finding.target)
    if scope is None:
        ev.in_scope = None
        ev.outcome = Outcome.VALID_WITH_UNVERIFIED_ELIGIBILITY
        ev.blockers.append(f"asset {finding.target!r} not listed in program scope")
        return ev
    if scope != "in_scope":
        ev.in_scope = False
        ev.outcome = Outcome.OUT_OF_SCOPE
        ev.blockers.append(f"asset {finding.target!r} is {scope}")
        return ev
    ev.in_scope = True
    ev.reasons.append(f"asset {finding.target!r} is in scope")

    # 3. Explicit exclusions.
    excluded = _is_excluded(policy, finding)
    if excluded:
        ev.outcome = Outcome.EXCLUDED_BY_POLICY
        ev.exclusions.append(excluded)
        ev.blockers.append(f"vulnerability class excluded by policy: {excluded!r}")
        return ev

    # 4. Duplicate / known issue.
    known = _is_known(policy, finding)
    if known:
        ev.outcome = Outcome.DUPLICATE_OR_KNOWN
        ev.blockers.append(f"matches a known issue: {known!r}")
        return ev

    # 5. Severity under the program's own definitions.
    sev, sev_reason = severity_for(policy, finding)
    if not sev:
        ev.outcome = Outcome.VALID_WITH_UNVERIFIED_ELIGIBILITY
        ev.blockers.append(sev_reason)
        return ev
    ev.severity = sev
    ev.reasons.append(sev_reason)

    # 6. Payout eligibility. A valid, in-scope, non-excluded finding whose severity
    #    the program does not pay for is VALID_BUT_NOT_PAYABLE -- never INVALID.
    if policy.minimum_severity:
        min_sev = Severity.coerce(policy.minimum_severity)
        if min_sev and Severity.rank(sev) < Severity.rank(min_sev):
            ev.payable = False
            ev.outcome = Outcome.VALID_BUT_NOT_PAYABLE
            ev.blockers.append(
                f"severity {sev!r} is below the program minimum {min_sev!r}"
            )
            return ev

    payout = policy.payouts.get(sev, "")
    if sev not in policy.payouts:
        ev.payable = None
        ev.outcome = Outcome.VALID_WITH_UNVERIFIED_ELIGIBILITY
        ev.blockers.append(f"program publishes no payout for severity {sev!r}")
        return ev
    if str(payout).strip() in ("", "0", "$0", "none", "not-applicable"):
        ev.payable = False
        ev.outcome = Outcome.VALID_BUT_NOT_PAYABLE
        ev.blockers.append(f"payout for severity {sev!r} is {payout!r}")
        return ev

    ev.payable = True
    ev.outcome = Outcome.VALID_AND_PAYABLE
    ev.reasons.append(f"payout for severity {sev!r} is {payout!r}")
    return ev


# --------------------------------------------------------------------------- #
# The ledger: evaluations are appended, never rewritten
# --------------------------------------------------------------------------- #

class BountyLedger:
    """A tamper-evident record of every evaluation, under the policy it used.

    Re-evaluation on a policy change appends a new record that ``supersedes`` the
    old one; the old record is never edited. That is what makes "the program
    changed its policy" auditable: both decisions and both policies survive.
    """

    def __init__(self, root: str | os.PathLike, name: str = "evaluations",
                 *, key: Optional[IntegrityKey] = None) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.log = ChainedLog(self.root / f"{name}.jsonl", key=key)
        self.path = self.log.path
        self.key = key

    def _rid(self, ev: Evaluation) -> str:
        return f"{ev.program}:{ev.finding_id}:{ev.policy_sha256[:12]}"

    def record(self, ev: Evaluation) -> Evaluation:
        self.log.append(self._rid(ev), ev.to_dict())
        return ev

    def get(self, program: str, finding_id: str, policy_sha256: str) -> Optional[Evaluation]:
        content = self.log.get(f"{program}:{finding_id}:{policy_sha256[:12]}")
        return Evaluation.from_dict(content) if content else None

    def for_finding(self, finding_id: str) -> list[Evaluation]:
        return [Evaluation.from_dict(c) for c in self.log.state().values()
                if c.get("finding_id") == finding_id]

    def latest(self, program: str, finding_id: str) -> Optional[Evaluation]:
        matches = [e for e in self.for_finding(finding_id) if e.program == program]
        return matches[-1] if matches else None

    def all(self) -> list[Evaluation]:
        return [Evaluation.from_dict(c) for c in self.log.state().values()]

    def verify_integrity(self, *, require_signatures: bool = False) -> dict:
        return self.log.verify_integrity(require_signatures=require_signatures)


def reevaluate(
    finding: Finding, new_policy: ProgramPolicy, ledger: BountyLedger,
) -> Evaluation:
    """Re-evaluate under a new policy, linking (not overwriting) the prior decision."""
    prior = ledger.latest(new_policy.program, finding.finding_id)
    ev = evaluate(finding, new_policy)
    if prior is not None and prior.policy_sha256 != ev.policy_sha256:
        ev.supersedes = f"{prior.policy_sha256[:12]}@{prior.evaluated_at}"
    return ledger.record(ev)


# --------------------------------------------------------------------------- #
# Submission: prepare a package, never submit
# --------------------------------------------------------------------------- #

def prepare_submission(finding: Finding, ev: Evaluation) -> dict:
    """Assemble an evidence-backed submission package for an operator to send.

    This **does not submit anything**. It returns a package and an explicit
    ``submission_allowed`` flag that is False unless the evaluation is
    VALID_AND_PAYABLE and the finding is submission-ready. The owner sends it.

    The package always carries the Gate D ``disposition`` so no caller has to
    re-derive whether the program's own rules permit a submission.
    """
    from ..models import Classification
    from ..report import submission_blockers

    blockers: list[str] = [] if ev.outcome == Outcome.VALID_AND_PAYABLE else list(ev.blockers)
    # A payable finding still needs an evidence-backed package: a submission with
    # no attached artefact cannot be reviewed by the program. This is a *bounty*
    # requirement, checked here rather than assumed from the report gate.
    if ev.outcome == Outcome.VALID_AND_PAYABLE:
        if not finding.evidence_ids:
            blockers.append("no evidence artefacts attached to the finding")
        blockers.extend(submission_blockers(finding))
    ready = ev.outcome == Outcome.VALID_AND_PAYABLE and not blockers
    disposition = disposition_for(
        ev.outcome,
        informational=finding.classification is Classification.INFORMATIONAL,
    )
    return {
        "program": ev.program,
        "finding_id": finding.finding_id,
        "outcome": ev.outcome,
        "disposition": disposition,
        "disposition_label": Disposition.LABELS.get(disposition, disposition),
        "severity": ev.severity,
        "policy_source": ev.policy_source,
        "policy_sha256": ev.policy_sha256,
        "policy_retrieved_at": ev.policy_retrieved_at,
        "evidence_ids": list(finding.evidence_ids),
        "submission_allowed": ready,
        "blockers": blockers,
        "note": "Prepared only. BLACKHEART never submits a report automatically; "
                "the owner reviews and sends it.",
    }


# --------------------------------------------------------------------------- #
# The mandatory official-policy gate (Gates A-D)
# --------------------------------------------------------------------------- #
# Imported last: :mod:`blackheart.bounty.gate` imports ``Severity`` and
# ``sha256_text`` from this module, so the symbols must exist first. The function
# is re-exported as ``gate_candidate`` because ``bounty.gate`` names the submodule.
from .gate import (  # noqa: E402
    CLASSIFICATIONS,
    MANDATORY_GATES,
    PAYMENT_DETERMINATIONS,
    CandidateRecord,
    Disposition,
    GateOutcome,
    classification_for,
    POLICY_UNVERIFIED_BLOCKER,
    SUBMISSION_READY_REQUIRES,
    assert_submission_ready,
    disposition_for,
    payment_determination,
)
from .gate import gate as gate_candidate  # noqa: E402
