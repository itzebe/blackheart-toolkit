"""Automatic findings documentation engine and persistent findings repository.

Mission section 4 requires that *every* meaningful research operation leave a
structured, persistent record, and section 5 requires that those records survive
restarts and be searchable, linkable, and exportable. This module is that
subsystem. It integrates with the existing architecture rather than replacing it:

  * it reuses the tamper-evidence primitives in :mod:`blackheart.integrity`
    (content hash + hash chain + optional HMAC), exactly as
    :class:`blackheart.investigation.InvestigationStore` does, so a finding record
    is as hard to edit undetected as an investigation state;
  * it reuses :class:`blackheart.evidence.EvidenceStore` ids for the evidence
    references, so a finding points at content-addressed, immutable artefacts;
  * it reuses :class:`blackheart.models.Classification` through an explicit
    verdict<->classification mapping, so a finding record can still drive the
    existing report and novelty pipelines;
  * it renders its own Markdown report (per-finding and consolidated) directly
    from the persisted records, so a report is always built from what was stored.

Two safety properties are enforced in code, never by convention:

  * **Confirmation is evidence-gated.** :meth:`FindingRecord.confirm` refuses to
    move a record to ``CONFIRMED`` unless it carries evidence, a verification
    result, and a named reviewer -- mirroring ``ResearchRecord.promote``. A review
    performed by the same model is a real review but is **not** independent
    verification, so it is refused here too: confirmation needs independent
    verification, and the reviewer model that provides it is optional, not
    required to operate the engine. A record with no evidence can be *many*
    things, but it can never be a confirmed vulnerability.
  * **A verdict change is a recorded event.** Status is derived by replaying the
    append-only log, so the history of a finding's status is never lost and a
    silent upgrade is impossible.

The repository never writes into tracked paths by default (the caller chooses the
root; the CLI defaults to ``research/private/findings``).
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING, Callable, Optional

if TYPE_CHECKING:  # pragma: no cover - import-time only, avoids a cycle
    from ..models import Finding

from ..doctrine import CONFIRMATION_REQUIRED_FIELDS, FINDING_SECTIONS
from ..integrity import (
    GENESIS,
    Checkpoint,
    IntegrityKey,
    chain_hash,
    content_hash,
    record_mac,
    verify_chain,
)
from ..models import (
    Classification, ReviewIndependence, evidenced_review_independence, utcnow,
)


# --------------------------------------------------------------------------- #
# Verdicts
# --------------------------------------------------------------------------- #

class FindingVerdict(str, Enum):
    """The lifecycle state of a finding (mission section 3, Phase 5).

    These are the seven verdicts from :data:`blackheart.doctrine.FINDING_VERDICTS`
    and they are kept distinct on purpose: the mission forbids conflating a
    confirmed vulnerability with a strong hypothesis, a false positive, an
    informational note, or an out-of-scope observation.
    """

    CONFIRMED = "CONFIRMED"
    STRONGLY_SUPPORTED = "STRONGLY_SUPPORTED"
    UNCONFIRMED = "UNCONFIRMED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    INFORMATIONAL = "INFORMATIONAL"
    NOT_REPRODUCIBLE = "NOT_REPRODUCIBLE"
    OUT_OF_SCOPE = "OUT_OF_SCOPE"


# The verdict a finding is created with: a live suspicion, nothing more.
DEFAULT_VERDICT = FindingVerdict.UNCONFIRMED

# The only verdict that may be read back as a real vulnerability.
CONFIRMED = FindingVerdict.CONFIRMED


# Explicit mapping to the existing technical classification, so a finding record
# can drive ``blackheart.report`` / ``blackheart.novelty`` without a second
# vocabulary.
_VERDICT_TO_CLASSIFICATION: dict[str, Classification] = {
    FindingVerdict.CONFIRMED.value: Classification.CONFIRMED,
    FindingVerdict.STRONGLY_SUPPORTED.value: Classification.NEEDS_MORE_EVIDENCE,
    FindingVerdict.UNCONFIRMED.value: Classification.NEEDS_MORE_EVIDENCE,
    FindingVerdict.FALSE_POSITIVE.value: Classification.FALSE_POSITIVE,
    FindingVerdict.INFORMATIONAL.value: Classification.INFORMATIONAL,
    FindingVerdict.NOT_REPRODUCIBLE.value: Classification.NEEDS_MORE_EVIDENCE,
    FindingVerdict.OUT_OF_SCOPE.value: Classification.OUT_OF_SCOPE,
}


def verdict_to_classification(verdict: FindingVerdict | str) -> Classification:
    value = verdict.value if isinstance(verdict, FindingVerdict) else str(verdict)
    return _VERDICT_TO_CLASSIFICATION.get(value, Classification.NEEDS_MORE_EVIDENCE)


def classification_to_verdict(classification: Classification | str) -> FindingVerdict:
    value = (
        classification.value
        if isinstance(classification, Classification)
        else str(classification)
    )
    if value == Classification.CONFIRMED.value:
        return FindingVerdict.CONFIRMED
    if value == Classification.FALSE_POSITIVE.value:
        return FindingVerdict.FALSE_POSITIVE
    if value == Classification.INFORMATIONAL.value:
        return FindingVerdict.INFORMATIONAL
    if value == Classification.OUT_OF_SCOPE.value:
        return FindingVerdict.OUT_OF_SCOPE
    return FindingVerdict.UNCONFIRMED


# --------------------------------------------------------------------------- #
# The finding record (mission section 4, sections A-J)
# --------------------------------------------------------------------------- #

@dataclass
class FindingRecord:
    """A complete, persistent finding record.

    The fields are grouped by the ten sections the mission requires (A-J; see
    :data:`blackheart.doctrine.FINDING_SECTIONS`). Only the identification fields
    are required at creation; a record is expected to fill in the rest as the
    investigation proceeds. Nothing here asserts a vulnerability: ``status`` is
    the only thing that classifies it, and it can only become ``CONFIRMED``
    through :meth:`confirm`.
    """

    # -- A. Identification ------------------------------------------------ #
    finding_id: str
    title: str
    target: str
    component: str = ""
    affected_version: str = ""
    discovery_date: str = field(default_factory=utcnow)
    researcher: str = "blackheart"
    status: str = DEFAULT_VERDICT.value

    # -- B. Technical classification ------------------------------------- #
    category: str = ""
    cwe: str = ""
    cvss_score: str = ""
    cvss_vector: str = ""
    severity: str = "info"
    security_boundary: str = ""
    attack_prerequisites: list[str] = field(default_factory=list)

    # -- C. Root cause --------------------------------------------------- #
    root_cause_file: str = ""
    root_cause_location: str = ""
    vulnerable_implementation: str = ""
    design_mistake: str = ""
    why_controls_failed: str = ""

    # -- D. Attack analysis ---------------------------------------------- #
    hypothesis: str = ""
    attacker_assumptions: list[str] = field(default_factory=list)
    attack_preconditions: list[str] = field(default_factory=list)
    attack_sequence: list[str] = field(default_factory=list)
    required_permissions: str = ""
    exploitability: str = ""
    consequences: str = ""
    attack_scenarios: list[str] = field(default_factory=list)

    # -- E. Proof of concept --------------------------------------------- #
    repro_environment: str = ""
    repro_steps: list[str] = field(default_factory=list)
    repro_commands: list[str] = field(default_factory=list)
    poc_code: str = ""
    expected_behavior: str = ""
    observed_behavior: str = ""
    execution_result: str = ""
    repro_success_rate: str = ""

    # -- F. Evidence ----------------------------------------------------- #
    evidence_ids: list[str] = field(default_factory=list)
    logs: list[str] = field(default_factory=list)
    source_refs: list[str] = field(default_factory=list)
    traces: list[str] = field(default_factory=list)
    before_after: str = ""
    evidence_hashes: list[str] = field(default_factory=list)

    # -- G. Independent verification ------------------------------------- #
    verification_methodology: str = ""
    reviewer: str = ""
    verification_result: str = ""
    alternative_explanations: list[str] = field(default_factory=list)
    false_positive_analysis: str = ""
    remaining_uncertainty: str = ""

    # -- H. Impact ------------------------------------------------------- #
    confidentiality_impact: str = ""
    integrity_impact: str = ""
    availability_impact: str = ""
    privilege_escalation: str = ""
    affected_scope: str = ""
    exploit_prerequisites: list[str] = field(default_factory=list)
    severity_justification: str = ""

    # -- I. Remediation -------------------------------------------------- #
    recommended_fix: str = ""
    affected_implementation: str = ""
    invariants_to_restore: list[str] = field(default_factory=list)
    regression_tests: list[str] = field(default_factory=list)
    retest_result: str = ""

    # -- J. Disclosure --------------------------------------------------- #
    disclosure_policy: str = ""
    reporting_channel: str = ""
    report_status: str = "not-prepared"
    submission_status: str = "not-submitted"
    submission_reference: str = ""
    org_response: str = ""

    # -- provenance ------------------------------------------------------ #
    related: list[str] = field(default_factory=list)
    duplicate_of: str = ""
    authorizations: list[str] = field(default_factory=list)
    created_at: str = field(default_factory=utcnow)
    updated_at: str = field(default_factory=utcnow)
    #: How the review was performed (:class:`ReviewIndependence` value). A
    #: same-model review may never back a CONFIRMED record, so this is part of the
    #: confirmation gate, not decoration. Declared last so it can never shift an
    #: existing positional field.
    review_independence: str = ReviewIndependence.UNRECORDED.value
    #: The deployment-truth record this finding depends on. A finding whose
    #: target names a deployed address cannot become CONFIRMED without one that
    #: binds verified source to the runtime. Declared last for positional safety.
    deployment_truth: dict = field(default_factory=dict)
    deployment_truth_required: bool = False

    # -- serialisation --------------------------------------------------- #
    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "FindingRecord":
        known = {f for f in cls.__dataclass_fields__}  # type: ignore[attr-defined]
        return cls(**{k: v for k, v in d.items() if k in known})

    # -- helpers --------------------------------------------------------- #
    def verdict(self) -> FindingVerdict:
        try:
            return FindingVerdict(self.status)
        except ValueError:
            return DEFAULT_VERDICT

    def is_confirmed(self) -> bool:
        """Is this a confirmed finding, with the evidence gate satisfied?

        The status flag alone is not enough: a record can be hand-built, loaded
        from an edited file, or carry a review whose provenance does not support
        independence. :meth:`missing_confirmation_fields` is the gate
        :meth:`confirm` enforces, so re-applying it here means a status flag set
        by any other route cannot make the record read back as confirmed. This is
        what :meth:`may_be_read_as_vulnerability` relies on.
        """
        return (self.status == FindingVerdict.CONFIRMED.value
                and not self.missing_confirmation_fields())

    def may_be_read_as_vulnerability(self) -> bool:
        """Only a CONFIRMED finding may be read back as a real vulnerability."""
        return self.is_confirmed()

    def requires_deployment_truth(self) -> bool:
        """Whether this finding makes a claim about a deployed address."""
        if self.deployment_truth_required:
            return True
        return bool(_ADDRESS_RE.search(self.target or "")
                    or _ADDRESS_RE.search(self.component or ""))

    def missing_confirmation_fields(self) -> list[str]:
        """Which of the evidence-gated fields are absent.

        A field is 'absent' when it is empty/blank. ``evidence_ids`` counts as
        present only when it holds at least one id. A review that was performed by
        the same model is also *absent* as independent verification: it is a real
        review, but it may not back a CONFIRMED record, so it is refused here
        rather than silently accepted. This is what :meth:`confirm` consults, and
        it is exposed so a caller can *show* why a confirmation was refused rather
        than silently failing.
        """
        missing: list[str] = []
        for name in CONFIRMATION_REQUIRED_FIELDS:
            value = getattr(self, name, None)
            if name == "evidence_ids":
                if not value:
                    missing.append(name)
            elif not (value or "").strip():
                missing.append(name)
        if ReviewIndependence.coerce(self.review_independence) == ReviewIndependence.SAME_MODEL:
            missing.append("independent verification (a same-model review is not independent)")
        elif (ReviewIndependence.coerce(self.review_independence)
              == ReviewIndependence.INDEPENDENT_MODEL
              and self.reviewer in _NON_INDEPENDENT_LABELS):
            # The recorded reviewer identity contradicts the claimed provenance:
            # the label names the same model or the deterministic verifier while
            # the record claims an independent model. A contradiction is not
            # evidence of independence, so it fails closed.
            missing.append(
                f"independent verification (reviewer label {self.reviewer!r} "
                "contradicts INDEPENDENT_MODEL provenance)"
            )
        # The reverse pairing -- an ``independent-verifier`` label with
        # ``UNRECORDED`` provenance -- is deliberately allowed. ``UNRECORDED``
        # passes gate 6 through the *deterministic* verifier, which re-derives the
        # verdict from evidence and is genuinely independent of any model; the
        # report still states "not an independent-model review" for it, so nothing
        # is upgraded. Refusing it would silently downgrade every record written
        # before this field existed.
        if self.requires_deployment_truth():
            from ..ingest.truth import validate_deployment_truth
            ok, reason = validate_deployment_truth(self.deployment_truth)
            if not ok:
                missing.append(f"deployment truth ({reason})")
        return missing

    def confirm(self, *, note: str = "") -> bool:
        """Attempt to move this record to ``CONFIRMED``.

        Returns ``True`` on success and ``False`` when the evidence gate refuses.
        The record is left unchanged when refused -- a refusal is not a partial
        success. This mirrors :meth:`blackheart.models.ResearchRecord.promote`:
        an unverified idea can never be read back as a vulnerability.
        """
        if self.missing_confirmation_fields():
            return False
        self.status = FindingVerdict.CONFIRMED.value
        self.updated_at = utcnow()
        return True

    def sections(self) -> dict[str, dict]:
        """Group the populated fields by the ten required sections."""
        out: dict[str, dict] = {}
        for section in FINDING_SECTIONS:
            out[section.letter] = {
                "name": section.name,
                "fields": {f: getattr(self, f, None) for f in section.fields},
            }
        return out

    def coverage(self) -> dict[str, bool]:
        """For each section, whether at least one of its fields is populated."""
        out: dict[str, bool] = {}
        for section in FINDING_SECTIONS:
            populated = False
            for f in section.fields:
                value = getattr(self, f, None)
                if isinstance(value, list):
                    populated = populated or bool(value)
                elif value:
                    populated = True
            out[section.letter] = populated
        return out


# --------------------------------------------------------------------------- #
# Repository
# --------------------------------------------------------------------------- #

class FindingRepository:
    """Append-only, replayable, tamper-evident store of :class:`FindingRecord`.

    State is a JSONL log; the current view of each finding is derived by replay,
    so a verdict change is a new event and the status history is never lost. Each
    state snapshot is hash-chained (and HMAC-signed when a key is configured)
    using the same primitives as the investigation store, so deletion, reordering,
    insertion, or truncation of records is detectable.
    """

    def __init__(
        self,
        root: str | os.PathLike,
        name: str = "findings",
        *,
        key: Optional[IntegrityKey] = None,
    ) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.path = self.root / f"{name}.jsonl"
        self.key = key

    # -- writing --------------------------------------------------------- #
    def _append(self, event: dict) -> None:
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps({"at": utcnow(), **event}, default=str) + "\n")

    def _events(self) -> list[dict]:
        if not self.path.exists():
            return []
        events: list[dict] = []
        skipped = 0
        for line in self.path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                skipped += 1
        self._last_skipped = skipped
        return events

    def corruption_report(self) -> dict:
        """Report how many log lines could not be parsed (crash-truncated log)."""
        self._events()
        skipped = getattr(self, "_last_skipped", 0)
        return {"skipped_lines": skipped, "ok": skipped == 0}

    def _head(self) -> tuple[int, str]:
        seq, prev = 0, GENESIS
        for ev in self._events():
            if ev.get("type") == "state" and ev.get("content"):
                prev = ev.get("chain_sha256") or chain_hash(
                    ev.get("seq", seq), prev, content_hash(ev["content"])
                )
                seq = ev.get("seq", seq) + 1
        return seq, prev

    def save(self, record: FindingRecord) -> FindingRecord:
        """Persist a full snapshot of ``record`` as the latest chained state.

        A persisted ``CONFIRMED`` record always carries the evidence-gated fields
        (evidence, an independent verification result, and a named reviewer): a
        record that *claims* CONFIRMED without them is downgraded here, so no path
        -- including loading a hand-written finding file through ``add`` -- can
        persist a confirmed vulnerability that the gate would refuse.
        """
        if record.status == FindingVerdict.CONFIRMED.value and record.missing_confirmation_fields():
            record.status = FindingVerdict.STRONGLY_SUPPORTED.value
            self._append({
                "type": "verdict", "id": record.finding_id,
                "status": record.status,
                "note": "claimed CONFIRMED without the required evidence/verification fields; "
                        "downgraded on persistence",
            })
        record.updated_at = utcnow()
        payload = record.to_dict()
        seq, prev = self._head()
        ch = content_hash(payload)
        chain = chain_hash(seq, prev, ch)
        event = {
            "type": "state",
            "id": record.finding_id,
            "content": payload,
            "seq": seq,
            "prev": prev,
            "content_sha256": ch,
            "chain_sha256": chain,
        }
        if self.key is not None:
            event["hmac"] = record_mac(self.key, seq, prev, ch)
            event["key_id"] = self.key.key_id
        self._append(event)
        return record

    def add(self, record: FindingRecord) -> FindingRecord:
        """Record a new finding (a thin alias for :meth:`save`)."""
        return self.save(record)

    def set_verdict(
        self, finding_id: str, verdict: FindingVerdict | str, note: str = ""
    ) -> Optional[FindingRecord]:
        """Change a finding's verdict, recording the transition as an event.

        Moving to ``CONFIRMED`` goes through the evidence gate: if the record is
        not independently verified with evidence, the verdict change is *refused*
        and the record is returned unchanged. Every other transition is recorded
        (a downgrade is a first-class result, not an error).
        """
        record = self.get(finding_id)
        if record is None:
            return None
        value = verdict.value if isinstance(verdict, FindingVerdict) else str(verdict)
        if value == FindingVerdict.CONFIRMED.value and not record.confirm(note=note):
            return record  # unchanged: the gate refused
        record.status = value
        record.updated_at = utcnow()
        self._append({"type": "verdict", "id": finding_id, "status": value, "note": note})
        self.save(record)
        return record

    def link(self, finding_id: str, other_id: str, *, relation: str = "related") -> bool:
        """Link two findings. ``relation='duplicate'`` sets ``duplicate_of``.

        Linking is additive: it never deletes or merges a record, so distinct
        vulnerabilities that share a symptom are not erased by duplicate
        detection (mission acceptance criterion 11).
        """
        record = self.get(finding_id)
        if record is None:
            return False
        if relation == "duplicate":
            record.duplicate_of = other_id
        if other_id not in record.related:
            record.related.append(other_id)
        self._append({"type": "link", "id": finding_id, "other": other_id,
                      "relation": relation})
        self.save(record)
        return True

    # -- reading --------------------------------------------------------- #
    def all(self) -> list[FindingRecord]:
        state: dict[str, FindingRecord] = {}
        for ev in self._events():
            if ev.get("type") == "state" and ev.get("content"):
                rec = FindingRecord.from_dict(ev["content"])
                state[rec.finding_id] = rec
            elif ev.get("type") == "link" and ev.get("id") in state:
                rec = state[ev["id"]]
                if ev.get("relation") == "duplicate":
                    rec.duplicate_of = ev.get("other", "")
                if ev.get("other") and ev["other"] not in rec.related:
                    rec.related.append(ev["other"])
            elif ev.get("type") == "verdict" and ev.get("id") in state:
                state[ev["id"]].status = ev.get("status", state[ev["id"]].status)
        return list(state.values())

    def get(self, finding_id: str) -> Optional[FindingRecord]:
        return next((r for r in self.all() if r.finding_id == finding_id), None)

    def history(self, finding_id: str) -> list[dict]:
        """The ordered verdict/link/state events for one finding."""
        return [
            ev for ev in self._events()
            if ev.get("id") == finding_id
            and ev.get("type") in {"state", "verdict", "link"}
        ]

    # -- buckets --------------------------------------------------------- #
    def by_verdict(self, verdict: FindingVerdict | str) -> list[FindingRecord]:
        value = verdict.value if isinstance(verdict, FindingVerdict) else str(verdict)
        return [r for r in self.all() if r.status == value]

    def confirmed(self) -> list[FindingRecord]:
        return self.by_verdict(FindingVerdict.CONFIRMED)

    def unconfirmed(self) -> list[FindingRecord]:
        return [r for r in self.all()
                if r.status in (FindingVerdict.UNCONFIRMED.value,
                                FindingVerdict.STRONGLY_SUPPORTED.value)]

    def false_positives(self) -> list[FindingRecord]:
        return self.by_verdict(FindingVerdict.FALSE_POSITIVE)

    def informational(self) -> list[FindingRecord]:
        return self.by_verdict(FindingVerdict.INFORMATIONAL)

    def awaiting_verification(self) -> list[FindingRecord]:
        """Findings that claim to be real but are not independently verified.

        A record is awaiting verification when it claims CONFIRMED/STRONGLY_SUPPORTED
        but lacks a verification result or a named reviewer, **or** when its only
        review was performed by the same model. A same-model review is a real
        review, but it is not independent verification, so it stays on this list.
        """
        return [r for r in self.all()
                if r.status in (FindingVerdict.CONFIRMED.value,
                                FindingVerdict.STRONGLY_SUPPORTED.value)
                and (not (r.verification_result and r.reviewer)
                     or ReviewIndependence.coerce(r.review_independence)
                     == ReviewIndependence.SAME_MODEL)]

    # -- search ---------------------------------------------------------- #
    def search(
        self,
        *,
        target: str = "",
        category: str = "",
        component: str = "",
        severity: str = "",
        status: str = "",
        text: str = "",
        limit: int = 50,
    ) -> list[FindingRecord]:
        """Conjunctive search by target, class, component, severity, status, text."""
        needle = text.lower().strip()
        hits: list[FindingRecord] = []
        for r in self.all():
            if target and r.target != target:
                continue
            if category and r.category != category:
                continue
            if component and r.component != component:
                continue
            if severity and r.severity != severity:
                continue
            if status and r.status != status:
                continue
            if needle:
                haystack = " ".join([
                    r.title, r.component, r.category, r.hypothesis, r.root_cause_file,
                    r.design_mistake, r.consequences, r.verification_result,
                ]).lower()
                if needle not in haystack:
                    continue
            hits.append(r)
        hits.sort(key=lambda r: r.updated_at, reverse=True)
        return hits[:limit]

    # -- duplicate detection --------------------------------------------- #
    @staticmethod
    def _root_cause_key(record: FindingRecord) -> tuple[str, str]:
        """The (component, normalised root cause) that defines 'the same bug'.

        Two findings with the same component and the same root-cause file +
        location + design mistake are the same defect however they are titled or
        exploited.
        """
        rc = " ".join([
            record.root_cause_file, record.root_cause_location,
            record.design_mistake,
        ]).strip().lower()
        return (record.component.strip().lower(), rc)

    def find_duplicates(self, record: FindingRecord) -> list[FindingRecord]:
        """Existing findings that appear to be the same root cause.

        Detection is *advisory*: it returns candidates so the caller can link
        them; it never deletes, merges, or hides a distinct finding.
        """
        key = self._root_cause_key(record)
        if not key[1]:  # no root cause recorded yet: cannot claim a duplicate
            return []
        return [
            r for r in self.all()
            if r.finding_id != record.finding_id
            and self._root_cause_key(r) == key
        ]

    # -- integrity ------------------------------------------------------- #
    def verify_integrity(
        self,
        *,
        key: Optional[IntegrityKey] = None,
        require_signatures: bool = False,
        checkpoint: Optional[Checkpoint] = None,
    ) -> dict:
        result = verify_chain(self.path, key=key or self.key,
                              require_signatures=require_signatures,
                              checkpoint=checkpoint)
        return result.to_dict()

    def head(self) -> tuple[int, str]:
        seq, prev = self._head()
        return seq - 1, prev

    # -- summary / export ------------------------------------------------ #
    def summary(self) -> dict:
        recs = self.all()
        return {
            "total": len(recs),
            "confirmed": len(self.confirmed()),
            "unconfirmed": len(self.unconfirmed()),
            "false_positives": len(self.false_positives()),
            "informational": len(self.informational()),
            "awaiting_verification": len(self.awaiting_verification()),
        }

    def export_json(self, record: FindingRecord) -> str:
        return json.dumps(record.to_dict(), indent=2, default=str, sort_keys=True)

    def export_markdown(self, record: FindingRecord) -> str:
        """Render one finding as Markdown, grouped by the ten required sections."""
        lines = [f"# {record.title}", ""]
        lines.append(f"- **Finding ID:** {record.finding_id}")
        lines.append(f"- **Verdict:** {record.status}")
        lines.append(f"- **Target:** {record.target}")
        lines.append(f"- **Component:** {record.component or '_unspecified_'}")
        lines.append(f"- **Severity:** {record.severity}")
        lines.append(f"- **Discovery date:** {record.discovery_date}")
        lines.append(f"- **Researcher:** {record.researcher}")
        lines.append("")
        lines.append("> A finding is only CONFIRMED when it carries evidence and an")
        lines.append("> independent verification result. Anything else is labelled")
        lines.append("> honestly by its verdict above.")
        for section in FINDING_SECTIONS:
            lines.append("")
            lines.append(f"## {section.letter}. {section.name}")
            lines.append("")
            wrote = False
            for f in section.fields:
                value = getattr(record, f, None)
                if isinstance(value, list):
                    if value:
                        lines.append(f"**{f}:**")
                        for item in value:
                            lines.append(f"- {item}")
                        wrote = True
                elif value:
                    lines.append(f"**{f}:** {value}")
                    wrote = True
            if not wrote:
                lines.append("_None recorded._")
        lines.append("")
        return "\n".join(lines)

    def consolidated_report(self) -> str:
        """A single research report over the whole repository, honestly bucketed."""
        lines = ["# BLACKHEART research report", ""]
        s = self.summary()
        lines.append(
            f"{s['total']} findings: {s['confirmed']} confirmed, "
            f"{s['unconfirmed']} unconfirmed, {s['false_positives']} false positive, "
            f"{s['informational']} informational, "
            f"{s['awaiting_verification']} awaiting verification."
        )
        for title, recs in (
            ("Confirmed", self.confirmed()),
            ("Unconfirmed / strongly supported", self.unconfirmed()),
            ("Awaiting independent verification", self.awaiting_verification()),
            ("False positives", self.false_positives()),
            ("Informational", self.informational()),
        ):
            lines.append("")
            lines.append(f"## {title} ({len(recs)})")
            lines.append("")
            if not recs:
                lines.append("_none_")
            for r in recs:
                dup = f" (duplicate of {r.duplicate_of})" if r.duplicate_of else ""
                lines.append(f"- **{r.finding_id}** [{r.status}] {r.target}: {r.title}{dup}")
        lines.append("")
        return "\n".join(lines)


# --------------------------------------------------------------------------- #
# Evidence-gated confirmation, backed by the evidence store
# --------------------------------------------------------------------------- #

def confirm_with_evidence(
    repo: FindingRepository,
    finding_id: str,
    *,
    evidence_exists: Callable[[str], bool],
    note: str = "",
) -> tuple[bool, str]:
    """Confirm a finding only when its evidence references actually resolve.

    ``evidence_exists`` is supplied by the caller (typically
    ``lambda eid: EvidenceStore(...).get(eid) is not None``) so this module does
    not need to know the evidence layout. Returns ``(ok, reason)``: a confirmation
    that cannot be backed by resolvable evidence is refused with the reason, and
    the record is left untouched.

    This is the code path that satisfies acceptance criterion 14 -- *missing or
    invalid evidence does not produce a confirmed vulnerability* -- at the level
    of the repository rather than only the record.
    """
    record = repo.get(finding_id)
    if record is None:
        return False, f"no such finding: {finding_id}"
    missing = record.missing_confirmation_fields()
    if missing:
        return False, "missing required fields: " + ", ".join(missing)
    unresolved = [eid for eid in record.evidence_ids if not evidence_exists(eid)]
    if unresolved:
        return False, "evidence does not resolve: " + ", ".join(unresolved)
    # The repository's own set_verdict re-checks the confirmation gate, so this
    # path cannot confirm a record the gate would refuse.
    updated = repo.set_verdict(finding_id, FindingVerdict.CONFIRMED, note=note)
    if updated is None or not updated.is_confirmed():
        return False, "confirmation gate refused"
    return True, "confirmed"


# --------------------------------------------------------------------------- #
# Automatic documentation: bridge from the existing pipeline
# --------------------------------------------------------------------------- #

def record_from_finding(finding: "Finding") -> FindingRecord:
    """Build a :class:`FindingRecord` from an existing :class:`blackheart.models.Finding`.

    The mission requires that every meaningful investigation *automatically*
    produces structured documentation. The engine already produces a
    ``Finding`` (with gates, evidence ids, and verification notes) at the end of
    the campaign / demonstration / verification pipelines; this converts one into
    the richer A–J record so those pipelines can persist their result without a
    human re-typing it.

    The verdict is taken from the finding's classification, so a finding that did
    not pass the gates arrives as a non-confirmed record. Evidence ids are carried
    across so the record points at the same content-addressed artefacts.
    """
    verdict = classification_to_verdict(finding.classification)
    record = FindingRecord(
        finding_id=finding.finding_id,
        title=finding.title,
        target=finding.target,
        component=finding.component,
        severity=finding.severity,
        category=finding.category,
        security_boundary=finding.scope_reference,
        attack_prerequisites=list(finding.prerequisites),
        repro_steps=list(finding.reproduction_steps),
        repro_commands=list(finding.commands),
        poc_code=finding.poc_path,
        expected_behavior=finding.expected_behavior,
        observed_behavior=finding.actual_behavior,
        execution_result=finding.actual_behavior,
        evidence_ids=list(finding.evidence_ids),
        consequences=finding.impact,
        verification_result=finding.verification_notes,
        remaining_uncertainty="; ".join(finding.limitations),
        authorizations=[finding.scope_reference] if finding.scope_reference else [],
        status=verdict.value,
    )
    # ``root_cause`` is free text on the Finding; keep it whole rather than
    # guessing at file/location splits.
    record.vulnerable_implementation = finding.root_cause

    # Carry the verification provenance from the finding's gates. The engine only
    # classifies a finding CONFIRMED after gate 6 passed, but *who* reviewed it
    # matters: a separately authenticated model is "independent-verifier"; the
    # same model in a fresh context is a real review that must never be recorded
    # as an independent one. Without gate 6 the reviewer stays blank and the
    # record cannot confirm.
    from ..models import GateStatus  # local: trivial import, avoids widening the top

    verified_gate = next(
        (g for g in finding.gates if g.gate == 6 and g.status == GateStatus.PASS),
        None,
    )
    if verified_gate is not None:
        # Honour the provenance only when the finding's own gate-6 record supports
        # it. A hand-edited finding that claims an independent model while its
        # gate-6 detail records a same-model or legacy review is downgraded to the
        # provenance its record actually proves, so the record path can never be
        # the weaker one.
        evidenced, _ = evidenced_review_independence(finding)
        record.review_independence = evidenced.value
        record.reviewer = _reviewer_label(evidenced)
        record.verification_result = finding.verification_notes or verified_gate.detail
        record.verification_methodology = verified_gate.detail

    # A caller may hold the record in memory before it is persisted, so the
    # persistence gate is applied here too: a record the evidence gate would
    # refuse must never leave this function claiming CONFIRMED.
    if record.status == FindingVerdict.CONFIRMED.value and record.missing_confirmation_fields():
        record.status = FindingVerdict.STRONGLY_SUPPORTED.value
    return record


#: The reviewer identity recorded for each provenance. The label is the durable
#: record of independence, so it may only claim independence when a separately
#: authenticated model actually did the review.
_REVIEWER_LABEL: dict[ReviewIndependence, str] = {
    ReviewIndependence.INDEPENDENT_MODEL: "independent-verifier",
    ReviewIndependence.SAME_MODEL: "same-model-adversarial-reviewer",
    ReviewIndependence.UNRECORDED: "deterministic-verifier",
}


def _reviewer_label(independence) -> str:
    return _REVIEWER_LABEL[ReviewIndependence.coerce(independence)]


#: The reviewer labels that never denote an independent model. Derived from
#: :data:`_REVIEWER_LABEL` so the two can never drift: a record carrying one of
#: these while claiming ``INDEPENDENT_MODEL`` contradicts itself and is refused.
_ADDRESS_RE = re.compile(r"0x[0-9a-fA-F]{40}")
_NON_INDEPENDENT_LABELS = frozenset(
    label for provenance, label in _REVIEWER_LABEL.items()
    if provenance != ReviewIndependence.INDEPENDENT_MODEL
)


def document_finding(
    repo: FindingRepository,
    finding: "Finding",
    *,
    evidence_exists: Optional[Callable[[str], bool]] = None,
) -> FindingRecord:
    """Persist an engine ``Finding`` as a finding record (automatic documentation).

    A CONFIRMED classification is only persisted as CONFIRMED when the evidence
    gate allows it; otherwise the record is stored with a non-confirmed verdict
    and the reason is visible through :meth:`FindingRecord.missing_confirmation_fields`.
    This keeps the automatic path honest: a pipeline result is documented, never
    upgraded by the act of documenting it.

    ``evidence_exists`` is required to persist a CONFIRMED record. When it is
    omitted, a CONFIRMED classification is *downgraded* rather than trusted: the
    automatic path never confirms a finding whose evidence it cannot resolve, so
    the store-level gate cannot be skipped by simply not supplying the check.
    """
    record = record_from_finding(finding)
    repo.add(record)
    if record.status == FindingVerdict.CONFIRMED.value:
        if evidence_exists is None:
            # No way to check the evidence: fail closed, never persist CONFIRMED.
            repo.set_verdict(
                record.finding_id, FindingVerdict.STRONGLY_SUPPORTED,
                note="documented without an evidence check; not persisted as CONFIRMED",
            )
        else:
            ok, _ = confirm_with_evidence(
                repo, record.finding_id, evidence_exists=evidence_exists
            )
            if not ok:
                # The classification claimed CONFIRMED but the evidence gate
                # refused: downgrade so the record never overstates.
                repo.set_verdict(
                    record.finding_id, FindingVerdict.STRONGLY_SUPPORTED,
                    note="classification claimed CONFIRMED but evidence gate refused",
                )
    return repo.get(record.finding_id) or record


__all__ = [
    "FindingVerdict", "DEFAULT_VERDICT", "CONFIRMED",
    "verdict_to_classification", "classification_to_verdict",
    "FindingRecord", "FindingRepository", "confirm_with_evidence",
    "record_from_finding", "document_finding",
]
