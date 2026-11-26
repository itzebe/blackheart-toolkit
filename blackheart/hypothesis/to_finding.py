"""Record an executed reproduction as a finding -- gated, never auto-confirmed.

A ``PASS`` from :func:`blackheart.hypothesis.to_target.poc_for_target` is an
*executed reproduction*. This records it in the findings repository with the PoC
and its run as evidence, then **attempts** :meth:`FindingRecord.confirm`. The
evidence gate refuses ``CONFIRMED`` unless the record also carries independent
verification (a real reviewer, a verification result and independent provenance).
So a reproduction with no independent review is recorded as
``STRONGLY_SUPPORTED`` -- it is never laundered into ``CONFIRMED``.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any

from ..findings import FindingRecord, FindingRepository, FindingVerdict
from ..models import ReviewIndependence


@dataclass
class FindingOutcome:
    """What recording a reproduction produced, and why a confirmation was refused."""

    status: str            # RECORDED | REFUSED | ERROR
    finding_id: str = ""
    verdict: str = ""
    detail: str = ""
    evidence_id: str = ""
    missing_confirmation_fields: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "status": self.status,
            "finding_id": self.finding_id,
            "verdict": self.verdict,
            "detail": self.detail,
            "evidence_id": self.evidence_id,
            "missing_confirmation_fields": list(self.missing_confirmation_fields),
            "note": "STRONGLY_SUPPORTED is an executed reproduction; CONFIRMED needs "
                    "independent verification and is never set automatically",
        }


def _finding_id(target: str, component: str, invariant_id: str) -> str:
    return "ext-" + hashlib.sha256(
        f"{target}|{component}|{invariant_id}".encode()).hexdigest()[:16]


def _sequence_from_cert(cert: Any) -> list[str]:
    for violation in getattr(cert, "violations", []) or []:
        seq = violation.get("minimal_sequence") or []
        if seq:
            return [f"{s.get('actor', '')}:{s.get('action', '')}".strip(":") for s in seq]
    return []


def record_reproduction(outcome: Any, poc: dict, *, target: str, findings_root: str,
                        evidence_root: str, reviewer: str = "",
                        review_independence: str = "",
                        verification_result: str = "",
                        authorizations: list[str] | None = None) -> FindingOutcome:
    """Record a PASS reproduction as a finding; refuse anything that did not run."""
    status = str((poc or {}).get("status", ""))
    if status != "PASS":
        return FindingOutcome(
            "REFUSED",
            detail=f"not an executed reproduction (status={status!r}); nothing recorded")
    component = str(getattr(outcome, "component", "") or "")
    invariant_id = str(poc.get("invariant_id", "") or "")
    category = ("authorization" if invariant_id.startswith("authorization:")
                else "invariant-violation")
    from ..evidence import EvidenceStore

    store = EvidenceStore(evidence_root)
    evidence = store.put_json(
        {"component": component, "invariant_id": invariant_id, "poc": poc,
         "target_outcome": outcome.as_dict()},
        kind="external-reproduction",
        description=f"{invariant_id or category} reproduced on {component}",
        command=str(poc.get("command", "") or ""),
        metadata={"component": component, "invariant_id": invariant_id},
    )
    record = FindingRecord(
        finding_id=_finding_id(target, component, invariant_id),
        title=f"{invariant_id or category} reproduced in {component}",
        target=target,
        component=component,
        category=category,
        severity="unrated",
        security_boundary="unprivileged actor",
        attack_prerequisites=["the component is reachable by an ordinary account"],
        hypothesis=(f"an unprivileged actor can break {invariant_id} on {component}"
                    if invariant_id else f"an unprivileged actor can abuse {component}"),
        attacker_assumptions=["ordinary unprivileged account", "no owner or privileged role"],
        attack_sequence=_sequence_from_cert(getattr(outcome, "certificate", None)),
        required_permissions="none beyond an ordinary account",
        exploitability="reproduced by a Foundry PoC",
        repro_environment="source-level Foundry PoC (external witness)",
        repro_commands=[str(poc.get("command", ""))] if poc.get("command") else [],
        poc_code=str(poc.get("test_source", "") or poc.get("source", "") or ""),
        execution_result="PASS",
        evidence_ids=[evidence.evidence_id],
        logs=[str(poc.get("detail", "") or "")],
        reviewer=reviewer,
        review_independence=(review_independence
                             or ReviewIndependence.SAME_MODEL.value),
        verification_result=verification_result,
        authorizations=list(authorizations or []),
    )
    confirmed = record.confirm()
    if not confirmed:
        record.status = FindingVerdict.STRONGLY_SUPPORTED.value
    FindingRepository(findings_root).save(record)
    return FindingOutcome(
        "RECORDED",
        finding_id=record.finding_id,
        verdict=record.status,
        detail=("CONFIRMED by an independent review"
                if confirmed else
                "recorded as STRONGLY_SUPPORTED; CONFIRMED refused until independently verified"),
        evidence_id=evidence.evidence_id,
        missing_confirmation_fields=record.missing_confirmation_fields(),
    )


__all__ = ["FindingOutcome", "record_reproduction"]
