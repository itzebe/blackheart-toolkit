"""Autonomous hunt controller: keep going across in-scope targets until payable.

The operator's only job is **independent review**. This controller drives the
existing engines over a list of in-scope targets, moves on from a target that
yields nothing, and stops *only* when one of these is true:

* ``PAYABLE_FOUND``  -- a candidate passes the official bounty gate (surface it).
* ``AWAITING_REVIEW``-- a reproduction awaits the operator's independent review.
* ``SCOPE_EXHAUSTED``-- every in-scope target was tried; none was payable.
* ``BUDGET_EXHAUSTED``-- the runtime/target budget ran out before the scope did.
* ``BLOCKED``         -- no target could run (missing record/policy/tool).

It never trusts the code: the controller delegates to a ``runner`` that runs the
certifier/PoC/evidence gate and a ``grader`` that reads the program's official
policy. A scanner lead is not a candidate; only a reproduced, gated result is
surfaced. The controller never confirms, never submits -- that is the human's one
job.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Optional


class TerminalReason(str, Enum):
    PAYABLE_FOUND = "PAYABLE_FOUND"
    AWAITING_REVIEW = "AWAITING_REVIEW"
    SCOPE_EXHAUSTED = "SCOPE_EXHAUSTED"
    BUDGET_EXHAUSTED = "BUDGET_EXHAUSTED"
    BLOCKED = "BLOCKED"


@dataclass
class Target:
    """One in-scope component the hunt may work on."""

    component: str
    path: str = ""
    repository: str = ""
    commit: str = ""
    compatibility: str = ""          # path to a validated compatibility record
    extra: dict = field(default_factory=dict)


@dataclass
class AutoHuntConfig:
    program: str = ""
    targets: list[Target] = field(default_factory=list)
    max_targets: int = 0             # 0 = no cap
    max_runtime_s: float = 0.0       # 0 = no cap
    stop_on_awaiting_review: bool = True


@dataclass
class Surface:
    """A candidate the operator must review."""

    target: str
    component: str
    disposition: str
    payable: bool
    finding_id: str = ""
    evidence_id: str = ""
    reason: str = ""

    @property
    def review_hint(self) -> str:
        bits = [f"review record {self.finding_id}" if self.finding_id
                else f"review {self.component}"]
        if self.evidence_id:
            bits.append(f"evidence {self.evidence_id}")
        bits.append("confirm only if you independently agree; nothing is submitted")
        return "; ".join(bits)

    def as_dict(self) -> dict:
        return {
            "target": self.target,
            "component": self.component,
            "disposition": self.disposition,
            "payable": self.payable,
            "finding_id": self.finding_id,
            "evidence_id": self.evidence_id,
            "reason": self.reason,
            "review_hint": self.review_hint,
        }


@dataclass
class AutoHuntResult:
    reason: str
    surfaced: list[Surface] = field(default_factory=list)
    targets_tried: int = 0
    targets_blocked: list[str] = field(default_factory=list)
    candidates_seen: int = 0
    detail: str = ""

    @property
    def needs_human_review(self) -> bool:
        return bool(self.surfaced)

    def as_dict(self) -> dict:
        return {
            "reason": self.reason,
            "needs_human_review": self.needs_human_review,
            "surfaced": [s.as_dict() for s in self.surfaced],
            "targets_tried": self.targets_tried,
            "targets_blocked": list(self.targets_blocked),
            "candidates_seen": self.candidates_seen,
            "detail": self.detail,
            "operator_job": "independent review of the surfaced candidates",
        }


def run_autohunt(config: AutoHuntConfig, *, runner: Callable[[Target], dict],
                 grader: Callable[[dict, Target], dict],
                 now: Callable[[], float] = time.monotonic) -> AutoHuntResult:
    """Drive ``runner``/``grader`` across the targets until payable or exhausted.

    ``runner(target) -> {"status", "detail", "findings"}`` where ``status`` is
    ``COMPLETED``/``BLOCKED``/``ERROR`` and each finding is a dict with at least
    ``reproduced`` (bool) and optionally ``finding_id``/``evidence_id``.
    ``grader(finding, target) -> {"disposition","payable","awaiting_review","reason"}``.
    """
    targets = list(config.targets)
    if config.max_targets:
        targets = targets[:config.max_targets]
    start = now()
    tried = 0
    blocked: list[str] = []
    surfaced: list[Surface] = []
    seen = 0

    for target in targets:
        if config.max_runtime_s and (now() - start) >= config.max_runtime_s:
            return AutoHuntResult(
                TerminalReason.BUDGET_EXHAUSTED.value, surfaced, tried, blocked,
                seen, f"runtime budget of {config.max_runtime_s}s exhausted")
        result = runner(target) or {}
        status = str(result.get("status", ""))
        if status in ("BLOCKED", "ERROR"):
            blocked.append(target.component)
            continue
        tried += 1
        for finding in result.get("findings", []) or []:
            seen += 1
            grade = grader(finding, target) or {}
            if grade.get("payable"):
                surfaced.append(Surface(
                    target=target.component, component=finding.get("component",
                                                                  target.component),
                    disposition=str(grade.get("disposition", "")), payable=True,
                    finding_id=str(finding.get("finding_id", "") or ""),
                    evidence_id=str(finding.get("evidence_id", "") or ""),
                    reason=str(grade.get("reason", ""))))
                return AutoHuntResult(
                    TerminalReason.PAYABLE_FOUND.value, surfaced, tried, blocked,
                    seen, "a payable candidate passed the official gate; stop for review")
            if grade.get("awaiting_review"):
                surfaced.append(Surface(
                    target=target.component, component=finding.get("component",
                                                                  target.component),
                    disposition=str(grade.get("disposition", "")), payable=False,
                    finding_id=str(finding.get("finding_id", "") or ""),
                    evidence_id=str(finding.get("evidence_id", "") or ""),
                    reason=str(grade.get("reason", ""))))
                if config.stop_on_awaiting_review:
                    return AutoHuntResult(
                        TerminalReason.AWAITING_REVIEW.value, surfaced, tried, blocked,
                        seen, "a reproduction awaits your independent review")

    if surfaced:
        return AutoHuntResult(
            TerminalReason.AWAITING_REVIEW.value, surfaced, tried, blocked, seen,
            "candidates await your independent review")
    if tried == 0 and blocked:
        return AutoHuntResult(
            TerminalReason.BLOCKED.value, surfaced, tried, blocked, seen,
            "no in-scope target could run (all blocked)")
    return AutoHuntResult(
        TerminalReason.SCOPE_EXHAUSTED.value, surfaced, tried, blocked, seen,
        "every in-scope target was tried; no payable candidate was found "
        "(this is not a proof of safety)")


# --------------------------------------------------------------------------- #
# Grading: the official bounty gate decides payable, not a score.
# --------------------------------------------------------------------------- #
def grade_from_gate_outcome(outcome: Any, *, reproduced: bool) -> dict:
    """Map a ``GateOutcome`` to the controller's grade fields.

    Only ``A_SUBMISSION_READY`` is payable. A reproduction is surfaced for review
    when it is ``B_POTENTIALLY_PAYABLE`` or ``F_NOT_ASSESSED`` (we could not grade
    it) -- but *not* when it is ``C_VALID_NOT_PAYABLE`` or worse, because those are
    ineligible and the hunt should keep moving to the next target.
    """
    from ..bounty.gate import Disposition

    disposition = str(getattr(outcome, "disposition", "") or "")
    payable = disposition == Disposition.SUBMISSION_READY
    reviewable = disposition in (Disposition.POTENTIALLY_PAYABLE,
                                 Disposition.NOT_ASSESSED)
    reason = "; ".join(list(getattr(outcome, "blockers", []) or [])
                       + list(getattr(outcome, "reasons", []) or []))
    if not reason:
        reason = str(getattr(outcome, "label", "") or disposition)
    return {
        "disposition": disposition,
        "payable": payable,
        "awaiting_review": bool(reproduced) and reviewable,
        "reason": reason,
    }


def candidate_from_finding(finding: dict, target: Target, policy: dict) -> Any:
    """Build the minimal ``CandidateRecord`` the official gate reads from a finding."""
    from ..bounty.gate import CandidateRecord

    def _policy(key: str, default: Any) -> Any:
        return policy.get(key, default) if isinstance(policy, dict) else default

    finding_id = str(finding.get("finding_id", "") or f"auto:{target.component}")
    return CandidateRecord(
        candidate_id=finding_id,
        target=target.component,
        component=target.component,
        program=_policy("program", ""),
        policy_url=_policy("policy_url", ""),
        policy_verified_at=_policy("retrieved_at", _policy("policy_verified_at", "")),
        policy_revision=_policy("revision", ""),
        policy_sha256=_policy("text_sha256", _policy("policy_sha256", "")),
        policy_text=_policy("text", _policy("policy_text", "")),
        in_scope_assets=list(_policy("in_scope_assets", []) or []),
        out_of_scope_assets=list(_policy("out_of_scope_assets", []) or []),
        exclusions=list(_policy("exclusions", []) or []),
        demonstrated_impact=str(finding.get("hypothesis", "") or ""),
        reproduction_status="PASS" if finding.get("reproduced") else "",
        evidence_refs=[str(finding.get("evidence_id", ""))] if finding.get("evidence_id") else [],
        affected_deployment=str(finding.get("component", target.component)),
        asset_scope=("in_scope"
                     if target.component in (_policy("in_scope_assets", []) or [])
                     else ""),
        vulnerability_class=str(finding.get("invariant_id", "") or ""),
    )


def bounty_grade(finding: dict, target: Target, *, policy: Optional[dict] = None,
                 candidate: Optional[dict] = None) -> dict:
    """Grade a finding with the official bounty gate (fails closed).

    The impact triage runs first: a claim with no executable surface, a name
    collision, or no unprivileged-attacker outcome is ``E_INFORMATIONAL`` and is
    never surfaced -- the official gate only ever sees a qualifying claim.
    """
    from ..impact import triage

    verdict = triage(
        impact=str(finding.get("hypothesis", "") or finding.get("detail", "")),
        surface=str(finding.get("surface", "contract")),
        identifiers=finding.get("identifiers", ()),
        outcome=str(finding.get("outcome", "") or ""),
        value_movement=finding.get("value_movement"),
        restriction_bypass=finding.get("restriction_bypass"),
    )
    if not verdict.qualifies:
        return {"disposition": "E_INFORMATIONAL", "payable": False,
                "awaiting_review": False,
                "reason": "impact triage: " + "; ".join(verdict.reasons)}
    reproduced = bool(finding.get("reproduced"))
    if candidate is not None:
        from ..bounty.gate import CandidateRecord, gate as _gate

        try:
            record = CandidateRecord(**candidate)
        except TypeError as exc:
            return {"disposition": "F_NOT_ASSESSED", "payable": False,
                    "awaiting_review": reproduced,
                    "reason": f"candidate record is incomplete: {exc}"}
        return grade_from_gate_outcome(_gate(record), reproduced=reproduced)
    if policy is not None:
        from ..bounty.gate import gate as _gate

        return grade_from_gate_outcome(
            _gate(candidate_from_finding(finding, target, policy)),
            reproduced=reproduced)
    return {"disposition": "F_NOT_ASSESSED", "payable": False,
            "awaiting_review": reproduced,
            "reason": "no verified policy snapshot or candidate record supplied"}


# --------------------------------------------------------------------------- #
# The default runner: the external chain built in this repository.
# --------------------------------------------------------------------------- #
def external_chain_runner(target: Target, *, scanner: str, do_poc: bool = True,
                          findings_root: str = "research/private/findings",
                          evidence_root: str = "research/private/evidence",
                          reviewer: str = "", review_independence: str = "",
                          verification_result: str = "",
                          max_depth: int = 4, timeout: int = 600) -> dict:
    """Run scanner -> hypothesis -> target -> certify -> PoC -> finding for one target."""
    if not target.compatibility:
        return {"status": "BLOCKED", "detail": "no compatibility record for the target",
                "findings": []}
    try:
        from ..engines.external import run_external
        from ..hypothesis.from_leads import leads_to_hypotheses
        from ..hypothesis.to_finding import record_reproduction
        from ..hypothesis.to_target import poc_for_target, targets_from_hypotheses
        from ..impact import outcome_for_invariant
        from ..toolchain.enforce import load_record

        record = load_record(target.compatibility)
    except Exception as exc:  # noqa: BLE001 -- reported as blocked, never hidden
        return {"status": "BLOCKED", "detail": f"could not prepare the run: {exc}",
                "findings": []}
    outcome = run_external(scanner, target.path, compatibility=record,
                           repository=target.repository,
                           commit=target.commit, timeout=timeout)
    if str(getattr(outcome, "status", "")) != "COMPLETED":
        return {"status": "BLOCKED",
                "detail": f"{scanner}: {getattr(outcome, 'detail', '')}",
                "findings": []}
    promotion = leads_to_hypotheses(outcome, component=target.component)
    targets = targets_from_hypotheses(promotion.promoted, root=target.path,
                                      certify_result=True, max_depth=max_depth)
    findings: list[dict] = []
    for tgt in targets:
        if not tgt.violations:
            continue
        inv_list = list(tgt.invariants)
        base = {"component": tgt.component, "invariant_id": ",".join(inv_list),
                "hypothesis": f"{tgt.component}: {tgt.violations} model witness(es)",
                "outcome": outcome_for_invariant(inv_list), "surface": "contract",
                "value_movement": any(str(i).startswith("conservation:") for i in inv_list),
                "restriction_bypass": any(str(i).startswith("authorization:") for i in inv_list)}
        if not do_poc:
            findings.append({**base, "reproduced": False,
                             "detail": "model violation; enable --poc to reproduce"})
            continue
        poc = poc_for_target(tgt, root=target.path, compatibility=record,
                             repository=target.repository, commit=target.commit,
                             timeout=timeout)
        if str(poc.get("status", "")) != "PASS":
            findings.append({**base, "reproduced": False,
                             "detail": str(poc.get("detail", "not reproduced"))})
            continue
        rec = record_reproduction(
            tgt, poc, target=target.component, findings_root=findings_root,
            evidence_root=evidence_root, reviewer=reviewer,
            review_independence=review_independence,
            verification_result=verification_result)
        findings.append({**base, "reproduced": True, "finding_id": rec.finding_id,
                         "evidence_id": rec.evidence_id, "verdict": rec.verdict,
                         "detail": rec.detail})
    return {"status": "COMPLETED",
            "detail": f"{len(findings)} candidate finding(s) from {scanner}",
            "findings": findings}


__all__ = [
    "TerminalReason", "Target", "AutoHuntConfig", "Surface", "AutoHuntResult",
    "run_autohunt", "grade_from_gate_outcome", "candidate_from_finding",
    "bounty_grade", "external_chain_runner",
]
