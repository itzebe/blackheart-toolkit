"""Submission-ready report generation (mission section 9).

Reports are written to a *private* engagement directory (never into tracked
paths). A report is only emitted as "confirmed" when the finding's classification
is CONFIRMED and all seven gates passed -- otherwise the header states the real
classification so no hypothesis is ever presented as a vulnerability.
"""

from __future__ import annotations

import os
from pathlib import Path

from ..models import (
    Classification, Finding, ReviewIndependence, Severity,
    evidenced_review_independence,
)


_TEMPLATE = """# {title}

- **Finding ID:** {finding_id}
- **Classification:** {classification}
- **Severity:** {severity}
- **Target asset:** {target}
- **Component:** {component}
- **Official scope reference:** {scope_reference}
- **Category:** {category}
- **Created:** {created_at}

> This report was produced by BLACKHEART. A finding is only "CONFIRMED" when all
> seven quality gates passed and the finding was reproduced by an independent
> verifier. Reviewer provenance for this report: {review_provenance}. Anything
> else is labelled honestly above.

## Summary

{summary}

## Attacker prerequisites

{prerequisites}

## Root cause

{root_cause}

## Reproduction steps

{reproduction_steps}

## Minimal PoC

```
{poc}
```

## Expected behaviour

{expected}

## Actual behaviour

{actual}

## Demonstrated impact

{impact}

## Economic account

{economics}

## Commands and outputs

{commands}

## Evidence

{evidence}

## Quality gates

{gates}

## Independent verification

{verification}

## Remediation recommendation

{remediation}

## Known limitations

{limitations}
"""


def _bullets(items: list[str], empty: str = "_None recorded._") -> str:
    if not items:
        return empty
    return "\n".join(f"- {i}" for i in items)


def _gates_table(finding: Finding) -> str:
    if not finding.gates:
        return "_No gates evaluated._"
    lines = ["| # | Gate | Status | Detail |", "|---|------|--------|--------|"]
    for g in finding.gates:
        lines.append(f"| {g.gate} | {g.name} | {g.status.value} | {g.detail} |")
    return "\n".join(lines)


def _economics_block(finding: Finding) -> str:
    """Render the finding's priced account, or state honestly that it was not priced."""
    acct = finding.economic
    if not acct:
        return "_Not priced. Run the value engine (`blackheart value analyse`) to price this finding._"
    rows = [
        ("Attacker", acct.get("attacker", "")),
        ("Attacker initial capital", acct.get("attacker_initial_capital")),
        ("Attacker final capital", acct.get("attacker_final_capital")),
        ("Attacker profit", acct.get("attacker_profit")),
        ("Victim loss", acct.get("victim_loss")),
        ("Protocol loss", acct.get("protocol_loss")),
        ("Value created (unbacked)", acct.get("value_created")),
        ("Conservation residual", acct.get("conservation_residual")),
        ("Repeatable", acct.get("repeatable")),
        ("Max extraction", acct.get("max_extraction")),
        ("Financial impact established", acct.get("financial_impact_established")),
        ("Tracked", acct.get("tracked")),
    ]
    lines = ["| Quantity | Value |", "|----------|-------|"]
    lines += [f"| {name} | `{value}` |" for name, value in rows]
    notes = acct.get("notes") or []
    if notes:
        lines.append("")
        lines += [f"- {n}" for n in notes]
    return "\n".join(lines)


def _review_provenance_text(finding: Finding) -> str:
    """A plain-language statement of who reviewed the finding."""
    value = ReviewIndependence.coerce(finding.review_independence)
    if value == ReviewIndependence.INDEPENDENT_MODEL:
        return "an independently authenticated reviewer model"
    if value == ReviewIndependence.SAME_MODEL:
        return ("the same model in a fresh adversarial context (NOT an independent "
                "second model; shared blind spots are not excluded)")
    return ("the deterministic verifier; no model reviewer provenance was recorded, "
            "so this is not an independent-model review")


def render_report(finding: Finding, remediation: str = "") -> str:
    summary = (
        f"{finding.title}. "
        + (finding.impact if finding.impact else "Impact not yet established.")
    )
    return _TEMPLATE.format(
        title=finding.title,
        finding_id=finding.finding_id,
        classification=finding.classification.value,
        severity=finding.severity,
        target=finding.target,
        component=finding.component or "_unspecified_",
        scope_reference=finding.scope_reference or "_not recorded_",
        category=finding.category or "_unspecified_",
        created_at=finding.created_at,
        review_provenance=_review_provenance_text(finding),
        summary=summary,
        prerequisites=_bullets(finding.prerequisites),
        root_cause=finding.root_cause or "_not established._",
        reproduction_steps=_bullets(finding.reproduction_steps),
        poc=finding.poc_path or "<no PoC path recorded>",
        expected=finding.expected_behavior or "_not recorded._",
        actual=finding.actual_behavior or "_not recorded._",
        impact=finding.impact or "_not demonstrated._",
        economics=_economics_block(finding),
        commands=_bullets([f"`{c}`" for c in finding.commands]),
        evidence=_bullets(finding.evidence_ids),
        gates=_gates_table(finding),
        verification=finding.verification_notes or "_verification not run._",
        remediation=remediation or "_To be completed before submission._",
        limitations=_bullets(finding.limitations),
    )


def write_report(finding: Finding, out_dir: str | os.PathLike, remediation: str = "") -> Path:
    """Write a report into a private directory and return its path."""
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    safe = "".join(c if c.isalnum() or c in "-_" else "-" for c in finding.title.lower())[:60]
    path = out / f"{finding.finding_id}-{safe}.md"
    path.write_text(render_report(finding, remediation), encoding="utf-8")
    return path


def _provenance_conflict(finding: Finding) -> str:
    """Why the finding's gate-6 record does not support its provenance claim.

    The rule itself lives in :func:`blackheart.models.evidenced_review_independence`
    so the report layer and the findings repository apply one definition; this
    only phrases the conflict for a human reading the blockers.
    """
    _, reason = evidenced_review_independence(finding)
    return reason


def is_submission_ready(finding: Finding) -> bool:
    """A report may be submitted only for a fully confirmed, in-scope finding.

    Additionally, when the finding carries evidence tags, it must also clear the
    deterministic triage gate (no kill signal for its class) -- a confirmed,
    in-scope finding of a class the gate rejects is still not submittable. A
    finding with no evidence tags is judged exactly as before.

    A finding whose review was performed by the same model is never submission-
    ready: gate 6 fails such a review, and this check refuses it even if the gates
    were hand-built to pass. For the same reason a claimed independent review that
    contradicts the finding's own gate-6 detail is refused.
    """
    if ReviewIndependence.coerce(finding.review_independence) == ReviewIndependence.SAME_MODEL:
        return False
    if _provenance_conflict(finding):
        return False
    if not (
        finding.classification == Classification.CONFIRMED
        and finding.gates_pass()
        and bool(finding.scope_reference)
    ):
        return False
    if finding.evidence_tags:
        from ..verify.triage import TriageGate

        verdict = TriageGate().evaluate(finding.category, finding.evidence_tags)
        # A *downgrade* (a chain-required class whose chain is not demonstrated)
        # must block submission just as a hard reject does -- otherwise a weak
        # finding could bypass triage through this path. A class whose required
        # chain evidence IS present is not downgraded, so genuine findings pass.
        if verdict.weak:
            return False
    return True


def submission_blockers(finding: Finding) -> list[str]:
    """Why a finding is not submission-ready (empty list means it is)."""
    blockers: list[str] = []
    if finding.classification != Classification.CONFIRMED:
        blockers.append(f"classification is {finding.classification.value}, not CONFIRMED")
    if ReviewIndependence.coerce(finding.review_independence) == ReviewIndependence.SAME_MODEL:
        blockers.append("reviewed only by the same model in a fresh context; "
                        "that is not independent verification")
    conflict = _provenance_conflict(finding)
    if conflict:
        if ReviewIndependence.coerce(finding.review_independence) \
                == ReviewIndependence.INDEPENDENT_MODEL:
            blockers.append(f"claimed an independent-model review, but {conflict}")
        else:
            blockers.append(f"the recorded review provenance is inconsistent: {conflict}")
    if not finding.gates_pass():
        blockers.append("not all seven quality gates passed")
    if not finding.scope_reference:
        blockers.append("no official scope reference recorded")
    if finding.evidence_tags:
        from ..verify.triage import TriageGate

        verdict = TriageGate().evaluate(finding.category, finding.evidence_tags)
        if verdict.weak:
            label = ("triage gate rejected the finding class"
                     if verdict.reject
                     else "triage gate downgraded the finding (chain not demonstrated)")
            blockers.append(f"{label}: " + "; ".join(verdict.reasons))
    return blockers


def is_submission_ready_with_novelty(finding: Finding, gate) -> tuple[bool, str]:
    """The full pre-submission gate, including the mandatory novelty review.

    Composes the technical gate (:func:`is_submission_ready`) with the novelty
    gate. A technically confirmed finding with no documented novelty review, or
    one classified as a duplicate / already-fixed / insufficient-evidence, is
    **not** submission-ready. Returns (allowed, reason).
    """
    if not is_submission_ready(finding):
        return False, (
            "technically not submission-ready: requires CONFIRMED classification, "
            "all gates passing, and a scope reference"
        )
    return gate.allows_submission(finding.finding_id)
