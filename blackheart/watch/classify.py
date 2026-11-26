"""Turn raw change observations into classified, scored investigation leads.

Two rules govern this module:

1. **A change is not a vulnerability.** Every event starts as a *lead*. Nothing
   here produces a finding, a severity, or a submission.
2. **A score is an argument, not a number.** Each of the seven components is
   computed from named evidence and returned with its rationale, so a reviewer
   can disagree with a specific component instead of a black-box total.

The seven weights are the mission's: exploitability 25, impact 20, novelty 15,
official bounty eligibility 15, evidence quality 10, reproducibility 10, research
effort efficiency 5. A lead is recommended for active investigation only at
``>= 80`` *and* only when the program's participation gates are satisfied.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Iterable, Optional

from ..models import utcnow
from .registry import KnownIssue, Target

__all__ = [
    "Status",
    "Kind",
    "Event",
    "Lead",
    "SCORE_WEIGHTS",
    "SCORE_THRESHOLD",
    "make_event",
    "assess_repo_change",
    "match_known_issue",
    "score_lead",
    "classify_event",
    "policy_block_reason",
    "SECURITY_PATH_RE",
]

SCORE_WEIGHTS = {
    "exploitability": 25,
    "impact": 20,
    "novelty": 15,
    "eligibility": 15,
    "evidence": 10,
    "reproducibility": 10,
    "effort": 5,
}
SCORE_THRESHOLD = 80


class Status:
    NEW_ACTIONABLE_CHANGE = "NEW ACTIONABLE CHANGE"
    INVESTIGATE = "INVESTIGATE"
    WATCH = "WATCH"
    NO_CHANGE = "NO CHANGE"
    POLICY_BLOCKED = "POLICY BLOCKED"
    KNOWN_DUPLICATE = "KNOWN / DUPLICATE"
    SOURCE_INACCESSIBLE = "SOURCE INACCESSIBLE"


class Kind:
    POLICY_NEW = "policy_new"
    POLICY_CHANGED = "policy_changed"
    REPO_HEAD = "repo_head"
    REPO_RELEASE = "repo_release"
    REPO_TAG = "repo_tag"
    CONTRACT_NEW = "contract_new"
    CONTRACT_CODE = "contract_code_changed"
    CONTRACT_IMPL = "contract_implementation_changed"
    CONTRACT_ADMIN = "contract_admin_changed"
    CONTRACT_OWNER = "contract_owner_changed"
    SOURCE_FAILED = "source_failed"


CONTRACT_KINDS = frozenset(
    {
        Kind.CONTRACT_NEW,
        Kind.CONTRACT_CODE,
        Kind.CONTRACT_IMPL,
        Kind.CONTRACT_ADMIN,
        Kind.CONTRACT_OWNER,
    }
)
REPO_KINDS = frozenset({Kind.REPO_HEAD, Kind.REPO_RELEASE, Kind.REPO_TAG})

#: Paths where a change can plausibly alter in-scope behaviour. Test and docs
#: changes are deliberately excluded from the "sensitive" set: they are still
#: reported, but they do not make a lead look exploitable.
SECURITY_PATH_RE = re.compile(
    r"(^|/)(contracts?|src|programs?|pallets?|modules?|core|protocol|vaults?|bridges?|"
    r"oracles?|accounting|accounts?|auth|access|proxy|upgrade|initializer|token|pool|"
    r"router|reward|fee|stake|staking|governance|kms|enclave|seal|signer|verify|"
    r"withdraw|deposit|escrow)(/|$)|\.(sol|rs|go|cairo|move)$",
    re.I,
)
_NON_CODE_RE = re.compile(r"(^|/)(tests?|testdata|docs?|examples?|scripts?/test)/|\.(md|txt|png|jpg|svg|lock)$", re.I)
SECURITY_MESSAGE_RE = re.compile(
    r"\b(security|vulnerab|exploit|fix|patch|cve|auth|signature|replay|oracle|upgrade|"
    r"access|permission|withdraw|bridge|reentran|overflow|underflow|precision|rounding|"
    r"accounting|invariant|initializ|proxy|owner|role|kms|attestation|seal)\b",
    re.I,
)


@dataclass
class Event:
    """One observed change, with the evidence needed to judge it."""

    id: str
    target: str
    kind: str
    component: str
    summary: str
    old: str = ""
    new: str = ""
    evidence_urls: tuple[str, ...] = ()
    security_relevant: bool = False
    detail: dict = field(default_factory=dict)
    detected_at: str = field(default_factory=utcnow)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "target": self.target,
            "kind": self.kind,
            "component": self.component,
            "summary": self.summary,
            "old": self.old,
            "new": self.new,
            "evidence_urls": list(self.evidence_urls),
            "security_relevant": self.security_relevant,
            "detail": self.detail,
            "detected_at": self.detected_at,
        }


@dataclass
class Lead:
    """A classified event: status, score, per-component reasoning and gates."""

    event: Event
    target: Target
    status: str
    score: int
    components: dict[str, int]
    rationale: list[str]
    recommend: bool = False
    policy_blocked: bool = False
    block_reason: str = ""
    known_issue: Optional[KnownIssue] = None

    def to_dict(self) -> dict:
        return {
            "event": self.event.to_dict(),
            "target": self.target.slug,
            "target_name": self.target.name,
            "status": self.status,
            "score": self.score,
            "components": self.components,
            "rationale": list(self.rationale),
            "recommend": self.recommend,
            "policy_blocked": self.policy_blocked,
            "block_reason": self.block_reason,
            "known_issue": (
                {
                    "id": self.known_issue.id,
                    "summary": self.known_issue.summary,
                    "status": self.known_issue.status,
                    "monitor": self.known_issue.monitor,
                }
                if self.known_issue
                else None
            ),
        }


def make_event(
    *,
    target: str,
    kind: str,
    component: str,
    summary: str,
    old: str = "",
    new: str = "",
    evidence_urls: Iterable[str] = (),
    security_relevant: bool = False,
    detail: Optional[dict] = None,
) -> Event:
    """Build an event with a deterministic id (so a repeat is deduplicated)."""
    ident = "\x1f".join([target, kind, component, old, new, summary])
    event_id = hashlib.sha256(ident.encode("utf-8")).hexdigest()[:20]
    return Event(
        id=event_id,
        target=target,
        kind=kind,
        component=component,
        summary=summary,
        old=old,
        new=new,
        evidence_urls=tuple(evidence_urls),
        security_relevant=security_relevant,
        detail=detail or {},
    )


def assess_repo_change(
    files: Iterable[str], messages: Iterable[str]
) -> tuple[bool, list[str], list[str]]:
    """Return ``(security_relevant, sensitive_files, sensitive_messages)``."""
    sensitive_files = [
        f for f in files if SECURITY_PATH_RE.search(f) and not _NON_CODE_RE.search(f)
    ]
    sensitive_messages = [m for m in messages if SECURITY_MESSAGE_RE.search(m)]
    return (bool(sensitive_files or sensitive_messages), sensitive_files, sensitive_messages)


def _keyword_hit(keyword: str, haystack: str) -> bool:
    kw = keyword.strip().lower()
    if not kw:
        return False
    if len(kw) <= 4 and kw.isalnum():
        return re.search(rf"\b{re.escape(kw)}\b", haystack) is not None
    return kw in haystack


def match_known_issue(target: Target, event: Event) -> Optional[KnownIssue]:
    """Match an event against the target's exclusions.

    The match is intentionally conservative: a known issue is only applied when
    one of its specific keywords appears in the event summary, component or
    changed paths. A generic word like "oracle" is not a keyword on its own.
    """
    haystack = " ".join(
        [
            event.summary,
            event.component,
            " ".join(str(x) for x in event.detail.get("files", []) or []),
            " ".join(str(x) for x in event.detail.get("messages", []) or []),
        ]
    ).lower()
    for issue in target.known_issues:
        if any(_keyword_hit(k, haystack) for k in issue.keywords):
            return issue
    return None


def policy_block_reason(target: Target) -> str:
    """Why a target cannot be treated as actionable, in one honest sentence."""
    reasons: list[str] = []
    if target.program_status != "ACTIVE":
        reasons.append(f"program status is {target.program_status}")
    if target.eligibility.ai_agent_allowed != "true":
        reasons.append(
            f"AI-agent participation is {target.eligibility.ai_agent_allowed}"
        )
    if not target.eligibility.participation_authorized:
        reasons.append("operator participation authorization is absent")
    if not target.eligibility.platform_participation_allowed:
        reasons.append("operator excludes the program's platform from participation")
    return "; ".join(reasons) if reasons else ""


_EXPLOITABILITY = {
    Kind.CONTRACT_IMPL: 22,
    Kind.CONTRACT_CODE: 20,
    Kind.CONTRACT_ADMIN: 18,
    Kind.CONTRACT_OWNER: 14,
    Kind.CONTRACT_NEW: 10,
    Kind.REPO_HEAD: 13,
    Kind.REPO_RELEASE: 9,
    Kind.REPO_TAG: 5,
    Kind.POLICY_CHANGED: 4,
    Kind.POLICY_NEW: 2,
    Kind.SOURCE_FAILED: 0,
}
_IMPACT = {"high": 18, "medium": 13, "low": 7}
_NOVELTY = {
    Kind.CONTRACT_IMPL: 12,
    Kind.CONTRACT_CODE: 10,
    Kind.CONTRACT_ADMIN: 9,
    Kind.CONTRACT_OWNER: 8,
    Kind.CONTRACT_NEW: 6,
    Kind.REPO_RELEASE: 6,
    Kind.REPO_HEAD: 5,
    Kind.REPO_TAG: 3,
    Kind.POLICY_CHANGED: 4,
    Kind.POLICY_NEW: 2,
    Kind.SOURCE_FAILED: 0,
}
_EVIDENCE = {
    Kind.CONTRACT_IMPL: 9,
    Kind.CONTRACT_CODE: 9,
    Kind.CONTRACT_ADMIN: 8,
    Kind.CONTRACT_OWNER: 7,
    Kind.CONTRACT_NEW: 9,
    Kind.REPO_RELEASE: 6,
    Kind.REPO_HEAD: 5,
    Kind.REPO_TAG: 4,
    Kind.POLICY_CHANGED: 4,
    Kind.POLICY_NEW: 3,
    Kind.SOURCE_FAILED: 0,
}
_REPRODUCIBILITY = {
    Kind.CONTRACT_IMPL: 8,
    Kind.CONTRACT_CODE: 8,
    Kind.CONTRACT_ADMIN: 7,
    Kind.CONTRACT_OWNER: 6,
    Kind.CONTRACT_NEW: 7,
    Kind.REPO_RELEASE: 6,
    Kind.REPO_HEAD: 6,
    Kind.REPO_TAG: 4,
    Kind.POLICY_CHANGED: 5,
    Kind.POLICY_NEW: 4,
    Kind.SOURCE_FAILED: 0,
}


def score_lead(
    event: Event,
    target: Target,
    *,
    sensitive_files: Iterable[str] = (),
    sensitive_messages: Iterable[str] = (),
) -> tuple[int, dict[str, int], list[str]]:
    """Score an event out of 100 with an explicit rationale per component."""
    files = list(sensitive_files)
    messages = list(sensitive_messages)
    rationale: list[str] = []

    exploitability = _EXPLOITABILITY.get(event.kind, 2)
    if files:
        exploitability += 3
        rationale.append(
            f"exploitability +3: {len(files)} security-sensitive path(s) changed"
        )
    if messages:
        exploitability += 2
        rationale.append(
            f"exploitability +2: {len(messages)} commit message(s) mention a security-relevant term"
        )
    exploitability = min(SCORE_WEIGHTS["exploitability"], exploitability)
    rationale.append(
        f"exploitability {exploitability}/25: change type {event.kind}"
    )

    impact = _IMPACT.get(target.value_class, 10)
    if event.kind in CONTRACT_KINDS:
        impact += 2
        rationale.append("impact +2: change is in deployed contract state/code")
    impact = min(SCORE_WEIGHTS["impact"], impact)
    rationale.append(
        f"impact {impact}/20: target value class is {target.value_class}"
    )

    novelty = _NOVELTY.get(event.kind, 2)
    rationale.append(f"novelty {novelty}/15: first observation of this {event.kind}")

    if target.submission_permitted:
        eligibility = 15
        rationale.append("eligibility 15/15: every participation gate is satisfied")
    elif target.program_status == "ACTIVE" and target.eligibility.platform_participation_allowed:
        eligibility = 8
        rationale.append(
            "eligibility 8/15: active program, but AI-agent permission is not confirmed"
        )
    elif target.program_status == "ACTIVE":
        eligibility = 4
        rationale.append(
            "eligibility 4/15: active program, but the operator excludes its platform"
        )
    else:
        eligibility = 0
        rationale.append(
            f"eligibility 0/15: program status is {target.program_status}"
        )

    evidence = _EVIDENCE.get(event.kind, 2)
    rationale.append(
        f"evidence {evidence}/10: "
        + ("on-chain observation" if event.kind in CONTRACT_KINDS else "public record")
    )
    reproducibility = _REPRODUCIBILITY.get(event.kind, 2)
    rationale.append(f"reproducibility {reproducibility}/10: {event.kind}")

    effort = 5 if event.kind in CONTRACT_KINDS else 4 if event.kind in REPO_KINDS else 3
    rationale.append(f"effort {effort}/5: bounded, targeted check")

    components = {
        "exploitability": exploitability,
        "impact": impact,
        "novelty": novelty,
        "eligibility": eligibility,
        "evidence": evidence,
        "reproducibility": reproducibility,
        "effort": effort,
    }
    return sum(components.values()), components, rationale


def classify_event(
    event: Event,
    target: Target,
    *,
    sensitive_files: Iterable[str] = (),
    sensitive_messages: Iterable[str] = (),
) -> Lead:
    """Assign a status and score to one event, enforcing every gate."""
    if event.kind == Kind.SOURCE_FAILED:
        return Lead(
            event=event,
            target=target,
            status=Status.SOURCE_INACCESSIBLE,
            score=0,
            components={k: 0 for k in SCORE_WEIGHTS},
            rationale=["source could not be read; this is a gap, not a clean result"],
        )

    known = match_known_issue(target, event)
    score, components, rationale = score_lead(
        event,
        target,
        sensitive_files=sensitive_files,
        sensitive_messages=sensitive_messages,
    )

    if known is not None and known.do_not_report:
        rationale.append(
            f"known issue {known.id} ({known.status}) matched; suppressed from reporting"
        )
        return Lead(
            event=event,
            target=target,
            status=Status.KNOWN_DUPLICATE,
            score=score,
            components=components,
            rationale=rationale,
            known_issue=known,
        )

    permitted = target.submission_permitted
    blocked = not permitted
    reason = policy_block_reason(target) if blocked else ""

    if permitted and score >= SCORE_THRESHOLD and event.security_relevant:
        status = Status.NEW_ACTIONABLE_CHANGE
        recommend = True
    elif event.security_relevant and score >= 50:
        status = Status.POLICY_BLOCKED if blocked else Status.INVESTIGATE
        recommend = False
    elif event.security_relevant:
        status = Status.WATCH
        recommend = False
    else:
        status = Status.WATCH
        recommend = False

    if blocked and event.security_relevant and status in (Status.INVESTIGATE, Status.WATCH):
        status = Status.POLICY_BLOCKED
    return Lead(
        event=event,
        target=target,
        status=status,
        score=score,
        components=components,
        rationale=rationale,
        recommend=recommend,
        policy_blocked=blocked,
        block_reason=reason,
        known_issue=known,
    )
