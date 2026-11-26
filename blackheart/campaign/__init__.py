"""Continuous attack loop (mission section 10).

Ties the pieces together for a single engagement:

    threat model -> objectives -> attack surface -> chains -> adversarial tests
    -> stateful fuzzing -> exploit attempts -> minimisation -> verification
    -> impact -> report -> new hypotheses

The loop is *authorization-gated*: it refuses to run active stages unless the
engagement's asset is AUTHORIZED. It never fabricates a result: the outcome of
each stage is whatever the underlying engine returned.

Stage 12 (new hypothesis generation) is driven by the ledger: hypotheses already
classified FALSE_POSITIVE are not re-run, and remaining open hypotheses are
surfaced as the next work items.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from ..authz import AuthorizationError, assert_authorized
from ..chains import generate_chains
from ..doctrine import LIFECYCLE as _LIFECYCLE
from ..evidence import EvidenceStore
from ..ledger import EngagementLedger
from ..mindset import ATTACKER_QUESTION
from ..models import (
    AssetStatus,
    AttackChain,
    AuthorizationRecord,
    Classification,
    Finding,
    Objective,
    utcnow,
)
from ..objectives import TargetProfile, generate_objectives
from ..toolchain.enforce import ExecutionTarget, guarded
from ..verify import IndependentVerifier, VerificationContext

# The lifecycle names the campaign follows, taken from the doctrine so the
# artefact cannot drift from the operation's doctrine.
DOCTRINE_LIFECYCLE: tuple[str, ...] = tuple(p.name for p in _LIFECYCLE)


@dataclass
class CampaignResult:
    engagement: str
    target: str
    allowed: bool
    objectives: list[Objective] = field(default_factory=list)
    chains: list[AttackChain] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    next_hypotheses: list[str] = field(default_factory=list)
    blocked_reason: str = ""
    # The single question this campaign answers, recorded verbatim so the
    # engagement's own artefact states the mindset it was run under.
    question: str = ATTACKER_QUESTION
    # The doctrine the campaign was run under: the lifecycle it follows and the
    # hard rules it holds. Recorded on the artefact so an engagement is
    # self-describing and cannot drift from the operation's doctrine.
    doctrine_lifecycle: tuple[str, ...] = DOCTRINE_LIFECYCLE

    def to_dict(self) -> dict:
        return {
            "engagement": self.engagement,
            "target": self.target,
            "allowed": self.allowed,
            "blocked_reason": self.blocked_reason,
            "question": self.question,
            "doctrine_lifecycle": list(self.doctrine_lifecycle),
            "objectives": [o.to_dict() for o in self.objectives],
            "chains": [c.to_dict() for c in self.chains],
            "findings": [f.to_dict() for f in self.findings],
            "next_hypotheses": self.next_hypotheses,
        }


class Campaign:
    def __init__(
        self,
        engagement: str,
        profile: TargetProfile,
        authz_record: AuthorizationRecord,
        workdir: str | Path,
    ) -> None:
        self.engagement = engagement
        self.profile = profile
        self.authz = authz_record
        self.workdir = Path(workdir)
        self.workdir.mkdir(parents=True, exist_ok=True)
        self.evidence = EvidenceStore(self.workdir / "evidence")
        self.ledger = EngagementLedger(self.workdir / "ledger", engagement)
        self.verifier = IndependentVerifier()

    # ------------------------------------------------------------------ #
    def threat_model(self) -> list[Objective]:
        """Stage 1-2: generate attacker objectives before function review."""
        objectives = generate_objectives(self.profile)
        self.evidence.put_json(
            {
                "stage": "objectives",
                "profile": self.profile.__dict__,
                "objectives": [o.to_dict() for o in objectives],
            },
            kind="objectives",
            description=f"{self.engagement}: {len(objectives)} attacker objectives",
        )
        for o in objectives:
            self.ledger.add_hypothesis(o.obj_id, o.title, o.description)
        return objectives

    def build_chains(self, objectives: list[Objective]) -> list[AttackChain]:
        """Stage 4: construct multi-operation attack chains."""
        chains: list[AttackChain] = []
        disproven = self.ledger.disproven_hypotheses()
        for o in objectives:
            if o.obj_id in disproven:
                continue
            chains.extend(generate_chains(o, self.profile.kind))
        self.evidence.put_json(
            {"stage": "chains", "chains": [c.to_dict() for c in chains]},
            kind="chains",
            description=f"{self.engagement}: {len(chains)} attack chains",
        )
        return chains

    # ------------------------------------------------------------------ #
    def run_active(
        self,
        asset: str,
        finding: Optional[Finding] = None,
        verification_ctx: Optional[VerificationContext] = None,
        compatibility: object = None,
    ) -> CampaignResult:
        """Run the active stages, gated on authorization *and* compatibility.

        The caller supplies the concrete exploit attempt separately (a local
        harness run); this method enforces both gates, records the hypothesis, and
        runs independent verification on any candidate finding.
        """
        target = ExecutionTarget(
            name=asset,
            repository=str(getattr(self.profile, "repository", "") or ""),
            commit=str(getattr(self.profile, "commit", "") or ""),
        )
        with guarded(compatibility, target, "Campaign.run_active"):
            return self._run_active(asset, finding, verification_ctx)

    def _run_active(
        self,
        asset: str,
        finding: Optional[Finding] = None,
        verification_ctx: Optional[VerificationContext] = None,
    ) -> CampaignResult:
        result = CampaignResult(engagement=self.engagement, target=asset, allowed=False)

        try:
            assert_authorized(self.authz, asset)
        except AuthorizationError as exc:
            result.blocked_reason = str(exc)
            self.ledger.record_event(
                {"type": "blocked", "asset": asset, "reason": str(exc)}
            )
            return result

        result.allowed = True
        result.objectives = self.threat_model()
        result.chains = self.build_chains(result.objectives)

        if finding is not None and verification_ctx is not None:
            vr = self.verifier.verify(finding, verification_ctx)
            self.ledger.set_status(
                finding.finding_id,
                vr.classification,
                note=vr.notes,
            )
            self.evidence.put_json(
                vr.to_dict(), kind="verification",
                description=f"{self.engagement}: verification of {finding.finding_id}",
            )
            result.findings.append(finding)

        result.next_hypotheses = [h["id"] for h in self.ledger.open_hypotheses()]
        return result

    # ------------------------------------------------------------------ #
    def next_priorities(self) -> list[dict]:
        """Stage 12: surface remaining open hypotheses as next work items."""
        return sorted(
            self.ledger.open_hypotheses(),
            key=lambda h: h["id"],
        )

    def write_summary(self, result: CampaignResult) -> Path:
        path = self.workdir / f"{self.engagement}-campaign.json"
        path.write_text(json.dumps(result.to_dict(), indent=2, default=str), encoding="utf-8")
        return path
