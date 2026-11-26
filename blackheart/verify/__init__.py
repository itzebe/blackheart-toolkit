"""Independent verification agent (mission sections 2E, 8, 11).

This agent's job is to *challenge* a candidate finding, not to confirm it. It
applies the seven finding-quality gates and actively tries to disprove the
hypothesis by asking a fixed set of adversarial questions. A finding is only
classified CONFIRMED when every gate passes and every challenge is answered.

The gates mirror mission section 8 exactly:
  1 Reachability   2 Control   3 Defense bypass   4 Reproduction
  5 Impact         6 Independent verification   7 Scope

The verifier is intentionally independent of the exploit developer: it re-derives
its verdict from evidence, not from the developer's summary, and it may downgrade
a finding to NEEDS_MORE_EVIDENCE or FALSE_POSITIVE.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Optional

from ..models import (
    Classification,
    Finding,
    GateResult,
    GateStatus,
    ReviewIndependence,
    gate6_detail,
)


# --------------------------------------------------------------------------- #
# Adversarial challenges
# --------------------------------------------------------------------------- #

CHALLENGES = [
    ("missing-precondition", "Does the attack require a precondition that an attacker cannot obtain?"),
    ("unreachable", "Is the vulnerable operation unreachable in practice (dead code, guarded path)?"),
    ("existing-protection", "Does an existing protocol protection already prevent this?"),
    ("intentional", "Is the behaviour intentional and documented, so not a vulnerability?"),
    ("theoretical-only", "Is the impact merely theoretical, with no measurable consequence?"),
    ("duplicate-known", "Is this a duplicate of a previously known/disclosed issue?"),
    ("out-of-scope", "Is the target or affected component outside the current program scope?"),
    ("attacker-control", "Does the attacker actually control the required input/state/sequence?"),
    # Mission Phase 5 additions -- each is opt-in (only applied when the verifier
    # supplies the corresponding fact) so existing verdicts are unchanged.
    ("root-cause", "Is the stated root cause the real vulnerable mechanism, not a symptom?"),
    ("reproduction-integrity", "Does the secure control also 'reproduce', i.e. is the PoC actually discriminating?"),
    ("authorization-boundary", "Is the asset explicitly AUTHORIZED by the gate, not merely in scope?"),
    ("false-positive-explanation", "Is there a benign explanation for the observed behaviour?"),
]


@dataclass
class VerificationResult:
    finding_id: str
    classification: Classification
    gates: list[GateResult] = field(default_factory=list)
    challenges: dict[str, str] = field(default_factory=dict)  # challenge -> answer
    notes: str = ""
    review_independence: ReviewIndependence = ReviewIndependence.UNRECORDED

    def to_dict(self) -> dict:
        return {
            "finding_id": self.finding_id,
            "classification": self.classification.value,
            "gates": [g.to_dict() for g in self.gates],
            "challenges": self.challenges,
            "notes": self.notes,
            "review_independence": ReviewIndependence.coerce(
                self.review_independence
            ).value,
        }


# --------------------------------------------------------------------------- #
# Verification context: the evidence a verifier needs to adjudicate
# --------------------------------------------------------------------------- #

@dataclass
class VerificationContext:
    """Facts the verifier uses, each backed by an evidence id or a callable.

    ``reproduce`` is a zero-argument callable that re-runs the minimal PoC and
    returns True if the vulnerability is reproduced independently.

    The ``root_cause_established`` / ``control_reproduces`` /
    ``authorization_gate_passed`` / ``benign_explanation`` fields are the mission
    Phase 5 additions. They are opt-in: leaving them ``None`` preserves the
    original verdict exactly, so a caller that supplies them only tightens the
    verifier, never loosens it.
    """

    in_scope: Optional[bool] = None
    scope_reference: str = ""
    protection_exists: Optional[bool] = None
    behavior_intentional: Optional[bool] = None
    duplicate_known: Optional[bool] = None
    attacker_controls_input: Optional[bool] = None
    reachable: Optional[bool] = None
    measurable_impact: Optional[bool] = None
    reproduce: Optional[Callable[[], bool]] = None
    evidence_ids: list[str] = field(default_factory=list)
    # -- Phase 5 additions (opt-in) ------------------------------------- #
    root_cause_established: Optional[bool] = None
    # True when the *secure control* ALSO "reproduces" the attack, meaning the
    # PoC does not discriminate a real vulnerability from a benign behaviour.
    control_reproduces: Optional[bool] = None
    # True only when the authorization gate classifies the asset AUTHORIZED.
    authorization_gate_passed: Optional[bool] = None
    # True when a benign, non-security explanation accounts for the observation.
    benign_explanation: Optional[bool] = None
    # -- Reviewer provenance --------------------------------------------- #
    # How the adversarial review was performed. ``INDEPENDENT_MODEL`` only when a
    # separately authenticated model did it. A same-model review in a fresh
    # context is ``SAME_MODEL``: a real review, but never labelled independent.
    # ``UNRECORDED`` (the default) means the caller did not state it.
    review_independence: ReviewIndependence = ReviewIndependence.UNRECORDED


# --------------------------------------------------------------------------- #
# The verifier
# --------------------------------------------------------------------------- #

def _gate(number: int, name: str, ok: Optional[bool], detail: str) -> GateResult:
    if ok is None:
        return GateResult(number, name, GateStatus.UNKNOWN, detail or "not established")
    return GateResult(number, name, GateStatus.PASS if ok else GateStatus.FAIL, detail)


#: The gate-6 detail for each reviewer provenance lives with
#: :class:`ReviewIndependence` in :mod:`blackheart.models`, so the verifier that
#: writes the gate and every consumer that reads it share one definition.
def _reviewer_gate(independence) -> GateResult:
    """Gate 6 from the reviewer's actual provenance -- never an assumed one."""
    status, detail = gate6_detail(independence)
    return GateResult(6, "independent-verification", status, detail)


class IndependentVerifier:
    """Applies the seven gates and the adversarial challenges."""

    def verify(self, finding: Finding, ctx: VerificationContext) -> VerificationResult:
        challenges: dict[str, str] = {}

        # ---- Gate 1: reachability
        g1 = _gate(1, "reachability", ctx.reachable,
                   "vulnerable operation is reachable by an external caller" if ctx.reachable
                   else "reachability not demonstrated")
        challenges["unreachable"] = (
            "disproved: the path is reachable" if ctx.reachable
            else "NOT disproved: reachability is unproven"
        )

        # ---- Gate 2: control
        g2 = _gate(2, "control", ctx.attacker_controls_input,
                   "attacker controls the required input/state/sequence" if ctx.attacker_controls_input
                   else "attacker control of the trigger is not established")
        challenges["attacker-control"] = (
            "disproved: attacker controls the trigger" if ctx.attacker_controls_input
            else "NOT disproved: attacker control unproven"
        )

        # ---- Gate 3: defense bypass
        defense_ok = (ctx.protection_exists is False)
        g3 = _gate(3, "defense-bypass", defense_ok,
                   "no existing protection prevents the attack" if defense_ok
                   else ("an existing protection blocks the attack"
                         if ctx.protection_exists else "protections not enumerated"))
        challenges["existing-protection"] = (
            "no blocking protection found" if defense_ok
            else "protection exists or unknown"
        )
        challenges["intentional"] = (
            "behaviour is not documented as intentional"
            if ctx.behavior_intentional is False else
            ("behaviour is intentional" if ctx.behavior_intentional else "intentionality unknown")
        )
        if ctx.behavior_intentional:
            g3 = GateResult(3, "defense-bypass", GateStatus.FAIL,
                            "behaviour is intentional/documented, not a vulnerability")

        # ---- Gate 4: reproduction
        reproduced: Optional[bool] = None
        detail = "reproduction callable not provided"
        if ctx.reproduce is not None:
            try:
                reproduced = bool(ctx.reproduce())
                detail = ("independently reproduced the minimal PoC" if reproduced
                          else "independent reproduction failed")
            except Exception as exc:  # a PoC that errors is not a reproduction
                reproduced = False
                detail = f"reproduction raised: {exc}"
        g4 = _gate(4, "reproduction", reproduced, detail)
        challenges["theoretical-only"] = (
            "disproved: reproduced with a minimal PoC" if reproduced
            else "NOT disproved: reproduction not achieved"
        )

        # ---- Gate 5: impact
        g5 = _gate(5, "impact", ctx.measurable_impact,
                   "a concrete security property is violated with measurable consequence"
                   if ctx.measurable_impact else "impact not measured")

        # ---- Gate 6: verification, with the reviewer's provenance stated
        # This agent re-runs the PoC deterministically, so by default the review
        # is independent of the model that authored the claim. When the caller
        # says a *model* performed the review, the gate reports which kind: only
        # a separately authenticated model is independent verification. A
        # same-model review is real but is NOT independent, so it cannot pass
        # this gate -- that would be a fabricated claim of independence.
        g6 = _reviewer_gate(ctx.review_independence)

        # ---- Gate 7: scope
        g7 = _gate(7, "scope", ctx.in_scope,
                   f"in scope per {ctx.scope_reference}" if ctx.in_scope
                   else "scope not established")
        challenges["out-of-scope"] = (
            "in scope" if ctx.in_scope else "scope unproven or out of scope"
        )
        challenges["duplicate-known"] = (
            "not a known duplicate" if ctx.duplicate_known is False
            else ("known/disclosed duplicate" if ctx.duplicate_known else "duplicate status unknown")
        )
        challenges["missing-precondition"] = (
            "no unobtainable precondition identified" if (g1.status == GateStatus.PASS and g2.status == GateStatus.PASS)
            else "a precondition may be unobtainable"
        )

        # ---- Phase 5 challenges (opt-in: only recorded when the caller supplies
        # the corresponding fact, so existing verdicts are unchanged).
        if ctx.root_cause_established is not None:
            challenges["root-cause"] = (
                "the stated root cause is the real vulnerable mechanism"
                if ctx.root_cause_established
                else "NOT established: the root cause may be a symptom, not the mechanism"
            )
        if ctx.control_reproduces is not None:
            challenges["reproduction-integrity"] = (
                "FAILED: the secure control ALSO reproduces, so the PoC does not "
                "discriminate a vulnerability from benign behaviour"
                if ctx.control_reproduces
                else "the secure control does not reproduce; the PoC discriminates"
            )
        if ctx.authorization_gate_passed is not None:
            challenges["authorization-boundary"] = (
                "the asset is explicitly AUTHORIZED by the gate"
                if ctx.authorization_gate_passed
                else "the asset is NOT authorized by the gate; active testing must not proceed"
            )
        if ctx.benign_explanation is not None:
            challenges["false-positive-explanation"] = (
                "a benign explanation accounts for the observation"
                if ctx.benign_explanation
                else "no benign explanation found"
            )

        gates = [g1, g2, g3, g4, g5, g6, g7]

        # ---- Classification
        classification = self._classify(ctx, gates)

        result = VerificationResult(
            finding_id=finding.finding_id,
            classification=classification,
            gates=gates,
            challenges=challenges,
            notes=self._notes(classification, gates),
            review_independence=ReviewIndependence.coerce(ctx.review_independence),
        )
        # Attach back to the finding so it is serialisable as one artefact.
        finding.gates = gates
        finding.classification = classification
        finding.verification_notes = result.notes
        finding.review_independence = result.review_independence
        return result

    # ------------------------------------------------------------------ #
    @staticmethod
    def _classify(ctx: VerificationContext, gates: list[GateResult]) -> Classification:
        if ctx.in_scope is False:
            return Classification.OUT_OF_SCOPE
        # Phase 5 guards: an explicit authorization failure, a non-discriminating
        # PoC, or a benign explanation each downgrade -- these are hard facts that
        # no amount of gate-passing may override.
        if ctx.authorization_gate_passed is False:
            return Classification.OUT_OF_SCOPE
        if ctx.control_reproduces is True or ctx.benign_explanation is True:
            return Classification.FALSE_POSITIVE
        if ctx.duplicate_known is True:
            return Classification.DUPLICATE_OR_KNOWN
        if ctx.behavior_intentional is True:
            return Classification.INFORMATIONAL
        if ctx.reproduce is None and ctx.reachable is None:
            return Classification.NEEDS_MORE_EVIDENCE
        if ctx.root_cause_established is False:
            return Classification.NEEDS_MORE_EVIDENCE
        if all(g.status == GateStatus.PASS for g in gates):
            return Classification.CONFIRMED
        # Any explicit FAIL on a hard gate downgrades.
        failed = {g.gate for g in gates if g.status == GateStatus.FAIL}
        if failed & {1, 2, 3}:
            return Classification.FALSE_POSITIVE
        if failed & {4, 5, 7}:
            return Classification.NEEDS_MORE_EVIDENCE
        return Classification.NEEDS_MORE_EVIDENCE

    @staticmethod
    def _notes(classification: Classification, gates: list[GateResult]) -> str:
        unknown = [g.name for g in gates if g.status == GateStatus.UNKNOWN]
        failed = [g.name for g in gates if g.status == GateStatus.FAIL]
        parts = [f"classification={classification.value}"]
        if failed:
            parts.append("failed gates: " + ", ".join(failed))
        if unknown:
            parts.append("unestablished gates: " + ", ".join(unknown))
        return "; ".join(parts)


def confirm_requires_all_gates(finding: Finding) -> bool:
    """CONFIRMED is only valid when all seven gates passed."""
    return finding.gates_pass()
