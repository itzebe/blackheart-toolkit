"""Autonomous hypothesis engine (mission Part 3).

Given a target and the persistent research memory, this engine:

  1. understands the target (a :class:`TargetProfile` -- assets, entry points,
     trust boundaries, roles, dependencies),
  2. enumerates candidate vulnerability hypotheses from the objective catalogue
     and the attack-chain templates,
  3. retrieves the relevant prior successes *and* failures from the memory,
  4. scores each candidate on exploitability, potential impact, novelty,
     evidence quality, and authorized-testing feasibility,
  5. selects the next investigation automatically, and
  6. explains, in words, why it selected that one.

It never re-runs a hypothesis that the memory has already *disproven* -- unless
the caller supplies new evidence that changes the conditions (``new_evidence``),
which is the only legitimate reason to revisit a falsified idea.

Nothing here claims a vulnerability. It produces ranked *hypotheses*; proving one
is the exploit laboratory's job and falsifying it is the verifier's.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from ..chains import generate_chains
from ..exploit.toolselect import select_tools
from ..mindset import ATTACKER_QUESTION, apply_lens
from ..models import Objective
from ..objectives import TargetProfile, generate_objectives
from ..research import ResearchMemory
from ..threatmodel import ThreatModel, steer_objectives
from .surface import applicability, detect_surface


class ThreatModelIncomplete(RuntimeError):
    """Raised when hunting is attempted before the threat model is complete (P1)."""


# --------------------------------------------------------------------------- #
# Strategy
# --------------------------------------------------------------------------- #

# Default scoring weights (sum to 1.0). A Strategy carries its own weights so an
# improvement is a *value*, not a source edit -- the learning engine can propose,
# benchmark, and adopt one without rewriting this module (mission Phase 6).
DEFAULT_WEIGHTS = {
    "exploitability": 0.30,
    "impact": 0.30,
    "novelty": 0.15,
    "evidence": 0.15,
    "feasibility": 0.10,
}

# Backwards-compatible alias (older callers import WEIGHTS).
WEIGHTS = DEFAULT_WEIGHTS


@dataclass
class Strategy:
    """A named, benchmarkable hypothesis-ranking strategy.

    ``use_surface`` gates the target-surface applicability model: when True the
    engine multiplies each class score by how well the target actually exposes the
    surface that class requires. Baseline has it off; the learned improvement
    turns it on.
    """

    name: str
    weights: dict[str, float] = field(default_factory=lambda: dict(DEFAULT_WEIGHTS))
    use_surface: bool = False
    notes: str = ""

    def __post_init__(self) -> None:
        # A Strategy may carry a partial weight map (a candidate improvement, or
        # an old config). Fill any missing component from the defaults so scoring
        # never raises a KeyError on an incomplete proposal.
        merged = dict(DEFAULT_WEIGHTS)
        merged.update({k: v for k, v in self.weights.items() if k in DEFAULT_WEIGHTS})
        self.weights = merged

    def to_dict(self) -> dict:
        return {"name": self.name, "weights": dict(self.weights),
                "use_surface": self.use_surface, "notes": self.notes}


# The unmodified strategy (what shipped before the learning upgrade).
BASELINE_STRATEGY = Strategy("baseline-v0", dict(DEFAULT_WEIGHTS), use_surface=False)

# Category -> potential-impact score (0..1). Mirrors the objective catalogue's
# own prioritisation but expressed as a bounded score for ranking.
_IMPACT = {
    "asset-theft": 1.0,
    "unbacked-debt": 0.95,
    "accounting-manipulation": 0.9,
    "signature-bypass": 0.9,
    "replay-forgery": 0.85,
    "cryptographic-protocol": 0.95,
    "oracle-manipulation": 0.8,
    "cross-protocol-trust": 0.8,
    "liquidation-bypass": 0.75,
    "privilege-escalation": 0.8,
    "state-inconsistency": 0.7,
    "cross-contract": 0.7,
    "rounding-precision": 0.65,
    "auth-bypass": 0.8,
    "ordering-timing": 0.6,
    "info-disclosure": 0.5,
    "supply-chain": 0.7,
    "callback-reentrancy": 0.85,
    "access-control": 0.85,
}

# Category -> base exploitability (how readily an external attacker can reach it).
_EXPLOITABILITY = {
    "asset-theft": 0.85,
    "unbacked-debt": 0.8,
    "oracle-manipulation": 0.85,
    "replay-forgery": 0.8,
    "rounding-precision": 0.8,
    "signature-bypass": 0.7,
    "proxy-initializer": 0.85,
    "accounting-manipulation": 0.7,
    "liquidation-bypass": 0.7,
    "cross-protocol-trust": 0.6,
    "cross-contract": 0.6,
    "state-inconsistency": 0.65,
    "ordering-timing": 0.6,
    "privilege-escalation": 0.55,
    "auth-bypass": 0.7,
    "info-disclosure": 0.6,
    "cryptographic-protocol": 0.5,
    "supply-chain": 0.6,
    "callback-reentrancy": 0.8,
    "access-control": 0.9,
}


@dataclass
class Hypothesis:
    """A ranked candidate investigation."""

    hyp_id: str
    objective_id: str
    title: str
    category: str
    hypothesis: str
    chain_id: str = ""
    invariant: str = ""
    score: float = 0.0
    score_parts: dict[str, float] = field(default_factory=dict)
    rationale: str = ""
    prior_lessons: list[str] = field(default_factory=list)
    skipped_disproven: bool = False
    recommended_tools: list[str] = field(default_factory=list)
    control: str = ""
    # The attacker lens this hypothesis answers: the outcome it targets and the
    # levers it uses (blackheart.mindset). Carried through so the selected work
    # item states, in the engine's own words, which part of the question it answers.
    attacker_outcome: str = ""
    attacker_levers: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "hyp_id": self.hyp_id,
            "objective_id": self.objective_id,
            "title": self.title,
            "category": self.category,
            "hypothesis": self.hypothesis,
            "chain_id": self.chain_id,
            "invariant": self.invariant,
            "score": round(self.score, 4),
            "score_parts": {k: round(v, 4) for k, v in self.score_parts.items()},
            "rationale": self.rationale,
            "prior_lessons": self.prior_lessons,
            "skipped_disproven": self.skipped_disproven,
            "recommended_tools": self.recommended_tools,
            "control": self.control,
        }


def _novelty(category: str, target: str, memory: Optional[ResearchMemory]) -> float:
    """1.0 when nothing similar was tried; lower as prior work accumulates.

    Prior *confirmed* work on the same (target, class) reduces novelty most --
    the search should move on. Prior *disproven* work also reduces it (do not
    repeat), but a different class on the same target keeps its novelty.
    """
    if memory is None:
        return 1.0
    same = memory.search(target=target, vulnerability_class=category, limit=100)
    if not same:
        return 1.0
    confirmed = sum(1 for r in same if r.status == "CONFIRMED")
    disproven = sum(1 for r in same if r.status == "DISPROVEN")
    # Each prior record discounts novelty; confirmed work discounts it more.
    penalty = 0.25 * confirmed + 0.15 * disproven + 0.05 * (len(same) - confirmed - disproven)
    return max(0.05, 1.0 - penalty)


def _evidence_quality(category: str, target: str, memory: Optional[ResearchMemory]) -> float:
    """Higher when prior work in this class produced strong evidence.

    A class where prior attempts reached reproduction is more promising than one
    where every attempt ended with no evidence at all.
    """
    if memory is None:
        return 0.5
    same = memory.search(target=target, vulnerability_class=category, limit=100)
    if not same:
        return 0.5  # neutral: untried
    with_evidence = sum(1 for r in same if r.evidence_hashes)
    return 0.3 + 0.7 * (with_evidence / len(same))


def _feasibility(category: str, tools_available: Optional[set[str]]) -> float:
    """Authorized-testing feasibility: can we actually run the right tools here?"""
    plan = select_tools(category, available=tools_available)
    if tools_available is None:
        return 0.8  # unknown environment: assume reasonable
    total = len(plan.primary)
    if not total:
        return 0.5
    usable = total - len([t for t in plan.primary if t in plan.missing])
    return max(0.2, usable / total)


class HypothesisEngine:
    """Generates, ranks, and selects the next investigation."""

    def __init__(
        self,
        profile: TargetProfile,
        memory: Optional[ResearchMemory] = None,
        *,
        tools_available: Optional[set[str]] = None,
        strategy: Optional[Strategy] = None,
        threat_model: "Optional[ThreatModel]" = None,
    ) -> None:
        self.profile = profile
        self.memory = memory
        self.tools_available = tools_available
        self.strategy = strategy or BASELINE_STRATEGY
        self.surface = detect_surface(profile)
        # Protocol intelligence (P1): when a threat model is supplied, hunting is
        # gated on it and objectives are steered toward the selected impacts.
        self.threat_model = threat_model

    # ------------------------------------------------------------------ #
    def generate(self, *, new_evidence: bool = False) -> list[Hypothesis]:
        """Enumerate and rank candidate hypotheses (highest score first).

        A (target, class) pair already disproven is skipped unless
        ``new_evidence`` is True -- the one reason to revisit a falsified idea.

        When a threat model is attached, hunting is *gated* on it (P1): an
        incomplete model raises rather than silently proceeding with generic
        pattern-matching, and the objectives are re-ranked so the selected impacts
        are investigated first.
        """
        objectives = generate_objectives(self.profile)
        if self.threat_model is not None:
            gaps = self.threat_model.missing()
            if gaps:
                raise ThreatModelIncomplete(
                    "threat model is incomplete; resolve before hunting: "
                    + "; ".join(gaps)
                )
            objectives = steer_objectives(objectives, self.threat_model)
        disproven = self.memory.disproven_signatures() if self.memory else set()
        hyps: list[Hypothesis] = []

        for obj in objectives:
            chains = generate_chains(obj, self.profile.kind)
            if not chains:
                continue
            for chain in chains:
                hyp = self._score_hypothesis(obj, chain, disproven, new_evidence)
                hyps.append(hyp)

        hyps.sort(key=lambda h: (-h.score, h.hyp_id))
        return hyps

    # ------------------------------------------------------------------ #
    def _score_hypothesis(self, obj: Objective, chain, disproven, new_evidence) -> Hypothesis:
        cat = obj.category
        skipped = False
        if (self.profile.name, cat) in disproven and not new_evidence:
            skipped = True

        exploitability = _EXPLOITABILITY.get(cat, 0.5)
        impact = _IMPACT.get(cat, 0.5)
        novelty = _novelty(cat, self.profile.name, self.memory)
        evidence = _evidence_quality(cat, self.profile.name, self.memory)
        feasibility = _feasibility(cat, self.tools_available)

        parts = {
            "exploitability": exploitability,
            "impact": impact,
            "novelty": novelty,
            "evidence": evidence,
            "feasibility": feasibility,
        }
        weights = self.strategy.weights
        score = sum(weights[k] * v for k, v in parts.items())

        # Surface applicability (learned improvement): damp classes whose required
        # surface the target does not expose, boost those it does. Recorded in
        # score_parts so the rationale and the benchmark both see the multiplier.
        app = applicability(cat, self.surface)
        if self.strategy.use_surface:
            parts["surface"] = app.multiplier
            score *= app.multiplier

        if skipped:
            # Rank a disproven hypothesis last, but keep it visible so the reason
            # is transparent rather than silently dropped.
            score = 0.0

        lessons = (
            self.memory.lessons_for(target=self.profile.name, vulnerability_class=cat)
            if self.memory
            else []
        )
        plan = select_tools(cat, available=self.tools_available)

        # Apply the attacker lens: name the outcome this work targets and the
        # levers it uses, so the selected item is an answer to the mission question
        # (blackheart.mindset), not a generic class.
        lens = apply_lens(cat, texts=(obj.title, obj.description, obj.expected_invariant,
                                      chain.hypothesis, chain.title,
                                      *obj.attacker_capabilities))

        rationale = self._explain(obj, chain, parts, score, skipped, lessons, plan,
                                  weights, lens)
        return Hypothesis(
            hyp_id=chain.chain_id,
            objective_id=obj.obj_id,
            title=chain.title,
            category=cat,
            hypothesis=chain.hypothesis or obj.description,
            chain_id=chain.chain_id,
            invariant="; ".join(chain.invariants_targeted),
            score=score,
            score_parts=parts,
            rationale=rationale,
            prior_lessons=lessons,
            skipped_disproven=skipped,
            recommended_tools=plan.primary,
            control=plan.control,
            attacker_outcome=lens.outcome,
            attacker_levers=list(lens.levers),
        )

    # ------------------------------------------------------------------ #
    @staticmethod
    def _explain(obj, chain, parts, score, skipped, lessons, plan, weights, lens) -> str:
        if skipped:
            return (
                f"SKIPPED: the memory records this (target, class) as DISPROVEN; "
                f"revisit only with new evidence. Prior lessons: "
                f"{'; '.join(lessons) if lessons else 'none recorded'}."
            )
        drivers = ", ".join(
            f"{k}={v:.2f}" for k, v in sorted(
                ((k, v) for k, v in parts.items() if k != "surface"),
                key=lambda kv: -weights.get(kv[0], 0.0) * kv[1],
            )[:3]
        )
        base = (
            f"Answers the attacker question by targeting '{lens.outcome}' using "
            f"levers: {', '.join(lens.levers)}. "
            f"Selected because score={score:.3f}, driven by {drivers}. "
            f"Attack class '{obj.category}' via chain '{chain.chain_id}' "
            f"({len(chain.steps)} operations across {', '.join(chain.actors)}). "
            f"Tooling: {plan.summary()}."
        )
        if "surface" in parts:
            base += f" Surface factor x{parts['surface']:.2f}."
        if lessons:
            base += f" Applying {len(lessons)} prior lesson(s) for this class."
        return base

    # ------------------------------------------------------------------ #
    def select_next(self, *, new_evidence: bool = False) -> Optional[Hypothesis]:
        """Return the single highest-ranked, non-disproven hypothesis (or None)."""
        for hyp in self.generate(new_evidence=new_evidence):
            if not hyp.skipped_disproven:
                return hyp
        return None

    def explain_selection(self, *, new_evidence: bool = False) -> str:
        """Human-readable account of what would be investigated next and why."""
        hyps = self.generate(new_evidence=new_evidence)
        chosen = next((h for h in hyps if not h.skipped_disproven), None)
        lines = [f"Target: {self.profile.name} ({self.profile.kind})",
                 f"Question: {ATTACKER_QUESTION}",
                 f"Candidate hypotheses: {len(hyps)} "
                 f"({sum(1 for h in hyps if h.skipped_disproven)} skipped as disproven)", ""]
        if chosen is None:
            lines.append("No runnable hypothesis remains (all disproven or none generated).")
            return "\n".join(lines)
        lines.append(f"NEXT: {chosen.hyp_id}")
        lines.append(f"  answers: {chosen.attacker_outcome} "
                     f"(levers: {', '.join(chosen.attacker_levers)})")
        lines.append(chosen.rationale)
        if chosen.prior_lessons:
            lines.append("Prior lessons applied:")
            lines.extend(f"  - {l}" for l in chosen.prior_lessons)
        lines.append("")
        lines.append("Ranked (top 5):")
        for h in hyps[:5]:
            mark = " [disproven]" if h.skipped_disproven else ""
            lines.append(f"  {h.score:.3f}  {h.hyp_id}{mark}")
        return "\n".join(lines)
