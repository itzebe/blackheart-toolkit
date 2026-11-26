"""P2 -- Hypothesis generation engine.

P1 (`blackheart.threatmodel`) produces a *validated* threat model: the
architecture, the critical assets, the trust boundaries, the assumptions, and a
stated security invariant per asset. P2 is the next step in the mission's
research architecture: it turns that model into **specific, falsifiable attack
hypotheses** -- not a list of generic attack ideas.

The distinction the mission draws is the whole point of this module. A generic
idea ("there might be an access-control bug") is useless: it cannot be tested,
cannot be falsified, and cannot be told apart from a thousand others. A genuine
hypothesis names the component and the entry point it attacks, the capability the
attacker needs, the trust boundary it crosses, the asset it endangers, the exact
invariant it violates, the observable impact, the strategy and tools to try, and
-- critically -- what result would *prove it wrong*. Every hypothesis this engine
emits carries all of those, or it is not emitted.

What this module is not:

  * It is not a scanner. It never claims a vulnerability; it produces ranked,
    falsifiable *claims about intended behaviour* that the P3 investigation
    workflow then tries to break.
  * It is not a generic idea generator. Every field is derived from the model
    (component/asset/boundary/invariant) or from the vulnerability class's own
    attack template, and the strategy text is composed with the hypothesis's own
    specifics, so two hypotheses on different components read differently.

Safety properties enforced here, not by convention:

  * **An incomplete threat model is refused.** ``generate`` raises
    :class:`~blackheart.hypothesis.ThreatModelIncomplete` rather than inventing
    hypotheses against a model that has not stated what it is protecting.
  * **A hypothesis missing a required field is not emitted.** The required set
    mirrors the mission's list; :meth:`GeneratedHypothesis.missing_fields` is the
    gate and incomplete drafts are dropped with a reason.
  * **Nothing unverified is promoted.** A generated hypothesis is a lead; the P3
    workflow and the independent verifier decide its fate. Rejected hypotheses
    are *preserved with their reason*, never deleted, so the same dead end is not
    re-explored.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Iterable, Optional

from ..exploit.toolselect import select_tools
from ..mindset import apply_lens
from ..models import utcnow
from ..objectives import TargetProfile
from ..research import ResearchMemory
from ..threatmodel import IMPACT_CATALOG, ThreatModel
from . import (
    _EXPLOITABILITY,
    _IMPACT,
    ThreatModelIncomplete,
)


# --------------------------------------------------------------------------- #
# Ranking weights
# --------------------------------------------------------------------------- #

# Explainable criteria the mission names. Each component is a "goodness" score in
# [0, 1]; ``research_cost`` is inverted into ``cost_efficiency`` so every term
# points the same way. The weights are a reviewable value, not a source constant
# the learning engine must edit (mission Phase 6).
DEFAULT_GENERATION_WEIGHTS = {
    "impact": 0.30,
    "exploitability": 0.25,
    "evidence": 0.20,
    "feasibility": 0.15,
    "cost_efficiency": 0.10,
}


# --------------------------------------------------------------------------- #
# Attack-strategy templates, by vulnerability class
# --------------------------------------------------------------------------- #

# Each template is composed with the hypothesis's own component / entry point /
# invariant, so the strategy is specific to the hypothesis rather than generic.
# ``repro`` and ``falsify`` state what a reproduction looks like and what would
# prove the hypothesis wrong -- the two things that make it a *falsifiable* claim.
@dataclass(frozen=True)
class StrategyTemplate:
    strategy: str
    repro: str
    falsify: str


_TEMPLATES: dict[str, StrategyTemplate] = {
    "access-control": StrategyTemplate(
        strategy=(
            "Invoke {entry_point} directly from an actor that holds none of the "
            "privileged roles and assert that {component}'s protected state changes."
        ),
        repro=(
            "An unprivileged call to {entry_point} on {component} mutates the state "
            "guarded by invariant {invariant}."
        ),
        falsify=(
            "The call reverts, or the state guarded by {invariant} is unchanged, for "
            "every non-privileged actor -- i.e. an authorization check the model did "
            "not record does gate {entry_point}."
        ),
    ),
    "callback-reentrancy": StrategyTemplate(
        strategy=(
            "Re-enter {entry_point} on {component} from the external callback before "
            "the first call commits its state, and observe whether {invariant} holds "
            "at the re-entry point."
        ),
        repro=(
            "A single transaction that calls {entry_point} and re-enters it from the "
            "callback leaves {invariant} false at the end of the outer call."
        ),
        falsify=(
            "State is committed (checks-effects-interactions) before the callback, so "
            "the re-entrant call observes consistent state and {invariant} holds."
        ),
    ),
    "accounting-manipulation": StrategyTemplate(
        strategy=(
            "Drive {component} through a sequence that changes its accounting inputs "
            "({entry_point}) without a matching change to its obligations, and check "
            "{invariant} after each step."
        ),
        repro=(
            "A concrete operation sequence reaches a state where {invariant} is false "
            "and a measurable value (shares, debt, redeemable assets) is wrong."
        ),
        falsify=(
            "Every reachable state keeps {invariant} true -- the accounting is "
            "internally consistent under all tested sequences."
        ),
    ),
    "rounding-precision": StrategyTemplate(
        strategy=(
            "Exercise {entry_point} on {component} with adversarial values (1 wei, "
            "max, off-by-one) across deposit/withdraw or borrow/repay and check "
            "{invariant} for a profitable rounding direction."
        ),
        repro=(
            "A value/rounding pair makes a participant gain value at another's "
            "expense, violating {invariant}."
        ),
        falsify=(
            "Rounding always favours the protocol or is exact; {invariant} holds for "
            "all boundary values tested."
        ),
    ),
    "oracle-manipulation": StrategyTemplate(
        strategy=(
            "Move {component}'s price input via {entry_point} within one transaction "
            "and act on the manipulated price before it is restored, testing whether "
            "{invariant} still holds."
        ),
        repro=(
            "A flash-loan-sized move of the price input lets the attacker extract "
            "value, breaking {invariant}."
        ),
        falsify=(
            "The price input is manipulation-resistant (TWAP, multiple sources, "
            "sanity bounds) so {invariant} holds under the same move."
        ),
    ),
    "signature-bypass": StrategyTemplate(
        strategy=(
            "Submit a signature that should be invalid (wrong signer, malleable s, "
            "wrong domain, reused nonce) to {entry_point} on {component} and check "
            "whether {invariant} is enforced."
        ),
        repro=(
            "An invalid signature is accepted and the authorized action completes, "
            "violating {invariant}."
        ),
        falsify=(
            "Every invalid signature is rejected (canonicalisation, domain binding, "
            "nonce) so {invariant} holds."
        ),
    ),
    "replay-forgery": StrategyTemplate(
        strategy=(
            "Replay a previously-valid message/authorization against {entry_point} on "
            "{component} (same chain, same domain) and check {invariant}."
        ),
        repro=(
            "The same authorization is accepted twice, violating {invariant}."
        ),
        falsify=(
            "Each authorization is single-use bound (nonce/commitment), so the second "
            "use is rejected and {invariant} holds."
        ),
    ),
    "state-inconsistency": StrategyTemplate(
        strategy=(
            "Reach a partially-updated state on {component} via {entry_point} and "
            "observe whether {invariant} is momentarily or permanently false."
        ),
        repro=(
            "An operation sequence leaves {component} in a state where {invariant} is "
            "false and a later operation behaves incorrectly as a result."
        ),
        falsify=(
            "Updates are atomic; {invariant} holds at every observable point."
        ),
    ),
    "cross-protocol-trust": StrategyTemplate(
        strategy=(
            "Have {component} consume a value produced by an external component via "
            "{entry_point} and check whether {invariant} still holds when that value "
            "is adversarial."
        ),
        repro=(
            "An external component returns a value the target trusts without "
            "validation, breaking {invariant}."
        ),
        falsify=(
            "The external value is validated/bounded before use, so {invariant} holds."
        ),
    ),
    "privilege-escalation": StrategyTemplate(
        strategy=(
            "Reach a privileged state on {component} from a low-privilege actor via "
            "{entry_point} and check whether {invariant} is enforced."
        ),
        repro=(
            "A low-privilege actor gains a role/capability it should not have, "
            "violating {invariant}."
        ),
        falsify=(
            "Every path to the privileged state is gated by the recorded role, so "
            "{invariant} holds."
        ),
    ),
    "asset-theft": StrategyTemplate(
        strategy=(
            "Drive {component} to release or misattribute an asset via {entry_point} "
            "without a matching right, and check {invariant}."
        ),
        repro=(
            "Value leaves {component} to an actor with no right to it, violating "
            "{invariant}."
        ),
        falsify=(
            "Every release is guarded by a solvency/authorization check, so {invariant} "
            "holds."
        ),
    ),
    "liquidation-bypass": StrategyTemplate(
        strategy=(
            "Bring {component} to a state that should be liquidatable (or should not) "
            "via {entry_point} and check whether {invariant} is enforced."
        ),
        repro=(
            "An account that should be liquidatable is not (or vice versa), violating "
            "{invariant}."
        ),
        falsify=(
            "The liquidation condition matches the recorded invariant under all "
            "reachable states."
        ),
    ),
    "ordering-timing": StrategyTemplate(
        strategy=(
            "Exploit ordering on {component} via {entry_point} (front-run / deadline / "
            "block-timestamp dependency) and check {invariant}."
        ),
        repro=(
            "A chosen ordering makes {invariant} false and benefits the attacker."
        ),
        falsify=(
            "The outcome is ordering-independent, so {invariant} holds regardless of "
            "transaction order."
        ),
    ),
}

# Fallback for a class the table does not name: still specific (it names the
# component, entry point, and invariant), just less prescriptive about the move.
_FALLBACK_TEMPLATE = StrategyTemplate(
    strategy=(
        "Attempt the '{category}' attack against {component} through {entry_point} "
        "and check whether {invariant} holds."
    ),
    repro=(
        "A concrete, reproducible input or sequence makes {invariant} false on "
        "{component} with a measurable consequence."
    ),
    falsify=(
        "The property {invariant} holds under all tested inputs/sequences, or the "
        "component is not reachable by the stated attacker."
    ),
)


def _template(category: str) -> StrategyTemplate:
    return _TEMPLATES.get(category, _FALLBACK_TEMPLATE)


# --------------------------------------------------------------------------- #
# The hypothesis record
# --------------------------------------------------------------------------- #

# The mission's required field set. A hypothesis missing any of these is not
# emitted (it is recorded as a dropped draft with the reason).
REQUIRED_FIELDS = (
    "component",
    "entry_point",
    "attacker_capability",
    "trust_boundary",
    "critical_asset",
    "invariant",
    "expected_impact",
    "strategy",
    "reproduction_criteria",
    "falsification_criteria",
    "authorization_requirement",
    "novelty_requirement",
)


@dataclass
class GeneratedHypothesis:
    """A specific, falsifiable attack hypothesis derived from a threat model.

    Every field the mission requires is present. ``score_parts`` records the
    explainable ranking inputs so a reviewer can see *why* it ranked where it did,
    and ``rationale`` states the reasoning in words.
    """

    hyp_id: str
    objective_id: str
    title: str
    category: str
    # -- the mission's required associations ---------------------------------
    component: str
    entry_point: str
    attacker_capability: str
    prerequisites: list[str] = field(default_factory=list)
    trust_boundary: str = ""
    critical_asset: str = ""
    invariant: str = ""
    invariant_id: str = ""
    chain_invariant: str = ""
    expected_impact: str = ""
    impact_id: str = ""
    # The attacker lens this hypothesis answers (blackheart.mindset): the outcome
    # it targets and the levers it uses. Every P2 hypothesis states, in the
    # engine's own words, which part of the mission question it addresses.
    attacker_outcome: str = ""
    attacker_levers: list[str] = field(default_factory=list)
    strategy: str = ""
    required_tools: list[str] = field(default_factory=list)
    reproduction_criteria: str = ""
    falsification_criteria: str = ""
    authorization_requirement: str = ""
    novelty_requirement: str = ""
    # -- ranking --------------------------------------------------------------
    score: float = 0.0
    score_parts: dict[str, float] = field(default_factory=dict)
    rationale: str = ""
    research_cost: float = 0.0
    # -- lifecycle ------------------------------------------------------------
    status: str = "ACTIVE"            # ACTIVE | REJECTED
    rejection_reason: str = ""
    duplicate_of: str = ""
    overlaps: list[str] = field(default_factory=list)
    prior_lessons: list[str] = field(default_factory=list)
    contradicts: str = ""             # id of a hypothesis this one replaces
    created_at: str = field(default_factory=utcnow)

    # ------------------------------------------------------------------ #
    def missing_fields(self) -> list[str]:
        """Return the required fields that are absent or blank."""
        gaps: list[str] = []
        for name in REQUIRED_FIELDS:
            value = getattr(self, name, "")
            if value is None or (isinstance(value, str) and not value.strip()):
                gaps.append(name)
        return gaps

    def is_complete(self) -> bool:
        return not self.missing_fields()

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class RejectionRecord:
    """A hypothesis that was generated but deliberately not pursued, with why.

    Preserving these is a mission requirement: a rejected hypothesis and its
    reason is knowledge -- it stops the next cycle from re-deriving the same dead
    end.
    """

    hyp_id: str
    title: str
    category: str
    component: str
    reason: str
    reason_kind: str = "rejected"     # rejected | duplicate | incomplete | out-of-scope
    at: str = field(default_factory=utcnow)

    def to_dict(self) -> dict:
        return asdict(self)


# --------------------------------------------------------------------------- #
# Scoring
# --------------------------------------------------------------------------- #

def _research_cost(chain_steps: int, missing: int, total_tools: int, has_prior: bool) -> float:
    """A bounded cost estimate: longer chains and unavailable tools cost more.

    Cost is *reduced* when prior work in the class means we already know how to
    test it -- familiarity lowers the cost of the next attempt.
    """
    cost = 0.30
    cost += min(0.30, 0.10 * max(0, chain_steps - 2))
    if total_tools:
        cost += 0.30 * (missing / total_tools)
    if has_prior:
        cost -= 0.15
    return max(0.0, min(1.0, cost))


def _evidence_strength(category: str, target: str, memory: Optional[ResearchMemory]) -> float:
    """How much prior evidence exists for this class on this target (0..1)."""
    if memory is None:
        return 0.5
    same = memory.search(target=target, vulnerability_class=category, limit=100)
    if not same:
        return 0.5
    with_evidence = sum(1 for r in same if r.evidence_hashes)
    return 0.3 + 0.7 * (with_evidence / len(same))


# --------------------------------------------------------------------------- #
# The generator
# --------------------------------------------------------------------------- #

class HypothesisGenerator:
    """Turn a validated threat model into ranked, falsifiable hypotheses.

    The generator is deterministic given the same (model, profile, memory,
    tools): hypotheses are produced in a stable order and given stable ids, so a
    stored generation can be re-derived and compared.
    """

    def __init__(
        self,
        threat_model: ThreatModel,
        profile: TargetProfile,
        *,
        memory: Optional[ResearchMemory] = None,
        tools_available: Optional[set[str]] = None,
        weights: Optional[dict[str, float]] = None,
        scope_reference: str = "",
    ) -> None:
        self.threat_model = threat_model
        self.profile = profile
        self.memory = memory
        self.tools_available = tools_available
        self.weights = {**DEFAULT_GENERATION_WEIGHTS, **(weights or {})}
        self.scope_reference = scope_reference

    # ------------------------------------------------------------------ #
    def generate(self, *, objective_ids: Optional[Iterable[str]] = None) -> "GenerationResult":
        """Produce the ranked hypothesis set, duplicates, and rejections.

        Raises :class:`ThreatModelIncomplete` if the model has not stated what it
        protects -- generating attack hypotheses against an unvalidated model is
        exactly the generic-pattern-matching failure the mission warns about.
        """
        from ..objectives import generate_objectives

        gaps = self.threat_model.missing()
        if gaps:
            raise ThreatModelIncomplete(
                "cannot generate hypotheses from an incomplete threat model; "
                "resolve before hunting: " + "; ".join(gaps)
            )

        wanted = set(objective_ids) if objective_ids else None
        objectives = generate_objectives(self.profile)
        # Impact steering (P1): investigate the impacts the researcher selected first.
        from ..threatmodel import steer_objectives

        objectives = steer_objectives(objectives, self.threat_model)

        drafts: list[GeneratedHypothesis] = []
        rejections: list[RejectionRecord] = []

        for obj in objectives:
            if wanted is not None and obj.obj_id not in wanted:
                continue
            for hyp in self._hypotheses_for_objective(obj):
                gaps_h = hyp.missing_fields()
                if gaps_h:
                    rejections.append(
                        RejectionRecord(
                            hyp_id=hyp.hyp_id, title=hyp.title, category=hyp.category,
                            component=hyp.component, reason_kind="incomplete",
                            reason=(
                                "hypothesis is missing required field(s): "
                                + ", ".join(gaps_h)
                            ),
                        )
                    )
                    continue
                drafts.append(hyp)

        deduped, duplicates, overlaps = self._deduplicate(drafts)
        rejections.extend(duplicates)
        for hyp in deduped:
            hyp.overlaps = overlaps.get(hyp.hyp_id, [])

        # Learning from the store: a (component, class) the memory already records
        # as CONFIRMED is not worth re-hunting -- it is a known bug, not a new lead.
        # This is how a later cycle *changes* its selection based on stored results.
        kept: list[GeneratedHypothesis] = []
        for hyp in deduped:
            if self._already_confirmed(hyp):
                hyp.status = "REJECTED"
                rejections.append(RejectionRecord(
                    hyp_id=hyp.hyp_id, title=hyp.title, category=hyp.category,
                    component=hyp.component, reason_kind="rejected",
                    reason=(
                        f"already CONFIRMED for '{hyp.component}' in a prior cycle; "
                        f"re-hunting a known bug is not novel -- move to another class"
                    ),
                ))
                continue
            kept.append(hyp)

        kept.sort(key=lambda h: (-h.score, h.hyp_id))
        return GenerationResult(
            target=self.threat_model.target,
            threat_model_revision=self.threat_model.revision,
            hypotheses=kept,
            rejections=rejections,
            generated_at=utcnow(),
        )

    def _already_confirmed(self, hyp: GeneratedHypothesis) -> bool:
        if self.memory is None:
            return False
        for rec in self.memory.confirmed():
            if (rec.vulnerability_class == hyp.category
                    and rec.target in (hyp.component, self.profile.name)):
                return True
        return False

    # ------------------------------------------------------------------ #
    def _hypotheses_for_objective(self, obj) -> list[GeneratedHypothesis]:
        """Build one specific hypothesis per (objective, chain)."""
        from ..chains import generate_chains

        chains = generate_chains(obj, self.profile.kind)
        out: list[GeneratedHypothesis] = []
        for chain in chains:
            out.append(self._build(obj, chain))
        return out

    def _build(self, obj, chain) -> GeneratedHypothesis:
        cat = obj.category
        component = self._component(obj, chain)
        entry_point = (obj.entry_points or self.threat_model.architecture or [component])[0]
        attacker = "; ".join(obj.attacker_capabilities) or (
            "; ".join(chain.actors) or "unprivileged external actor"
        )
        boundary = (obj.trust_boundaries or self.profile.trust_boundaries or [""])[0]
        asset = (obj.assets_at_risk or self.threat_model.critical_assets or [""])[0]
        inv_id, invariant = self._invariant_for(asset, cat)
        chain_invariant = (chain.invariants_targeted or [obj.expected_invariant or ""])[0]
        impact_id, impact_text = self._impact_for(cat)

        tpl = _template(cat)
        fmt = {
            "component": component,
            "entry_point": entry_point,
            "invariant": invariant or "(invariant to be named)",
            "category": cat,
        }
        strategy = tpl.strategy.format(**fmt)
        repro = tpl.repro.format(**fmt)
        falsify = tpl.falsify.format(**fmt)

        plan = select_tools(cat, available=self.tools_available)
        missing = len(plan.missing)
        total = len(plan.primary) + len(plan.secondary)
        prior = bool(self.memory and self.memory.search(
            target=self.profile.name, vulnerability_class=cat, limit=1
        ))
        cost = _research_cost(len(chain.steps), missing, total, prior)

        # Apply the attacker lens so the strategy states which part of the mission
        # question this hypothesis answers and which levers it uses.
        lens = apply_lens(cat, texts=(obj.title, obj.description, chain.title,
                                      chain.hypothesis, strategy, invariant,
                                      *obj.attacker_capabilities))
        strategy = (
            f"[attacker lens -- outcome: {lens.outcome}; "
            f"levers: {', '.join(lens.levers)}] {strategy}"
        )

        hyp = GeneratedHypothesis(
            hyp_id=f"P2-{obj.obj_id}-{chain.chain_id}",
            objective_id=obj.obj_id,
            title=chain.title or obj.title,
            category=cat,
            component=component,
            entry_point=entry_point,
            attacker_capability=attacker,
            prerequisites=list(obj.preconditions) or list(chain.actors),
            trust_boundary=boundary,
            critical_asset=asset,
            invariant=invariant,
            invariant_id=inv_id,
            chain_invariant=chain_invariant,
            expected_impact=impact_text,
            impact_id=impact_id,
            attacker_outcome=lens.outcome,
            attacker_levers=list(lens.levers),
            strategy=strategy,
            required_tools=plan.primary,
            reproduction_criteria=repro,
            falsification_criteria=falsify,
            authorization_requirement=self._authorization_requirement(asset),
            novelty_requirement=(
                "Before this hypothesis may be treated as submission-ready, a "
                "NoveltyReview must classify it LIKELY_NEW or POSSIBLE_VARIANT "
                "(blackheart.novelty). A strong PoC does not establish originality."
            ),
            research_cost=cost,
        )
        self._score(hyp)
        hyp.prior_lessons = (
            self.memory.lessons_for(target=self.profile.name, vulnerability_class=cat)
            if self.memory else []
        )
        hyp.rationale = self._explain(hyp, plan, prior)
        return hyp

    # ------------------------------------------------------------------ #
    def _component(self, obj, chain) -> str:
        """Name the *real* component this hypothesis attacks.

        The threat model's architecture is the target-specific truth; a chain's
        ``contracts_involved`` are template placeholders (e.g. "aToken"/"wrapper")
        and must not be presented as this target's components. Preference order:
        an architecture element the objective's entry points belong to, then the
        first architecture element, then the chain's placeholder, then the
        profile's name. The choice is recorded, never silently generic.
        """
        arch = self.threat_model.architecture
        if arch:
            for element in arch:
                token = element.lower()
                if any(token in ep.lower() or ep.lower() in token for ep in obj.entry_points):
                    return element
            return arch[0]
        if chain.contracts_involved:
            return chain.contracts_involved[0]
        if obj.entry_points:
            return obj.entry_points[0]
        return self.profile.name

    def _invariant_for(self, asset: str, category: str) -> tuple[str, str]:
        """Choose the stated invariant this hypothesis attacks.

        The threat model's stated invariant for the endangered asset is
        authoritative -- it is what the researcher declared must hold. Preference:
        a model invariant that applies to the asset, then any model invariant,
        then a chain-template invariant. Returns ``(invariant_id, statement)``;
        the id is blank when only a template invariant is available, so nothing
        pretends a template property is one the researcher stated.
        """
        invs = self.threat_model.invariants
        for inv in invs:
            if asset and asset in inv.applies_to:
                return inv.inv_id, inv.statement
        if invs:
            return invs[0].inv_id, invs[0].statement
        return "", ""

    def _impact_for(self, category: str) -> tuple[str, str]:
        """Map a vulnerability class to a selected impact id + consequence text.

        The mapping is derived from the model's own selected impacts so a
        hypothesis is only credited with an impact the researcher said matters.
        """
        from ..threatmodel import _IMPACT_TO_CATEGORIES  # reuse the P1 table

        for impact_id in self.threat_model.selected_impacts:
            if category in _IMPACT_TO_CATEGORIES.get(impact_id, set()):
                meta = IMPACT_CATALOG[impact_id]
                return impact_id, f"{meta['title']}: {meta['consequence']}"
        # No selected impact maps to this class: name it honestly rather than
        # borrowing a consequence the researcher did not select.
        return "", f"unclassified for this target (class '{category}'); impact not among selected"

    def _authorization_requirement(self, asset: str) -> str:
        scope = self.scope_reference or "(scope reference to be recorded)"
        return (
            f"Active testing requires the authorization gate to classify "
            f"'{asset}' AUTHORIZED against {scope} (blackheart.authz); an UNKNOWN "
            f"or OUT_OF_SCOPE asset must not be tested."
        )

    def _score(self, hyp: GeneratedHypothesis) -> None:
        impact = _IMPACT.get(hyp.category, 0.5)
        exploitability = _EXPLOITABILITY.get(hyp.category, 0.5)
        evidence = _evidence_strength(hyp.category, self.profile.name, self.memory)
        plan = select_tools(hyp.category, available=self.tools_available)
        if self.tools_available is None:
            feasibility = 0.8
        else:
            total = len(plan.primary)
            usable = total - len([t for t in plan.primary if t in plan.missing])
            feasibility = max(0.2, usable / total) if total else 0.5
        cost_efficiency = 1.0 - hyp.research_cost

        parts = {
            "impact": impact,
            "exploitability": exploitability,
            "evidence": evidence,
            "feasibility": feasibility,
            "cost_efficiency": cost_efficiency,
        }
        hyp.score_parts = parts
        hyp.score = sum(self.weights[k] * v for k, v in parts.items())

    @staticmethod
    def _explain(hyp: GeneratedHypothesis, plan, prior: bool) -> str:
        parts = hyp.score_parts
        drivers = ", ".join(
            f"{k}={v:.2f}" for k, v in sorted(parts.items(), key=lambda kv: -kv[1])[:3]
        )
        line = (
            f"score={hyp.score:.3f} (driven by {drivers}). Answers the attacker "
            f"question by targeting '{hyp.attacker_outcome}' via levers: "
            f"{', '.join(hyp.attacker_levers)}. Attacks '{hyp.component}' "
            f"via '{hyp.entry_point}' across the trust boundary '{hyp.trust_boundary}', "
            f"endangering '{hyp.critical_asset}', by violating invariant "
            f"'{hyp.invariant}'. Research cost estimate {hyp.research_cost:.2f}. "
            f"Tooling: {plan.summary()}."
        )
        if prior:
            line += " Prior work exists in this class; cost is reduced."
        return line

    # ------------------------------------------------------------------ #
    # De-duplication and overlap
    # ------------------------------------------------------------------ #
    @staticmethod
    def _deduplicate(
        drafts: list[GeneratedHypothesis],
    ) -> tuple[list[GeneratedHypothesis], list[RejectionRecord], dict[str, list[str]]]:
        """Collapse duplicates and mark overlapping hypotheses.

        Two hypotheses are **duplicates** when they share the same root cause --
        the same (component, category, invariant) triple. This mirrors the
        novelty gate's rule that the same root cause on the same component is the
        same bug however it is exploited. They **overlap** when they share a
        component and class but target a different invariant (related leads, kept
        but linked).
        """
        kept: list[GeneratedHypothesis] = []
        duplicates: list[RejectionRecord] = []
        seen: dict[tuple[str, str, str], GeneratedHypothesis] = {}
        overlaps: dict[str, list[str]] = {}

        # Deterministic: process by descending score so the best-ranked survives.
        for hyp in sorted(drafts, key=lambda h: (-h.score, h.hyp_id)):
            key = (hyp.component.lower(), hyp.category, hyp.invariant.lower())
            if key in seen:
                original = seen[key]
                hyp.status = "REJECTED"
                hyp.duplicate_of = original.hyp_id
                duplicates.append(
                    RejectionRecord(
                        hyp_id=hyp.hyp_id, title=hyp.title, category=hyp.category,
                        component=hyp.component, reason_kind="duplicate",
                        reason=(
                            f"duplicate of {original.hyp_id}: same component "
                            f"'{hyp.component}', class '{hyp.category}', and invariant "
                            f"'{hyp.invariant}'"
                        ),
                    )
                )
                continue
            seen[key] = hyp
            kept.append(hyp)

        # Overlap: same (component, category), different invariant.
        by_comp_cat: dict[tuple[str, str], list[str]] = {}
        for hyp in kept:
            by_comp_cat.setdefault((hyp.component.lower(), hyp.category), []).append(hyp.hyp_id)
        for hyp in kept:
            siblings = [
                h for h in by_comp_cat[(hyp.component.lower(), hyp.category)]
                if h != hyp.hyp_id
            ]
            if siblings:
                overlaps[hyp.hyp_id] = sorted(siblings)
        return kept, duplicates, overlaps


# --------------------------------------------------------------------------- #
# Result + persistence
# --------------------------------------------------------------------------- #

@dataclass
class GenerationResult:
    target: str
    threat_model_revision: str
    hypotheses: list[GeneratedHypothesis]
    rejections: list[RejectionRecord] = field(default_factory=list)
    generated_at: str = field(default_factory=utcnow)

    def active(self) -> list[GeneratedHypothesis]:
        return [h for h in self.hypotheses if h.status == "ACTIVE"]

    def select_next(self) -> Optional[GeneratedHypothesis]:
        """The single highest-ranked active hypothesis (or None)."""
        actives = self.active()
        return actives[0] if actives else None

    def summary(self) -> dict:
        return {
            "target": self.target,
            "threat_model_revision": self.threat_model_revision,
            "hypotheses": len(self.hypotheses),
            "active": len(self.active()),
            "rejected": len(self.rejections),
            "generated_at": self.generated_at,
        }

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "threat_model_revision": self.threat_model_revision,
            "generated_at": self.generated_at,
            "hypotheses": [h.to_dict() for h in self.hypotheses],
            "rejections": [r.to_dict() for r in self.rejections],
        }


class HypothesisStore:
    """Append-only persistence for generation runs (mission: preserve rejections).

    The store keeps every generation run, every hypothesis, and every rejection
    with its reason, so a later cycle can retrieve what was already considered and
    why it was set aside. It is JSONL, so a crash or a new sandbox loses nothing.
    """

    def __init__(self, root: str | Path, name: str = "hypotheses") -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.path = self.root / f"{name}.jsonl"

    def _append(self, event: dict) -> None:
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps({"at": utcnow(), **event}, default=str) + "\n")

    def save(self, result: GenerationResult) -> None:
        self._append({
            "type": "generation",
            "target": result.target,
            "threat_model_revision": result.threat_model_revision,
            "generated_at": result.generated_at,
            "hypotheses": [h.to_dict() for h in result.hypotheses],
            "rejections": [r.to_dict() for r in result.rejections],
        })

    def _events(self) -> list[dict]:
        if not self.path.exists():
            return []
        return [
            json.loads(line)
            for line in self.path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]

    def hypotheses(self) -> list[GeneratedHypothesis]:
        out: list[GeneratedHypothesis] = []
        for ev in self._events():
            if ev.get("type") == "generation":
                for h in ev.get("hypotheses", []):
                    known = {f for f in GeneratedHypothesis.__dataclass_fields__}
                    out.append(GeneratedHypothesis(**{k: v for k, v in h.items() if k in known}))
        return out

    def rejections(self) -> list[RejectionRecord]:
        out: list[RejectionRecord] = []
        for ev in self._events():
            if ev.get("type") == "generation":
                for r in ev.get("rejections", []):
                    out.append(RejectionRecord(**r))
        return out

    def find(self, hyp_id: str) -> Optional[GeneratedHypothesis]:
        return next((h for h in self.hypotheses() if h.hyp_id == hyp_id), None)

    def already_rejected(self, *, component: str, category: str) -> Optional[RejectionRecord]:
        """Has this (component, class) already been rejected? If so, return why.

        This is what lets a later cycle *learn*: it does not re-derive a dead end.
        """
        for r in self.rejections():
            if r.component.lower() == component.lower() and r.category == category:
                return r
        return None


# --------------------------------------------------------------------------- #
# Alternatives on contradiction (mission: "generate alternatives when evidence
# contradicts the original")
# --------------------------------------------------------------------------- #

def alternatives(
    original: GeneratedHypothesis,
    contradiction: str,
    generator: HypothesisGenerator,
) -> list[GeneratedHypothesis]:
    """Generate hypotheses that replace ``original`` after evidence contradicts it.

    The replacement keeps the same endangered asset and impact (the thing worth
    protecting) but uses a *different* vulnerability class, so the investigation
    pivots rather than repeating a falsified idea. The contradiction is recorded
    on each alternative so the reason for the pivot is auditable.
    """
    result = generator.generate()
    out: list[GeneratedHypothesis] = []
    for hyp in result.active():
        if hyp.category == original.category:
            continue
        if original.critical_asset and hyp.critical_asset != original.critical_asset:
            continue
        hyp.contradicts = original.hyp_id
        hyp.prior_lessons = list(hyp.prior_lessons) + [
            f"alternative to {original.hyp_id} after contradiction: {contradiction}"
        ]
        out.append(hyp)
    out.sort(key=lambda h: (-h.score, h.hyp_id))
    return out


__all__ = [
    "GeneratedHypothesis",
    "GenerationResult",
    "HypothesisGenerator",
    "HypothesisStore",
    "RejectionRecord",
    "StrategyTemplate",
    "REQUIRED_FIELDS",
    "DEFAULT_GENERATION_WEIGHTS",
    "alternatives",
]
