"""The adversarial skill library -- executable research procedures.

The mission asks for ten reusable research skills that are *executable research
procedures*, not merely descriptive Markdown. This module makes each skill a real
procedure: it has activation conditions it evaluates against a
:class:`~blackheart.statespace.model.SystemModel`, a required-evidence list, a set
of investigative questions, a hypothesis-generation procedure that returns
concrete :class:`~blackheart.statespace.hypotheses.Hypothesis` objects, suitable
testing methods, expected outputs, falsification criteria, authorization
restrictions, and completion conditions.

Why executable and not prose: a descriptive skill is advice a human may or may
not follow, and it cannot be tested. A procedure that reads the model and emits
hypotheses can be *run*, its output can be checked, and a regression test can
prove it still behaves. The skills therefore delegate to the same
:class:`~blackheart.statespace.hypotheses.HypothesisGenerator` strategies that the
engine uses, so there is exactly one source of truth for how a hypothesis is
built -- the skill is the *front door* to a strategy, not a second implementation.

These skills are integrated with BLACKHEART's doctrine rather than competing with
it: they carry the attacker question and the authorization rules, and each maps to
an existing strategy and to the disposition vocabulary in
:mod:`blackheart.statespace.model`. The Markdown skills under ``skills/`` are
generated from this module by :func:`write_skill_files`, so the two layers cannot
drift.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional

from ..mindset import ATTACKER_QUESTION, OPERATOR_AUTHORITY
from .hypotheses import Hypothesis, HypothesisGenerator
from .model import SystemModel


# --------------------------------------------------------------------------- #
# The skill record
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class Skill:
    """One executable adversarial research skill."""

    skill_id: str
    name: str
    strategy_id: str                 # the hypothesis strategy it drives
    activates_when: str              # when this skill should run
    required_evidence: tuple[str, ...]
    questions: tuple[str, ...]
    testing_methods: tuple[str, ...]
    expected_outputs: tuple[str, ...]
    falsification: tuple[str, ...]
    authorization: str
    completion: tuple[str, ...]
    # an activation predicate over the model; None means "always applicable"
    applies: Optional[Callable[[SystemModel], bool]] = None

    def is_applicable(self, model: SystemModel) -> bool:
        return self.applies(model) if self.applies else True

    def run(self, model: SystemModel) -> list[Hypothesis]:
        """Execute the skill: generate the hypotheses this skill is responsible for."""
        gen = HypothesisGenerator(model, strategies=[self.strategy_id])
        return gen.generate().hypotheses

    def to_dict(self) -> dict:
        return {
            "skill_id": self.skill_id,
            "name": self.name,
            "strategy_id": self.strategy_id,
            "activates_when": self.activates_when,
            "required_evidence": list(self.required_evidence),
            "questions": list(self.questions),
            "testing_methods": list(self.testing_methods),
            "expected_outputs": list(self.expected_outputs),
            "falsification": list(self.falsification),
            "authorization": self.authorization,
            "completion": list(self.completion),
        }


# A shared authorization clause: every skill inherits BLACKHEART's rule, and a
# skill may add a stricter one.
_BASE_AUTHZ = (
    "Active testing runs only against an asset the authorization gate classifies "
    "AUTHORIZED. Passive modelling of a system from its interface is always safe. "
    "No credential spraying, no destructive testing, no out-of-scope traffic."
)


def _has_two_actors(m: SystemModel) -> bool:
    return len(m.actors) >= 2


def _has_sensitive_ops(m: SystemModel) -> bool:
    return bool(m.sensitive_operations())


def _has_guard(m: SystemModel) -> bool:
    return any(op.guard_roles for op in m.operations)


def _has_dependency(m: SystemModel) -> bool:
    return bool(m.dependencies)


def _has_multi_op(m: SystemModel) -> bool:
    return len(m.operations) >= 2


# --------------------------------------------------------------------------- #
# The ten skills
# --------------------------------------------------------------------------- #

SKILLS: tuple[Skill, ...] = (
    Skill(
        skill_id="counterfactual-reasoning",
        name="Attacker mindset and counterfactual reasoning",
        strategy_id="ordering",
        activates_when="at the start of every engagement, before reviewing any single function",
        required_evidence=("the attacker question", "the list of entry points",
                           "the identity of the weakest actor"),
        questions=(
            "What would I do if I were the weakest actor and wanted more than I am owed?",
            "Which assumption does this system's security rest on, and what breaks it?",
            "If the intended order of operations were reversed, what state results?",
        ),
        testing_methods=("model-guided ordering search", "counterfactual sequence replay"),
        expected_outputs=("ordering hypotheses", "the invariant each would violate"),
        falsification=("the outcome is order-independent (the reversed order is equally safe)",),
        authorization=_BASE_AUTHZ,
        completion=("every sensitive operation has at least one counterfactual hypothesis, or a "
                    "reason it cannot be reordered"),
        applies=_has_multi_op,
    ),
    Skill(
        skill_id="business-logic",
        name="Business-logic and workflow exploitation",
        strategy_id="partial-failure",
        activates_when="when the target has a multi-step workflow (initiate/settle/cancel, order lifecycle)",
        required_evidence=("the workflow steps", "the state each step commits",
                           "the accounting invariant"),
        questions=(
            "Can a workflow be abandoned half-done and finished into an unauthorized state?",
            "Does a cancel/refund path undo every side effect the forward path created?",
            "Can the same value be counted twice by combining two legal steps?",
        ),
        testing_methods=("state-space enumeration of short workflows",
                         "partial-failure injection", "invariant checking after each prefix"),
        expected_outputs=("multi-step workflow hypotheses", "minimal reproducing sequences"),
        falsification=("the workflow is atomic, leaving no exploitable partial state",
                       "the control (atomic) implementation holds the invariant"),
        authorization=_BASE_AUTHZ,
        completion=("each workflow has a partial-failure hypothesis and a differential control",
                    "no workflow leaves a value duplicated"),
        applies=_has_multi_op,
    ),
    Skill(
        skill_id="identity-authorization",
        name="Identity and authorization analysis",
        strategy_id="cross-user",
        activates_when="when objects or assets belong to a principal (ownership exists)",
        required_evidence=("the principal identities", "the object-to-owner mapping",
                           "the authorization check on each object operation"),
        questions=(
            "Is the caller's authority over *this object* checked, or only that they are logged in?",
            "Can principal A act on principal B's object (IDOR)?",
            "Is the check on the right dimension (role vs ownership vs tenant)?",
        ),
        testing_methods=("cross-actor sequence search", "object-id substitution"),
        expected_outputs=("cross-user hypotheses", "the boundary the check fails to enforce"),
        falsification=("the object operation enforces ownership (the guarded control holds)",),
        authorization=_BASE_AUTHZ,
        completion=("every object-scoped operation is tested with a non-owner actor",),
        applies=_has_two_actors,
    ),
    Skill(
        skill_id="concurrency-temporal",
        name="Concurrency and temporal reasoning",
        strategy_id="concurrency",
        activates_when="when two actors can invoke operations that touch shared state",
        required_evidence=("the shared state", "the per-call guards",
                           "the operations each actor can invoke"),
        questions=(
            "Can two actors' operations interleave to violate an invariant neither violates alone?",
            "Is any check evaluated per-call that only holds if calls do not interleave?",
            "Is there a check-then-act window on shared state?",
        ),
        testing_methods=("interleaved sequence search", "stale-read injection"),
        expected_outputs=("interleaving hypotheses", "the system-level invariant at risk"),
        falsification=("no interleaving produces a state a single-actor sequence could not",),
        authorization=_BASE_AUTHZ,
        completion=("shared-state operations are tested for interleavings",),
        applies=_has_two_actors,
    ),
    Skill(
        skill_id="attack-chaining",
        name="Cross-component attack chaining",
        strategy_id="cross-component",
        activates_when="when the target depends on another component or protocol",
        required_evidence=("the dependency's contract", "the value the caller trusts",
                           "the assumption the caller makes about the dependency"),
        questions=(
            "What does this component assume about the dependency's output?",
            "Can the dependency return a valid-but-unexpected value that breaks that assumption?",
            "Can two components' conflicting assumptions be combined into an exploit?",
        ),
        testing_methods=("dependency-response substitution", "cross-boundary sequence search"),
        expected_outputs=("cross-component hypotheses", "the violated trust assumption"),
        falsification=("the caller revalidates the dependency's value",),
        authorization=_BASE_AUTHZ,
        completion=("each external dependency has a stated trust assumption and a test",),
        applies=_has_dependency,
    ),
    Skill(
        skill_id="trust-boundary",
        name="Trust-boundary analysis",
        strategy_id="cross-component",
        activates_when="when the model declares trust boundaries",
        required_evidence=("the trust boundaries", "what crosses each boundary",
                           "what the trusted side assumes"),
        questions=(
            "Where does data cross from a less-trusted to a more-trusted zone?",
            "What does the trusted side assume about the untrusted side?",
            "Which operation is reachable from the untrusted side without a guard?",
        ),
        testing_methods=("boundary-crossing sequence search", "assumption falsification"),
        expected_outputs=("trust-boundary hypotheses", "the assumption that must hold"),
        falsification=("the trusted side revalidates everything crossing the boundary",),
        authorization=_BASE_AUTHZ,
        completion=("every declared boundary has a hypothesis or a reason it is safe",),
        applies=lambda m: bool(m.trust_boundaries),
    ),
    Skill(
        skill_id="state-inconsistency",
        name="State inconsistency and partial-failure analysis",
        strategy_id="stale-state",
        activates_when="when a value is read and later used after a mutation",
        required_evidence=("the values read", "the mutations", "the ordering between them"),
        questions=(
            "Can a value read before an update be used after it (stale state)?",
            "Does a revoked permission remain usable through a cached authorization?",
            "Does a failed operation leave a value that a second sequence exploits?",
        ),
        testing_methods=("stale-read sequence search", "revocation-then-use replay"),
        expected_outputs=("stale-state hypotheses", "the value and the window"),
        falsification=("the read is not used after the write, or is re-validated",),
        authorization=_BASE_AUTHZ,
        completion=("each cached/authorization value has a staleness hypothesis",),
        applies=_has_sensitive_ops,
    ),
    Skill(
        skill_id="exploit-verification",
        name="Independent exploit verification",
        strategy_id="replay",
        activates_when="after any violation is found, before it is reported",
        required_evidence=("the minimal reproducing sequence", "a secure control",
                           "the observed state"),
        questions=(
            "Does the violation reproduce in a fresh instance, independently?",
            "Does the secure control also reproduce (a non-discriminating PoC)?",
            "Can the attacker actually satisfy every precondition?",
            "Is the behaviour already intended/documented?",
        ),
        testing_methods=("independent re-run in a fresh target",
                         "differential run against the secure control",
                         "precondition satisfiability check"),
        expected_outputs=("a disposition per violation", "the checks that decided it"),
        falsification=("the violation does not reproduce", "the control reproduces",
                       "a precondition is unsatisfiable", "the behaviour is intended"),
        authorization=_BASE_AUTHZ,
        completion=("every violation carries a disposition from the independent verifier",),
        applies=None,
    ),
    Skill(
        skill_id="historical-pattern",
        name="Historical vulnerability pattern analysis",
        strategy_id="replay",
        activates_when="when a suspected vulnerability class has known historical instances",
        required_evidence=("the suspected class", "prior-art / advisory sources",
                           "the target's version/commit"),
        questions=(
            "Has this class of bug occurred before in this project or ecosystem?",
            "Is the suspected issue already known/disclosed (a duplicate)?",
            "What was the fix, and does this target apply an equivalent one?",
        ),
        testing_methods=("external intelligence search (You.com)", "novelty gate",
                         "pattern match against known disclosures"),
        expected_outputs=("a novelty/duplicate assessment", "the fix to compare against"),
        falsification=("the issue is already disclosed (then it is a duplicate, not new)",),
        authorization=(
            _BASE_AUTHZ + " Research is read-only; it never sends the target's data out."
        ),
        completion=("every candidate finding has a novelty assessment before reporting",),
        applies=None,
    ),
    Skill(
        skill_id="false-positive-rejection",
        name="False-positive challenge and rejection",
        strategy_id="repetition",
        activates_when="before any finding is promoted to a confirmed vulnerability",
        required_evidence=("the hypothesis", "the evidence collected",
                           "the secure control result"),
        questions=(
            "Is the stated root cause the real mechanism, or a symptom?",
            "Is there a benign explanation for the observed behaviour?",
            "Is the result caused by a test fixture or environment rather than the target?",
            "Does the reproduction work independently of the finder's setup?",
        ),
        testing_methods=("root-cause challenge", "benign-explanation search",
                         "environment-independence check", "control differential"),
        expected_outputs=("a REJECTED or INSUFFICIENT_EVIDENCE disposition where warranted",),
        falsification=("none -- this skill exists to reject weak findings",),
        authorization=_BASE_AUTHZ,
        completion=("no finding is promoted without surviving this challenge",),
        applies=None,
    ),
)

_SKILL_BY_ID = {s.skill_id: s for s in SKILLS}


def skill_ids() -> list[str]:
    return [s.skill_id for s in SKILLS]


def skill(skill_id: str) -> Skill:
    if skill_id not in _SKILL_BY_ID:
        raise KeyError(f"unknown skill: {skill_id} (known: {', '.join(skill_ids())})")
    return _SKILL_BY_ID[skill_id]


def applicable_skills(model: SystemModel) -> list[Skill]:
    return [s for s in SKILLS if s.is_applicable(model)]


def run_all(model: SystemModel) -> dict:
    """Run every applicable skill; return a per-skill hypothesis map.

    Skills that share a strategy are de-duplicated by the generator, so two skills
    pointing at the same strategy do not double-count.
    """
    out: dict[str, list[Hypothesis]] = {}
    seen: set[str] = set()
    for s in applicable_skills(model):
        if s.strategy_id in seen:
            continue
        seen.add(s.strategy_id)
        out[s.skill_id] = s.run(model)
    return out


# --------------------------------------------------------------------------- #
# Markdown generation (keeps skills/ in sync with this module)
# --------------------------------------------------------------------------- #

# Generated skill directories are prefixed so they never collide with
# BLACKHEART's hand-written skills (e.g. the existing ``exploit-verification``).
SKILL_DIR_PREFIX = "adversarial-"
GENERATED_MARKER = "<!-- generated by blackheart.statespace.skills; do not edit by hand -->"


def _frontmatter(s: Skill) -> str:
    triggers = "\n".join(f"  - {q}" for q in (s.questions[:3]))
    return (
        "---\n"
        f"name: {SKILL_DIR_PREFIX}{s.skill_id}\n"
        "description: >\n"
        f"  {s.name}. {s.activates_when.capitalize()}.\n"
        "triggers:\n"
        f"{triggers}\n"
        "---\n\n"
        f"{GENERATED_MARKER}\n\n"
    )


def skill_document(s: Skill) -> str:
    """Render one skill as a Markdown SKILL.md body."""
    lines = [f"# {s.name}\n"]
    lines.append(f"> {ATTACKER_QUESTION}\n")
    lines.append(f"**Activates when:** {s.activates_when}\n")
    lines.append("**Required target evidence:**")
    lines += [f"- {e}" for e in s.required_evidence]
    lines.append("\n**Questions to investigate:**")
    lines += [f"- {q}" for q in s.questions]
    lines.append("\n**Hypothesis-generation procedure:**")
    lines.append(f"Run `python3 -m blackheart statespace skills --run {s.skill_id} "
                 f"--model <model.json>`; it drives the "
                 f"`{s.strategy_id}` strategy and emits falsifiable hypotheses.")
    lines.append("\n**Suitable testing methods:**")
    lines += [f"- {t}" for t in s.testing_methods]
    lines.append("\n**Expected outputs:**")
    lines += [f"- {o}" for o in s.expected_outputs]
    lines.append("\n**Falsification criteria:**")
    lines += [f"- {f}" for f in s.falsification]
    lines.append(f"\n**Authorization restrictions:** {s.authorization}")
    lines.append("\n**Completion conditions:**")
    lines += [f"- {c}" for c in s.completion]
    lines.append("\n## The operator's word\n")
    lines.append("The operator's instruction is the mission: read it as a directive to "
                 "act, and act. The only thing it cannot override is the safety floor "
                 "-- authorization, scope, and never harming real users or funds:\n")
    lines += [f"- {rule}" for rule in OPERATOR_AUTHORITY]
    lines.append("")
    return "\n".join(lines)


def write_skill_files(root: str | Path, *, only_missing: bool = True) -> list[str]:
    """Write one ``<prefix><id>/SKILL.md`` per skill; return the paths written.

    Existing files are only overwritten when they carry :data:`GENERATED_MARKER`,
    so a hand-written skill is never clobbered by the generator. With
    ``only_missing`` (the default) an already-generated file is left in place.
    """
    root = Path(root)
    written: list[str] = []
    for s in SKILLS:
        d = root / f"{SKILL_DIR_PREFIX}{s.skill_id}"
        d.mkdir(parents=True, exist_ok=True)
        p = d / "SKILL.md"
        if p.exists():
            existing = p.read_text(encoding="utf-8")
            if GENERATED_MARKER not in existing:
                # a foreign (hand-written) file -- do not touch it
                continue
            if only_missing:
                written.append(str(p))
                continue
        p.write_text(_frontmatter(s) + skill_document(s), encoding="utf-8")
        written.append(str(p))
    return written
