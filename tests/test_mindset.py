"""Tests for the attacker mindset (blackheart.mindset).

The mindset is one question, held for the whole mission, plus the doctrine that
follows from it. These tests assert it is (a) well-formed, (b) genuinely wired
into the thinking layer rather than merely defined, and (c) enforced on the
artefacts a mission produces -- objectives, hypotheses, campaign summaries, and
the multi-model role prompts.
"""

from __future__ import annotations

from blackheart import mindset
from blackheart.mindset import (
    ATTACKER_QUESTION,
    BLACKHEART_PERSONA,
    DOCTRINE,
    LEVERS,
    LEVER_DETAIL,
    OPERATOR_AUTHORITY,
    OUTCOMES,
    PERSONA_TAGLINE,
    PERSONA_TRAITS,
    agent_lens_block,
    apply_lens,
    doctrine,
    frame_rationale,
    levers_for,
    operator_authority,
    outcome_for,
    persona,
    persona_traits,
    prompt_block,
    question,
    skill_document,
)
from blackheart.objectives import TargetProfile, generate_objectives


def _profile() -> TargetProfile:
    return TargetProfile(
        name="Vault", kind="smart-contract",
        assets=["shares", "funds"],
        entry_points=["deposit(uint256)", "withdraw(uint256)", "borrow(uint256)"],
        trust_boundaries=["market <-> oracle"],
        roles=["depositor", "borrower"],
        external_deps=["oracle"],
    )


# --------------------------------------------------------------------------- #
# The persona -- who BLACKHEART is
# --------------------------------------------------------------------------- #

def test_the_persona_is_a_wise_and_dangerous_black_heart_hacker():
    p = BLACKHEART_PERSONA.lower()
    assert "blackheart" in p
    assert "wise" in p
    assert "dangerous" in p
    assert "black heart" in p
    # A black heart is a method, not a licence: the safety boundary is explicit.
    assert "authorized scope" in p
    assert "never the admin" in p


def test_the_persona_carries_a_temperament():
    assert len(PERSONA_TRAITS) >= 6
    joined = " ".join(PERSONA_TRAITS).lower()
    for trait in ("wise", "dangerous", "patient", "precise", "honest"):
        assert trait in joined, trait


def test_persona_tagline_names_the_identity():
    assert "wise and dangerous" in PERSONA_TAGLINE.lower()
    assert "black heart" in PERSONA_TAGLINE.lower()


def test_persona_accessors_return_copies():
    t = persona_traits()
    t.append("mutated")
    assert len(persona_traits()) == len(PERSONA_TRAITS)
    assert persona() == BLACKHEART_PERSONA


def test_the_persona_leads_the_initial_prompt():
    block = prompt_block()
    # The identity is first: every role and future mission inherits it first.
    assert block.startswith(BLACKHEART_PERSONA)
    assert "wise and dangerous" in block.lower()
    # ...and the question is still right there in the same block.
    assert ATTACKER_QUESTION in block


# --------------------------------------------------------------------------- #
# The question and its structure
# --------------------------------------------------------------------------- #

def test_the_question_names_actor_outcomes_and_levers():
    q = ATTACKER_QUESTION.lower()
    assert "unprivileged" in q
    # The three outcomes are all present in the question itself.
    assert "more assets than" in q
    assert "bypass a restriction" in q
    assert "absorb my loss" in q
    # The five levers are all present in the question itself.
    for lever in LEVERS:
        assert lever in q, lever


def test_outcomes_and_levers_are_the_canonical_sets():
    assert OUTCOMES == (
        "receive more assets than entitled to",
        "bypass a restriction",
        "make another user's position absorb my loss",
    )
    assert LEVERS == (
        "transaction sequence", "inputs", "timing", "account state",
        "market conditions",
    )
    # Each lever is documented with concrete examples, never left abstract.
    assert {l.name for l in LEVER_DETAIL} == set(LEVERS)
    for lever in LEVER_DETAIL:
        assert lever.meaning
        assert lever.examples


def test_doctrine_states_the_unprivileged_position():
    rules = " ".join(DOCTRINE).lower()
    assert "no role" in rules
    assert "outside party" in rules
    assert "inflicts on themselves is not an attack" in rules
    assert "a failing test is not a vulnerability" in rules
    assert len(DOCTRINE) >= 10


def test_value_doctrine_makes_economic_impact_mandatory():
    from blackheart.mindset import VALUE_DOCTRINE, value_doctrine

    rules = " ".join(VALUE_DOCTRINE).lower()
    assert "deriving value is the point" in rules
    assert "state manipulation, not a" in rules
    assert "blackheart.value" in rules
    # Returned as a copy, and non-trivial.
    assert len(VALUE_DOCTRINE) >= 4
    d = value_doctrine()
    d.append("mutated")
    assert len(value_doctrine()) == len(VALUE_DOCTRINE)


def test_prompt_block_carries_the_value_doctrine():
    from blackheart.mindset import prompt_block
    block = prompt_block()
    assert "Deriving value is the point" in block
    assert "blackheart.value" in block


def test_question_and_doctrine_are_returned_as_copies():
    q = question()
    d = doctrine()
    d.append("mutated")
    assert len(doctrine()) == len(DOCTRINE)
    assert q == ATTACKER_QUESTION


# --------------------------------------------------------------------------- #
# Applying the lens to an artefact
# --------------------------------------------------------------------------- #

def test_outcome_for_maps_categories_to_the_three_outcomes():
    assert outcome_for("asset-theft") in OUTCOMES
    assert outcome_for("auth-bypass") == "bypass a restriction"
    assert outcome_for("callback-reentrancy") == "make another user's position absorb my loss"
    # An unknown class still answers the question (defaults to the primary outcome).
    assert outcome_for("something-new") == OUTCOMES[0]


def test_levers_for_detects_concrete_attacker_dimensions():
    assert "timing" in levers_for("front-run the oracle update")
    assert "inputs" in levers_for("supply a boundary amount and a replayed message")
    assert "market conditions" in levers_for("flash-loan to move the spot price")
    assert levers_for("nothing relevant here") == []


def test_apply_lens_reports_a_gap_when_no_lever_is_named():
    # An artefact that names no attacker-controlled dimension is flagged: the
    # attack would be assuming a precondition rather than achieving the outcome.
    app = apply_lens("", texts=("a vague idea with no lever",))
    assert app.applied
    assert app.gaps and "no attacker-controlled lever" in app.gaps[0]


def test_frame_rationale_prefixes_the_question_answer():
    text = frame_rationale("do the thing", "asset-theft",
                           texts=("sequence of calls",))
    assert text.startswith("Attacker lens [")
    assert "receive more assets than entitled to" in text
    assert "do the thing" in text


# --------------------------------------------------------------------------- #
# The lens reaches the artefacts a mission produces
# --------------------------------------------------------------------------- #

def test_every_objective_answers_the_question():
    for o in generate_objectives(_profile()):
        assert o.attacker_outcome in OUTCOMES
        assert o.attacker_levers, f"{o.category} names no attacker lever"
        assert set(o.attacker_levers) <= set(LEVERS)
        assert "Attacker lens" in o.rationale
        # The objective's own outcome must appear in its rationale.
        assert o.attacker_outcome in o.rationale


def test_objective_lens_survives_serialisation():
    from blackheart.models import Objective

    obj = generate_objectives(_profile())[0]
    restored = Objective.from_dict(obj.to_dict())
    assert restored.attacker_outcome == obj.attacker_outcome
    assert restored.attacker_levers == obj.attacker_levers


def test_hypothesis_engine_explains_in_terms_of_the_question():
    from blackheart.hypothesis import HypothesisEngine

    eng = HypothesisEngine(_profile())
    explanation = eng.explain_selection()
    assert ATTACKER_QUESTION in explanation
    chosen = eng.select_next()
    assert chosen is not None
    assert chosen.attacker_outcome in OUTCOMES
    assert chosen.attacker_levers
    assert "Answers the attacker question" in chosen.rationale


def test_generated_hypothesis_carries_the_lens_in_its_strategy():
    from blackheart.hypothesis.generation import HypothesisGenerator
    from blackheart.threatmodel import ThreatModel

    tm = ThreatModel(target="Vault", summary="An ERC4626 vault.",
                     architecture=["Vault"], critical_assets=["funds"])
    tm.add_trust_boundary("user <-> vault", "user", "vault",
                          assumption="a user cannot mint shares without depositing")
    tm.add_assumption("shares are minted only for assets", depends_on="deposit()",
                      if_false="share/asset accounting breaks")
    tm.add_invariant("INV-1", "redeemable value never exceeds assets held",
                     applies_to=["funds"], expression="invariant_accounting_consistent()")
    tm.select_impacts(["theft-or-freeze"])

    result = HypothesisGenerator(tm, _profile()).generate()
    actives = result.active()
    assert actives
    for h in actives:
        assert h.attacker_outcome in OUTCOMES
        assert h.attacker_levers
        assert "[attacker lens" in h.strategy
        assert "Answers the attacker question" in h.rationale


def test_campaign_summary_records_the_question(tmp_path):
    from blackheart.authz import new_record
    from blackheart.campaign import Campaign

    rec = new_record("eng", "immunefi", "https://x", "https://scope")
    rec.assets = {"asset-a": "UNKNOWN"}
    camp = Campaign("eng", _profile(), rec, tmp_path)
    result = camp.run_active("asset-a")
    assert result.question == ATTACKER_QUESTION
    assert result.to_dict()["question"] == ATTACKER_QUESTION
    # The doctrine the campaign was run under is on the artefact too.
    from blackheart.doctrine import LIFECYCLE

    assert result.to_dict()["doctrine_lifecycle"] == [p.name for p in LIFECYCLE]


# --------------------------------------------------------------------------- #
# The lens reaches the thinking layer (multi-model roles)
# --------------------------------------------------------------------------- #

def test_every_role_holds_the_persona_and_question_and_stays_distinct():
    from blackheart.providers.roles import ROLES

    prompts = {name: role.system for name, role in ROLES.items()}
    # The identity leads every role's system prompt, followed by the question.
    for name, system in prompts.items():
        assert system.startswith(BLACKHEART_PERSONA), name
        assert "unprivileged" in system, name
        assert "levers" in system, name
    # The roles must still ask different questions.
    assert len(set(prompts.values())) == len(prompts)


def test_prompt_block_is_self_contained():
    block = prompt_block()
    assert "unprivileged" in block
    assert "wise and dangerous" in block.lower()
    for lever in LEVERS:
        assert lever in block
    for outcome in OUTCOMES:
        assert outcome in block


def test_skill_document_is_complete():
    doc = skill_document()
    assert ATTACKER_QUESTION in doc
    assert "Who you are" in doc
    for lever in LEVER_DETAIL:
        assert lever.name in doc
    assert doc.count("- ") >= len(DOCTRINE)


# --------------------------------------------------------------------------- #
# The operator's word reaches every layer
# --------------------------------------------------------------------------- #

def test_operator_authority_is_the_documented_rule():
    rules = operator_authority()
    assert rules == list(OPERATOR_AUTHORITY)
    joined = " ".join(rules).lower()
    assert "directive to act" in joined
    assert "default to action" in joined
    # The safety floor is the single thing the operator's word cannot override.
    assert "safety floor" in joined
    assert "authoriz" in joined


def test_operator_authority_is_in_every_prompt_block():
    for block in (prompt_block(), agent_lens_block()):
        assert "operator" in block.lower()
        for rule in OPERATOR_AUTHORITY:
            assert rule in block


def test_every_agent_carries_the_operators_word():
    from pathlib import Path

    agents = sorted((Path(__file__).resolve().parent.parent / "agents").glob("*.md"))
    assert agents
    missing = [p.stem for p in agents
               if "## The operator's word" not in p.read_text(encoding="utf-8")]
    assert not missing, f"agents missing the operator's word: {missing}"


def test_mindset_skill_carries_the_operators_word():
    from pathlib import Path

    skill = (Path(__file__).resolve().parent.parent
             / "skills" / "attacker-mindset" / "SKILL.md")
    assert "## The operator's word" in skill.read_text(encoding="utf-8")


def test_every_skill_carries_the_operators_word():
    from pathlib import Path

    skills = sorted((Path(__file__).resolve().parent.parent / "skills").glob("*/SKILL.md"))
    assert skills
    missing = [p.parent.name for p in skills
               if "## The operator's word" not in p.read_text(encoding="utf-8")]
    assert not missing, f"skills missing the operator's word: {missing}"


def test_module_exports_are_stable():
    # A smoke check that the public surface the rest of the engine imports exists.
    for name in ("ATTACKER_QUESTION", "BLACKHEART_PERSONA", "PERSONA_TRAITS",
                 "PERSONA_TAGLINE", "OUTCOMES", "LEVERS", "LEVER_DETAIL",
                 "DOCTRINE", "VALUE_DOCTRINE", "apply_lens", "frame_rationale",
                 "prompt_block", "agent_lens_block", "value_doctrine",
                 "outcome_for", "levers_for", "question", "doctrine",
                 "persona", "persona_traits", "skill_document"):
        assert hasattr(mindset, name), name
