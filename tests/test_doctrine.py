"""Tests for the BLACKHEART operational doctrine (mission sections 2, 3, 6, 7, 9).

The doctrine is the authoritative mission definition and the lifecycle the
orchestrator follows. These tests assert that it is *exposed* (acceptance
criterion 1), that it is internally consistent, and that the prioritisation model
is transparent and refuses to reward bounty size.
"""

from __future__ import annotations

import json

from blackheart import doctrine
from blackheart.doctrine import (
    ATTACK_SURFACES,
    DISPOSITIONS,
    FINDING_SECTIONS,
    FINDING_VERDICTS,
    FORBIDDEN_OPERATIONS,
    HYPOTHESIS_REQUIRED_FIELDS,
    INVESTIGATION_METHODS,
    LIFECYCLE,
    OPERATIONAL_IDENTITY,
    PHASE_BY_KEY,
    PRIORITISATION_NON_FACTORS,
    PRIORITY_FACTORS,
    RESPONSIBILITIES,
    REVIEW_QUESTIONS,
    SECURITY_INVARIANTS,
    SUCCESS_METRIC,
    VALIDATION_REQUIREMENTS,
    doctrine_dict,
    doctrine_document,
    doctrine_prompt_block,
    phase,
    priority_score,
    prioritize,
)


# --------------------------------------------------------------------------- #
# Acceptance criterion 1 -- the doctrine is exposed to the orchestrator
# --------------------------------------------------------------------------- #

def test_doctrine_dict_exposes_the_whole_operation():
    d = doctrine_dict()
    for key in (
        "identity", "dispositions", "success_metric", "question", "lifecycle",
        "attack_surfaces", "hypothesis_required_fields", "investigation_methods",
        "validation_requirements", "finding_verdicts", "review_questions",
        "finding_sections", "priority_factors", "responsibilities",
        "security_invariants",
    ):
        assert key in d, key
    # It must serialise (the orchestrator may hand it to a model or write it out).
    assert json.loads(json.dumps(d))["identity"] == OPERATIONAL_IDENTITY


def test_prompt_block_names_the_lifecycle_and_hard_rules():
    block = doctrine_prompt_block()
    for p in LIFECYCLE:
        assert p.name in block
    assert "never promote a hypothesis" in block.lower()
    assert "fail-closed" in block


def test_document_renders_every_section():
    doc = doctrine_document()
    assert OPERATIONAL_IDENTITY in doc
    for p in LIFECYCLE:
        assert p.name in doc
    for s in FINDING_SECTIONS:
        assert f"{s.letter}. {s.name}" in doc


# --------------------------------------------------------------------------- #
# Identity and dispositions (mission section 2)
# --------------------------------------------------------------------------- #

def test_identity_is_quality_not_quantity():
    assert "not the number of vulnerabilities it claims to discover" in OPERATIONAL_IDENTITY
    assert "quality" in SUCCESS_METRIC and "reproducibility" in SUCCESS_METRIC
    joined = " ".join(DISPOSITIONS).lower()
    for word in ("adversarially", "scientifically", "independently", "professionally"):
        assert word in joined, word


# --------------------------------------------------------------------------- #
# Lifecycle (mission section 3)
# --------------------------------------------------------------------------- #

def test_lifecycle_has_the_six_phases_in_order():
    assert [p.number for p in LIFECYCLE] == [1, 2, 3, 4, 5, 6]
    assert [p.key for p in LIFECYCLE] == [
        "TARGET_INTELLIGENCE", "ATTACK_SURFACE_DISCOVERY",
        "ATTACK_HYPOTHESIS_DEVELOPMENT", "ADVERSARIAL_INVESTIGATION",
        "EXPLOIT_VALIDATION", "INDEPENDENT_ADVERSARIAL_REVIEW",
    ]
    assert PHASE_BY_KEY["EXPLOIT_VALIDATION"].number == 5


def test_every_phase_has_questions_produce_gate_and_modules():
    for p in LIFECYCLE:
        assert p.questions, p.key
        assert p.produces, p.key
        assert p.gate, p.key
        assert p.modules, p.key


def test_phase_lookup_and_unknown_key():
    assert phase("TARGET_INTELLIGENCE").number == 1
    try:
        phase("NOPE")
        assert False, "expected KeyError"
    except KeyError:
        pass


def test_phase_4_gate_is_authorization_and_phase_5_gate_is_evidence():
    assert "AUTHORIZED" in PHASE_BY_KEY["ADVERSARIAL_INVESTIGATION"].gate
    assert "evidence" in PHASE_BY_KEY["EXPLOIT_VALIDATION"].gate.lower()
    assert "never promoted" in PHASE_BY_KEY["INDEPENDENT_ADVERSARIAL_REVIEW"].gate


# --------------------------------------------------------------------------- #
# Surfaces, hypotheses, methods, validation, verdicts (mission section 3)
# --------------------------------------------------------------------------- #

def test_attack_surfaces_cover_the_mission_list():
    joined = " ".join(ATTACK_SURFACES).lower()
    for needle in ("authentication", "authorization", "session", "api", "cryptograph",
                   "key management", "storage", "deployment", "supply-chain",
                   "smart contracts", "agent", "recovery", "trust"):
        assert needle in joined, needle


def test_hypothesis_requires_all_six_fields():
    assert len(HYPOTHESIS_REQUIRED_FIELDS) == 6
    joined = " ".join(HYPOTHESIS_REQUIRED_FIELDS).lower()
    assert "assumption" in joined and "disprove" in joined
    assert "authorization" in joined


def test_forbidden_operations_are_named():
    joined = " ".join(FORBIDDEN_OPERATIONS).lower()
    for needle in ("destructive", "persistence", "credential theft",
                   "exfiltration", "unauthorized access"):
        assert needle in joined, needle


def test_verdicts_are_distinct_and_only_confirmed_is_real():
    assert len(set(FINDING_VERDICTS)) == len(FINDING_VERDICTS)
    for v in ("CONFIRMED", "STRONGLY_SUPPORTED", "UNCONFIRMED", "FALSE_POSITIVE",
              "INFORMATIONAL", "NOT_REPRODUCIBLE", "OUT_OF_SCOPE"):
        assert v in FINDING_VERDICTS, v
    assert set(doctrine.NON_CONFIRMED_VERDICTS) == set(FINDING_VERDICTS) - {"CONFIRMED"}


def test_validation_requirements_and_review_questions():
    assert len(VALIDATION_REQUIREMENTS) >= 8
    assert len(REVIEW_QUESTIONS) == 7
    assert any("intentional" in q for q in REVIEW_QUESTIONS)


def test_investigation_methods_are_offered():
    joined = " ".join(INVESTIGATION_METHODS).lower()
    for needle in ("source-code", "static", "dependency", "protocol", "differential",
                   "property-based", "proof-of-concept"):
        assert needle in joined, needle


# --------------------------------------------------------------------------- #
# Finding record sections (mission section 4)
# --------------------------------------------------------------------------- #

def test_ten_finding_sections_A_through_J():
    assert [s.letter for s in FINDING_SECTIONS] == list("ABCDEFGHIJ")
    fields = {f for s in FINDING_SECTIONS for f in s.fields}
    for needle in ("finding_id", "cwe", "cvss_vector", "root_cause_file",
                   "attack_sequence", "repro_steps", "evidence_ids",
                   "verification_result", "confidentiality_impact",
                   "recommended_fix", "submission_status"):
        assert needle in fields, needle


# --------------------------------------------------------------------------- #
# Prioritisation (mission section 7)
# --------------------------------------------------------------------------- #

def test_priority_weights_are_reviewable_and_sum_to_one():
    total = sum(f.weight for f in PRIORITY_FACTORS)
    assert abs(total - 1.0) < 1e-9, total


def test_priority_score_is_bounded_and_ignores_unknowns():
    assert priority_score({}) == 0.0
    full = {f.key: 1.0 for f in PRIORITY_FACTORS}
    assert priority_score(full) == 1.0
    # A partially-specified candidate is not penalised for the unknown factors.
    partial = priority_score({"security_impact": 1.0})
    assert 0.0 < partial < 1.0


def test_bounty_size_is_not_a_prioritisation_factor():
    joined = " ".join(PRIORITISATION_NON_FACTORS).lower()
    assert "bounty" in joined
    assert all("bounty" not in f.key for f in PRIORITY_FACTORS)


def test_prioritize_ranks_by_score_and_annotates():
    candidates = [
        {"name": "low", "factors": {"security_impact": 0.1}},
        {"name": "high", "factors": {"security_impact": 1.0, "exploitability": 1.0}},
    ]
    ranked = prioritize(candidates)
    assert ranked[0]["name"] == "high"
    assert "priority_score" in ranked[0]
    # The original inputs are not mutated.
    assert "priority_score" not in candidates[0]


# --------------------------------------------------------------------------- #
# Responsibilities (mission section 6) and invariants (mission section 9)
# --------------------------------------------------------------------------- #

def test_nine_logical_responsibilities_each_map_to_an_agent():
    assert len(RESPONSIBILITIES) == 9
    keys = {r.key for r in RESPONSIBILITIES}
    for needle in ("intelligence_analyst", "attack_surface_analyst",
                   "hypothesis_researcher", "offensive_researcher",
                   "verification_researcher", "adversarial_reviewer",
                   "impact_analyst", "documentation_analyst", "disclosure_analyst"):
        assert needle in keys, needle
    for r in RESPONSIBILITIES:
        assert r.agents, r.key  # every responsibility names a real agent


def test_security_invariants_are_non_negotiable_and_cover_the_mission():
    joined = " ".join(SECURITY_INVARIANTS).lower()
    for needle in ("fail-closed", "scope", "audit", "provenance", "never fabricate",
                   "without evidence", "never submitted", "secrets",
                   "never weakened", "human approval"):
        assert needle in joined, needle


def test_module_exports_are_stable():
    for name in ("OPERATIONAL_IDENTITY", "LIFECYCLE", "PHASE_BY_KEY", "phase",
                 "ATTACK_SURFACES", "HYPOTHESIS_REQUIRED_FIELDS",
                 "INVESTIGATION_METHODS", "VALIDATION_REQUIREMENTS",
                 "FINDING_VERDICTS", "REVIEW_QUESTIONS", "FINDING_SECTIONS",
                 "PRIORITY_FACTORS", "priority_score", "prioritize",
                 "RESPONSIBILITIES", "SECURITY_INVARIANTS", "doctrine_dict",
                 "doctrine_prompt_block", "doctrine_document"):
        assert hasattr(doctrine, name), name


def test_docs_doctrine_is_generated_from_the_module(repo_root):
    """docs/DOCTRINE.md embeds the module's doctrine verbatim (no drift)."""
    doc = (repo_root / "docs" / "DOCTRINE.md").read_text(encoding="utf-8")
    assert doctrine_document().rstrip() in doc
