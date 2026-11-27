"""A model may propose hypotheses, but only grounded, complete ones survive.

These tests pin the anti-hallucination gate: a proposal naming a component or
asset the threat model does not contain is rejected with its reason, a provider
failure is an error rather than an empty success, and a converted hypothesis still
carries every required field.
"""

from __future__ import annotations

import json

from blackheart.hypothesis.llm import (
    REQUIRED_FIELDS,
    SYSTEM_PROMPT,
    as_generated_hypothesis,
    build_prompt,
    grounding_from_witness,
    grounding_lines,
    propose,
)
from blackheart.mindset import ATTACKER_QUESTION
from blackheart.providers.adapters import MockProvider
from blackheart.threatmodel import ThreatModel


def _model() -> ThreatModel:
    tm = ThreatModel(target="Vault", summary="A collateral vault.")
    tm.architecture = ["Vault", "Oracle"]
    tm.critical_assets = ["user funds"]
    tm.add_invariant("inv-solvency", "collateral always covers debt", applies_to=["Vault"])
    return tm


def _hypothesis(**overrides) -> dict:
    base = {name: f"{name} value" for name in REQUIRED_FIELDS}
    base.update({
        "component": "Vault",
        "entry_point": "liquidate(address)",
        "critical_asset": "user funds",
        "invariant": "collateral always covers debt",
        "category": "liquidation",
        "title": "liquidate seizes collateral without a shortfall",
    })
    base.update(overrides)
    return base


def _provider(*hypotheses: dict) -> MockProvider:
    return MockProvider(responses=[json.dumps({"hypotheses": list(hypotheses)})])


def test_no_provider_is_reported_not_silently_empty():
    result = propose(_model(), provider=None)
    assert result.status == "NO_PROVIDER"
    assert result.proposals == []


def test_grounding_is_in_the_prompt_the_provider_receives():
    provider = _provider(_hypothesis())
    fact = {"fact": "function mint is unguarded", "source": "Vault.sol:5",
            "evidence": "no modifier"}
    result = propose(_model(), provider=provider, grounding=[fact])
    assert result.ok
    prompt = provider.calls[0][0]
    assert "VERIFIED GROUNDING" in prompt
    assert "function mint is unguarded" in prompt
    assert "Vault.sol:5" in prompt


def test_a_solver_witness_becomes_a_grounding_fact():
    fact = grounding_from_witness({"cd0": 800, "_halt": "revert", "_pc": 20},
                                  target="Vault")
    assert "cd0=800" in fact["fact"]
    assert "revert" in fact["fact"]
    assert fact["source"] == "symbolic-evm:Vault"
    assert fact["evidence"] == "pc=20"


def test_grounding_lines_skip_empty_and_render_sources():
    assert grounding_lines(["a fact", {"fact": ""}, {"fact": "b", "source": "s"}]) == [
        "- a fact", "- b [s]"]


def test_a_grounded_complete_proposal_survives():
    result = propose(_model(), provider=_provider(_hypothesis()))
    assert result.ok
    assert len(result.proposals) == 1
    assert result.proposals[0].component == "Vault"
    assert result.rejected == []


def test_an_ungrounded_component_is_rejected():
    result = propose(_model(), provider=_provider(_hypothesis(component="Bridge")))
    assert result.ok
    assert result.proposals == []
    assert "not in the threat model" in result.rejected[0]["reason"]


def test_an_ungrounded_asset_is_rejected():
    result = propose(_model(), provider=_provider(_hypothesis(critical_asset="oracle keys")))
    assert result.proposals == []
    assert "critical asset" in result.rejected[0]["reason"]


def test_a_proposal_missing_a_required_field_is_rejected():
    item = _hypothesis()
    item.pop("falsification_criteria")
    result = propose(_model(), provider=_provider(item))
    assert result.proposals == []
    assert "missing required field" in result.rejected[0]["reason"]


def test_a_failing_provider_is_an_error():
    result = propose(_model(), provider=MockProvider(fail_times=1))
    assert result.status == "ERROR"
    assert result.error


def test_non_json_is_an_error():
    result = propose(_model(), provider=MockProvider(responses=["not json"]))
    assert result.status == "ERROR"


def test_the_system_prompt_carries_the_question():
    assert ATTACKER_QUESTION in SYSTEM_PROMPT


def test_prompt_carries_the_model_and_marks_source_untrusted():
    prompt = build_prompt(_model(), source_excerpts=["function withdraw() {}"])
    assert "UNTRUSTED SOURCE" in prompt
    assert "Vault" in prompt and "inv-solvency" in prompt
    assert "function withdraw()" in prompt


def test_converted_hypothesis_has_every_required_field():
    result = propose(_model(), provider=_provider(_hypothesis()))
    hyp = as_generated_hypothesis(result.proposals[0], hyp_id="H-1")
    assert hyp.missing_fields() == []
    assert hyp.status == "ACTIVE"
