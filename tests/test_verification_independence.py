"""A fresh instance is a re-run; only a distinct engine is independent."""

from __future__ import annotations

from dataclasses import replace

from blackheart.invariants import InvariantSpec, OpSpec
from blackheart.models import AttackStep
from blackheart.statespace.explore import Violation
from blackheart.statespace.verify import (
    IndependentSequenceVerifier,
    VerificationIndependence,
    VerifyConfig,
)
from blackheart.toolchain.enforce import (
    ExecutionTarget,
    authorized_execution,
    self_test_record,
)


class _Vulnerable:
    name = "fixture"

    def reset(self):
        return {"x": 0}

    def ops(self):
        return [OpSpec("bump", ["attacker"], {})]

    def invariants(self):
        return [InvariantSpec("safe", "x stays zero", lambda s: s["x"] == 0)]

    def step(self, state, op_name, actor, params):
        state["x"] += 1

    def snapshot(self, state):
        return dict(state)


class _Control(_Vulnerable):
    def step(self, state, op_name, actor, params):
        return None


def _violation():
    step = AttackStep(index=0, actor="attacker", action="bump", params={})
    return Violation(
        invariant_id="safe", sequence=[step], minimal_sequence=[step], seed=0,
        actor_roles=["attacker"], observed={"x": 1}, reachable_by_attacker=True,
    )


def _verify(**overrides):
    cfg = dict(
        control_factory=_Control,
        in_scope=True,
        authorization_gate_passed=True,
        producer_engine="bounded-exhaustive",
        verifier_engine="foundry",
        require_distinct_engine=True,
    )
    cfg.update(overrides)
    verifier = IndependentSequenceVerifier(_Vulnerable, VerifyConfig(**cfg))
    record = replace(self_test_record(), target_component="fixture")
    with authorized_execution(record,
                              ExecutionTarget(name="fixture",
                                              repository="blackheart"), "test"):
        return verifier.verify(_violation(), preconditions_satisfiable=True)


def test_a_distinct_engine_is_independent():
    result = _verify()
    assert result.disposition == "INDEPENDENTLY_VERIFIED"
    assert result.independence is VerificationIndependence.INDEPENDENT_ENGINE
    assert result.checks["independent_engine"][0] is True


def test_a_same_engine_is_reproduced_not_independent():
    result = _verify(verifier_engine="bounded-exhaustive")
    assert result.disposition == "REPRODUCED"
    assert result.independence is VerificationIndependence.SAME_ENGINE
    assert result.checks["independent_engine"][0] is False
    assert any("distinct verifier engine" in reason for reason in result.reasons)


def test_unrecorded_provenance_is_not_a_distinct_engine():
    result = _verify(verifier_engine="")
    assert result.disposition == "REPRODUCED"
    assert result.independence is VerificationIndependence.UNRECORDED
    assert result.checks["independent_engine"][0] is None


def test_an_engine_can_be_required_without_changing_the_legacy_default():
    legacy = _verify(verifier_engine="bounded-exhaustive",
                     require_distinct_engine=False)
    assert legacy.disposition == "INDEPENDENTLY_VERIFIED"
    assert legacy.independence is VerificationIndependence.SAME_ENGINE


def test_the_source_pipeline_strict_mode_does_not_confirm_without_a_distinct_engine(tmp_path):
    from blackheart.pipeline import PipelineConfig, run_source_pipeline

    vulnerable = tmp_path / "Vulnerable.sol"
    vulnerable.write_text(
        "contract Vault { address public owner; "
        "function setOwner(address newOwner) external { owner = newOwner; } }",
        encoding="utf-8",
    )
    guarded = tmp_path / "Guarded.sol"
    guarded.write_text(
        "contract Vault { address public owner; "
        "function setOwner(address newOwner) external { "
        "require(msg.sender == owner); owner = newOwner; } }",
        encoding="utf-8",
    )
    result = run_source_pipeline(PipelineConfig(
        source_path=str(vulnerable), contract_name="Vault",
        control_source=str(guarded), control_contract="Vault",
        max_depth=2, in_scope=True, authorization_gate_passed=True,
        require_independent_engine=True,
        write_finding=False, evidence_root=str(tmp_path / "evidence"),
    ))
    assert result.status == "REPRODUCED"
    assert result.verification["disposition"] == "REPRODUCED"
    assert result.verification["checks"]["independent_engine"]["passed"] is None
    assert any("distinct verifier engine" in reason for reason in result.reasons)
