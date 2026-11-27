"""Tests for P3 -- the investigation workflow engine.

Covers the mission's P3 requirements: the guarded lifecycle and its entry
criteria, persistence and resumption, the authorization gate on REPRODUCTION,
the independent-challenge requirement before CONFIRMED, honest outcome
classification, and reuse of the research memory and evidence store.
"""

from __future__ import annotations

import pytest

from blackheart.authz import new_record
from blackheart.evidence import EvidenceStore
from blackheart.hypothesis.generation import GeneratedHypothesis
from blackheart.investigation import (
    STAGE_ORDER,
    InvestigationEngine,
    InvestigationStore,
    InvalidTransition,
    Observation,
    Outcome,
    Stage,
    TestPlan,
    Triage,
    classify_outcome,
    plan_from_tools,
)
from blackheart.models import InvestigationStatus
from blackheart.research import ResearchMemory


# --------------------------------------------------------------------------- #
# Fixtures / helpers
# --------------------------------------------------------------------------- #

def _hypothesis(**overrides) -> GeneratedHypothesis:
    base = dict(
        hyp_id="P2-Target:accounting-manipulation::x",
        objective_id="Target:accounting-manipulation",
        title="Donation breaks the share/asset accounting invariant",
        category="accounting-manipulation",
        component="Vault",
        entry_point="flashLoan",
        attacker_capability="any external actor with a token balance",
        trust_boundary="user <-> vault",
        critical_asset="vault-liquidity",
        invariant="convertToShares(totalSupply) == totalAssets()",
        expected_impact="state-corruption: accounting diverges from assets",
        impact_id="state-corruption",
        strategy="donate to shift the live balance without minting shares",
        required_tools=["forge", "echidna"],
        reproduction_criteria="after a donation the invariant is false",
        falsification_criteria="the invariant holds for every donation",
        authorization_requirement="asset must be AUTHORIZED",
        novelty_requirement="a NoveltyReview must classify it LIKELY_NEW",
    )
    base.update(overrides)
    return GeneratedHypothesis(**base)


def _authorized_record(asset="vault-liquidity"):
    rec = new_record(
        program="DVDF-training", platform="local", target_url="local://dvdf",
        scope_url="local://dvdf/scope",
        program_active=True, safe_harbor=True, poc_required=True,
        nigerian_eligible=True, payout_feasible=True, zero_cost=True,
    )
    rec.verified = True
    rec.evidence = ["ev-training-scope"]
    rec.asset_classes = {asset: "AUTHORIZED"}
    return rec


def _plan() -> TestPlan:
    return TestPlan(method="dvdf", command="forge test --match-contract UnstoppablePoC -vv",
                    expected="2 pass", falsify="invariant holds")


# --------------------------------------------------------------------------- #
# Lifecycle: stage order and entry criteria
# --------------------------------------------------------------------------- #

def test_stage_order_is_the_mission_lifecycle():
    assert STAGE_ORDER == [
        "HYPOTHESIS", "TRIAGE", "SOURCE_ANALYSIS", "TEST_DESIGN",
        "REPRODUCTION", "INDEPENDENT_CHALLENGE", "VERDICT",
    ]


def test_incomplete_hypothesis_cannot_start(tmp_path):
    engine = InvestigationEngine(InvestigationStore(tmp_path))
    bad = _hypothesis(component="")   # missing a required field
    with pytest.raises(InvalidTransition) as exc:
        engine.start(bad)
    assert "incomplete hypothesis" in str(exc.value)


def test_illegal_transition_is_refused(tmp_path):
    engine = InvestigationEngine(InvestigationStore(tmp_path))
    state = engine.start(_hypothesis())
    # Jumping straight to TEST_DESIGN (skipping TRIAGE and SOURCE_ANALYSIS) is illegal.
    with pytest.raises(InvalidTransition):
        engine.design_test(state, _plan())


def test_cannot_design_test_without_sources(tmp_path):
    engine = InvestigationEngine(InvestigationStore(tmp_path))
    state = engine.start(_hypothesis())
    state = engine.triage(state, Triage.PURSUE)
    assert state.stage == Stage.SOURCE_ANALYSIS
    # No source recorded yet -> TEST_DESIGN entry criteria unmet.
    with pytest.raises(InvalidTransition) as exc:
        engine.design_test(state, _plan())
    assert "source" in str(exc.value).lower()


def test_test_plan_must_have_a_command(tmp_path):
    engine = InvestigationEngine(InvestigationStore(tmp_path))
    state = engine.start(_hypothesis())
    state = engine.triage(state, Triage.PURSUE)
    engine.add_source(state, "src/Vault.sol", function="flashLoan")
    with pytest.raises(InvalidTransition):
        engine.design_test(state, TestPlan(method="forge", command=""))


def test_reject_at_triage_requires_a_reason(tmp_path):
    engine = InvestigationEngine(InvestigationStore(tmp_path))
    state = engine.start(_hypothesis())
    with pytest.raises(InvalidTransition):
        engine.triage(state, Triage.REJECT)   # no reason
    state = engine.triage(state, Triage.REJECT, reason="already known / fixed upstream")
    assert state.status == "REJECTED_TRIAGE"
    assert state.is_terminal()


def test_defer_is_resumable(tmp_path):
    engine = InvestigationEngine(InvestigationStore(tmp_path))
    state = engine.start(_hypothesis())
    state = engine.triage(state, Triage.DEFER, reason="awaiting scope confirmation")
    assert state.stage == Stage.TRIAGE and not state.is_terminal()
    assert engine.store.get(state.investigation_id).triage_decision == Triage.DEFER


# --------------------------------------------------------------------------- #
# Authorization gate
# --------------------------------------------------------------------------- #

def test_reproduction_requires_authorization(tmp_path):
    """Without an authorization record, REPRODUCTION is refused."""
    engine = InvestigationEngine(InvestigationStore(tmp_path))   # no authz
    state = engine.start(_hypothesis())
    state = engine.triage(state, Triage.PURSUE)
    engine.add_source(state, "src/Vault.sol", function="flashLoan")
    state = engine.design_test(state, _plan())
    with pytest.raises(InvalidTransition) as exc:
        engine.reproduce(state, reproduce=lambda: (True, "boom"))
    assert "authorization" in str(exc.value).lower()


def test_out_of_scope_asset_cannot_reproduce(tmp_path):
    rec = _authorized_record()
    rec.asset_classes = {"vault-liquidity": "OUT_OF_SCOPE"}
    engine = InvestigationEngine(InvestigationStore(tmp_path), authorization=rec)
    state = engine.start(_hypothesis())
    state = engine.triage(state, Triage.PURSUE)
    engine.add_source(state, "src/Vault.sol", function="flashLoan")
    state = engine.design_test(state, _plan())
    with pytest.raises(InvalidTransition) as exc:
        engine.reproduce(state, reproduce=lambda: (True, "boom"))
    assert "OUT_OF_SCOPE" in str(exc.value) or "only AUTHORIZED" in str(exc.value)


def test_stale_authorization_blocks_reproduction(tmp_path):
    rec = _authorized_record()
    rec.checked_at = "2020-01-01T00:00:00+00:00"   # far older than the 7-day window
    engine = InvestigationEngine(InvestigationStore(tmp_path), authorization=rec)
    state = engine.start(_hypothesis())
    state = engine.triage(state, Triage.PURSUE)
    engine.add_source(state, "src/Vault.sol", function="flashLoan")
    state = engine.design_test(state, _plan())
    with pytest.raises(InvalidTransition) as exc:
        engine.reproduce(state, reproduce=lambda: (True, "boom"))
    assert "stale" in str(exc.value).lower()


def test_authorized_asset_reproduces(tmp_path):
    engine = InvestigationEngine(InvestigationStore(tmp_path),
                                 authorization=_authorized_record(),
                                 evidence=EvidenceStore(tmp_path / "ev"))
    state = engine.start(_hypothesis())
    state = engine.triage(state, Triage.PURSUE)
    engine.add_source(state, "src/Vault.sol", function="flashLoan")
    state = engine.design_test(state, _plan())
    state = engine.reproduce(state, reproduce=lambda: (True, "invariant violated"))
    assert state.reproduction["ran"] and state.reproduction["reproduced"]


# --------------------------------------------------------------------------- #
# Confirmation gate (independent challenge)
# --------------------------------------------------------------------------- #

def test_genuine_violation_needs_independent_challenge_to_confirm(tmp_path):
    engine = InvestigationEngine(InvestigationStore(tmp_path),
                                 authorization=_authorized_record(),
                                 evidence=EvidenceStore(tmp_path / "ev"))
    state = engine.start(_hypothesis())
    state = engine.triage(state, Triage.PURSUE)
    engine.add_source(state, "src/Vault.sol", function="flashLoan")
    state = engine.design_test(state, _plan())
    state = engine.reproduce(state, reproduce=lambda: (True, "violated"))
    # Challenge recorded but it did NOT reproduce -> must not be CONFIRMED.
    state = engine.challenge(state, independent=True, reproduced=False)
    state = engine.verdict(state, Observation(reproduced=True, impact_demonstrated=True))
    assert state.status == InvestigationStatus.UNCONFIRMED.value
    assert "did NOT reproduce" in state.verdict["gated_reason"]


def test_confirmed_when_independently_reproduced(tmp_path):
    engine = InvestigationEngine(InvestigationStore(tmp_path),
                                 authorization=_authorized_record(),
                                 evidence=EvidenceStore(tmp_path / "ev"))
    state = engine.start(_hypothesis())
    state = engine.triage(state, Triage.PURSUE)
    engine.add_source(state, "src/Vault.sol", function="flashLoan")
    state = engine.design_test(state, _plan())
    state = engine.reproduce(state, reproduce=lambda: (True, "violated"))
    state = engine.challenge(state, independent=True, reproduced=True, evidence_id="ev-2")
    state = engine.verdict(state, Observation(reproduced=True, impact_demonstrated=True))
    assert state.status == InvestigationStatus.CONFIRMED.value


def test_verdict_requires_a_challenge(tmp_path):
    engine = InvestigationEngine(InvestigationStore(tmp_path),
                                 authorization=_authorized_record(),
                                 evidence=EvidenceStore(tmp_path / "ev"))
    state = engine.start(_hypothesis())
    state = engine.triage(state, Triage.PURSUE)
    engine.add_source(state, "src/Vault.sol", function="flashLoan")
    state = engine.design_test(state, _plan())
    state = engine.reproduce(state, reproduce=lambda: (True, "violated"))
    with pytest.raises(InvalidTransition):
        engine.verdict(state, Observation(reproduced=True, impact_demonstrated=True))


def test_terminal_investigation_cannot_advance(tmp_path):
    engine = InvestigationEngine(InvestigationStore(tmp_path))
    state = engine.start(_hypothesis())
    state = engine.triage(state, Triage.REJECT, reason="out of scope for this program")
    with pytest.raises(InvalidTransition):
        engine.triage(state, Triage.PURSUE)


# --------------------------------------------------------------------------- #
# Outcome classification
# --------------------------------------------------------------------------- #

def test_outcome_precedence_is_honest():
    # Environmental failure beats everything: it is not a statement about the target.
    assert classify_outcome(Observation(environmental_error=True, reproduced=True,
                                        impact_demonstrated=True)) == Outcome.ENVIRONMENTAL_FAILURE
    # A correct rejection of malformed input is NOT a vulnerability.
    assert classify_outcome(Observation(malformed_input_rejected=True)) == Outcome.MALFORMED_INPUT_REJECTED
    # Self-DoS harms only the attacker.
    assert classify_outcome(Observation(self_harm_only=True, reproduced=True,
                                        impact_demonstrated=True)) == Outcome.SELF_DOS
    # The secure control also reproducing means the PoC does not discriminate.
    assert classify_outcome(Observation(control_reproduces=True, reproduced=True,
                                        impact_demonstrated=True)) == Outcome.FALSE_POSITIVE
    # Genuine violation requires reproduction *and* demonstrated impact.
    assert classify_outcome(Observation(reproduced=True, impact_demonstrated=True)) == Outcome.GENUINE_VIOLATION
    assert classify_outcome(Observation(reproduced=True, impact_demonstrated=False)) == Outcome.INCONCLUSIVE


def test_environmental_failure_is_incomplete_not_disproven(tmp_path):
    """An env failure must be retryable (INCOMPLETE), never 'disproven'."""
    mem = ResearchMemory(tmp_path / "mem")
    engine = InvestigationEngine(InvestigationStore(tmp_path / "inv"),
                                 authorization=_authorized_record(), memory=mem,
                                 evidence=EvidenceStore(tmp_path / "ev"))
    state = engine.start(_hypothesis())
    state = engine.triage(state, Triage.PURSUE)
    engine.add_source(state, "src/Vault.sol", function="flashLoan")
    state = engine.design_test(state, _plan())
    state = engine.reproduce(state, reproduce=lambda: (False, "forge not found"))
    state = engine.challenge(state, independent=True, reproduced=False)
    state = engine.verdict(state, Observation(environmental_error=True,
                                              note="forge binary missing"))
    assert state.status == InvestigationStatus.INCOMPLETE.value
    rec = mem.get(state.investigation_id)
    assert rec is not None and rec.status == InvestigationStatus.INCOMPLETE.value


def test_malformed_input_rejection_is_disproven(tmp_path):
    mem = ResearchMemory(tmp_path / "mem")
    engine = InvestigationEngine(InvestigationStore(tmp_path / "inv"),
                                 authorization=_authorized_record(), memory=mem,
                                 evidence=EvidenceStore(tmp_path / "ev"))
    state = engine.start(_hypothesis())
    state = engine.triage(state, Triage.PURSUE)
    engine.add_source(state, "src/Vault.sol", function="flashLoan")
    state = engine.design_test(state, _plan())
    state = engine.reproduce(state, reproduce=lambda: (False, "server rejected malformed sig"))
    state = engine.challenge(state, independent=True, reproduced=False)
    state = engine.verdict(state, Observation(malformed_input_rejected=True,
                                              note="the server correctly rejected it"))
    assert state.status == InvestigationStatus.DISPROVEN.value
    # And the reason is preserved in memory for the next cycle.
    rec = mem.get(state.investigation_id)
    assert rec is not None and "rejected" in rec.false_positive_reason


# --------------------------------------------------------------------------- #
# Persistence / resumption / failure recovery
# --------------------------------------------------------------------------- #

def test_interrupted_investigation_resumes_from_disk(tmp_path):
    store = InvestigationStore(tmp_path)
    engine = InvestigationEngine(store, authorization=_authorized_record(),
                                 evidence=EvidenceStore(tmp_path / "ev"))
    state = engine.start(_hypothesis())
    state = engine.triage(state, Triage.PURSUE)
    engine.add_source(state, "src/Vault.sol", function="flashLoan")
    state = engine.design_test(state, _plan())

    # Simulate a restart: a brand-new store + engine over the same directory.
    store2 = InvestigationStore(tmp_path)
    engine2 = InvestigationEngine(store2, authorization=_authorized_record(),
                                  evidence=EvidenceStore(tmp_path / "ev"))
    resumed = engine2.resume(state.investigation_id)
    assert resumed.stage == Stage.TEST_DESIGN
    assert resumed.sources and resumed.test_plan["command"]
    # And it can carry on to completion.
    resumed = engine2.reproduce(resumed, reproduce=lambda: (True, "violated"))
    assert resumed.reproduction["reproduced"]


def test_truncated_log_line_is_skipped_and_reported(tmp_path):
    store = InvestigationStore(tmp_path)
    engine = InvestigationEngine(store)
    state = engine.start(_hypothesis())
    # Simulate a crash that left a half-written final line.
    with store.path.open("a", encoding="utf-8") as fh:
        fh.write('{"type": "state", "id": "INV-x", "content": {')  # truncated
    recovered = store.get(state.investigation_id)
    assert recovered is not None, "a truncated tail must not lose the whole log"
    report = store.corruption_report()
    assert report["skipped_lines"] == 1 and report["ok"] is False


def test_store_is_append_only_and_replayable(tmp_path):
    store = InvestigationStore(tmp_path)
    engine = InvestigationEngine(store, authorization=_authorized_record())
    state = engine.start(_hypothesis())
    engine.triage(state, Triage.PURSUE)
    # Multiple state snapshots; replay yields the latest.
    states = store.all()
    assert len(states) == 1
    assert states[0].stage == Stage.SOURCE_ANALYSIS


# --------------------------------------------------------------------------- #
# Evidence integration
# --------------------------------------------------------------------------- #

def test_reproduction_captures_evidence(tmp_path):
    ev = EvidenceStore(tmp_path / "evidence")
    engine = InvestigationEngine(InvestigationStore(tmp_path / "inv"),
                                 authorization=_authorized_record())
    state = engine.start(_hypothesis())
    state = engine.triage(state, Triage.PURSUE)
    engine.add_source(state, "src/Vault.sol", function="flashLoan")
    state = engine.design_test(state, _plan())
    state = engine.reproduce(state, reproduce=lambda: (True, "INVARIANT VIOLATED"), evidence=ev)
    assert state.reproduction["evidence_id"]
    assert ev.get(state.reproduction["evidence_id"]) is not None


# --------------------------------------------------------------------------- #
# Test-plan construction from the tool selector
# --------------------------------------------------------------------------- #

def test_plan_from_tools_uses_class_aware_selection():
    hyp = _hypothesis(category="accounting-manipulation")
    plan = plan_from_tools(hyp, tools_available={"forge", "echidna"})
    assert plan.method in {"stateful-fuzz", "differential-pair"}
    assert "forge" in plan.tools
    assert plan.command


def test_plan_from_tools_notes_missing_tools():
    hyp = _hypothesis(category="accounting-manipulation")
    plan = plan_from_tools(hyp, tools_available=set())
    # The plan still names the tools the class needs; availability is a caller
    # concern (the tool selector reports missing separately).
    assert plan.tools


# --------------------------------------------------------------------------- #
# Novelty gate integration
# --------------------------------------------------------------------------- #

def test_novelty_gate_blocks_confirmation(tmp_path):
    class _BlockingGate:
        def allows_submission(self, finding_id):
            return False, "classified LIKELY_DUPLICATE (OSS-001)"

    engine = InvestigationEngine(InvestigationStore(tmp_path),
                                 authorization=_authorized_record(),
                                 evidence=EvidenceStore(tmp_path / "ev"),
                                 novelty_gate=_BlockingGate())
    state = engine.start(_hypothesis())
    state = engine.triage(state, Triage.PURSUE)
    engine.add_source(state, "src/Vault.sol", function="flashLoan")
    state = engine.design_test(state, _plan())
    state = engine.reproduce(state, reproduce=lambda: (True, "violated"))
    state = engine.challenge(state, independent=True, reproduced=True)
    state = engine.verdict(state, Observation(reproduced=True, impact_demonstrated=True))
    # A reproduced, independently-verified finding is still held if the novelty
    # gate blocks it -- a strong PoC does not establish originality.
    assert state.status == InvestigationStatus.UNCONFIRMED.value
    assert "novelty gate" in state.verdict["gated_reason"]
