"""Acceptance tests for the universal hunt orchestrator (T3).

The hunt is a *composition*: it must run the existing engines in order, pass each
stage's real output to the next, and never upgrade a lead it did not prove. These
tests assert the honest verdict ladder and that the composition introduces no new
claim: a certified-but-uncontrolled candidate is not a finding, a controlled one
is, and the differential (vulnerable vs guarded) is respected end to end.
"""

from __future__ import annotations

from blackheart.hunt import HUNT_STAGES, HuntConfig, HuntResult, hunt


def _small_config(**kw) -> HuntConfig:
    """A fast hunt config: the composition, not the search depth, is under test."""
    base = dict(stages=("search", "certify", "verify"),
                certify_depth=2, corpus_sequences=600, random_runs=120)
    base.update(kw)
    return HuntConfig(**base)


def test_hunt_stages_are_the_doctrine_order():
    assert HUNT_STAGES == ("recall", "search", "certify", "verify", "order", "remember")


def test_hunt_runs_every_requested_stage_and_reports_each():
    res = hunt("vulnerable", _small_config())
    assert isinstance(res, HuntResult)
    ran = {s.stage for s in res.stages if s.ran}
    assert {"search", "certify", "verify"} <= ran
    # Every stage in HUNT_STAGES is represented (ran or explicitly skipped).
    assert {s.stage for s in res.stages} == set(HUNT_STAGES)


def test_hunt_certifies_a_candidate_and_is_honest_without_a_control():
    # No control factory: the verifier cannot establish control integrity, so the
    # verdict is "reproduced, not yet controlled" -- never "verified".
    res = hunt("vulnerable", _small_config())
    assert res.candidates, "the vulnerable target must yield candidates"
    assert res.certified, "every candidate must be certified to a witness"
    assert res.verified == []
    assert res.reproduced
    assert res.verdict_line().startswith("REPRODUCED, NOT YET CONTROLLED")


def test_hunt_independently_verifies_with_a_control():
    cfg = _small_config(
        control_factory=lambda: __import__(
            "blackheart.invariants.registry", fromlist=["make_target"]
        ).make_target("safe"),
        in_scope=True, authorization_gate_passed=True,
    )
    res = hunt("vulnerable", cfg)
    assert res.verified, "a discriminating control must promote to INDEPENDENTLY_VERIFIED"
    assert res.reproduced == []
    assert res.verdict_line().startswith("VERIFIED")


def test_hunt_is_a_bounded_negative_on_the_guarded_target():
    res = hunt("safe", _small_config())
    assert res.candidates == []
    assert res.certified == []
    assert res.verified == []
    line = res.verdict_line()
    assert "NOT FOUND" in line
    # A clean result is bounded, never a proof of absence.
    assert "NOT a proof of absence" in line or "does NOT cover" in line


def test_hunt_certifies_but_does_not_verify_when_verify_is_skipped():
    res = hunt("vulnerable", _small_config(stages=("search", "certify")))
    assert res.certified
    assert res.verifications == []
    assert res.verdict_line().startswith("CERTIFIED LEAD")


def test_hunt_memory_round_trip_writes_only_proven_attacks(tmp_path):
    mem = str(tmp_path / "mem.jsonl")
    cfg = _small_config(
        stages=("search", "certify", "verify", "remember"),
        control_factory=lambda: __import__(
            "blackheart.invariants.registry", fromlist=["make_target"]
        ).make_target("safe"),
        in_scope=True, authorization_gate_passed=True, memory=True, memory_path=mem,
    )
    res = hunt("vulnerable", cfg)
    assert res.verified
    assert res.remembered == len(res.certified)
    assert (tmp_path / "mem.jsonl").exists()


def test_hunt_memory_writes_nothing_unproven(tmp_path):
    # Without a control the candidates are not proven; the memory must stay empty.
    mem = str(tmp_path / "mem.jsonl")
    res = hunt("vulnerable", _small_config(
        stages=("search", "certify", "verify", "remember"), memory=True, memory_path=mem))
    assert res.verified == []
    assert res.remembered == 0
    assert not (tmp_path / "mem.jsonl").exists()


def test_hunt_ordering_stage_searches_interleavings():
    res = hunt("vulnerable", _small_config(
        stages=("order",), scenario="sandwich", max_attacker_steps=2, max_orderings=800))
    assert res.ordering is not None
    assert res.ordering["orderings_tried"] > 0


def test_hunt_ordering_unknown_scenario_is_an_honest_error():
    res = hunt("vulnerable", _small_config(stages=("order",), scenario="not-a-scenario"))
    stage = next(s for s in res.stages if s.stage == "order")
    assert stage.error and "unknown scenario" in stage.error
    assert res.ordering is None


def test_hunt_result_serialises_to_dict():
    res = hunt("vulnerable", _small_config())
    d = res.to_dict()
    assert d["target"]
    assert isinstance(d["stages"], list)
    assert isinstance(d["verdict"], str)
    assert "candidates" in d and "certified" in d and "verifications" in d


def test_hunt_accepts_a_target_object():
    from blackheart.invariants.registry import make_target

    res = hunt(make_target("vulnerable"), _small_config())
    assert res.target == "vulnerable-vault"
    assert res.candidates
