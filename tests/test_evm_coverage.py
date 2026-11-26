"""Acceptance tests for real EVM execution coverage (T2.5).

The behavioural coverage signal works on every target, but on a real EVM the
strongest signal is the actual instruction stream the contract executed. These
tests pin the EVM coverage oracle (struct-log -> bitmap features), its honesty
when tracing is unavailable, and the universal hook that lets the fuzzer consume
it -- while leaving every non-instrumented target unchanged.
"""

from __future__ import annotations

from blackheart.fuzz.coverage import _target_coverage_features, behaviour_features
from blackheart.models import AttackStep
from blackheart.statespace.runtime.evm_coverage import (
    EvmCoverageOracle,
    features_from_struct_logs,
)

TRACE = {
    "structLogs": [
        {"pc": 0, "op": "PUSH1", "depth": 1},
        {"pc": 2, "op": "CALL", "depth": 1},
        {"pc": 10, "op": "SSTORE", "depth": 2},
    ]
}


def test_struct_logs_become_opcode_pc_and_edge_features():
    tc = features_from_struct_logs(TRACE, label="deposit")
    assert tc.steps == 3
    assert ("evm_op", "deposit", "CALL") in tc.features
    assert ("evm_pc", "deposit", 2, 10) in tc.features        # depth 2, pc 10
    assert ("evm_edge", "deposit", 0, 2) in tc.features       # pc transition
    assert not tc.note


def test_distinct_code_paths_produce_distinct_features():
    # Two runs over the same pc set in a different order must differ on the edge
    # features -- that is the branch signal the fuzzer needs.
    a = features_from_struct_logs({"structLogs": [{"pc": 0, "op": "A", "depth": 1},
                                                  {"pc": 2, "op": "B", "depth": 1}]})
    b = features_from_struct_logs({"structLogs": [{"pc": 2, "op": "B", "depth": 1},
                                                  {"pc": 0, "op": "A", "depth": 1}]})
    assert set(a.features) != set(b.features)


def test_empty_or_unexpected_trace_is_honest_not_invented():
    assert features_from_struct_logs({"structLogs": []}).note
    assert features_from_struct_logs(None).features == []
    assert features_from_struct_logs({"unexpected": 1}).features == []


def test_oracle_collects_features_and_records_failures_without_raising():
    class FakeRpc:
        def __init__(self, fail=False):
            self.fail = fail

        def call(self, method, params=None):
            if self.fail:
                raise RuntimeError("no debug api")
            return TRACE

    ok = EvmCoverageOracle(FakeRpc())
    ok.begin_run()
    ok.collect("0xabc", label="deposit")
    assert len(ok.features()) == 8
    assert ok.to_dict()["transactions_traced"] == 1

    bad = EvmCoverageOracle(FakeRpc(fail=True))
    bad.begin_run()
    bad.collect("0xdef")                    # must not raise
    assert bad.features() == []
    assert bad.to_dict()["notes"]


def test_oracle_begin_run_clears_the_previous_buffer():
    class FakeRpc:
        def call(self, method, params=None):
            return TRACE

    o = EvmCoverageOracle(FakeRpc())
    o.begin_run()
    o.collect("0x1")
    assert o.features()
    o.begin_run()
    assert o.features() == []               # a new run starts clean


def test_coverage_hook_is_optional_and_never_breaks_a_plain_target():
    class Plain:
        pass

    assert _target_coverage_features(Plain(), "step") == ()
    assert _target_coverage_features(Plain(), "run") == ()

    class Hooked:
        def step_coverage_features(self):
            return [("evm_pc", "x", 0)]

    assert list(_target_coverage_features(Hooked(), "step")) == [("evm_pc", "x", 0)]


def test_hooked_coverage_is_folded_into_the_behavioural_bitmap():
    # A target whose *state* never changes but whose code path does must still be
    # distinguished by coverage -- the hook is what carries that signal.
    from blackheart.invariants.engine import InvariantSpec, OpSpec

    class Stateful:
        name = "stateful"

        def __init__(self):
            self.path = 0

        def reset(self):
            self.path = 0
            return {}

        def ops(self):
            return [OpSpec("a", ["x"], {}), OpSpec("b", ["x"], {})]

        def invariants(self):
            return [InvariantSpec("inv", "holds", lambda st: True)]

        def step(self, state, op_name, actor, params):
            self.path += 1

        def snapshot(self, state):
            return {"constant": 1}      # deliberately unchanging

        def run_coverage_features(self):
            return [("evm_path", self.path)]

    t = Stateful()
    seq_a = [AttackStep(0, "x", "a", {})]
    seq_ab = [AttackStep(0, "x", "a", {}), AttackStep(1, "x", "b", {})]
    buckets_a, _, _ = behaviour_features(t, seq_a)
    buckets_ab, _, _ = behaviour_features(t, seq_ab)
    assert set(buckets_a) != set(buckets_ab)
