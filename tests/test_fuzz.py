"""Acceptance tests for the coverage-guided corpus fuzzer.

These assert the properties the capability claims, each against real code paths
(no mocks):

  * determinism -- the same seed gives the same report;
  * a real separation -- on the deep, ordered, state-gated fixture the coverage-
    guided fuzzer detects the bug and the random stateful fuzzer does not, at the
    same budget;
  * no false positives -- neither engine reports the invariant on the guarded
    control;
  * the value account is attached to a priced finding;
  * the coverage signal distinguishes states the random walk cannot.
"""

from __future__ import annotations

from blackheart.fuzz import CorpusConfig, CoverageGuidedFuzzer
from blackheart.fuzz.coverage import CoverageMap, behaviour_features
from blackheart.invariants.engine import FuzzConfig, StatefulFuzzer
from blackheart.statespace.hard import (
    DeepGatedEscalation,
    GuardedDeepGatedEscalation,
    make_hard,
)

BUDGET = 3000
STEPS = 20
SEED = 0


def test_corpus_fuzzer_is_deterministic():
    a = CoverageGuidedFuzzer(make_hard("deep-gated-escalation"),
                             CorpusConfig(seed=7, max_sequences=1500, max_steps=STEPS)).run()
    b = CoverageGuidedFuzzer(make_hard("deep-gated-escalation"),
                             CorpusConfig(seed=7, max_sequences=1500, max_steps=STEPS)).run()
    assert a.to_dict() == b.to_dict()


def test_corpus_fuzzer_finds_deep_ordered_bug_random_misses():
    inv = "no-overdraw"
    corpus = CoverageGuidedFuzzer(
        make_hard("deep-gated-escalation"),
        CorpusConfig(seed=SEED, max_sequences=BUDGET, max_steps=STEPS),
    ).run()
    assert any(f.inv_id == inv for f in corpus.failures), (
        "coverage-guided fuzzer must reach the 8-step ordered escalation"
    )

    random_report = StatefulFuzzer(
        make_hard("deep-gated-escalation"),
        FuzzConfig(runs=BUDGET, steps_per_run=STEPS, seed=SEED),
    ).run()
    assert not any(f.inv_id == inv for f in random_report.failures), (
        "the random baseline is not expected to reach the deep ordered bug at "
        "this budget -- if it now does, the separation claim must be re-measured"
    )


def test_neither_engine_flags_the_guarded_control():
    inv = "no-overdraw"
    corpus = CoverageGuidedFuzzer(
        make_hard("deep-gated-escalation-guarded"),
        CorpusConfig(seed=SEED, max_sequences=BUDGET, max_steps=STEPS),
    ).run()
    assert not any(f.inv_id == inv for f in corpus.failures)

    random_report = StatefulFuzzer(
        make_hard("deep-gated-escalation-guarded"),
        FuzzConfig(runs=BUDGET, steps_per_run=STEPS, seed=SEED),
    ).run()
    assert not any(f.inv_id == inv for f in random_report.failures)


def test_finding_carries_a_priced_economic_account():
    report = CoverageGuidedFuzzer(
        make_hard("deep-gated-escalation"),
        CorpusConfig(seed=SEED, max_sequences=BUDGET, max_steps=STEPS,
                     price_findings=True),
    ).run()
    assert report.failures, "expected a finding"
    assert len(report.economic) == len(report.failures)
    # The attacker overdraws a 100 balance by 1000: the account must show a real
    # gain, not a fabricated one.
    acct = report.economic[0]
    assert acct["attacker_profit"] > 0
    assert acct["field_kinds"], "field classification must be recorded"


def test_report_records_sequences_to_detection():
    report = CoverageGuidedFuzzer(
        make_hard("deep-gated-escalation"),
        CorpusConfig(seed=SEED, max_sequences=BUDGET, max_steps=STEPS),
    ).run()
    assert report.detection_at, "a detection must record when it happened"
    assert all(1 <= at <= BUDGET for at in report.detection_at)


def test_coverage_distinguishes_ordered_states():
    """Two sequences that reach different stages must differ in coverage.

    This is the whole premise: a state counter's value is the signal, so the
    bitmap separates stage 2 from stage 3 (which the random walk cannot exploit).
    """
    target = DeepGatedEscalation()
    from blackheart.models import AttackStep

    def seq(*ops):
        return [AttackStep(index=i, actor="attacker", action=o, params={})
                for i, o in enumerate(ops)]

    cover = CoverageMap()
    early = behaviour_features(target, seq("register", "verify"))[0]
    deeper = behaviour_features(target, seq("register", "verify", "upgrade"))[0]
    assert cover.merge(early) > 0
    assert cover.merge(deeper) > 0, "a deeper ordered prefix must add coverage"
