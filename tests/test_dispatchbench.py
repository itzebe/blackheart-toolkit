"""The dispatcher benchmark must measure against execution, not against itself.

Every assertion here exists because the benchmark, while it was being written, got
something wrong that made it report a number it had not earned:

* the fixture generator emitted ``DUP1`` where the solc shape needs the selector
  duplicated *before* the constant is pushed, so the comparison compared a value
  against itself and every selector looked reachable;
* a compare block with no jump over the bodies fell through into the first body,
  so an undispatched selector executed a body and the answer key was wrong;
* the oracle originally asked "did any storage write happen?", which counts a
  fallback write as a body entry;
* one answer key asserted a selector was unreachable when execution genuinely
  diverged to ``BAD_JUMP``.

The benchmark is only worth its output if the oracle and the answer key are
checked against each other. These tests hold that line.

Two further defects were found by an adversarial review *after* the first pass and
are pinned below: a fixed ``0x00000000`` fallback sentinel collided with a legal
selector, and ambiguous-but-reachable cases were excluded from the recall
denominator.
"""

from __future__ import annotations

import pytest

from blackheart.deployed import function_selector
from blackheart.dispatchbench import (
    FIXTURES,
    ConfusionMatrix,
    _classic_dispatch,
    _executes_body,
    _execution_signature,
    _pick_sentinel,
    run_benchmark,
    run_fixture,
)

A = function_selector("transfer(address,uint256)")
B = function_selector("balanceOf(address)")
# Never a fixed constant: 0x00000000 is a legal selector, and using it as the
# "unknown" probe would declare a contract that dispatches on it unreachable.
UNKNOWN = _pick_sentinel([A, B])


def _unused(dispatched: list[str]) -> str:
    """A selector that is neither dispatched nor the fallback sentinel."""
    taken = {"0x" + s for s in dispatched} | {UNKNOWN}
    value = 0xDEADBEEF
    while "0x%08x" % value in taken:
        value += 1
    return "0x%08x" % value


# --------------------------------------------------------------------------- #
# The oracle
# --------------------------------------------------------------------------- #

def test_oracle_separates_a_dispatched_selector_from_the_fallback():
    code = _classic_dispatch([A])
    sentinel = _pick_sentinel([A])
    assert _executes_body(code, A, sentinel) is True
    assert _executes_body(code, _unused([A]), sentinel) is False


def test_oracle_compares_against_the_fallback_not_against_a_storage_write():
    """Reachability is "a different code path ran", not "storage was written".

    The original oracle asked "did any storage write happen?", which scores a
    fallback that writes as though every selector reached a body. The differential
    signature is what makes the fallback's own behaviour irrelevant: a dispatched
    selector must differ from the fallback signature.
    """
    code = _classic_dispatch([A])
    sentinel = _pick_sentinel([A])
    assert _execution_signature(code, A) != _execution_signature(code, sentinel)


def test_oracle_treats_a_reverting_body_as_reached():
    """A body that reverts ran; calling it unreachable would score a right answer wrong."""
    code = _classic_dispatch([A])
    assert _executes_body(code, A, _pick_sentinel([A]))


def test_oracle_reports_an_unknown_selector_as_not_reachable():
    code = _classic_dispatch([A, B])
    sentinel = _pick_sentinel([A, B])
    assert _executes_body(code, _unused([A, B]), sentinel) is False


# --------------------------------------------------------------------------- #
# The fixture generator
# --------------------------------------------------------------------------- #

def test_two_selector_dispatcher_dispatches_both_and_neither_other():
    code = _classic_dispatch([A, B])
    sentinel = _pick_sentinel([A, B])
    assert _executes_body(code, A, sentinel)
    assert _executes_body(code, B, sentinel)
    assert not _executes_body(code, function_selector("approve(address,uint256)"), sentinel)


def test_compare_blocks_do_not_fall_through_into_a_body():
    """An undispatched selector must not execute the first body.

    This is the exact shape bug: without the unconditional JUMP over the bodies, a
    selector that matched no comparison ran the first body and the benchmark
    believed it was dispatched.
    """
    code = _classic_dispatch([A, B])
    unused = function_selector("renounceOwnership()")
    assert not _executes_body(code, unused, _pick_sentinel([A, B, unused]))


# --------------------------------------------------------------------------- #
# The answer key is checked against execution
# --------------------------------------------------------------------------- #

def test_every_answer_key_entry_agrees_with_execution():
    """A wrong answer key is a hard error, not a silent miscalculation."""
    report = run_benchmark()
    assert report.errors == [], f"answer key rejected by execution: {report.errors}"


def test_every_fixture_is_scored():
    report = run_benchmark()
    assert len(report.fixtures) == len(FIXTURES)
    assert report.cases, "the benchmark produced no cases"


# --------------------------------------------------------------------------- #
# The measured numbers
# --------------------------------------------------------------------------- #

def test_benchmark_measures_precision_and_recall_honestly():
    """Pin the measured performance so a regression is visible, not silent.

    Precision is 1.0: the analyser never called an unreachable selector reachable.
    Recall is below 1.0 by exactly one case -- a comparison that jumps to an
    invalid destination, which *does* divert execution (to ``BAD_JUMP``) but which
    the analyser reports as PRESENT_ONLY because the target is not a JUMPDEST.
    That is a real, documented false negative, and the assertion below states the
    measured value rather than pretending the gap does not exist.
    """
    report = run_benchmark()
    matrix = report.matrix
    assert matrix.precision == 1.0
    assert matrix.recall is not None
    assert 0.8 <= matrix.recall < 1.0
    assert matrix.false_positive == 0
    assert matrix.unresolved == 0


def test_the_known_false_negative_is_the_bad_jump_case():
    """Name the one disagreement, so it cannot quietly become a second one."""
    report = run_benchmark()
    disagreements = [c for c in report.cases if c.agree is False]
    assert len(disagreements) == 1
    case = disagreements[0]
    assert case.predicted == "PRESENT_ONLY"
    assert case.actual == "REACHABLE"


def test_a_wrong_answer_key_is_caught_rather_than_trusted():
    """The check that caught three of this benchmark's own bugs must still fire."""
    from blackheart.dispatchbench import Fixture

    bad = Fixture(
        name="deliberately-wrong-key",
        code=_classic_dispatch([A]),
        expected_reachable=[function_selector("renounceOwnership()")],
        note="claims a selector is reachable that the dispatcher never dispatches",
    )
    with pytest.raises(AssertionError):
        run_fixture(bad)


# --------------------------------------------------------------------------- #
# Two defects an adversarial review found after the first pass
# --------------------------------------------------------------------------- #

def test_the_fallback_probe_never_collides_with_a_real_selector():
    """A fixed sentinel is a latent bug: 0x00000000 is a legal selector.

    An adversarial review found that using 0x00000000 as the "unknown" probe
    would declare a contract that dispatches on 0x00000000 unreachable without
    executing it. The sentinel must be chosen from values absent from the
    candidate set.
    """
    sentinel = _pick_sentinel([A, B, "0x00000000"])
    assert sentinel not in {"0x" + A, "0x" + B, "0x00000000"}

    # A contract that really dispatches on 0x00000000 must be measured by
    # execution, not short-circuited by the sentinel.
    zero = "0x00000000"
    code = _classic_dispatch([zero])
    other = _pick_sentinel([zero])
    assert _executes_body(code, zero, other) is True


def test_executes_body_refuses_a_sentinel_that_is_also_the_selector():
    """The old silent ``return False`` hid the collision; it must raise instead."""
    code = _classic_dispatch([A])
    with pytest.raises(ValueError):
        _executes_body(code, A, A)


def test_recall_counts_a_reachable_selector_left_unresolved():
    """An ambiguous reachable selector is a miss, not a free pass.

    An adversarial review found that ``unresolved`` cases were excluded from the
    recall denominator, so an analyser that answered AMBIGUOUS for every
    reachable selector could report perfect recall on nothing.
    """
    matrix = ConfusionMatrix(true_positive=1, unresolved=3, unresolved_reachable=3)
    assert matrix.recall == pytest.approx(1 / 4)
    # The denominator is reported so a reader can see what was excluded.
    assert matrix.to_dict()["recall_denominator"] == 4


def test_a_fixture_that_dispatches_on_0x00000000_is_scored_by_execution():
    """The fallback sentinel must not shadow a real 0x00000000 dispatcher.

    This is the end-to-end form of the sentinel test: it runs the whole fixture
    path (``run_fixture`` -> ``_observed_reachable`` -> ``_pick_sentinel``), so a
    regressed hard-coded 0x00000000 sentinel raises here instead of silently
    declaring a dispatched selector unreachable.
    """
    from blackheart.dispatchbench import Fixture

    zero = "0x00000000"
    fixture = Fixture(
        name="dispatches-on-the-zero-selector",
        code=_classic_dispatch([zero]),
        expected_reachable=[zero],
        note="the fixture dispatches on 0x00000000, a legal selector",
    )
    cases = run_fixture(fixture)
    scored = {c.selector: c for c in cases}
    assert scored[zero].actual == "REACHABLE"
    assert scored[zero].agree is not None


def test_known_answer_corpus_declares_a_positive_so_recall_is_measurable():
    """A corpus of negatives only makes precision look perfect and recall undefined.

    Before this test the known-answer corpus declared 16 cases and *none* with
    ``expect_defect: True``, so ``testsparker --known-answer`` could not compute
    recall at all -- and the generator dropped the field even when it was present,
    so the metric would have stayed unavailable regardless. Both halves are pinned
    here: a declared positive reaches the test, and the adapter finds it.
    """
    from blackheart.evaluation import compute_metrics
    from blackheart.testsparker import get_adapter

    adapter = get_adapter("dispatch")
    corpus = adapter.known_answer_corpus()
    assert any(c.get("expect_defect") for c in corpus), "no positive case in the corpus"

    tests = adapter.generate(corpus=corpus)
    outcomes = [adapter.execute(t) for t in tests]
    expected = {t.test_id for t in tests if t.expectation.get("expect_defect")}
    assert expected, "the declared ground truth never reached a generated test"

    metrics = compute_metrics(outcomes, known_answer=True, expected_defects=expected)
    assert metrics["recall"]["value"] == 1.0, metrics["recall"]
    assert metrics["false_positives"] == 0, metrics
    assert metrics["false_negatives"] == 0, metrics


def test_cli_reports_precision_and_recall_with_known_answer(tmp_path, capsys):
    import json as _json

    from blackheart.cli import main

    # A known-answer run is a measurement, so a correct detection exits 0.
    assert main(["testsparker", "--known-answer", "--json"]) == 0
    payload = _json.loads(capsys.readouterr().out)
    assert payload["metrics"]["recall"]["value"] == 1.0
    assert payload["metrics"]["precision"]["value"] == 1.0
