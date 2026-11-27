"""The multi-frame EVM must agree with a real EVM, or its "PASS" means nothing.

A differential suite is only evidence if three things hold: the reference is real,
the cases actually exercise the semantics they claim, and a case that cannot be
compared reports SKIPPED rather than PASS. Each of those has failed here at least
once while the module was being written:

* anvil's exceptional halts were treated as skips, so a whole class of disagreement
  was invisible;
* a call case never emitted the CALL opcode, so ten "PASS"es compared two engines
  on a program that did nothing;
* operands were pushed in reverse order, so every call went to address zero.

The tests below are the standing guard. They require a real ``anvil``; when it is
absent they skip, and a skip is not a pass.
"""

from __future__ import annotations

import pytest

from blackheart.evmdiff import (
    CROSS_CASES,
    DEFAULT_CASES,
    SKIPPED,
    _reached_addresses,
    _selfcheck_cases,
    anvil_available,
    run_case,
    run_full_suite,
)

requires_anvil = pytest.mark.skipif(
    not anvil_available(), reason="anvil not installed; nothing was compared"
)


@pytest.fixture(scope="module")
def node():
    if not anvil_available():
        pytest.skip("anvil not installed; nothing was compared")
    from blackheart.statespace.runtime.evm import AnvilNode

    n = AnvilNode()
    n.start()
    try:
        yield n
    finally:
        n.stop()


# --------------------------------------------------------------------------- #
# Structural self-checks: no case may claim semantics its bytecode lacks
# --------------------------------------------------------------------------- #

def test_no_case_claims_semantics_its_bytecode_does_not_exercise():
    """A case naming CALL must contain a CALL opcode.

    This is the check that caught ten vacuous passes: the call cases asserted they
    exercised ``CALL`` while emitting no call opcode at all, so both engines were
    compared on a program that did nothing and agreed perfectly.
    """
    assert _selfcheck_cases() == []


def test_every_cross_case_declares_the_call_it_makes():
    assert CROSS_CASES, "the cross-contract cases are the point of a multi-frame EVM"
    for case in CROSS_CASES:
        assert case.exercises, f"{case.name} exercises nothing"


def test_the_suite_has_both_single_frame_and_cross_frame_cases():
    assert DEFAULT_CASES
    assert CROSS_CASES
    assert len(DEFAULT_CASES) + len(CROSS_CASES) == len(DEFAULT_CASES + CROSS_CASES)


# --------------------------------------------------------------------------- #
# A skip is not a pass
# --------------------------------------------------------------------------- #

def test_a_case_with_no_reference_node_reports_skipped_not_passed():
    case = DEFAULT_CASES[0]
    outcome = run_case(case, node=None)
    assert outcome.status is SKIPPED


# --------------------------------------------------------------------------- #
# The differential result against a real EVM
# --------------------------------------------------------------------------- #

@requires_anvil
def test_full_suite_agrees_with_anvil(node):
    report = run_full_suite(node)
    # Pin the count: a suite that silently stops running cases would otherwise
    # report a perfect score on nothing.
    assert len(report.cases) == len(DEFAULT_CASES) + len(CROSS_CASES)
    assert len(report.cases) == 26
    assert report.failed == 0, [
        (c.name, c.mismatches) for c in report.cases if c.status is not None and c.mismatches
    ]
    assert report.skipped == 0, [
        (c.name, c.detail) for c in report.cases if c.status is SKIPPED
    ]
    assert report.ok


@requires_anvil
def test_cross_contract_cases_prove_the_callee_actually_ran(node):
    """A cross-contract case must show the callee was reached, not merely that a
    call opcode existed. Comparing two engines on a call that never lands is the
    same vacuous pass in a different costume."""
    for case in CROSS_CASES:
        outcome = run_case(case, node)
        reached = outcome.ours["reached"]
        # The outermost frame is always "reached"; a cross-contract case must show
        # at least one *other* address whose code actually executed.
        assert len(reached) >= 2, f"{case.name}: only the outer frame ran: {reached}"


# --------------------------------------------------------------------------- #
# Mutation: the suite must detect a broken interpreter
# --------------------------------------------------------------------------- #

@requires_anvil
def test_the_suite_detects_a_deliberately_broken_call(node):
    """Inject a fault into the interpreter and confirm the suite notices.

    A differential suite that passes both before and after a real semantic bug is
    not measuring anything. This flips one call's destination and requires a FAIL.
    """
    from blackheart import evmworld

    original = evmworld._Frame._op_call
    calls = {"n": 0}

    def broken(self, *, kind: str) -> None:
        calls["n"] += 1
        # Corrupt only the first call, so the failure is attributable and the rest
        # of the suite stays comparable. A no-op replaces the real call: the frame
        # that should have run the callee's code never does.
        if calls["n"] == 1:
            return None
        return original(self, kind=kind)

    evmworld._Frame._op_call = broken
    try:
        report = run_full_suite(node)
    finally:
        evmworld._Frame._op_call = original

    assert report.failed > 0, (
        "a corrupted call was not detected by the differential suite; the suite "
        "is not comparing the semantics it claims to"
    )
