"""TestSparker must actually detect defects, and must never invent one.

Two failure modes are tested here, and the second matters more than the first:

* **A vacuous adapter** that never reports anything is useless. So the adapter is
  required to catch a *real, historically-documented* regression: the via-IR
  ``SUB``-for-zero equality bug. The test injects that exact regression and asserts
  the adapter fires. If this test passes while the adapter is broken, the adapter
  has no oracle.
* **An over-eager adapter** that calls every difference a vulnerability is worse
  than useless -- it burns investigation budget on fiction. So the adapter is
  required to report *zero* defects against the correct analyser, including on
  contracts whose fallback/receive paths legitimately differ.

Both directions are checked because a test suite that only checks "does it fire"
can be satisfied by an adapter that always fires.
"""

from __future__ import annotations

import pytest

from blackheart import deployed_selectors as ds
from blackheart.testsparker import (
    DISPOSITION_CONFIRMED_DEFECT,
    DISPOSITION_INCONCLUSIVE,
    DISPOSITION_NO_SIGNAL,
    GeneratedTest,
    adapter_names,
    get_adapter,
)


@pytest.fixture()
def adapter():
    return get_adapter("dispatch")


def test_dispatch_is_the_registered_first_adapter():
    assert "dispatch" in adapter_names()


def test_generation_is_deterministic(adapter):
    a = [t.to_dict() for t in adapter.generate(seed=7)]
    b = [t.to_dict() for t in adapter.generate(seed=7)]
    assert a == b, "same seed must produce the same tests"


def test_generation_executes_nothing(adapter):
    """generate() must be pure: it may not run code under test."""
    tests = adapter.generate(seed=0, limit=5)
    for t in tests:
        assert t.kind and t.adapter == "dispatch"
        assert t.rationale, "every generated test explains what it targets"


def test_validate_rejects_a_bad_selector(adapter):
    bad = GeneratedTest(
        test_id="x", adapter="dispatch", kind="analysis_matches_execution",
        code="6001", input={"selector": "abcd"},  # 2 bytes, not 4
    )
    assert adapter.validate(bad) is not None


def test_validate_rejects_non_hex_code(adapter):
    bad = GeneratedTest(
        test_id="x", adapter="dispatch", kind="analysis_matches_execution",
        code="zzzz", input={"selector": "aabbccdd"},
    )
    assert adapter.validate(bad) is not None


def test_validate_rejects_unknown_kind(adapter):
    bad = GeneratedTest(
        test_id="x", adapter="dispatch", kind="not_a_kind", code="6001",
    )
    assert adapter.validate(bad) is not None


def test_an_invalid_test_is_inconclusive_not_a_pass(adapter):
    bad = GeneratedTest(
        test_id="x", adapter="dispatch", kind="analysis_matches_execution",
        code="zzzz", input={"selector": "aabbccdd"},
    )
    outcome = adapter.execute(bad)
    assert outcome.disposition == DISPOSITION_INCONCLUSIVE
    assert not outcome.defect_signal, "a test that did not run cannot report a defect"


def test_the_correct_analyser_produces_no_false_defects(adapter):
    """The whole suite against the real analyser must be silent.

    A single CONFIRMED_DEFECT here means the adapter manufactures findings. That
    is the failure this assertion exists to prevent.
    """
    outcomes = [adapter.execute(t) for t in adapter.generate(seed=0)]
    assert outcomes, "no tests generated"
    signals = [o for o in outcomes if o.defect_signal]
    assert signals == [], f"false defects: {[o.detail for o in signals][:3]}"
    assert all(
        o.disposition in (DISPOSITION_NO_SIGNAL, DISPOSITION_INCONCLUSIVE)
        for o in outcomes
    )


def test_the_adapter_detects_the_real_via_ir_regression(adapter, monkeypatch):
    """Inject the historic bug and require the adapter to catch it.

    The bug: solc's via-IR pipeline tests selector equality as ``a - b == 0``, so
    the analyser must accept ``SUB``. Disabling that path reproduces the real
    false negative that shipped once. The adapter's oracle is the contract's own
    ABI, so it must fire.
    """
    tests = [t for t in adapter.generate(seed=0) if t.generation.get("case", "").endswith("_ir")]
    assert tests, "no via-IR fixtures found"

    monkeypatch.setattr(ds, "_SUB", -1)
    outcomes = [adapter.execute(t) for t in tests]
    caught = [o for o in outcomes if o.disposition == DISPOSITION_CONFIRMED_DEFECT]
    assert caught, "the adapter failed to detect the injected via-IR false negative"
    assert any("false negative" in o.detail for o in caught)


def test_the_adapter_detects_a_false_positive_claim(adapter):
    """A claim of REACHABLE for a selector that is not in the ABI must be checked.

    Built directly: a contract with a bogus jump destination claims a selector is
    reachable, but the jump can never land. Execution is the arbiter.
    """
    head = bytes.fromhex("60003560e01c")
    compare = bytes.fromhex("63" + "aaaaaaaa" + "14")
    dest = len(head) + len(compare) + 3
    code = (head + compare + b"\x61" + dest.to_bytes(2, "big") + b"\x57"
            + bytes.fromhex("60006000fd"))
    test = GeneratedTest(
        test_id="bogus", adapter="dispatch",
        kind="bogus_destination_is_not_reachable",
        code=code.hex(), input={"selector": "aaaaaaaa", "calldata_suffix": "00" * 32},
    )
    outcome = adapter.execute(test)
    # The analyser rejects a non-JUMPDEST destination, so there is no reachable
    # claim; execution also fails. They agree -> no defect.
    assert outcome.disposition == DISPOSITION_NO_SIGNAL


def test_reports_are_machine_readable(adapter):
    import json

    payload = [t.to_dict() for t in adapter.generate(seed=0, limit=3)]
    json.dumps(payload)  # must not raise
    outcomes = [adapter.execute(GeneratedTest.from_dict(d)).to_dict() for d in payload]
    json.dumps(outcomes)


def test_round_trip_through_dict(adapter):
    original = adapter.generate(seed=0, limit=1)[0]
    restored = GeneratedTest.from_dict(original.to_dict())
    assert restored.to_dict() == original.to_dict()
