"""Compiled bytecode differential: the guarded revision must refuse the window."""

from __future__ import annotations

from blackheart.evm_fuzz import (
    calldata_words,
    coverage_fuzz,
    differential_fuzz,
    run_bytecode,
)


def _window() -> bytes:
    return bytes([
        0x60, 0x00, 0x35, 0x61, 0x02, 0xEE, 0x10,
        0x60, 0x00, 0x35, 0x61, 0x03, 0x20, 0x10, 0x15, 0x16,
        0x60, 0x14, 0x57, 0x00, 0x5B,
        0x60, 0x00, 0x60, 0x00, 0xFD,
    ])


def _guarded() -> bytes:
    return bytes([
        0x60, 0x00, 0x35, 0x61, 0x03, 0x20, 0x10,
        0x60, 0x0B, 0x57, 0x00, 0x5B,
        0x60, 0x00, 0x60, 0x00, 0xFD,
    ])


def test_the_window_is_a_real_outcome_divergence():
    report = differential_fuzz(_window(), _guarded(),
                               calldata_words([500, 751, 800, 801, 1000]))
    assert report.checked == 5
    assert report.identical == 1
    assert [d.kind for d in report.divergences] == ["outcome"] * 4
    by_value = {int(d.calldata, 16): d for d in report.divergences}
    for value in (751, 800):
        assert by_value[value].vulnerable["succeeded"] is False
        assert by_value[value].guarded["succeeded"] is True
    for value in (801, 1000):
        assert by_value[value].vulnerable["succeeded"] is True
        assert by_value[value].guarded["succeeded"] is False


def test_a_storage_difference_is_reported_when_both_succeed():
    store_one = bytes([0x60, 0x01, 0x60, 0x00, 0x55, 0x00])   # SSTORE(0, 1)
    store_two = bytes([0x60, 0x02, 0x60, 0x00, 0x55, 0x00])   # SSTORE(0, 2)
    report = differential_fuzz(store_one, store_two, [b""])
    assert report.checked == 1
    assert report.divergences and report.divergences[0].kind == "state"


def test_identical_revisions_produce_no_divergence():
    report = differential_fuzz(_window(), _window(), calldata_words([1, 2, 3]))
    assert report.checked == 3
    assert report.identical == 3
    assert not report.found


def test_run_bytecode_returns_the_concrete_outcome():
    result = run_bytecode(_window(), calldata_words([800])[0])
    assert not result.succeeded
    assert str(result.halt) == "REVERT"


# if calldata[0] != 0 jump to 7; otherwise stop at 6
_BRANCH = bytes([0x60, 0x00, 0x35, 0x60, 0x07, 0x57, 0x00, 0x5B, 0x00])


def test_pc_collection_is_opt_in():
    assert run_bytecode(_BRANCH, b"").frame.pcs == []
    traced = run_bytecode(_BRANCH, b"", collect_pcs=True)
    assert traced.frame.pcs and traced.frame.pcs[0] == 0


def test_coverage_fuzz_reaches_both_sides_of_a_branch():
    report = coverage_fuzz(_BRANCH, [b""], iterations=200, seed=1)
    assert 6 in report.covered
    assert 7 in report.covered
    assert report.new_paths >= 1
    assert report.corpus_size >= 2


def test_coverage_fuzz_records_reverting_inputs():
    always_reverts = bytes([0x60, 0x00, 0x60, 0x00, 0xFD])
    report = coverage_fuzz(always_reverts, [b""], iterations=5, seed=2)
    assert report.reverting
