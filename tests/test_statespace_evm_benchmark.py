"""Fair comparison of the external-EVM discovery approaches.

Mission 04 asks for a fair competitive comparison against conventional approaches,
each given the same target, operations and budget. These tests exercise the
comparison machinery and assert the *honest* properties it must have:

  * every approach is judged on the same invariant;
  * the random baseline is a real uniform sampler over the identical space, not a
    straw man, and receives the same reproduction/verification treatment;
  * the project's own upstream test is recorded as provenance only, never as a
    detection result;
  * the search-space cardinality is reported, so the regime is explicit.

Node-backed rows skip when the harness is not built (a skip is not a pass).
"""

from __future__ import annotations

import pytest

from blackheart.statespace.runtime.evm_benchmark import (
    _search_space,
    compare_case,
    native_test_result,
)
from blackheart.statespace.runtime.evm_registry import ALL_CASES


def _no_foundry() -> bool:
    from blackheart.statespace.runtime.evm import _foundry_bin

    return _foundry_bin("anvil") is None or _foundry_bin("cast") is None


#: cases with a mapped upstream Foundry test (see ``evm_benchmark._NATIVE_TESTS``)
_MAPPED_CASES = frozenset({
    "dvdf-unstoppable", "dvdf-truster", "dvdf-naive-receiver",
    "ethernaut-fallout", "ethernaut-token",
})


def _mapped_harness_ready(name: str, *, dvdf_ready: bool, ethernaut_ready: bool) -> bool:
    """A mapped case's provenance row can only be asserted when its upstream
    harness is built; otherwise ``native_test_result`` returns a "could not run"
    diagnostic and the row must be skipped, never asserted."""
    return ethernaut_ready if name.startswith("ethernaut") else dvdf_ready


def test_search_space_cardinality_is_reported():
    from blackheart.statespace import ExploreConfig

    cfg = ExploreConfig(max_steps=6)
    for name in ALL_CASES:
        space = _search_space(name, cfg)
        assert space["operations"] >= 1
        assert space["per_step_choices"] >= 1
        # a strictly growing sum over lengths 1..max_steps
        assert space["distinct_sequences"] >= space["per_step_choices"]


def test_native_test_note_is_provenance_only(dvdf_ready, ethernaut_ready):
    # For cases with a mapped upstream test, the provenance column is labelled as
    # provenance, never as a BLACKHEART detection. Reading that column runs the
    # upstream project's own Foundry test, so a row can only be asserted when its
    # harness is built; on a bare checkout the row is SKIPPED, never asserted (an
    # unguarded assertion here made a clean checkout FAIL instead of skip).
    checked = 0
    for name in ALL_CASES:
        if name not in _MAPPED_CASES:
            continue
        if not _mapped_harness_ready(name, dvdf_ready=dvdf_ready,
                                     ethernaut_ready=ethernaut_ready):
            continue
        res = native_test_result(name)
        if res is None:
            continue
        assert "provenance" in res["note"].lower()
        assert "interpretation" in res
        checked += 1
    if checked == 0:
        pytest.skip("external harness not built; run the harness fetch.sh")


def test_mapped_case_gate_tracks_harness_readiness():
    """The provenance assertion must be gated on harness readiness so a bare
    checkout SKIPS it instead of failing -- an unguarded assertion is what made the
    Mission 05.1 clean-checkout total diverge from the primary repository. This locks
    the gate: it must be False whenever the relevant harness is absent."""
    assert _mapped_harness_ready("dvdf-truster", dvdf_ready=False, ethernaut_ready=False) is False
    assert _mapped_harness_ready("ethernaut-token", dvdf_ready=False, ethernaut_ready=False) is False
    assert _mapped_harness_ready("dvdf-truster", dvdf_ready=True, ethernaut_ready=False) is True
    assert _mapped_harness_ready("ethernaut-token", dvdf_ready=False, ethernaut_ready=True) is True
    # a ready DVDF harness must not make an Ethernaut row assertable, and vice versa
    assert _mapped_harness_ready("ethernaut-token", dvdf_ready=True, ethernaut_ready=False) is False
    assert _mapped_harness_ready("dvdf-truster", dvdf_ready=False, ethernaut_ready=True) is False


@pytest.mark.skipif(_no_foundry(), reason="foundry (anvil/cast) not installed")
def test_random_baseline_is_a_fair_sampler(dvdf_ready):
    """The random baseline must search the same space and be scored the same way."""
    if not dvdf_ready:
        pytest.skip("dvdf-external harness not built")
    from blackheart.statespace.runtime.evm_benchmark import run_random_baseline

    res = run_random_baseline("dvdf-truster", seed=0, max_sequences=200, max_steps=6)
    assert res.approach == "random"
    assert res.sequences_tried >= 1
    # it is allowed to succeed (it does, on these tiny cases) -- but if it does it
    # must carry the same reproduction treatment as the guided path
    if res.detected:
        assert res.reproduced is True
        # the patched control must reject the attack, so the metric is True
        assert res.control_rejected is True


@pytest.mark.skipif(_no_foundry(), reason="foundry (anvil/cast) not installed")
def test_compare_case_reports_both_approaches(dvdf_ready):
    if not dvdf_ready:
        pytest.skip("dvdf-external harness not built")
    cmp = compare_case("dvdf-unstoppable", random_sequences=100)
    assert set(cmp.approaches) == {"guided", "random"}
    assert cmp.approaches["guided"].detected
    assert cmp.search_space["distinct_sequences"] >= 1
    # the upstream test is recorded separately from the two approaches
    assert cmp.native_test is not None
    assert "provenance" in cmp.native_test["note"].lower()


def test_evm_violation_reachability_is_derived_not_asserted():
    """The EVM verifier path must derive attacker-reachability from the sequence's
    actors, not assert it. A privileged-only sequence must not be reported as
    attacker-reachable."""
    from blackheart.models import AttackStep
    from blackheart.statespace.runtime.evm_benchmark import _as_violation

    privileged = [AttackStep(index=0, actor="owner", action="set_owner",
                             params={"new": "attacker"})]
    unprivileged = [AttackStep(index=0, actor="attacker", action="set_owner",
                               params={"new": "attacker"})]
    # any registered case name works here; only the actor rule is under test
    case_name = next(iter(ALL_CASES))
    assert _as_violation(case_name, privileged).reachable_by_attacker is False
    assert _as_violation(case_name, unprivileged).reachable_by_attacker is True
