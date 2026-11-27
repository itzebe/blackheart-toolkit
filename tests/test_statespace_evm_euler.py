"""Third external-source EVM target: Euler V1 (euler-legacy-xyz/euler-contracts).

Mission 08 asks whether the engine generalizes to a target whose architecture is
unlike the previous two. DVDF is a graph of small DeFi contracts; Ethernaut is a
set of standalone CTF challenges; Euler V1 is a single **diamond-proxy** lending
protocol -- one ``Euler`` core holds all storage and every module is reached
through a proxy that delegate-calls into the core.

These tests drive *real bytecode* on an ephemeral local anvil node. The harness is
git-ignored and re-created by ``harnesses/euler-v1/fetch.sh``; on a fresh checkout
these tests skip (a skip is not a pass).

Coverage: registry/provenance (no node), case loading and deployment against the
real diamond proxies, end-to-end discovery + independent verification with the
differential control, and the discrimination proof (the patched EToken keeps the
invariant).
"""

from __future__ import annotations

import pytest

from blackheart.statespace.runtime.evm_cases_euler import (
    ALL_CASES as EULER_ALL_CASES,
    ALL_CONTROL_CASES as EULER_ALL_CONTROLS,
    BLIND_CASES as EULER_BLIND_CASES,
    CONTROL_CASES as EULER_CONTROLS,
    EULER_COMMIT,
    EULER_REPO,
)
from blackheart.statespace.runtime.evm_registry import (
    get_case,
    has_control,
    target_for,
)
from blackheart.statespace.runtime.evm_run import run_evm_case


def _no_foundry() -> bool:
    from blackheart.statespace.runtime.evm import _foundry_bin

    return _foundry_bin("anvil") is None or _foundry_bin("cast") is None


# --------------------------------------------------------------------------- #
# Pure: provenance (no node needed)
# --------------------------------------------------------------------------- #


def test_euler_provenance_is_pinned_not_invented():
    assert EULER_REPO == "https://github.com/euler-legacy-xyz/euler-contracts"
    # a full 40-hex commit, not a moving branch
    assert len(EULER_COMMIT) == 40
    int(EULER_COMMIT, 16)
    t = target_for("euler-v1-donate")
    assert t.commit == EULER_COMMIT
    assert t.project == "Euler V1"


def test_euler_case_documents_ground_truth_and_reference():
    for name, factory in EULER_BLIND_CASES.items():
        case = factory()
        assert case.name == name
        assert case.ground_truth
        assert case.reference.startswith("euler-legacy-xyz/euler-contracts")
        assert case.suite == "blind"


def test_euler_control_is_registered_and_interface_compatible():
    for name in EULER_BLIND_CASES:
        assert name in EULER_CONTROLS
        assert has_control(name)
        control = EULER_CONTROLS[name]()
        assert control.name == name + "-control"
        assert control.suite == "control"
        # the control's operation list mirrors the vulnerable case (same interface)
        vuln = EULER_BLIND_CASES[name]()
        assert [o.name for o in control.ops] == [o.name for o in vuln.ops]
    assert "euler-v1-donate" in EULER_ALL_CASES
    assert "euler-v1-donate" in EULER_ALL_CONTROLS


def test_unknown_euler_case_is_rejected():
    with pytest.raises(KeyError):
        get_case("euler-v1-does-not-exist")


# --------------------------------------------------------------------------- #
# Node-backed: discovery + independent verification on the third target
# --------------------------------------------------------------------------- #

@pytest.mark.skipif(_no_foundry(), reason="foundry (anvil/cast) not installed")
def test_euler_engine_discovers_and_verifies(euler_ready):
    if not euler_ready:
        pytest.skip("euler-v1 harness not built; run harnesses/euler-v1/fetch.sh")
    report = run_evm_case("euler-v1-donate", verify=True)
    assert report.executed, report.errors
    assert report.detected, "engine found no violation for euler-v1-donate"
    assert report.minimal_sequence
    assert report.verdict == "INDEPENDENTLY_VERIFIED", report.verdict
    assert report.independently_verified is True
    # the differential control did NOT reproduce the violation (the hit discriminates)
    assert report.control_reproduced is False
    # the discovered exploit is the three-step deposit -> borrow -> donate sequence
    actions = [s["action"] for s in report.minimal_sequence]
    assert actions == ["deposit", "borrow", "donate"], actions
    # provenance travels with the result
    assert report.target == "Euler V1"
    assert report.commit == EULER_COMMIT


@pytest.mark.skipif(_no_foundry(), reason="foundry (anvil/cast) not installed")
def test_euler_control_does_not_violate(euler_ready):
    """The patched control must NOT yield a violation for the same sequence.

    This is the discrimination proof: the engine's declared solvency invariant is
    not trivially true of any contract; the *fixed* EToken (which checks liquidity
    on the donation path) keeps it. We take the minimal sequence the engine found on
    the vulnerable contract and replay it against the patched control.
    """
    if not euler_ready:
        pytest.skip("euler-v1 harness not built")
    from blackheart.models import AttackStep
    from blackheart.statespace.explore import run_sequence
    from blackheart.statespace.runtime.evm_run import build_evm_target

    vuln = run_evm_case("euler-v1-donate", verify=False)
    assert vuln.detected, vuln.errors
    steps = [AttackStep(index=i, actor=s["actor"], action=s["action"],
                        params=dict(s["params"]))
             for i, s in enumerate(vuln.minimal_sequence)]

    _, target = build_evm_target("euler-v1-donate", control=True)
    try:
        _, bad = run_sequence(target, steps)
    finally:
        target.adapter.close()
    assert "INV-SOLVENCY" not in bad, "the fixed contract should not violate INV-SOLVENCY"
