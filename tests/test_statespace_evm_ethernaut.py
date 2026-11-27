"""Second external-source EVM target: OpenZeppelin Ethernaut.

Mission 04 asks whether the engine generalizes beyond the single application it was
validated on in Mission 03 (Damn Vulnerable DeFi). These tests exercise the *same*
unchanged engine against a different, independently-maintained project with a
different architecture (standalone challenge contracts) and different vulnerability
classes (a misnamed constructor / access-control flaw, and an integer underflow).

Like the DVDF tests, these drive *real bytecode* on an ephemeral local anvil node.
The harness is git-ignored and re-created by
``harnesses/ethernaut-external/fetch.sh``; on a fresh checkout these tests skip (a
skip is not a pass).

Coverage: the registry exposing two targets, case loading/deployment, end-to-end
discovery + independent verification with the differential control, and the fair
comparison (guided vs random vs the project's own upstream test).
"""

from __future__ import annotations

import pytest

from blackheart.statespace.runtime.evm_cases_ethernaut import (
    ETHERNAUT_COMMIT,
    ETHERNAUT_REPO,
    ALL_CASES as ETH_ALL_CASES,
    ALL_CONTROL_CASES as ETH_ALL_CONTROLS,
    BLIND_CASES as ETH_BLIND_CASES,
    CONTROL_CASES as ETH_CONTROLS,
    VALIDATION_CASES as ETH_CASES,
)
from blackheart.statespace.runtime.evm_registry import (
    ALL_CASES,
    TARGETS,
    catalogue,
    get_case,
    has_control,
    target_for,
)
from blackheart.statespace.runtime.evm_run import run_evm_case


def _no_foundry() -> bool:
    from blackheart.statespace.runtime.evm import _foundry_bin

    return _foundry_bin("anvil") is None or _foundry_bin("cast") is None


# --------------------------------------------------------------------------- #
# Pure: registry and provenance (no node needed)
# --------------------------------------------------------------------------- #


def test_external_targets_are_registered():
    keys = {t.key for t in TARGETS}
    assert keys == {"dvdf", "ethernaut", "euler"}
    # every case maps to exactly one target and is listed in the catalogue
    for name in ALL_CASES:
        assert target_for(name).key in keys
    listed = {row["case"] for row in catalogue()}
    assert listed == set(ALL_CASES)


def test_ethernaut_provenance_is_pinned_not_invented():
    assert ETHERNAUT_REPO == "https://github.com/OpenZeppelin/ethernaut"
    # a full 40-hex commit, not a moving branch
    assert len(ETHERNAUT_COMMIT) == 40
    int(ETHERNAUT_COMMIT, 16)
    t = target_for("ethernaut-fallout")
    assert t.commit == ETHERNAUT_COMMIT
    assert t.project == "OpenZeppelin Ethernaut"


def test_ethernaut_cases_document_ground_truth_and_reference():
    for name, factory in ETH_CASES.items():
        case = factory()
        assert case.name == name
        assert case.ground_truth
        assert case.reference.startswith("OpenZeppelin Ethernaut")
        assert case.suite == "validation"


def test_ethernaut_controls_are_interface_compatible_and_registered():
    # each validation case has a control (the patched contract) and a matching name
    for name in ETH_CASES:
        assert name in ETH_CONTROLS
        assert has_control(name)
        control = ETH_CONTROLS[name]()
        assert control.name == name + "-control"
        assert control.suite == "control"
        # the control's operation list mirrors the vulnerable case (same interface)
        vuln = ETH_CASES[name]()
        assert [o.name for o in control.ops] == [o.name for o in vuln.ops]


def test_unknown_ethernaut_case_is_rejected():
    with pytest.raises(KeyError):
        get_case("ethernaut-does-not-exist")


# --------------------------------------------------------------------------- #
# Node-backed: discovery + independent verification on the second target
# --------------------------------------------------------------------------- #

_ETH_CASE_NAMES = sorted(ETH_CASES)


@pytest.mark.skipif(_no_foundry(), reason="foundry (anvil/cast) not installed")
@pytest.mark.parametrize("name", _ETH_CASE_NAMES)
def test_ethernaut_engine_discovers_and_verifies(ethernaut_ready, name):
    if not ethernaut_ready:
        pytest.skip("ethernaut-external harness not built; run "
                    "harnesses/ethernaut-external/fetch.sh")
    report = run_evm_case(name, verify=True)
    assert report.executed, report.errors
    assert report.detected, f"engine found no violation for {name}"
    assert report.minimal_sequence
    assert report.verdict == "INDEPENDENTLY_VERIFIED", report.verdict
    assert report.independently_verified is True
    # the differential control did NOT reproduce the violation (the hit discriminates)
    assert report.control_reproduced is False
    # provenance travels with the result
    assert report.target == "OpenZeppelin Ethernaut"
    assert report.commit == ETHERNAUT_COMMIT


@pytest.mark.skipif(_no_foundry(), reason="foundry (anvil/cast) not installed")
def test_ethernaut_control_does_not_violate(ethernaut_ready):
    """The patched control must NOT yield a violation for the same sequence.

    This is the discrimination proof: the engine's declared invariant is not
    trivially true of any contract; the *fixed* contract keeps it. We take the
    minimal sequence the engine found on the vulnerable contract and replay it
    against the patched control, asserting the invariant holds there.
    """
    if not ethernaut_ready:
        pytest.skip("ethernaut-external harness not built")
    from blackheart.models import AttackStep
    from blackheart.statespace.explore import run_sequence
    from blackheart.statespace.runtime.evm_run import build_evm_target

    vuln = run_evm_case("ethernaut-token", verify=False)
    assert vuln.detected, vuln.errors
    steps = [AttackStep(index=i, actor=s["actor"], action=s["action"],
                        params=dict(s["params"]))
             for i, s in enumerate(vuln.minimal_sequence)]

    _, target = build_evm_target("ethernaut-token", control=True)
    try:
        _, bad = run_sequence(target, steps)
    finally:
        target.adapter.close()
    assert "INV-SUPPLY" not in bad, "the fixed contract should not violate INV-SUPPLY"


# --------------------------------------------------------------------------- #
# Blind case (mission 07): NaughtCoin -- a time-lock bypassed through an
# inherited, un-overridden transfer path.
# --------------------------------------------------------------------------- #

def test_naughtcoin_is_registered_as_a_blind_case_with_a_control():
    assert "ethernaut-naughtcoin" in ETH_BLIND_CASES
    case = ETH_BLIND_CASES["ethernaut-naughtcoin"]()
    assert case.suite == "blind"
    assert case.ground_truth
    assert case.reference.startswith("OpenZeppelin Ethernaut")
    assert "ethernaut-naughtcoin" in ETH_ALL_CASES
    assert "ethernaut-naughtcoin" in ETH_ALL_CONTROLS
    assert has_control("ethernaut-naughtcoin")
    # the declared transition names the approval that enables the delegated transfer
    ops = [t.operation for t in case.transitions]
    assert "approve_spender" in ops


@pytest.mark.skipif(_no_foundry(), reason="foundry (anvil/cast) not installed")
def test_naughtcoin_engine_discovers_and_verifies_blind(ethernaut_ready):
    if not ethernaut_ready:
        pytest.skip("ethernaut-external harness not built; run "
                    "harnesses/ethernaut-external/fetch.sh")
    report = run_evm_case("ethernaut-naughtcoin", verify=True)
    assert report.executed, report.errors
    assert report.detected, "engine found no violation for ethernaut-naughtcoin"
    assert report.verdict == "INDEPENDENTLY_VERIFIED", report.verdict
    assert report.independently_verified is True
    assert report.control_reproduced is False, "the hit must discriminate from the control"
    # the discovered exploit is the two-step approval-then-transferFrom sequence
    actions = [s["action"] for s in report.minimal_sequence]
    assert actions == ["approve_spender", "pull_via_transferFrom"], actions
    assert report.commit == ETHERNAUT_COMMIT


@pytest.mark.skipif(_no_foundry(), reason="foundry (anvil/cast) not installed")
def test_naughtcoin_control_does_not_violate(ethernaut_ready):
    """The patched control must keep the lock when the same sequence is replayed."""
    if not ethernaut_ready:
        pytest.skip("ethernaut-external harness not built")
    from blackheart.models import AttackStep
    from blackheart.statespace.explore import run_sequence
    from blackheart.statespace.runtime.evm_run import build_evm_target

    vuln = run_evm_case("ethernaut-naughtcoin", verify=False)
    assert vuln.detected, vuln.errors
    steps = [AttackStep(index=i, actor=s["actor"], action=s["action"],
                        params=dict(s["params"]))
             for i, s in enumerate(vuln.minimal_sequence)]

    _, target = build_evm_target("ethernaut-naughtcoin", control=True)
    try:
        _, bad = run_sequence(target, steps)
    finally:
        target.adapter.close()
    assert "INV-LOCK" not in bad, "the fixed contract should not violate INV-LOCK"
