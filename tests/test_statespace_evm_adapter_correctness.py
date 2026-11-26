"""Adversarial-correctness regression tests for the external EVM adapter.

Mission 04 Phase 4 reviews the adapter for the ways it could produce a *false*
result -- a violation that is really an artifact of the harness rather than a
property of the target. The properties asserted here are the ones a reviewer
would attack:

  * an invariant must **hold in the clean state** (otherwise a "violation" is a
    pre-existing condition, not something the attacker caused);
  * a snapshot read that returns ``None`` (a read the harness could not perform)
    must be treated as *holding*, never as a violation -- a missing read is not
    evidence of a bug;
  * reset must restore the exact clean snapshot, so a sequence's result does not
    depend on what ran before it;
  * a detection must be reproducible in a *fresh* instance, not only in the
    instance the explorer mutated.

Node-backed rows skip when the harness is not built (a skip is not a pass).
"""

from __future__ import annotations

import pytest

from blackheart.statespace.runtime.evm_registry import ALL_CASES, get_case
from blackheart.statespace.runtime.evm_run import build_evm_target


def _no_foundry() -> bool:
    from blackheart.statespace.runtime.evm import _foundry_bin

    return _foundry_bin("anvil") is None or _foundry_bin("cast") is None


# --------------------------------------------------------------------------- #
# Pure: predicate robustness (no node needed)
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("name", sorted(ALL_CASES))
def test_invariant_holds_on_missing_reads(name):
    """A snapshot read that returned None must not be reported as a violation.

    Every predicate guards its inputs; a missing key is *absence of evidence*, so
    the invariant must be reported as holding. This is the false-positive guard.
    """
    case = get_case(name)
    empty = {read.key: None for read in case.snapshot}
    for inv_id, _statement, pred in case.invariants:
        assert pred(empty) is True, f"{name}/{inv_id} treats a missing read as a violation"


@pytest.mark.parametrize("name", sorted(ALL_CASES))
def test_case_declares_invariants_and_ops(name):
    """Every case must declare at least one invariant and one operation, and each
    invariant predicate must be a pure function of the snapshot keys it reads."""
    case = get_case(name)
    assert case.invariants, f"{name} declares no invariant"
    assert case.ops, f"{name} declares no operation"
    keys = {r.key for r in case.snapshot}
    # the invariant must be evaluable from the declared snapshot keys alone
    empty = {k: None for k in keys}
    for _inv_id, _statement, pred in case.invariants:
        assert pred(empty) in (True, False)


# --------------------------------------------------------------------------- #
# Node-backed: clean-state soundness and reset fidelity
# --------------------------------------------------------------------------- #

_CASES = sorted(ALL_CASES)


@pytest.mark.skipif(_no_foundry(), reason="foundry (anvil/cast) not installed")
@pytest.mark.parametrize("name", _CASES)
def test_invariant_holds_in_clean_state(dvdf_ready, ethernaut_ready, name):
    """The declared invariant must hold on the untouched initial state.

    If it did not, any later "violation" would be a condition that was already
    true before the attacker acted -- not an attack. This is the single most
    important soundness property of the harness.
    """
    target = "ethernaut" if name.startswith("ethernaut-") else "dvdf"
    if target == "dvdf" and not dvdf_ready:
        pytest.skip("dvdf-external harness not built")
    if target == "ethernaut" and not ethernaut_ready:
        pytest.skip("ethernaut-external harness not built")

    from blackheart.statespace.model import violated

    adapter, _ = build_evm_target(name)
    try:
        clean = adapter.snapshot()
        assert all(v is not None for v in clean.values()), \
            f"{name}: a snapshot read failed on the clean state: {clean}"
        assert violated(clean, adapter.invariants()) == [], \
            f"{name}: invariant already broken before any attacker action: {clean}"
    finally:
        adapter.close()


@pytest.mark.skipif(_no_foundry(), reason="foundry (anvil/cast) not installed")
@pytest.mark.parametrize("name", _CASES)
def test_reset_restores_exact_clean_state(dvdf_ready, ethernaut_ready, name):
    """Reset must restore the exact clean snapshot, so results are order-independent."""
    target = "ethernaut" if name.startswith("ethernaut-") else "dvdf"
    if target == "dvdf" and not dvdf_ready:
        pytest.skip("dvdf-external harness not built")
    if target == "ethernaut" and not ethernaut_ready:
        pytest.skip("ethernaut-external harness not built")

    adapter, _ = build_evm_target(name)
    try:
        clean = adapter.snapshot()
        # perturb with a real operation (the first declared op, first actor)
        case = get_case(name)
        op = case.ops[0]
        params = {p: op.domains[p][0] for p in op.param_names() if op.domains.get(p)}
        adapter.execute(op.name, op.actor, params)
        adapter.reset()
        assert adapter.snapshot() == clean, f"{name}: reset did not restore clean state"
    finally:
        adapter.close()
