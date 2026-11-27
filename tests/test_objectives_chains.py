"""Tests for objective generation and attack-chain construction."""

from __future__ import annotations

from blackheart.chains import generate_chains
from blackheart.objectives import TargetProfile, generate_objectives


def _profile() -> TargetProfile:
    return TargetProfile(
        name="t",
        kind="smart-contract",
        assets=["funds"],
        entry_points=["deposit(uint256)", "withdraw(uint256)", "borrow(uint256)"],
        trust_boundaries=["market <-> oracle"],
        roles=["depositor", "borrower", "attacker"],
        external_deps=["oracle"],
    )


def test_objectives_are_structured_and_prioritised():
    objectives = generate_objectives(_profile())
    assert objectives
    for o in objectives:
        assert o.obj_id and o.title
        assert o.expected_invariant, "every objective must name the invariant it breaks"
        assert o.attacker_capabilities
        assert o.preconditions
        assert o.safe_environment
    # Highest priority first.
    assert objectives == sorted(objectives, key=lambda o: -o.priority)


def test_objective_catalogue_is_broader_than_cve_checklists():
    objectives = generate_objectives(_profile())
    categories = {o.category for o in objectives}
    # The mission's attacker goals must all be representable.
    assert {"asset-theft", "unbacked-debt", "auth-bypass", "rounding-precision",
            "oracle-manipulation", "ordering-timing"} <= categories


def test_chains_are_multi_operation_and_structured():
    objectives = generate_objectives(_profile())
    chains = []
    for o in objectives:
        chains.extend(generate_chains(o, "smart-contract"))
    assert chains
    multi = [c for c in chains if len(c.steps) >= 2]
    assert multi, "at least some chains must combine multiple operations"
    for c in chains:
        assert c.chain_id and c.objective_id
        assert c.hypothesis
        assert c.actors


def test_chain_ids_are_unique_per_objective():
    objectives = generate_objectives(_profile())
    ids = []
    for o in objectives:
        for c in generate_chains(o, "smart-contract"):
            ids.append(c.chain_id)
    assert len(ids) == len(set(ids)), "chain ids must be unique"
