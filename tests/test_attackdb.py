"""Tests for the executable attack-chain database (mission sections 2B, 10)."""

from __future__ import annotations

import pytest

from blackheart.attackdb import (
    all_chains,
    chains_for_target,
    get_chain,
    run_chain,
    run_chain_control,
    verify_all_chains,
    verify_chain,
)
from blackheart.invariants.registry import available_targets


def test_every_chain_targets_a_registered_target():
    known = set(available_targets())
    for chain in all_chains():
        assert chain.target in known, f"{chain.chain_id} targets unknown {chain.target}"
        assert chain.guarded_target in known
        assert chain.steps, f"{chain.chain_id} has no steps"
        assert chain.invariant


def test_chains_have_unique_ids():
    ids = [c.chain_id for c in all_chains()]
    assert len(ids) == len(set(ids))


def test_every_chain_breaks_vulnerable_and_not_guarded():
    """Each chain must be a real class demonstration: vuln breaks, guarded does not."""
    report = verify_all_chains()
    assert report["passed"] == report["total"], [
        c["chain_id"] for c in report["chains"] if not c["verified"]
    ]


def test_run_chain_reports_targeted_invariant():
    result = run_chain("permit-sign-once-spend-twice")
    assert result.targeted_invariant_broke
    assert result.attacker_reachable
    assert "authorization-used-once" in result.broken_invariants


def test_guarded_control_holds():
    control = run_chain_control("permit-sign-once-spend-twice")
    assert control.broke is False


def test_verify_chain_shape():
    v = verify_chain("oracle-pump-then-borrow")
    assert set(v) >= {"chain_id", "vulnerable", "guarded", "verified"}
    assert v["verified"] is True


def test_unknown_chain_raises():
    with pytest.raises(KeyError):
        get_chain("no-such-chain")


def test_chains_for_target_finds_both_members():
    ids = {c.chain_id for c in chains_for_target("permit-guarded")}
    assert "permit-sign-once-spend-twice" in ids
