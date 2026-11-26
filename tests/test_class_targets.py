"""Tests for the new executable attack classes and the Foundry generator
(mission sections 2C, 3)."""

from __future__ import annotations

from pathlib import Path

import pytest

from blackheart.foundry import (
    default_out_path,
    render_foundry_test,
    renderable_chains,
    write_foundry_test,
)
from blackheart.invariants import FuzzConfig, StatefulFuzzer
from blackheart.invariants.registry import make_target


@pytest.mark.parametrize(
    "vuln,guard",
    [("callback-reentrancy", "callback-guarded"), ("access-control", "access-guarded")],
)
def test_new_class_breaks_vulnerable_and_holds_guarded(vuln, guard):
    cfg = FuzzConfig(runs=400, steps_per_run=8, seed=0)
    vr = StatefulFuzzer(make_target(vuln), cfg).run()
    gr = StatefulFuzzer(make_target(guard), cfg).run()
    reachable = [f for f in vr.failures if f.reachable_by_attacker]
    assert reachable, f"{vuln} produced no attacker-reachable violation"
    assert not gr.failures, f"{guard} must not violate any invariant"


def test_reentrancy_profit_is_material():
    """The reentrancy model must show a *material* gain, not dust."""
    report = StatefulFuzzer(
        make_target("callback-reentrancy"), FuzzConfig(runs=200, steps_per_run=6, seed=0)
    ).run()
    assert any("no-material-attacker-profit" in f.inv_id for f in report.failures)


def test_foundry_renderable_chains_are_registered():
    from blackheart.attackdb import get_chain

    for chain_id in renderable_chains():
        get_chain(chain_id)  # must exist


def test_render_unknown_chain_raises():
    with pytest.raises(ValueError):
        render_foundry_test("no-such-chain")


def test_render_is_syntactically_plausible_solidity():
    src = render_foundry_test("erc4626-first-depositor-inflation")
    assert "pragma solidity" in src
    assert "contract GeneratedPoC" in src
    assert "function test_chain_is_exploitable" in src
    assert "function test_chain_blocked_on_guarded_vault" in src


def test_write_foundry_test_uses_default_path(tmp_path: Path):
    out = default_out_path("erc4626-first-depositor-inflation", tmp_path)
    path = write_foundry_test("erc4626-first-depositor-inflation", out)
    assert path.exists()
    assert path.name == "Generated_erc4626_first_depositor_inflation.t.sol"
