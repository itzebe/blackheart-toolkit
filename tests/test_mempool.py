"""Acceptance tests for mempool ordering search (T2.7).

The harness must find a sandwich on a pool whose only defect is that the victim's
slippage limit is unenforced, and must find *nothing* on the guarded control. It
must report the honest bound it searched, and it must distinguish "a profitable
ordering" from "an ordering that broke a stated invariant" -- the two are not the
same finding.
"""

from __future__ import annotations

from blackheart.invariants.registry import make_target
from blackheart.models import AttackStep
from blackheart.statespace.mempool import (
    MempoolScenario,
    _interleave,
    search_ordering,
)


def _sandwich_scenario(guarded: bool) -> MempoolScenario:
    target = make_target("sandwich-guarded" if guarded else "sandwich-slippage")
    flow = [AttackStep(0, "victim", "victim_swap", {"amount": 100, "min_out": 90})]
    return MempoolScenario(
        name="sandwich", target=target, victim_flow=flow,
        attacker_ops=["swap_a_for_b", "swap_b_for_a"])


def test_interleave_places_steps_in_the_right_gaps():
    flow = [AttackStep(0, "victim", "a"), AttackStep(1, "victim", "b")]
    inserts = [AttackStep(0, "attacker", "front"), AttackStep(0, "attacker", "back")]
    seq, insertions = _interleave(flow, inserts, (0, 2))
    assert [s.action for s in seq] == ["front", "a", "b", "back"]
    assert insertions == [0, 2]


def test_sandwich_is_found_on_the_vulnerable_pool():
    rep = search_ordering(_sandwich_scenario(guarded=False), max_attacker_steps=2)
    assert rep.violating is not None
    assert "victim-slippage-protected" in rep.violating.violated
    assert rep.most_profitable is not None
    assert rep.most_profitable.attacker_profit > 0
    # A real sandwich: front-run before the victim, back-run after.
    assert rep.violating.insertions[0] == 0


def test_no_ordering_extracts_value_on_the_guarded_pool():
    rep = search_ordering(_sandwich_scenario(guarded=True), max_attacker_steps=2)
    assert rep.violating is None
    assert rep.most_profitable is None


def test_report_records_the_bound_it_searched():
    rep = search_ordering(_sandwich_scenario(guarded=False), max_attacker_steps=2)
    assert rep.bound["max_attacker_steps"] == 2
    assert rep.bound["victim_flow_len"] == 1
    assert rep.orderings_tried > 0


def test_orderings_budget_is_respected():
    rep = search_ordering(_sandwich_scenario(guarded=False),
                          max_attacker_steps=3, max_orderings=25)
    assert rep.orderings_tried <= 25
    assert any("budget" in n for n in rep.notes)


def test_ordering_search_is_deterministic():
    a = search_ordering(_sandwich_scenario(guarded=False), max_attacker_steps=2)
    b = search_ordering(_sandwich_scenario(guarded=False), max_attacker_steps=2)
    assert a.to_dict() == b.to_dict()


def test_scenario_with_no_attacker_ops_is_reported_not_crashed():
    target = make_target("sandwich-slippage")
    flow = [AttackStep(0, "victim", "victim_swap", {"amount": 100, "min_out": 90})]
    sc = MempoolScenario(name="empty", target=target, victim_flow=flow, attacker_ops=[])
    # No attacker ops named -> every op is reachable, so a result is expected; the
    # point is that an *unreachable* name set degrades gracefully.
    sc.attacker_ops = ["nonexistent_op"]
    rep = search_ordering(sc)
    assert rep.orderings_tried == 0
    assert any("no attacker-reachable" in n for n in rep.notes)


def test_cli_lists_and_runs_scenarios(capsys):
    from blackheart.cli import main
    import json as _json

    assert main(["statespace", "mempool"]) == 0
    names = _json.loads(capsys.readouterr().out)
    assert "sandwich" in names and "sandwich-guarded" in names

    assert main(["statespace", "mempool", "sandwich", "--max-attacker-steps", "2"]) == 0
    rep = _json.loads(capsys.readouterr().out)
    assert rep["violating"] is not None
    assert rep["most_profitable"]["attacker_profit"] > 0

    assert main(["statespace", "mempool", "sandwich-guarded", "--max-attacker-steps", "2"]) == 0
    guarded = _json.loads(capsys.readouterr().out)
    assert guarded["violating"] is None and guarded["most_profitable"] is None
