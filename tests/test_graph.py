"""Acceptance bar for the dual research graph."""

from __future__ import annotations

import pytest

from blackheart.graph import ResearchGraph


def test_asset_graph_dedup():
    g = ResearchGraph()
    a = g.add_asset("root_domain", "example.com", company="acme")
    a2 = g.add_asset("root_domain", "example.com", company="acme")
    assert a == a2
    ep = g.add_asset("endpoint", "/login", parent=a, company="acme")
    assert ep != a
    assert g.asset(ep).parent_id == a


def test_lineage_goal_to_finding():
    g = ResearchGraph()
    goal = g.add_node("goal", "own the site")
    intent = g.add_node("intent", "test login", parent=goal)
    finding = g.add_node("finding", "sqli in login", parent=intent)
    g.add_edge(goal, intent, "spawns")
    g.add_edge(intent, finding, "yields")
    assert [n.kind for n in g.lineage(finding)] == ["goal", "intent", "finding"]


def test_coverage_tested_vs_untested():
    g = ResearchGraph()
    tested = g.add_asset("endpoint", "/login", company="acme")
    g.add_asset("endpoint", "/admin", company="acme")
    finding = g.add_node("finding", "sqli")
    g.anchor(finding, tested)
    cov = {r["key"]: r for r in g.coverage("acme")}
    assert cov["/login"]["explored"] and cov["/login"]["tested"]
    assert not cov["/admin"]["explored"] and not cov["/admin"]["tested"]
    assert g.coverage_summary("acme") == {
        "total": 2,
        "explored": 1,
        "tested": 1,
        "untested": 1,
    }


def test_unknown_kind_rejected():
    g = ResearchGraph()
    with pytest.raises(ValueError):
        g.add_asset("nonsense", "x")
    with pytest.raises(ValueError):
        g.add_node("bogus", "y")
    with pytest.raises(ValueError):
        g.add_edge(1, 2, "not-a-relation")


def test_persists_to_file(tmp_path):
    path = tmp_path / "graph.db"
    with ResearchGraph(path) as g:
        g.add_asset("root_domain", "example.com")
        n = g.add_node("goal", "own it")
    with ResearchGraph(path) as g2:
        # reopened file still has the data
        assert g2.coverage_summary()["total"] == 1
        assert g2.node(n) is not None
