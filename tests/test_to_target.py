"""A promoted hypothesis's component becomes a Target -- model-level, never a finding."""

from __future__ import annotations

from blackheart.hypothesis.to_target import (
    target_from_hypothesis, targets_from_hypotheses,
)

VULN = """pragma solidity ^0.8.0;
contract C {
    address public owner;
    function setOwner(address a) external { owner = a; }
}
"""
GUARD = """pragma solidity ^0.8.0;
contract G {
    address public owner;
    function setOwner(address a) external { require(msg.sender == owner); owner = a; }
}
"""


def _tree(tmp_path):
    (tmp_path / "C.sol").write_text(VULN)
    (tmp_path / "G.sol").write_text(GUARD)
    return str(tmp_path)


def test_vulnerable_component_certifies_with_model_witnesses(tmp_path):
    out = target_from_hypothesis({"component": "C"}, root=_tree(tmp_path),
                                 certify_result=True)
    assert out.status == "CERTIFIED"
    assert out.violations >= 1
    assert out.modelled_ops >= 1
    assert "authorization:owner" in out.invariants
    assert out.searchable is True


def test_guarded_twin_has_no_model_violation(tmp_path):
    out = target_from_hypothesis({"component": "G"}, root=_tree(tmp_path),
                                 certify_result=True)
    assert out.status == "NO_VIOLATION"
    assert out.violations == 0


def test_missing_component_is_not_found(tmp_path):
    out = target_from_hypothesis({"component": "Missing"}, root=_tree(tmp_path))
    assert out.status == "NOT_FOUND"
    assert "Missing" in out.detail


def test_synthesize_only_does_not_certify(tmp_path):
    out = target_from_hypothesis({"component": "C"}, root=_tree(tmp_path),
                                 certify_result=False)
    assert out.status == "SYNTHESIZED"
    assert "not a finding" in out.detail


def test_no_component_is_an_error(tmp_path):
    out = target_from_hypothesis({}, root=_tree(tmp_path))
    assert out.status == "ERROR"


def test_outcome_is_model_level_not_a_finding(tmp_path):
    data = target_from_hypothesis({"component": "C"}, root=_tree(tmp_path),
                                  certify_result=True).as_dict()
    assert "disposition" not in data and "confirmed" not in data
    assert "never a confirmed finding" in data["note"]
    assert data["status"] == "CERTIFIED"


def test_targets_from_hypotheses_runs_each(tmp_path):
    outs = targets_from_hypotheses(
        [{"component": "C"}, {"component": "Missing"}],
        root=_tree(tmp_path), certify_result=False)
    assert [o.status for o in outs] == ["SYNTHESIZED", "NOT_FOUND"]
