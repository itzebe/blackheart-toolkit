"""The certified witness becomes a runnable PoC -- fail-closed, never a fake PASS."""

from __future__ import annotations

from blackheart.cli import main
from blackheart.hypothesis.to_target import poc_for_target, target_from_hypothesis

VULN = """pragma solidity ^0.8.0;
contract C {
    address public owner;
    function setOwner(address a) external { owner = a; }
}
"""


def _tree(tmp_path):
    (tmp_path / "C.sol").write_text(VULN)
    return str(tmp_path)


def test_poc_without_a_record_is_fail_closed_never_pass(tmp_path):
    root = _tree(tmp_path)
    out = target_from_hypothesis({"component": "C"}, root=root, certify_result=True)
    assert out.violations >= 1
    ex = poc_for_target(out, root=root, compatibility=None)
    assert ex["status"] != "PASS"
    assert ex["status"] in {"BLOCKED", "UNSUPPORTED"}


def test_poc_without_a_certificate_is_skipped(tmp_path):
    root = _tree(tmp_path)
    out = target_from_hypothesis({"component": "C"}, root=root, certify_result=False)
    ex = poc_for_target(out, root=root, compatibility=None)
    assert ex["status"] == "SKIPPED"


def test_poc_flag_requires_a_compatibility_record(tmp_path, capsys):
    rc = main(["external", "--run", "semgrep", "--target", str(tmp_path),
               "--to-hypotheses", "--to-target", "--certify", "--poc"])
    assert rc == 2
    assert "needs --compatibility" in capsys.readouterr().err
