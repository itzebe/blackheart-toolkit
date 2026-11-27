"""Acceptance bar for the key-free EVMbench scorer.

The scorer exists to answer one question honestly -- did an analyser point at the
line a maintainer's fix changed -- and to refuse the two ways that question gets
inflated:

  * a *file* hit reported as a *line* hit (the analyser touched the file at all);
  * a *line* hit reported as a *detection*, when the overlapping detector is
    noise that covers a fifth of the file by chance.

The real run this module was built against is the reason for the last one: Slither
scored 2/2 on line overlap and 0/2 once the detector class had to be plausible.
These tests encode that lesson so it cannot be lost.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from blackheart import evmbench as E

REAL_DIFF = """diff --git a/vault/src/Vault.sol b/vault/src/Vault.sol
index e92ecaf..04d8758 100644
--- a/vault/src/Vault.sol
+++ b/vault/src/Vault.sol
@@ -1120,7 +1125,7 @@ contract Vault is ERC4626 {
-    _twabController.mint(_receiver, uint96(_shares));
+    _twabController.mint(_receiver, _shares.toUint96());
@@ -1152,7 +1157,7 @@ contract Vault is ERC4626 {
-    _twabController.transfer(_from, _to, uint96(_shares));
+    _twabController.transfer(_from, _to, _shares.toUint96());
"""


def _finding(check: str, file: str, start: int, end: int) -> E.Finding:
    return E.Finding(check=check, file=file, start=start, end=end)


def _truth(title: str = "a user can steal deposits by truncation") -> E.GroundTruth:
    return E.GroundTruth(audit="a", vulnerability="H-01", title=title,
                         hunks=E.parse_unified_diff(REAL_DIFF))


# -- diff parsing ----------------------------------------------------------- #

def test_parse_unified_diff_takes_the_vulnerable_side_lines():
    hunks = E.parse_unified_diff(REAL_DIFF)
    assert [h.file for h in hunks] == ["vault/src/Vault.sol"] * 2
    # ``@@ -1120,7`` -- the *old* side is the vulnerable code.
    assert (hunks[0].start, hunks[0].length) == (1120, 7)
    assert (hunks[1].start, hunks[1].length) == (1152, 7)


def test_parse_unified_diff_ignores_a_diff_with_no_hunks():
    assert E.parse_unified_diff("diff --git a/x b/x\n--- a/x\n+++ b/x\n") == []


def test_hunk_overlap_is_inclusive():
    h = E.Hunk(file="a.sol", start=10, length=3)      # 10..12
    assert h.overlaps(12, 20) and h.overlaps(1, 10)
    assert not h.overlaps(13, 20) and not h.overlaps(1, 9)


# -- path matching ---------------------------------------------------------- #

def test_same_file_tolerates_a_leading_directory():
    # Slither says ``src/Vault.sol``; the diff says ``vault/src/Vault.sol``.
    assert E._same_file("src/Vault.sol", "vault/src/Vault.sol")
    assert E._same_file("vault/src/Vault.sol", "src/Vault.sol")


def test_same_file_does_not_match_a_different_contract():
    assert not E._same_file("src/Vault.sol", "src/Other.sol")


# -- scoring: the three levels stay separate -------------------------------- #

def test_file_hit_does_not_imply_line_hit():
    truth = _truth()
    score = E.score_audit(truth, [_finding("reentrancy-eth", "src/Vault.sol", 1, 2)])
    assert score.file_hit and not score.line_hit


def test_line_hit_requires_an_overlapping_range():
    truth = _truth()
    score = E.score_audit(truth, [_finding("divide-before-multiply", "src/Vault.sol",
                                           1122, 1124)])
    assert score.file_hit and score.line_hit and score.class_hit


def test_noise_detector_scores_a_line_hit_but_not_a_class_hit():
    """The exact inflation the real run exposed."""
    truth = _truth()
    noise = _finding("naming-convention", "src/Vault.sol", 1120, 1126)
    score = E.score_audit(truth, [noise])
    assert score.line_hit, "the noise finding does overlap the hunk"
    assert not score.class_hit, (
        "a naming-convention finding must never be credited as the audited bug")


def test_class_hit_requires_the_expected_family():
    truth = _truth("reentrancy lets an attacker drain the vault")
    reentrant = _finding("reentrancy-eth", "src/Vault.sol", 1121, 1123)
    score = E.score_audit(truth, [reentrant])
    assert score.class_hit


# -- the report never divides by zero -------------------------------------- #

def test_empty_report_reports_none_not_perfect():
    rep = E.EvalReport()
    assert rep.file_recall is None and rep.line_recall is None and rep.class_recall is None
    assert rep.to_dict()["class_recall"] is None


def test_unscored_vulnerabilities_are_excluded_from_the_denominator(tmp_path):
    audit = tmp_path / "audits" / "x"
    (audit / "patch").mkdir(parents=True)
    (audit / "config.yaml").write_text(
        'id: x\n\nvulnerabilities:\n'
        '  - id: "H-01"\n    title: "no fix shipped"\n    award: 0.0\n',
        encoding="utf-8")
    rep = E.evaluate(tmp_path, [])
    assert rep.scored == 0
    assert rep.unscored and rep.unscored[0][1] == "H-01"
    assert rep.class_recall is None, "an unscored vuln must not become a miss"


def test_scored_vulnerability_with_a_patch_enters_the_denominator(tmp_path):
    audit = tmp_path / "audits" / "x"
    (audit / "patch").mkdir(parents=True)
    (audit / "config.yaml").write_text(
        'id: x\n\nvulnerabilities:\n'
        '  - id: "H-01"\n    title: "a user can steal deposits"\n    award: 1.0\n',
        encoding="utf-8")
    (audit / "patch" / "H-01.diff").write_text(REAL_DIFF, encoding="utf-8")
    rep = E.evaluate(tmp_path, [_finding("divide-before-multiply", "src/Vault.sol",
                                         1121, 1123)])
    assert rep.scored == 1 and rep.class_hits == 1


# -- chance baseline -------------------------------------------------------- #

def test_chance_baseline_measures_the_no_skill_hit_rate():
    findings = [_finding("naming-convention", "src/Vault.sol", 1, 50)]
    # 50 of 100 lines covered -> a random line is hit half the time.
    assert E.chance_baseline(findings, "src/Vault.sol", 100) == pytest.approx(0.5)


def test_chance_baseline_is_none_for_an_empty_file():
    assert E.chance_baseline([], "src/Vault.sol", 0) is None


def test_chance_baseline_ignores_findings_in_other_files():
    findings = [_finding("x", "src/Other.sol", 1, 100)]
    assert E.chance_baseline(findings, "src/Vault.sol", 100) == 0.0


# -- slither normalization -------------------------------------------------- #

def test_load_slither_findings_reads_line_spans(tmp_path):
    import json
    report = {
        "success": True,
        "results": {"detectors": [{
            "check": "divide-before-multiply", "impact": "Medium",
            "confidence": "High",
            "elements": [
                {"source_mapping": {"filename_relative": "src/Vault.sol",
                                    "lines": [1121, 1122, 1123]}},
                {"source_mapping": {}},   # an element with no location is skipped
            ],
        }]},
    }
    p = tmp_path / "r.json"
    p.write_text(json.dumps(report), encoding="utf-8")
    findings = E.load_slither_findings(p)
    assert len(findings) == 1
    assert (findings[0].start, findings[0].end) == (1121, 1123)
    assert findings[0].check == "divide-before-multiply"
