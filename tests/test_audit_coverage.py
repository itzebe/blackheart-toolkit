"""Acceptance bar for ``blackheart audit coverage``."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from blackheart.audit_coverage import (
    build_audit_coverage, load_audit_findings, map_findings, parse_json_findings,
)

ROOT = Path(__file__).resolve().parent.parent

SOURCE = """\
pragma solidity ^0.8.0;

contract Demo {
    address public owner;

    function setOwner(address next) external {
        owner = next;
    }

    function withdraw() external {
        payable(msg.sender).transfer(address(this).balance);
    }

    function helper() internal view returns (uint256) {
        return 1;
    }
}
"""


def _setup(tmp_path: Path, audit: object) -> tuple[Path, Path]:
    (tmp_path / "Demo.sol").write_text(SOURCE, encoding="utf-8")
    audit_path = tmp_path / "audit.json"
    audit_path.write_text(json.dumps(audit), encoding="utf-8")
    return tmp_path, audit_path


def test_maps_a_finding_and_lists_the_unaudited_surface(tmp_path: Path) -> None:
    target, audit = _setup(tmp_path, [
        {"id": "H-01", "title": "Unguarded setter", "severity": "High",
         "function": "setOwner", "file": "Demo.sol", "line": 6},
    ])
    payload = build_audit_coverage(str(target), str(audit))
    assert payload["supported"] is True
    assert payload["findings_total"] == 1
    assert payload["findings_mapped"] == 1
    audited = {item["function"] for item in payload["audited_functions"]}
    unaudited = {item["function"] for item in payload["unaudited_functions"]}
    assert "Demo.setOwner" in audited
    assert "Demo.withdraw" in unaudited
    assert "Demo.helper" not in unaudited  # internal, not a reachable entry point
    assert payload["coverage"]["reachable_functions"] == 2


def test_unmapped_finding_is_reported_not_guessed(tmp_path: Path) -> None:
    target, audit = _setup(tmp_path, [
        {"id": "X-1", "title": "Nowhere", "file": "Ghost.sol", "line": 999},
    ])
    payload = build_audit_coverage(str(target), str(audit))
    assert payload["findings_mapped"] == 0
    assert payload["unmapped_findings"][0]["id"] == "X-1"
    assert payload["unaudited_functions"]  # nothing was mapped


def test_markdown_report_is_parsed_heuristically(tmp_path: Path) -> None:
    report = tmp_path / "audit.md"
    report.write_text(
        "# Security Review\n\n"
        "## [H-01] Unguarded setter\n\n"
        "Severity: High\n\n"
        "Affected: Demo.sol:6\n\n"
        "The `setOwner` function has no access control.\n",
        encoding="utf-8",
    )
    findings, uncertainties = load_audit_findings(str(report))
    assert len(findings) == 1
    finding = findings[0]
    assert finding.id == "H-01"
    assert finding.severity == "high"
    assert finding.file == "Demo.sol"
    assert finding.line == 6
    assert uncertainties == []


def test_json_location_object_and_list_wrapper() -> None:
    findings = parse_json_findings(json.dumps({"findings": [
        {"id": "M-2", "name": "Reentrancy", "risk": "Medium",
         "location": {"file": "src/Pool.sol", "line": 42, "function": "withdraw"}},
    ]}))
    assert findings[0].file == "src/Pool.sol"
    assert findings[0].line == 42
    assert findings[0].function == "withdraw"
    assert findings[0].severity == "medium"


def test_cli_json(tmp_path: Path) -> None:
    target, audit = _setup(tmp_path, [
        {"id": "H-01", "title": "Unguarded setter", "severity": "High",
         "function": "setOwner"},
    ])
    result = subprocess.run(
        [sys.executable, "-m", "blackheart", "audit", "coverage", str(target),
         "--audit", str(audit), "--json"],
        cwd=ROOT, capture_output=True, text=True, timeout=240,
    )
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["findings_total"] == 1
    assert "coverage" in payload
