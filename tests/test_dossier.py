"""Acceptance bar for ``blackheart dossier``.

The dossier is a composition, not an engine: it must report what the scanner,
rule engine, interrogation and dataflow passes already report, rank it, and never
render a lead as a confirmed vulnerability.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from blackheart.dossier import build_dossier, render_markdown

ROOT = Path(__file__).resolve().parent.parent

VULNERABLE = """\
pragma solidity ^0.8.0;

contract Demo {
    address public owner;
    mapping(address => uint256) public balances;

    function setOwner(address next) external {
        owner = next;
    }

    function withdraw() external {
        uint256 amount = balances[msg.sender];
        balances[msg.sender] = 0;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
    }

    function isAdmin() external view returns (bool) {
        return tx.origin == owner;
    }

    function kill() external {
        selfdestruct(payable(msg.sender));
    }
}
"""


def _write(tmp_path: Path) -> Path:
    (tmp_path / "Demo.sol").write_text(VULNERABLE, encoding="utf-8")
    return tmp_path


def test_dossier_composes_surface_leads_claims_and_flows(tmp_path: Path) -> None:
    dossier = build_dossier(str(_write(tmp_path)))
    assert dossier["blocked"] is False
    assert dossier["language"] == "solidity"
    surface = dossier["surface"]
    assert surface["contracts"] >= 1
    assert surface["functions"] >= 3
    assert surface["leads"], "expected at least one candidate lead"
    assert dossier["interrogation"]["supported"] is True
    assert dossier["dataflow"]["supported"] is True
    assert dossier["next_probes"], "expected a ranked next-probe list"


def test_dossier_ranks_probes_and_keeps_the_lead_discipline(tmp_path: Path) -> None:
    dossier = build_dossier(str(_write(tmp_path)))
    kinds = {probe["kind"] for probe in dossier["next_probes"]}
    assert kinds <= {"candidate-lead", "falsified-claim", "unprivileged-flow"}
    severities = [p["severity"] for p in dossier["next_probes"]]
    order = {"critical": 0, "high": 0, "medium": 1, "low": 2, "info": 3}
    assert severities == sorted(severities, key=lambda s: order.get(s, 9))
    text = render_markdown(dossier)
    assert "map, not a finding" in text


def test_dossier_cli_json(tmp_path: Path) -> None:
    target = _write(tmp_path)
    result = subprocess.run(
        [sys.executable, "-m", "blackheart", "dossier", str(target), "--json"],
        cwd=ROOT, capture_output=True, text=True, timeout=240,
    )
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["language"] == "solidity"
    assert "surface" in payload and "next_probes" in payload


def test_dossier_empty_tree_is_honest(tmp_path: Path) -> None:
    (tmp_path / "Empty.sol").write_text("pragma solidity ^0.8.0;\n", encoding="utf-8")
    dossier = build_dossier(str(tmp_path))
    assert dossier["blocked"] is False
    assert dossier["surface"]["functions"] == 0
    assert dossier["next_probes"] == []
    assert "not a proof of safety" in render_markdown(dossier)
