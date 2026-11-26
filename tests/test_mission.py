"""A mission writes the pipeline's own result; it never upgrades it."""

from pathlib import Path

from blackheart.mission import run_mission
from blackheart.pipeline import PipelineConfig

VULNERABLE = """
contract Vault {
    address public owner;
    mapping(address => uint256) public balanceOf;
    uint256 public totalSupply;

    function deposit(uint256 amount) external {
        balanceOf[msg.sender] += amount;
        totalSupply += amount;
    }

    function setOwner(address newOwner) external { owner = newOwner; }
}
"""


def test_mission_writes_json_and_markdown_with_the_pipeline_verdict(tmp_path):
    source = tmp_path / "Vault.sol"
    source.write_text(VULNERABLE, encoding="utf-8")
    out = tmp_path / "mission"
    artifacts = run_mission(PipelineConfig(
        source_path=str(source), contract_name="Vault", max_depth=3,
        write_finding=False, evidence_root=str(tmp_path / "evidence"),
    ), directory=out)
    assert artifacts.result.status in {"REPRODUCED", "VERIFIED"}
    payload = artifacts.to_dict()
    assert payload["result"]["status"] == artifacts.result.status
    assert Path(payload["artifacts"]["json"]).exists()
    assert Path(payload["artifacts"]["markdown"]).exists()
    markdown = Path(payload["artifacts"]["markdown"]).read_text(encoding="utf-8")
    assert "## Stages" in markdown
    assert "not a deployment claim" in markdown
