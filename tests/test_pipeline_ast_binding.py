"""The compiler AST must be sliced from the source unit it came from."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from blackheart.ingest.solc import compile_sources
from blackheart.pipeline import (
    _ast_contracts_from_artifacts, _project_root, _read_source_files,
)

TOKEN = """
pragma solidity ^0.8.0;
contract Token {
    uint256 public x;
    function bump() external { x += 1; }
}
"""

VAULT = """
pragma solidity ^0.8.0;
import {Token} from "./Token.sol";
contract Vault {
    Token public token;
    uint256 public total;
    function deposit(uint256 amount) external { total += amount; }
}
"""


@pytest.mark.skipif(
    shutil.which("solc") is None and shutil.which("forge") is None,
    reason="no Solidity compiler installed",
)
def test_ast_body_comes_from_the_compiled_source_not_the_first_file(tmp_path: Path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "Token.sol").write_text(TOKEN)
    (src / "Vault.sol").write_text(VAULT)
    (tmp_path / "foundry.toml").write_text(
        "[profile.default]\nsrc='src'\nout='out'\nast=true\nbuild_info=true\n")

    files = _read_source_files(str(src / "Vault.sol"))
    assert "Token.sol" in files
    compiled = compile_sources(
        files, entry_files=("Vault.sol",), project_root=tmp_path)
    assert compiled.ok, compiled.reason
    contracts = _ast_contracts_from_artifacts(compiled.artifacts, files)
    vault = next(c for c in contracts if c.name == "Vault")
    deposit = next(f for f in vault.functions if f.name == "deposit")
    assert "total += amount" in deposit.body
    assert "x += 1" not in deposit.body


def test_project_root_walks_to_the_nearest_manifest(tmp_path: Path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "Vault.sol").write_text(VAULT)
    (tmp_path / "foundry.toml").write_text("[profile.default]\n")
    assert _project_root(str(src / "Vault.sol")) == tmp_path.resolve()


def test_pipeline_and_mission_default_to_the_compiler_ast():
    from blackheart.cli import build_parser

    parser = build_parser()
    pipeline = parser.parse_args(["pipeline", "--source", "Vault.sol"])
    assert pipeline.compiler_ast is True
    assert parser.parse_args(
        ["pipeline", "--source", "Vault.sol", "--scanner"]).compiler_ast is False
    mission = parser.parse_args(["mission", "--source", "Vault.sol"])
    assert mission.compiler_ast is True
    assert parser.parse_args(
        ["mission", "--source", "Vault.sol", "--scanner"]).compiler_ast is False
