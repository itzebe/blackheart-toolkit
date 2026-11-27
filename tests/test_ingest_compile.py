"""Compilation must be fail-closed and its parsers must not invent artifacts.

A build failure is not a clean build, and a blocked run must never invoke the
compiler. These tests pin the gate, the two output parsers, and the model bridge,
without requiring a compiler to be installed.
"""

from __future__ import annotations

import subprocess

import pytest

from blackheart.ingest import compile as compile_mod
from blackheart.ingest.compile import (
    CompileOutcome,
    compile_project,
    models_from_compiled,
    parse_forge_artifacts,
    parse_solc_combined_json,
)
from blackheart.toolchain.enforce import self_test_record

FORGE_PAYLOAD = {
    "src/Token.sol:Token": {
        "abi": [
            {"type": "function", "name": "mint", "stateMutability": "nonpayable",
             "inputs": [{"name": "to", "type": "address"},
                        {"name": "amount", "type": "uint256"}], "outputs": []},
        ],
        "bytecode": {"object": "0x6001"},
    },
    "src/Token.sol:IERC20": {"abi": [], "bytecode": {"object": "0x"}},
}

SOLC_PAYLOAD = {
    "contracts": {
        "src/Token.sol:Token": {
            "abi": '[{"type":"function","name":"mint","stateMutability":"nonpayable",'
                   '"inputs":[],"outputs":[]}]',
            "bin": "6001",
        }
    }
}


def test_parse_forge_artifacts_reads_mapping_shape():
    artifacts = parse_forge_artifacts(FORGE_PAYLOAD)
    assert set(artifacts) == {"Token", "IERC20"}
    assert artifacts["Token"].abi[0]["name"] == "mint"
    assert artifacts["Token"].bytecode == "0x6001"


def test_parse_forge_artifacts_reads_list_shape():
    artifacts = parse_forge_artifacts([{"contractName": "Foo", "abi": [], "bytecode": "0x"}])
    assert set(artifacts) == {"Foo"}


def test_parse_solc_combined_json_decodes_string_abi():
    artifacts = parse_solc_combined_json(SOLC_PAYLOAD)
    assert set(artifacts) == {"Token"}
    assert artifacts["Token"].abi[0]["name"] == "mint"


def test_compile_without_a_record_is_blocked_and_invokes_nothing(monkeypatch):
    calls = []
    monkeypatch.setattr(compile_mod.subprocess, "run",
                        lambda *a, **k: calls.append(a) or (_ for _ in ()).throw(AssertionError))
    outcome = compile_project(".", compatibility=None, target_component="x",
                              repository="blackheart")
    assert outcome.status == "BLOCKED"
    assert calls == []


def test_compile_without_a_compiler_is_blocked(monkeypatch):
    monkeypatch.setattr(compile_mod, "find_compiler", lambda: None)
    outcome = compile_project(".", compatibility=self_test_record(),
                              target_component="x", repository="blackheart")
    assert outcome.status == "BLOCKED"
    assert "compiler" in outcome.reason


def test_compile_parses_a_successful_forge_build(monkeypatch, tmp_path):
    monkeypatch.setattr(compile_mod, "find_compiler", lambda: ("forge", "/usr/bin/forge"))

    def fake_run(cmd, **kwargs):
        return subprocess.CompletedProcess(cmd, 0, stdout=__import__("json").dumps(FORGE_PAYLOAD),
                                           stderr="")

    monkeypatch.setattr(compile_mod.subprocess, "run", fake_run)
    outcome = compile_project(tmp_path, compatibility=self_test_record(),
                              target_component="x", repository="blackheart")
    assert outcome.status == "OK"
    assert outcome.tool == "forge"
    assert "Token" in outcome.artifacts


def test_a_compiler_that_produces_nothing_is_incomplete_not_clean(monkeypatch, tmp_path):
    monkeypatch.setattr(compile_mod, "find_compiler", lambda: ("forge", "/usr/bin/forge"))

    def fake_run(cmd, **kwargs):
        return subprocess.CompletedProcess(cmd, 1, stdout="not json", stderr="boom")

    monkeypatch.setattr(compile_mod.subprocess, "run", fake_run)
    outcome = compile_project(tmp_path, compatibility=self_test_record(),
                              target_component="x", repository="blackheart")
    assert outcome.status == "INCOMPLETE"
    assert not outcome.ok


def test_models_from_compiled_builds_a_model_per_contract():
    outcome = CompileOutcome(
        "forge", "OK", artifacts=parse_forge_artifacts(FORGE_PAYLOAD))
    models = models_from_compiled(outcome)
    assert set(models) == {"Token", "IERC20"}
    assert {o.name for o in models["Token"].operations} == {"mint"}


def test_find_compiler_returns_the_resolved_binary(monkeypatch):
    from blackheart.engines.solidity import base

    class Paths:
        binary = "/opt/foundry/bin/forge"

    monkeypatch.setattr(base, "resolve_tool",
                        lambda tool: Paths() if tool == "forge" else None)
    assert compile_mod.find_compiler() == ("forge", "/opt/foundry/bin/forge")


def test_parse_forge_artifacts_attaches_the_standard_json_source_ast():
    # Foundry 1.10 emits the compiler's standard JSON: the AST lives on the
    # source unit, while the ABI lives under contracts[path][name][*].contract.
    payload = {
        "sources": {
            "src/Token.sol": [
                {"source_file": {"ast": {"nodeType": "SourceUnit", "nodes": []}}},
            ],
        },
        "contracts": {
            "src/Token.sol": {
                "Token": [{"contract": {
                    "abi": [{"type": "function", "name": "mint",
                             "inputs": [], "outputs": [],
                             "stateMutability": "nonpayable"}],
                    "bytecode": {"object": "0x6001"},
                }}],
            },
        },
    }
    artifacts = parse_forge_artifacts(payload)
    assert set(artifacts) == {"Token"}
    assert artifacts["Token"].abi[0]["name"] == "mint"
    assert artifacts["Token"].ast["nodeType"] == "SourceUnit"
