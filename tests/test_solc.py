"""Source compilation is real, fail-closed, and picks the matching runtime."""

from __future__ import annotations

import json
import subprocess

from blackheart.ingest import solc as solc_mod
from blackheart.ingest.solc import compile_sources, recompile_runtime

PAYLOAD = {
    "contracts": {
        "src/Vault.sol:Vault": {
            "abi": "[]",
            "bin": "6001",
            "bin-runtime": "6002",
        },
        "src/Other.sol:Other": {
            "abi": "[]",
            "bin": "6003",
            "bin-runtime": "6004",
        },
    }
}


def test_compile_sources_reads_runtime_bytecode(monkeypatch):
    monkeypatch.setattr(solc_mod, "find_compiler", lambda: ("solc", "/usr/bin/solc"))

    def runner(cmd, **kwargs):
        return subprocess.CompletedProcess(cmd, 0, json.dumps(PAYLOAD), "")

    outcome = compile_sources({"Vault.sol": "contract Vault {}"}, runner=runner)
    assert outcome.ok
    assert outcome.tool == "solc"
    assert outcome.runtimes()["Vault"] == b"\x60\x02"
    assert outcome.runtimes()["Other"] == b"\x60\x04"


def test_no_compiler_is_a_named_gap_not_a_clean_build(monkeypatch):
    monkeypatch.setattr(solc_mod, "find_compiler", lambda: None)
    outcome = compile_sources({"Vault.sol": "contract Vault {}"})
    assert outcome.status == "NO_COMPILER"
    assert not outcome.ok


def test_a_failed_build_is_incomplete(monkeypatch):
    monkeypatch.setattr(solc_mod, "find_compiler", lambda: ("solc", "/usr/bin/solc"))

    def runner(cmd, **kwargs):
        return subprocess.CompletedProcess(cmd, 1, "not json", "boom")

    outcome = compile_sources({"Vault.sol": "contract Vault {}"}, runner=runner)
    assert outcome.status == "INCOMPLETE"
    assert not outcome.ok


def test_recompile_runtime_prefers_the_exact_match(monkeypatch):
    monkeypatch.setattr(solc_mod, "find_compiler", lambda: ("solc", "/usr/bin/solc"))

    def runner(cmd, **kwargs):
        return subprocess.CompletedProcess(cmd, 0, json.dumps(PAYLOAD), "")

    assert recompile_runtime({"Vault.sol": "contract Vault {}"}, "", b"\x60\x04",
                             runner=runner) == b"\x60\x04"


def test_recompile_runtime_reports_no_artifact(monkeypatch):
    monkeypatch.setattr(solc_mod, "find_compiler", lambda: ("solc", "/usr/bin/solc"))

    def runner(cmd, **kwargs):
        return subprocess.CompletedProcess(cmd, 1, "", "boom")

    try:
        recompile_runtime({"Vault.sol": "contract Vault {}"}, "", b"\x60\x02",
                          runner=runner)
    except RuntimeError as exc:
        assert "parseable" in str(exc) or "failed" in str(exc)
    else:
        raise AssertionError("a failed build must not return runtime bytecode")


def test_an_explicit_compiler_path_is_used_not_replaced_by_autodetection(tmp_path):
    import json
    import subprocess
    from blackheart.ingest.solc import compile_sources

    compiler = tmp_path / "solc"
    compiler.write_text("#!/bin/sh\n", encoding="utf-8")
    seen = {}

    def runner(cmd, **kwargs):
        seen["cmd"] = cmd
        payload = {"contracts": {"src/A.sol:A": {
            "abi": [], "bin": "6000", "bin-runtime": "6001"}}}
        return subprocess.CompletedProcess(cmd, 0, json.dumps(payload), "")

    result = compile_sources({"A.sol": "contract A {}"}, compiler=str(compiler),
                             runner=runner)
    assert result.status == "OK"
    assert seen["cmd"][0] == str(compiler)


def test_a_sourcify_version_string_uses_an_installed_compiler(monkeypatch, tmp_path):
    import json
    import subprocess
    from blackheart.ingest import solc as solc_mod

    monkeypatch.setattr(solc_mod, "find_compiler",
                        lambda: ("forge", "/fake/forge"))
    seen = {}

    def runner(cmd, **kwargs):
        seen["cmd"] = cmd
        payload = {"src/A.sol:A": {
            "abi": [], "bytecode": {"object": "0x6000"},
            "deployedBytecode": {"object": "0x6001"}}}
        return subprocess.CompletedProcess(cmd, 0, json.dumps(payload), "")

    result = solc_mod.compile_sources({"A.sol": "contract A {}"},
                                      compiler="0.8.20+commit.a1b79de6",
                                      runner=runner)
    assert result.status == "OK"
    assert seen["cmd"][0] == "/fake/forge"


def test_discover_compile_inputs_reads_foundry_remappings_and_node_modules(tmp_path):
    from blackheart.ingest.solc import discover_compile_inputs

    root = tmp_path / "packages" / "core"
    (root / "lib").mkdir(parents=True)
    (root / "node_modules").mkdir()
    (root.parent / "node_modules").mkdir()
    (root / "foundry.toml").write_text(
        '[profile.default]\n'
        'libs = ["lib"]\n'
        'allow_paths = ["../node_modules"]\n'
        'remappings = ["@oz/=../node_modules/@oz/"]\n',
        encoding="utf-8",
    )
    includes, remappings, libs = discover_compile_inputs(root)
    assert str((root / "lib").resolve()) in includes
    assert str((root.parent / "node_modules").resolve()) in includes
    assert f"@oz/={root.parent / 'node_modules' / '@oz'}/" in remappings
    assert str((root / "lib").resolve()) in libs


def test_entry_files_compile_only_the_import_closure(tmp_path):
    compiler = tmp_path / "solc"
    compiler.write_text("#!/bin/sh\n", encoding="utf-8")
    seen = {}

    def runner(cmd, **kwargs):
        seen["cmd"] = cmd
        payload = {"contracts": {"src/A.sol:A": {
            "abi": [], "bin": "6000", "bin-runtime": "6001"}}}
        return subprocess.CompletedProcess(cmd, 0, json.dumps(payload), "")

    files = {
        "contracts/A.sol": 'import "./B.sol"; contract A {}',
        "contracts/B.sol": "contract B {}",
        "contracts/Broken.sol": 'import "missing/Dep.sol"; contract Broken {}',
    }
    outcome = compile_sources(
        files, compiler=str(compiler), entry_files=("contracts/A.sol",),
        runner=runner,
    )
    assert outcome.status == "OK", outcome.reason
    assert any(path.endswith("src/contracts/A.sol") for path in seen["cmd"])
    assert any(path.endswith("src/contracts/B.sol") for path in seen["cmd"])
    assert not any(path.endswith("Broken.sol") for path in seen["cmd"])


def test_a_missing_import_is_named_from_the_compiler(tmp_path):
    compiler = tmp_path / "solc"
    compiler.write_text("#!/bin/sh\n", encoding="utf-8")

    def runner(cmd, **kwargs):
        return subprocess.CompletedProcess(
            cmd, 1, "", 'Error: Source "missing/Dep.sol" not found: File not found.')

    outcome = compile_sources(
        {"contracts/A.sol": 'import "missing/Dep.sol"; contract A {}'},
        compiler=str(compiler), entry_files=("contracts/A.sol",), runner=runner,
    )
    assert outcome.status == "INCOMPLETE"
    assert "missing/Dep.sol" in outcome.reason
    assert "not found" in outcome.reason


def test_explicit_include_paths_and_remappings_reach_solc(tmp_path):
    compiler = tmp_path / "solc"
    compiler.write_text("#!/bin/sh\n", encoding="utf-8")
    include = tmp_path / "deps"
    include.mkdir()
    seen = {}

    def runner(cmd, **kwargs):
        seen["cmd"] = cmd
        payload = {"contracts": {"src/A.sol:A": {
            "abi": [], "bin": "6000", "bin-runtime": "6001"}}}
        return subprocess.CompletedProcess(cmd, 0, json.dumps(payload), "")

    compile_sources(
        {"A.sol": "contract A {}"}, compiler=str(compiler),
        entry_files=("A.sol",), include_paths=(str(include),),
        remappings=("@oz/=deps/",), project_root=tmp_path, runner=runner,
    )
    cmd = seen["cmd"]
    assert "--include-path" in cmd and str(include.resolve()) in cmd
    assert any(item.startswith("@oz/=") for item in cmd)


def test_an_exact_pragma_selects_the_installed_version(monkeypatch, tmp_path):
    from blackheart.ingest import solc as solc_mod

    compiler = tmp_path / "solc-0.8.16"
    compiler.write_text("#!/bin/sh\n", encoding="utf-8")
    monkeypatch.setattr(solc_mod, "_versioned_solc",
                        lambda version="": str(compiler) if version == "0.8.16" else None)
    seen = {}

    def runner(cmd, **kwargs):
        seen["cmd"] = cmd
        payload = {"contracts": {"src/A.sol:A": {
            "abi": [], "bin": "6000", "bin-runtime": "6001"}}}
        return subprocess.CompletedProcess(cmd, 0, json.dumps(payload), "")

    outcome = compile_sources(
        {"A.sol": "pragma solidity 0.8.16; contract A {}"},
        entry_files=("A.sol",), runner=runner,
    )
    assert outcome.status == "OK", outcome.reason
    assert seen["cmd"][0] == str(compiler)
