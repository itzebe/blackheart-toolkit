"""Tests for the five Solidity engine adapters.

Each adapter is exercised against the *real* on-disk format its engine writes --
Slither's ``slither_results.json``, Wake's ``.wake/detections.json``, Echidna's
JSON stream, Medusa's per-sequence corpus files, Halmos' JSON report -- using
small synthetic fixtures that reproduce those shapes. Nothing here claims an
engine ran: a fixture stands in for a file an engine writes, so the parsers, the
exit-code contract and the normalization are tested without a toolchain.

Live execution is covered separately by ``tests/test_engines_live.py``, which
skips when a binary is absent. The two are complementary: this file proves the
adapter never *lies* about output, the live file proves it can produce output.
"""

from __future__ import annotations

import json

import pytest

from blackheart.engines import get_adapter
from blackheart.engines.contract import (
    EngineState,
    ExecutionMetadata,
    ExecutionResult,
)
from blackheart.engines.solidity.base import SolidityEngineAdapter
from blackheart.engines.solidity.medusa import _sequence_signature, _violated_properties

ALL_ENGINES = ("slither", "wake", "halmos", "echidna", "medusa")


def _result(records, *, exit_code=0, artifacts=None, version="1.0.0",
            stdout="") -> ExecutionResult:
    return ExecutionResult(
        metadata=ExecutionMetadata(
            engine="fixture",
            version=version,
            argv=["fixture"],
            cwd="/tmp",
            started_at="2026-01-01T00:00:00+00:00",
            finished_at="2026-01-01T00:00:01+00:00",
            exit_code=exit_code,
            target="/tmp/target",
        ),
        raw_stdout=stdout,
        raw_stderr="",
        artifacts=artifacts or {},
        raw_records=list(records),
    )


# --------------------------------------------------------------------------- #
# Exit-code contract: a finding is not a failure, a crash is not a clean scan
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("name,clean,finding", [
    ("slither", 0, 255),
    ("wake", 0, 3),
    ("halmos", 0, 1),
    ("echidna", 0, 1),
    ("medusa", 0, 7),
])
def test_finding_exit_codes_are_success_and_crashes_are_failures(name, clean, finding):
    adapter = get_adapter(name, "/tmp")
    assert isinstance(adapter, SolidityEngineAdapter)
    assert clean in adapter.CLEAN_EXIT_CODES
    assert finding in adapter.FINDING_EXIT_CODES
    # A code in neither set is a tool failure, never "no bugs found".
    assert 99 not in adapter.CLEAN_EXIT_CODES
    assert 99 not in adapter.FINDING_EXIT_CODES


@pytest.mark.parametrize("name", ALL_ENGINES)
def test_crash_with_no_artifact_is_failed_not_clean(name):
    adapter = get_adapter(name, "/tmp")
    state, reason = adapter._classify_exit(99, False, False, parsed=False)
    assert state is EngineState.FAILED
    assert "99" in reason


@pytest.mark.parametrize("name", ALL_ENGINES)
def test_timeout_is_failed(name):
    adapter = get_adapter(name, "/tmp")
    state, reason = adapter._classify_exit(None, True, False, parsed=False)
    assert state is EngineState.FAILED
    assert reason == "timeout"


@pytest.mark.parametrize("name", ALL_ENGINES)
def test_clean_exit_without_artifact_is_partial_not_completed(name):
    """A clean exit we could not read is a partial run, never a clean scan."""
    adapter = get_adapter(name, "/tmp")
    state, reason = adapter._classify_exit(0, False, False, parsed=False)
    assert state is EngineState.PARTIAL
    assert "no parseable artifact" in reason


@pytest.mark.parametrize("name", ALL_ENGINES)
def test_clean_exit_with_an_artifact_is_completed(name):
    adapter = get_adapter(name, "/tmp")
    state, _ = adapter._classify_exit(0, False, False, parsed=True)
    assert state is EngineState.COMPLETED


@pytest.mark.parametrize("name", ALL_ENGINES)
def test_unlisted_nonzero_exit_is_failed_even_when_parsed(name):
    """Slither exits 255 for findings; 42 is a crash, not a quieter finding."""
    adapter = get_adapter(name, "/tmp")
    state, _ = adapter._classify_exit(42, False, False, parsed=True)
    assert state is EngineState.FAILED


# --------------------------------------------------------------------------- #
# Slither
# --------------------------------------------------------------------------- #

SLITHER_DETECTOR = {
    "check": "reentrancy-eth",
    "impact": "High",
    "confidence": "Medium",
    "description": "Reentrancy in Vault.withdraw(uint256)",
    "elements": [
        {"type": "function", "name": "withdraw",
         "source_mapping": {"filename_relative": "src/Vault.sol",
                            "lines": [42, 43, 44]}},
        {"type": "contract", "name": "Vault"},
    ],
}


def test_slither_normalizes_name_location_and_cwe(tmp_path):
    adapter = get_adapter("slither", tmp_path)
    report = tmp_path / "slither_results.json"
    report.write_text(json.dumps({"success": True, "results": {
        "detectors": [SLITHER_DETECTOR]}}), encoding="utf-8")

    findings = adapter.normalize_findings(
        _result([SLITHER_DETECTOR],
                artifacts={"slither_results.json": str(report)}))

    assert len(findings) == 1
    f = findings[0]
    assert f.source_engine == "slither"
    assert "reentrancy-eth" in f.title
    assert f.severity == "high"
    assert f.cwe == "CWE-841"
    assert f.source_location.startswith("src/Vault.sol:42")
    # A static observation never claims to be reproduced.
    assert f.reproduction_status == "not_attempted"
    assert f.reproduction == ""
    assert f.exploit_steps == []


def test_slither_confidence_is_not_folded_into_severity(tmp_path):
    """High impact / Low confidence stays High severity with Low confidence."""
    adapter = get_adapter("slither", tmp_path)
    record = {"check": "divide-before-multiply", "impact": "Medium",
              "confidence": "Low", "description": "x", "elements": []}
    f = adapter.normalize_findings(_result([record]))[0]
    assert f.severity == "medium"
    assert f.confidence.lower() == "low"


def test_slither_unknown_detector_asserts_no_cwe(tmp_path):
    adapter = get_adapter("slither", tmp_path)
    record = {"check": "some-new-detector", "impact": "Low",
              "confidence": "High", "description": "x", "elements": []}
    assert adapter.normalize_findings(_result([record]))[0].cwe == ""


def test_slither_detector_without_a_name_is_dropped(tmp_path):
    adapter = get_adapter("slither", tmp_path)
    assert adapter.normalize_findings(_result([{"impact": "High"}])) == []


# --------------------------------------------------------------------------- #
# Wake
# --------------------------------------------------------------------------- #

WAKE_DETECTION = {
    "detector_name": "reentrancy",
    "impact": "high",
    "confidence": "medium",
    "uri": "src/Vault.sol",
    "detection": {
        "message": "External call before state update",
        "location": {"relative_path": "src/Vault.sol", "start_line": 57,
                     "contract": "Vault"},
    },
}


def test_wake_normalizes_detections_with_provenance(tmp_path):
    adapter = get_adapter("wake", tmp_path)
    findings = adapter.normalize_findings(_result([WAKE_DETECTION]))

    assert len(findings) == 1
    f = findings[0]
    assert f.source_engine == "wake"
    assert "reentrancy" in f.title
    assert f.severity == "high"
    assert f.source_location == "src/Vault.sol:57"
    assert f.component == "Vault"
    # Wake's static detectors observe; they do not execute the target.
    assert f.reproduction_status == "not_attempted"


def test_wake_detection_without_detector_name_is_dropped(tmp_path):
    adapter = get_adapter("wake", tmp_path)
    assert adapter.normalize_findings(_result([{"impact": "high"}])) == []


# --------------------------------------------------------------------------- #
# Echidna
# --------------------------------------------------------------------------- #

def test_echidna_falsified_property_is_a_finding(tmp_path):
    adapter = get_adapter("echidna", tmp_path)
    record = {
        "status": "failed",
        "property": "echidna_no_value_extraction",
        "contract": "EchidnaVulnerableVault",
        "transactions": [
            {"function": "deposit", "arguments": ["0"]},
            {"function": "reentrancyAttack", "arguments": ["0"]},
        ],
    }
    findings = adapter.normalize_findings(
        _result([record], exit_code=1, version="2.4.0"))

    assert len(findings) == 1
    f = findings[0]
    assert "echidna_no_value_extraction" in f.title
    assert f.reproduction_status == "observed"
    assert "deposit(0)" in f.reproduction
    # A fuzzed counterexample is a real execution, but not a verified exploit.
    assert f.confidence == "fuzzed"


def test_echidna_passing_property_is_not_a_finding(tmp_path):
    """Echidna reports every property it touched; only falsified ones count."""
    adapter = get_adapter("echidna", tmp_path)
    record = {"status": "passed", "property": "echidna_no_value_extraction",
              "transactions": []}
    assert adapter.normalize_findings(_result([record], exit_code=0)) == []


def test_echidna_predicate_names_are_read_from_harness_source(tmp_path):
    """Echidna's JSON echoes the literal key ``"name"``; the source has the truth."""
    adapter = get_adapter("echidna", tmp_path)
    harness = tmp_path / "Echidna.sol"
    harness.write_text(
        "contract EchidnaVulnerableVault {\n"
        "    function echidna_no_value_extraction() public view returns (bool) {\n"
        "        return true;\n    }\n}\n", encoding="utf-8")
    assert adapter._predicate_names(harness) == ["echidna_no_value_extraction"]


def test_echidna_echoed_key_is_not_accepted_as_a_property_name(tmp_path):
    """``"name": "name"`` is the bug in Echidna's JSON; it must not leak through."""
    adapter = get_adapter("echidna", tmp_path)
    record = {"status": "failed", "name": "name", "transactions": []}
    findings = adapter.normalize_findings(_result([record], exit_code=1))
    assert len(findings) == 1
    assert "unresolved" in findings[0].title


# --------------------------------------------------------------------------- #
# Medusa
# --------------------------------------------------------------------------- #

def test_medusa_violated_property_extraction_strips_ansi_and_contract():
    stdout = ("\x1b[1m\x1b[31m[FAILED] \x1b[0m"
              "Property Test: Vault.property_noValueExtraction()")
    assert _violated_properties(stdout) == ["property_noValueExtraction"]


def test_medusa_violated_property_absent_returns_nothing():
    assert _violated_properties("Test summary: 5 test(s) passed, 0 test(s) failed") == []


def test_medusa_sequence_signature_ignores_nonce_and_gas():
    a = [{"call": {"to": "0xabc", "nonce": 1, "gasLimit": 100,
                   "dataAbiValues": {"methodSignature": "deposit(uint256)",
                                     "inputValues": ["1"]}}}]
    b = [{"call": {"to": "0xabc", "nonce": 9, "gasLimit": 999,
                   "dataAbiValues": {"methodSignature": "deposit(uint256)",
                                     "inputValues": ["1"]}}}]
    assert _sequence_signature(a) == _sequence_signature(b)


def test_medusa_sequence_signature_separates_different_calls():
    a = [{"call": {"to": "0xabc", "dataAbiValues": {
        "methodSignature": "deposit(uint256)", "inputValues": ["1"]}}}]
    b = [{"call": {"to": "0xabc", "dataAbiValues": {
        "methodSignature": "withdraw(uint256)", "inputValues": ["1"]}}}]
    assert _sequence_signature(a) != _sequence_signature(b)


def _medusa_record(property_name: str, argument: str, path: str) -> dict:
    return {"kind": "failing_sequence", "property": property_name,
            "sequence_file": path,
            "sequence": [{"call": {"to": "0xabc", "dataAbiValues": {
                "methodSignature": "deposit(uint256)", "inputValues": [argument]}}}]}


def test_medusa_collapses_corpus_files_for_one_property(tmp_path):
    """Several corpus files falsifying one property are one defect, not several."""
    adapter = get_adapter("medusa", tmp_path)
    records = [_medusa_record("property_noValueExtraction", str(i), f"/tmp/seq{i}.json")
               for i in range(6)]

    findings = adapter.normalize_findings(_result(records, exit_code=7))
    assert len(findings) == 1
    assert "property_noValueExtraction" in findings[0].title
    assert findings[0].reproduction_status == "observed"


def test_medusa_distinct_properties_are_separate_findings(tmp_path):
    adapter = get_adapter("medusa", tmp_path)
    records = [_medusa_record("property_a", "1", "/tmp/a.json"),
               _medusa_record("property_b", "2", "/tmp/b.json")]
    assert len(adapter.normalize_findings(_result(records, exit_code=7))) == 2


def test_medusa_sequence_without_calls_is_dropped(tmp_path):
    adapter = get_adapter("medusa", tmp_path)
    record = {"kind": "failing_sequence", "property": "property_a", "sequence": []}
    assert adapter.normalize_findings(_result([record], exit_code=7)) == []


# --------------------------------------------------------------------------- #
# Halmos
# --------------------------------------------------------------------------- #

def test_halmos_counterexample_is_symbolic_not_reproduced(tmp_path):
    adapter = get_adapter("halmos", tmp_path)
    record = {
        "name": "check_unprotected_initializer_cannot_be_taken",
        "exitcode": 1,
        "contract": "Symbolic",
        "num_paths": [3],
        "models": [{"model": {"p_owner": {
            "variable_name": "p_owner", "solidity_type": "address",
            "value": "0x000000000000000000000000000000000000dead"}}}],
    }
    findings = adapter.normalize_findings(
        _result([record], exit_code=1, version="0.2.0"))

    assert len(findings) == 1
    f = findings[0]
    assert "symbolic counterexample" in f.title.lower()
    # Symbolic exploration is explicitly not a concrete reproduction.
    assert f.reproduction_status == "symbolic-counterexample"
    assert f.confidence == "symbolic"
    assert "p_owner" in f.reproduction


def test_halmos_passing_test_is_not_a_finding(tmp_path):
    adapter = get_adapter("halmos", tmp_path)
    record = {"name": "check_ok", "exitcode": 0, "models": []}
    assert adapter.normalize_findings(_result([record], exit_code=0)) == []


# --------------------------------------------------------------------------- #
# Every engine: the same invariants
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("name", ALL_ENGINES)
def test_adapter_identity_and_metadata(name):
    adapter = get_adapter(name, "/tmp")
    assert adapter.name == name
    assert adapter.upstream_url
    assert adapter.license_id


@pytest.mark.parametrize("name", ALL_ENGINES)
def test_adapter_without_a_binary_is_missing_not_operational(name, tmp_path, monkeypatch):
    """No binary anywhere on this host must read as MISSING, never operational."""
    monkeypatch.setenv("PATH", str(tmp_path))
    monkeypatch.delenv(f"BLACKHEART_{name.upper()}", raising=False)
    monkeypatch.setattr("blackheart.engines.solidity.base._VENV_ROOT",
                        tmp_path / "no-venvs")
    monkeypatch.setattr("blackheart.engines.solidity.base._BIN_ROOT",
                        tmp_path / "no-bin")
    monkeypatch.setattr("blackheart.engines.solidity.base._TOOLCHAIN_DIRS",
                        (tmp_path / "no-toolchain",))
    monkeypatch.setattr("blackheart.engines.solidity.base._EXTRA_BIN_DIRS",
                        (tmp_path / "no-extra",))

    adapter = get_adapter(name, tmp_path)
    health = adapter.verify_health()
    assert health.state is EngineState.MISSING
    assert health.detail
    assert adapter.detect_installation() is False


@pytest.mark.parametrize("name", ALL_ENGINES)
def test_engine_candidates_are_never_confirmed_by_the_engine(name, tmp_path):
    """No engine may promote its own output: every finding starts unconfirmed."""
    adapter = get_adapter(name, tmp_path)
    findings = adapter.normalize_findings(_result(_sample_record(name)))
    assert findings, f"{name} produced no finding from its own sample record"
    for finding in findings:
        assert finding.may_be_read_as_vulnerability() is False
        assert finding.disposition == "NEEDS_MORE_EVIDENCE"
        assert finding.verification_status == "unverified"


# --------------------------------------------------------------------------- #
# Slither target resolution and the "clean scan of nothing" defect
# --------------------------------------------------------------------------- #

def test_slither_targets_a_framework_project_at_the_root(tmp_path):
    """A declared framework means ``slither .`` can compile; use the root."""
    (tmp_path / "foundry.toml").write_text("[profile.default]\n")
    adapter = get_adapter("slither", tmp_path)
    assert adapter._target_args(tmp_path) == ["."]


def test_slither_targets_the_contracts_directory_without_a_framework(tmp_path):
    """A bare ``contracts/`` layout is not compilable as ``.``.

    crytic-compile analyses *zero* contracts for a framework-less directory and
    Slither still reports ``success: true``; the adapter must point at the
    source directory instead so real code is compiled.
    """
    contracts = tmp_path / "contracts"
    contracts.mkdir()
    (contracts / "Vault.sol").write_text("pragma solidity ^0.8.0;\ncontract V {}\n")
    adapter = get_adapter("slither", tmp_path)
    assert adapter._target_args(tmp_path) == ["contracts"]


def test_slither_targets_src_directory_as_a_fallback(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "Vault.sol").write_text("pragma solidity ^0.8.0;\ncontract V {}\n")
    adapter = get_adapter("slither", tmp_path)
    assert adapter._target_args(tmp_path) == ["src"]


def test_slither_lists_solidity_files_when_no_conventional_layout(tmp_path):
    (tmp_path / "A.sol").write_text("pragma solidity ^0.8.0;\ncontract A {}\n")
    adapter = get_adapter("slither", tmp_path)
    assert adapter._target_args(tmp_path) == ["A.sol"]


@pytest.mark.parametrize("stream", ["stdout", "stderr"])
def test_slither_scan_of_nothing_is_never_reported_clean(stream, tmp_path):
    """A zero-contract run is unparseable, not a clean scan.

    Slither writes ``{"success": true, "results": {}}`` both for a genuinely
    clean project and for a project it could not compile into a unit. Only the
    contract count on the console distinguishes them, and it is printed to
    stderr by current releases, so both streams must be inspected.
    """
    adapter = get_adapter("slither", tmp_path)
    report = tmp_path / "slither_results.json"
    report.write_text(json.dumps({"success": True, "error": None, "results": {}}))
    adapter.config["json_out"] = str(report)
    message = ". analyzed (0 contracts with 100 detectors), 0 result(s) found"
    kwargs = {"stdout": message} if stream == "stdout" else {"stderr": message}
    artifacts, records = adapter._collect(tmp_path, **kwargs)
    assert records is None, f"a 0-contract scan read as clean via {stream}"


def test_slither_argv_carries_the_resolved_target(tmp_path):
    """The resolved target must reach the command line, not just the helper."""
    contracts = tmp_path / "contracts"
    contracts.mkdir()
    (contracts / "Vault.sol").write_text("pragma solidity ^0.8.0;\ncontract V {}\n")
    adapter = get_adapter("slither", tmp_path)
    argv = adapter._build_argv(tmp_path, {})
    assert "contracts" in argv, argv
    assert "." not in argv, f"bare '.' would analyse zero contracts: {argv}"


def test_slither_genuinely_clean_scan_is_parsed(tmp_path):
    """The counterpart: a real 1-contract clean run must still be COMPLETED."""
    adapter = get_adapter("slither", tmp_path)
    report = tmp_path / "slither_results.json"
    report.write_text(json.dumps({"success": True, "error": None, "results": {}}))
    adapter.config["json_out"] = str(report)
    _, records = adapter._collect(
        tmp_path, ". analyzed (1 contracts with 100 detectors), 0 result(s) found")
    assert records == []


def test_foundry_evm_version_is_pinned_to_the_solc_ceiling(tmp_path):
    """forge's default EVM target outran the pinned solc and broke compilation.

    crytic-compile forwards forge's default (``osaka``) to solc 0.8.26, which
    rejects it, so every Foundry target failed to compile for a reason unrelated
    to its own code. The adapter pins the compiler's ceiling via the environment.
    """
    (tmp_path / "foundry.toml").write_text("[profile.default]\nsrc = 'src'\n")
    adapter = get_adapter("medusa", tmp_path)
    env = adapter._build_env(tmp_path)
    assert env["FOUNDRY_EVM_VERSION"] == "cancun"


def test_a_targets_own_evm_version_is_left_alone(tmp_path):
    """An explicit choice by the target's author is not overridden."""
    (tmp_path / "foundry.toml").write_text(
        "[profile.default]\nsrc = 'src'\nevm_version = 'paris'\n")
    adapter = get_adapter("medusa", tmp_path)
    env = adapter._build_env(tmp_path)
    assert "FOUNDRY_EVM_VERSION" not in env


def test_an_operator_supplied_evm_version_wins(tmp_path, monkeypatch):
    (tmp_path / "foundry.toml").write_text("[profile.default]\n")
    monkeypatch.setenv("FOUNDRY_EVM_VERSION", "shanghai")
    adapter = get_adapter("medusa", tmp_path)
    assert adapter._build_env(tmp_path)["FOUNDRY_EVM_VERSION"] == "shanghai"


def _sample_record(name: str) -> list[dict]:
    """One minimal record in each engine's own format."""
    if name == "slither":
        return [SLITHER_DETECTOR]
    if name == "wake":
        return [WAKE_DETECTION]
    if name == "echidna":
        return [{"status": "failed", "property": "echidna_p",
                 "transactions": [{"function": "f", "arguments": []}]}]
    if name == "medusa":
        return [_medusa_record("property_p", "1", "/tmp/p.json")]
    return [{"name": "check_p", "exitcode": 1, "models": []}]
