"""Semantic equivalence adds selector evidence to a bytecode match."""

from __future__ import annotations

import json
import subprocess

from blackheart.ingest.equivalence import (
    check_equivalence, selector_from_signature, selectors_in_bytecode,
)

FILES = {"Vault.sol": "contract Vault { function transfer(address,uint256) external {} }"}
TRANSFER = selector_from_signature("transfer(address,uint256)")
MINT = selector_from_signature("mint(address,uint256)")


def _payload(abi):
    return {"contracts": {"src/Vault.sol:Vault": {
        "abi": json.dumps(abi), "bin": "00", "bin-runtime": "63" + TRANSFER + "00",
    }}}


def _runner(payload):
    def run(cmd, **kwargs):
        return subprocess.CompletedProcess(cmd, 0, json.dumps(payload), "")
    return run


def _abi(name, types):
    return [{"type": "function", "name": name,
             "inputs": [{"type": t} for t in types]}]


def test_a_matching_selector_is_equivalent():
    report = check_equivalence(
        FILES, bytes.fromhex("63" + TRANSFER + "00"), compiler="/bin/true",
        runner=_runner(_payload(_abi("transfer", ["address", "uint256"]))))
    assert report.status == "EQUIVALENT"
    assert TRANSFER in report.deployed_selectors
    assert not report.missing_in_deployment


def test_a_source_selector_the_deployment_does_not_dispatch_is_reported():
    report = check_equivalence(
        FILES, bytes.fromhex("63" + TRANSFER + "00"), compiler="/bin/true",
        runner=_runner(_payload(_abi("mint", ["address", "uint256"]))))
    assert report.status == "SELECTOR_MISMATCH"
    assert report.missing_in_deployment == [MINT]


def test_selector_scan_is_a_heuristic_not_a_proof():
    assert selectors_in_bytecode(bytes.fromhex("63" + TRANSFER + "00")) == {TRANSFER}
    assert selectors_in_bytecode(b"\x00\x01") == set()


def _semantic_payload(abi, layout=None, ast=None):
    payload = _payload(abi)
    if layout is not None:
        payload["contracts"]["src/Vault.sol:Vault"]["storage-layout"] = layout
    if ast is not None:
        payload["sources"] = {"src/Vault.sol": {"AST": ast}}
    return payload


def test_a_storage_layout_difference_is_reported():
    layout = {"storage": [{"label": "owner", "slot": "0", "offset": 0, "type": "t_address"}]}
    expected = {"storage": [{"label": "owner", "slot": "1", "offset": 0, "type": "t_address"}]}
    report = check_equivalence(
        FILES, bytes.fromhex("63" + TRANSFER + "00"), compiler="/bin/true",
        runner=_runner(_semantic_payload(_abi("transfer", ["address", "uint256"]), layout)),
        expected_storage_layout=expected)
    assert report.status == "LAYOUT_MISMATCH"
    assert report.layout_match is False


def test_an_ast_difference_is_reported_and_an_equal_ast_passes():
    ast = {"nodeType": "SourceUnit", "nodes": [{"nodeType": "PragmaDirective",
                                                 "name": "solidity", "value": "^0.8.20"}]}
    payload = _semantic_payload(_abi("transfer", ["address", "uint256"]), ast=ast)
    same = check_equivalence(
        FILES, bytes.fromhex("63" + TRANSFER + "00"), compiler="/bin/true",
        runner=_runner(payload), expected_ast=ast)
    assert same.status == "EQUIVALENT"
    assert same.ast_match is True
    different = {"nodeType": "SourceUnit", "nodes": [{"nodeType": "PragmaDirective",
                                                       "name": "solidity", "value": "^0.7.0"}]}
    report = check_equivalence(
        FILES, bytes.fromhex("63" + TRANSFER + "00"), compiler="/bin/true",
        runner=_runner(payload), expected_ast=different)
    assert report.status == "AST_MISMATCH"
    assert report.ast_match is False
