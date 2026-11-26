"""The seams between subsystems must carry a document from one step to the next.

Each test here pins a defect found by driving the CLI the way an operator does:

* `compat template` writes a file that `compat check` must load (BH-01);
* `bounty capture` writes a snapshot that `bounty evaluate` must accept (BH-03);
* `findings export` writes a record that `bounty evaluate` must evaluate (BH-04).

A seam that fails is not a cosmetic bug: it strands a recorded investigation at the
step where it would become a submission, so the failure is pinned at the level of
the documented workflow rather than of a single function.
"""

from __future__ import annotations

import json

import pytest

from blackheart.bounty import (
    PolicySnapshot,
    ProgramPolicy,
    Severity,
    evaluate,
    finding_payload_from_record,
    is_finding_record,
    sha256_text,
)
from blackheart.models import Classification, Finding
from blackheart.toolchain import CompatibilityRecord, admit, template

# --------------------------------------------------------------------------- #
# BH-01: a template must be loadable by the gate that printed it
# --------------------------------------------------------------------------- #

FILLED_RECORD = {
    "target_component": "ExampleVault",
    "language": "Solidity",
    "language_version": "0.8.30",
    "framework": "Foundry",
    "runtime": "EVM",
    "tool": "Foundry",
    "compatibility_evidence": "registry:Solidity/Foundry",
    "selection_reason": "the target is Solidity and Foundry is the registered fuzzer",
    "expected_coverage": "invariant sequences over deposit and withdraw",
    "known_limitations": "single block timestamp, no cross-chain state",
    "smoke_test": "passed",
    "repository": "example/vault",
    "commit": "0" * 40,
    "control_component": "ExampleVaultGuarded",
}


def test_compat_template_loads_back_through_the_gate():
    """`compat template` emits `_policy`/`_statuses`; the gate must still read it."""
    record = CompatibilityRecord.from_dict(template())
    assert record.complete is False, "a blank template must not look complete"


def test_filled_template_is_admitted():
    """The documented remedy -- fill the template, pass it back -- must work."""
    data = {**template(), **FILLED_RECORD}
    decision = admit(CompatibilityRecord.from_dict(data))
    assert decision.admitted, decision.reasons


def test_unknown_compat_field_still_fails_closed():
    """Only `_`-prefixed commentary is tolerated; a typo is still a rejection."""
    with pytest.raises(ValueError, match="unknown compatibility field"):
        CompatibilityRecord.from_dict({**template(), "target_compnent": "typo"})


# --------------------------------------------------------------------------- #
# BH-03: a capture must be a usable policy, and a missing snapshot must block
# --------------------------------------------------------------------------- #

def _capture(tmp_path, text="Scope: contracts. PoC required.") -> dict:
    snapshot = PolicySnapshot(
        program="example",
        source_url="https://example.test/policy",
        retrieved_at="2026-11-21",
        sha256=sha256_text(text),
        captured_text=text,
    )
    path = tmp_path / "capture.json"
    path.write_text(json.dumps(snapshot.to_dict()))
    return json.loads(path.read_text())


def test_bounty_capture_is_accepted_as_a_policy(tmp_path):
    """`bounty capture --out` writes a bare snapshot; `bounty evaluate --policy`
    must read it without the operator reshaping it into a ProgramPolicy."""
    policy = ProgramPolicy.from_dict(_capture(tmp_path))
    assert policy.program == "example"
    assert policy.snapshot.is_verified(), "the captured text must verify against its hash"


def test_policy_without_a_snapshot_fails_closed(tmp_path):
    """An absent snapshot must be an error, never an empty one read as unverified."""
    with pytest.raises(ValueError, match="policy has no snapshot"):
        ProgramPolicy.from_dict({"program": "example", "assets": {"a": "in_scope"}})


def test_empty_snapshot_object_fails_closed():
    with pytest.raises(ValueError, match="policy has no snapshot"):
        ProgramPolicy.from_dict({"program": "example", "snapshot": {}})


def test_partial_snapshot_fails_closed():
    with pytest.raises(ValueError, match="policy snapshot is incomplete"):
        ProgramPolicy.from_dict({"program": "example", "snapshot": {"program": "example"}})


# --------------------------------------------------------------------------- #
# BH-04: a findings-repository record must be evaluable by the bounty layer
# --------------------------------------------------------------------------- #

RECORD = {
    "finding_id": "EX-1",
    "title": "Example defect",
    "target": "Example",
    "component": "Vault",
    "status": "STRONGLY_SUPPORTED",
    "severity": "Medium",
    "category": "access control",
    "attack_prerequisites": "an unprivileged account",
    "root_cause_file": "Vault.sol",
    "root_cause_location": "withdraw",
    "vulnerable_implementation": "no owner check",
    "repro_steps": "forge test --match-test exploit",
    "repro_commands": "forge test",
    "poc_code": "test/Vault.t.sol",
    "expected_behavior": "the call reverts",
    "observed_behavior": "the call succeeds",
    "consequences": "funds drained",
    "evidence_ids": "test-output.txt, dump.txt",
    "verification_result": "reproduced",
    "remaining_uncertainty": "whether the relayer credits it",
    "discovery_date": "2026-11-21",
    "reporting_channel": "https://example.test/report",
}


def test_record_is_recognised_and_translated():
    assert is_finding_record(RECORD)
    assert not is_finding_record({"finding_id": "x", "title": "y"})
    payload = finding_payload_from_record(RECORD)
    finding = Finding.from_dict(payload)
    assert finding.finding_id == "EX-1"
    assert finding.severity == Severity.MEDIUM
    assert finding.evidence_ids == ["test-output.txt", "dump.txt"]
    assert finding.review_independence.value == "UNRECORDED", (
        "a record that names no reviewer provenance must never read as independent"
    )


@pytest.mark.parametrize(
    "verdict,expected",
    [
        ("CONFIRMED", Classification.CONFIRMED),
        ("STRONGLY_SUPPORTED", Classification.NEEDS_MORE_EVIDENCE),
        ("UNCONFIRMED", Classification.NEEDS_MORE_EVIDENCE),
        ("NOT_REPRODUCIBLE", Classification.NEEDS_MORE_EVIDENCE),
        ("INFORMATIONAL", Classification.INFORMATIONAL),
        ("FALSE_POSITIVE", Classification.FALSE_POSITIVE),
        ("OUT_OF_SCOPE", Classification.OUT_OF_SCOPE),
    ],
)
def test_adapter_never_promotes_a_verdict(verdict, expected):
    payload = finding_payload_from_record({**RECORD, "status": verdict})
    assert payload["classification"] == expected.value


def test_translated_record_is_evaluated(tmp_path):
    """The whole documented chain: capture a policy, evaluate a recorded finding."""
    policy = ProgramPolicy.from_dict(
        {**_capture(tmp_path), "assets": {"Vault": "in_scope"}}
    )
    finding = Finding.from_dict(finding_payload_from_record(RECORD))
    evaluation = evaluate(finding, policy)
    assert evaluation.finding_id == "EX-1"
    assert evaluation.outcome, "an evaluation must state an outcome"
    assert evaluation.outcome != "PAYABLE", (
        "a non-confirmed classification must not be payable without reproduction"
    )
