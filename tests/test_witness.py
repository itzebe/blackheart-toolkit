"""A witness must map back to a real source line, never an invented one."""

from __future__ import annotations

from blackheart.ingest.solidity import scan_source
from blackheart.models import AttackStep
from blackheart.witness import source_trace


SOURCE = """
contract Vault {
    address public owner;
    function setOwner(address newOwner) external {
        owner = newOwner;
    }
}
"""


def test_witness_maps_to_the_function_and_line():
    contract = scan_source(SOURCE, "Vault.sol")[0]
    frames = source_trace(contract, [
        AttackStep(0, "attacker", "setOwner", {"newOwner": "attacker"}),
    ], source_path="Vault.sol")
    assert len(frames) == 1
    frame = frames[0]
    assert frame.mapped is True
    assert frame.function == "setOwner"
    assert frame.line == 5
    assert "owner = newOwner" in frame.snippet


def test_unknown_step_is_reported_unmapped():
    contract = scan_source(SOURCE, "Vault.sol")[0]
    frame = source_trace(contract, [AttackStep(0, "attacker", "missing")])[0]
    assert frame.mapped is False
    assert "no function" in frame.reason


def test_minimize_witness_returns_the_certifier_prefix():
    from blackheart.assurance.certify import CertifyConfig, certify
    from blackheart.discovery import corpus
    from blackheart.models import AttackStep
    from blackheart.witness import minimize_witness

    case = next(c for c in corpus.modelled_cases() if c.case_id == "H03-oracle-spot")
    target = case.vulnerable()
    cert = certify(target, CertifyConfig(max_depth=3, price_findings=False))
    violation = cert.violations[0]
    steps = [AttackStep(**item) for item in violation["minimal_sequence"]]
    result = minimize_witness(target, steps, violation["invariant_id"])
    assert result.proven is True
    assert result.certificate["proven"] is True
    assert result.steps
    assert len(result.steps) <= len(steps)
