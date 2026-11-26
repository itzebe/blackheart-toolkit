"""The composed ERC4626 model: share inflation is reachable and priced.

The single-contract model could not see the attack because the vault's
``asset.transferFrom`` and the token's nested ``allowance`` write were outside
the statement subset. The protocol target now models internal view calls,
external token calls and the derived invariant, so the vulnerable vault and its
guarded twin are distinguishable at the model layer.
"""

from pathlib import Path

from blackheart.discovery.certify import certify_path
from blackheart.ingest.protocol import build_protocol
from blackheart.ingest.solidity import scan_source
from blackheart.ingest.synthesize import synthesize
from blackheart.models import AttackStep

FIXTURES = Path(__file__).resolve().parents[1] / "harnesses" / "erc4626" / "src"


def _surfaces():
    files = {path.name: path.read_text(encoding="utf-8") for path in FIXTURES.glob("*.sol")}
    return files, {contract.name: contract for text in files.values()
                   for contract in scan_source(text, "fixture.sol")}


def _protocol(vault: str):
    files, surfaces = _surfaces()
    target, report = build_protocol({name: surfaces[name]
                                     for name in ("MockERC20", vault)})
    return files, target, report


def _steps():
    return [
        AttackStep(index=0, actor="attacker", action="MockERC20.mint",
                   params={"to": "attacker", "amount": 100}, target_contract="protocol"),
        AttackStep(index=1, actor="attacker", action="MockERC20.approve",
                   params={"spender": "VulnerableVault", "amount": 100},
                   target_contract="protocol"),
        AttackStep(index=2, actor="attacker", action="VulnerableVault.deposit",
                   params={"assets": 1}, target_contract="protocol"),
        AttackStep(index=3, actor="attacker", action="MockERC20.transfer",
                   params={"to": "VulnerableVault", "amount": 2},
                   target_contract="protocol"),
    ]


def test_internal_and_external_calls_are_modelled():
    files, surfaces = _surfaces()
    target, report = synthesize(surfaces["VulnerableVault"])
    assert "convertToShares" in report.modelled_ops
    assert "deposit" in report.modelled_ops
    assert report.unmodelled_ops == ()
    deposit = target.op_model("deposit")
    assert deposit is not None
    assert any(call.receiver == "" and call.op == "convertToShares"
               for call in deposit.calls)
    assert any(call.receiver == "asset" and call.op == "transferFrom"
               for call in deposit.calls)


def test_share_inflation_breaks_the_derived_invariant():
    _files, target, _report = _protocol("VulnerableVault")
    cert = certify_path(target, _steps(),
                        invariant_id="VulnerableVault:erc4626:nonzero-shares")
    assert cert.proven
    assert cert.invariant_id == "VulnerableVault:erc4626:nonzero-shares"


def test_guarded_twin_survives_the_same_sequence():
    _files, target, _report = _protocol("SafeVault")
    steps = _steps()
    steps[1] = AttackStep(index=1, actor="attacker", action="MockERC20.approve",
                          params={"spender": "SafeVault", "amount": 100},
                          target_contract="protocol")
    steps[2] = AttackStep(index=2, actor="attacker", action="SafeVault.deposit",
                          params={"assets": 1}, target_contract="protocol")
    steps[3] = AttackStep(index=3, actor="attacker", action="MockERC20.transfer",
                          params={"to": "SafeVault", "amount": 2},
                          target_contract="protocol")
    cert = certify_path(target, steps,
                        invariant_id="SafeVault:erc4626:nonzero-shares")
    assert not cert.proven
