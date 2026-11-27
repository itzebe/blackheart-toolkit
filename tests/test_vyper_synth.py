"""Vyper modules reach the same model, certifier and invariant as Solidity."""

from __future__ import annotations

from blackheart.assurance.certify import CertifyConfig, certify
from blackheart.discovery.certify import certify_exhaustive
from blackheart.ingest.vyper_synth import synthesize_vyper, vyper_to_surface

VULNERABLE = """
owner: public(address)
balanceOf: public(HashMap[address, uint256])
totalSupply: public(uint256)

@external
def deposit(amount: uint256):
    self.balanceOf[msg.sender] += amount
    self.totalSupply += amount

@external
def set_owner(new_owner: address):
    self.owner = new_owner

@external
def drain():
    assert msg.sender == self.owner
    self.totalSupply = 0
"""

GUARDED = VULNERABLE.replace(
    "def set_owner(new_owner: address):\n    self.owner = new_owner",
    "def set_owner(new_owner: address):\n    assert msg.sender == self.owner\n    self.owner = new_owner",
)


def test_the_surface_is_translated_without_guessing():
    surface = vyper_to_surface(VULNERABLE, name="Vault")
    names = {f.name for f in surface.functions}
    assert {"deposit", "set_owner", "drain"} <= names
    setter = next(f for f in surface.functions if f.name == "set_owner")
    assert setter.visibility == "external"
    assert setter.params == ("address new_owner",)
    drain = next(f for f in surface.functions if f.name == "drain")
    assert "require(msg.sender == owner)" in drain.body


def test_the_unguarded_setter_reaches_the_owner_only_drain():
    target, report = synthesize_vyper(VULNERABLE, name="Vault")
    assert "set_owner" in report.modelled_ops
    cert = certify(target, CertifyConfig(max_depth=4, price_findings=False))
    assert cert.broke
    assert any(v["invariant_id"] == "authorization:owner"
               for v in cert.violations)
    sequences = [[step["action"] for step in v["minimal_sequence"]]
                 for v in cert.violations]
    assert any("set_owner" in actions and "drain" in actions
               for actions in sequences)


def test_the_guarded_setter_keeps_the_drain_unreachable():
    target, _ = synthesize_vyper(GUARDED, name="Vault")
    assert not certify_exhaustive(target, max_depth=4).proven


def test_an_unreadable_construct_is_marked_unmodelled():
    source = """
@external
def loop():
    for i in range(10):
        self.x = i
"""
    _, report = synthesize_vyper(source)
    assert "loop" in report.unmodelled_ops
