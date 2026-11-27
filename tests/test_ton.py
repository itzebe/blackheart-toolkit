"""Acceptance bar for the TON (The Open Network) reference model.

The invariant engine is target-agnostic, but TON had no target. These tests pin
the model's three bug classes -- authorization (unguarded mint), conservation
(double-credit transfer) and replay (unadvanced wallet seqno) -- and the
guarded/vulnerable contrast that proves the model can tell them apart.
"""

from __future__ import annotations

from blackheart.assurance import CertifyConfig, certify
from blackheart.ton import TONTarget


def _cert(target: TONTarget):
    return certify(target, CertifyConfig(max_depth=3, max_sequences=20_000,
                                         price_findings=False))


def test_guarded_ton_model_holds_its_invariants():
    cert = _cert(TONTarget())
    assert cert.violations == []
    assert cert.unevaluable == []
    assert cert.alphabet_size > 0


def test_vulnerable_ton_breaks_conservation():
    cert = _cert(TONTarget(vulnerable=True))
    broken = {v["invariant_id"] for v in cert.violations}
    assert "ton:supply-conservation" in broken


def test_vulnerable_ton_breaks_admin_only_mint():
    cert = _cert(TONTarget(vulnerable=True))
    broken = {v["invariant_id"] for v in cert.violations}
    assert "ton:admin-only-mint" in broken


def test_vulnerable_ton_breaks_wallet_replay():
    cert = _cert(TONTarget(vulnerable=True))
    broken = {v["invariant_id"] for v in cert.violations}
    assert "ton:wallet-seqno-advanced" in broken


def test_ton_model_lists_unmodelled_surfaces():
    from blackheart.ton import UNMODELLED

    assert any("boc" in item or "gas" in item.lower() for item in UNMODELLED)
