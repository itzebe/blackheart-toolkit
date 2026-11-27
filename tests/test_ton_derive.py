"""Acceptance bar for deriving a TON model from a recovered Tact surface."""

from __future__ import annotations

from blackheart.assurance import CertifyConfig, certify
from blackheart.ton.derive import derive_target
from blackheart.ton.tact import scan_tact

UNGUARDED_MINT = '''\
message Mint { amount: Int; }
contract J {
    owner: Address;
    total: Int;
    receive(msg: Mint) { self.total += msg.amount; }
}
'''

GUARDED_MINT = '''\
message Mint { amount: Int; }
contract J {
    owner: Address;
    total: Int;
    receive(msg: Mint) { require(sender() == self.owner, "no"); self.total += msg.amount; }
}
'''


def _cert(target):
    return certify(target, CertifyConfig(max_depth=2, max_sequences=20_000,
                                         price_findings=False))


def _write(tmp_path, text):
    (tmp_path / "j.tact").write_text(text, encoding="utf-8")
    return str(tmp_path)


def test_unguarded_mint_derives_a_lead(tmp_path):
    target = derive_target(scan_tact(_write(tmp_path, UNGUARDED_MINT)))
    assert "mint" in target.enabled_ops
    assert "mint" in target.derived_unguarded
    broken = {v["invariant_id"] for v in _cert(target).violations}
    assert "ton:admin-only-mint" in broken


def test_guarded_mint_holds(tmp_path):
    target = derive_target(scan_tact(_write(tmp_path, GUARDED_MINT)))
    assert "mint" in target.enabled_ops
    assert target.derived_unguarded == frozenset()
    assert _cert(target).violations == []


def test_guarded_transfer_maps_and_holds(tmp_path):
    src = ('message Transfer { amount: Int; }\n'
           'contract J { receive(msg: Transfer) { '
           'require(sender() == self.owner, "no"); self.x += msg.amount; } }\n')
    target = derive_target(scan_tact(_write(tmp_path, src)))
    assert "transfer" in target.enabled_ops
    assert _cert(target).violations == []


def test_unknown_handler_is_unmodelled(tmp_path):
    src = 'message Ping {}\ncontract J { receive(msg: Ping) { self.x = 1; } }\n'
    target = derive_target(scan_tact(_write(tmp_path, src)))
    assert "Ping" in target.unmodelled_handlers
    assert target.enabled_ops == frozenset()
