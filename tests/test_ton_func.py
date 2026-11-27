"""Acceptance bar for the FunC source surface scanner."""

from __future__ import annotations

from blackheart.assurance import CertifyConfig, certify
from blackheart.ton.derive import derive_target
from blackheart.ton.func import scan_func

SAMPLE = '''\
() recv_internal(int my_balance, int msg_value, cell in_msg_full, slice in_msg_body) impure {
    if (in_msg_body.slice_empty?()) { return (); }
    int op = in_msg_body~load_uint(32);
    if (op == op::mint()) {
        int amount = in_msg_body~load_coins();
        set_data(begin_cell().store_coins(amount).end_cell());
    }
    if (op == op::transfer()) {
        throw_unless(401, equal_slices(sender_address, owner_address));
        int amount = in_msg_body~load_coins();
        set_data(begin_cell().store_coins(amount).end_cell());
    }
}
'''


def _write(tmp_path, text):
    (tmp_path / "jetton.fc").write_text(text, encoding="utf-8")
    return str(tmp_path)


def _cert(target):
    return certify(target, CertifyConfig(max_depth=2, max_sequences=20_000,
                                         price_findings=False))


def test_recovers_op_dispatch_and_guards(tmp_path):
    surface = scan_func(_write(tmp_path, SAMPLE))
    by_name = {h.name: h for h in surface.handlers}
    assert set(by_name) == {"mint", "transfer"}
    assert by_name["mint"].guarded is False
    assert by_name["mint"].writes_state is True
    assert by_name["mint"].kind == "func-op"
    assert by_name["transfer"].guarded is True
    assert by_name["transfer"].writes_state is True


def test_unguarded_mint_derives_a_lead(tmp_path):
    target = derive_target(scan_func(_write(tmp_path, SAMPLE)))
    assert "mint" in target.enabled_ops
    assert "mint" in target.derived_unguarded
    broken = {v["invariant_id"] for v in _cert(target).violations}
    assert "ton:admin-only-mint" in broken


def test_trivial_entry_is_not_a_surface(tmp_path):
    src = "() recv_internal(int a, int b, cell c, slice d) impure { return (); }\n"
    assert scan_func(_write(tmp_path, src)).handlers == []
