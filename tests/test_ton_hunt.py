"""Acceptance bar: the full hunt runs on a TON model derived from source."""

from __future__ import annotations

from blackheart.hunt.orchestrator import HuntConfig, hunt
from blackheart.toolchain.enforce import self_test_record
from blackheart.ton.derive import derive_target
from blackheart.ton.func import scan_func

# An unguarded privileged handler: mint writes state with no sender check.
FUNC = '''\
() recv_internal(int my_balance, int msg_value, cell in_msg_full, slice in_msg_body) impure {
    int op = in_msg_body~load_uint(32);
    if (op == op::mint()) {
        set_data(begin_cell().store_coins(in_msg_body~load_coins()).end_cell());
    }
}
'''

# The guarded twin: same handler, but it checks the sender first.
GUARDED = '''\
() recv_internal(int my_balance, int msg_value, cell in_msg_full, slice in_msg_body) impure {
    int op = in_msg_body~load_uint(32);
    if (op == op::mint()) {
        throw_unless(401, equal_slices(sender_address, owner_address));
        set_data(begin_cell().store_coins(in_msg_body~load_coins()).end_cell());
    }
}
'''


def _tree(tmp_path, name, text):
    directory = tmp_path / name
    directory.mkdir()
    (directory / "jetton.fc").write_text(text, encoding="utf-8")
    return directory


def _mk(path):
    target = derive_target(scan_func(str(path)))
    target.repository = "blackheart"
    return target


def _hunt(vuln, control=None, *, scope=True):
    cfg = HuntConfig(
        stages=("search", "certify", "verify"), certify_depth=2,
        certify_max_sequences=20_000,
        target_factory=lambda: _mk(vuln),
        control_factory=(lambda: _mk(control)) if control else None,
        in_scope=True if scope else None,
        authorization_gate_passed=True if scope else None,
        scope_reference="test" if scope else "",
    )
    return hunt(_mk(vuln), cfg, compatibility=self_test_record()).to_dict()


def test_without_a_control_the_result_is_a_lead_not_a_finding(tmp_path):
    data = _hunt(_tree(tmp_path, "v", FUNC))
    assert "ton:admin-only-mint" in {c["invariant_id"] for c in data["certified"]}
    verify = next(s for s in data["stages"] if s["stage"] == "verify")
    assert verify["ran"] and not verify["error"]
    assert "NOT YET CONTROLLED" in data["verdict"]
    assert "INDEPENDENTLY_VERIFIED" not in data["verdict"]


def test_a_guarded_twin_lifts_to_independently_verified(tmp_path):
    vuln = _tree(tmp_path, "v", FUNC)
    control = _tree(tmp_path, "c", GUARDED)
    data = _hunt(vuln, control)
    assert {v["disposition"] for v in data["verifications"]} == {"INDEPENDENTLY_VERIFIED"}
    assert data["verdict"].startswith("VERIFIED")


def test_a_control_that_also_breaks_is_rejected(tmp_path):
    vuln = _tree(tmp_path, "v", FUNC)
    also_bad = _tree(tmp_path, "b", FUNC)  # same unguarded source: non-discriminating
    data = _hunt(vuln, also_bad)
    assert "REJECTED" in {v["disposition"] for v in data["verifications"]}
    assert not data["verdict"].startswith("VERIFIED")
