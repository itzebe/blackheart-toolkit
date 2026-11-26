"""Acceptance bar for the Tact source surface scanner."""

from __future__ import annotations

from blackheart.ton.tact import scan_tact

SAMPLE = '''\
message Mint { amount: Int as uint128; }
message Withdraw { amount: Int as uint128; }

contract Jetton {
    owner: Address;
    total: Int as uint128;

    receive(msg: Mint) {
        self.total += msg.amount;
    }

    receive(msg: Withdraw) {
        require(sender() == self.owner, "not owner");
        self.total -= msg.amount;
    }

    receive("reset") {
        self.total = 0;
    }
}
'''


def _write(tmp_path, name, text):
    (tmp_path / name).write_text(text, encoding="utf-8")
    return tmp_path


def test_recovers_handlers_and_guards(tmp_path):
    _write(tmp_path, "jetton.tact", SAMPLE)
    surface = scan_tact(str(tmp_path))
    assert surface.contracts == ["Jetton"]
    assert "Mint" in surface.messages and "Withdraw" in surface.messages
    by_name = {h.name: h for h in surface.handlers}
    assert set(by_name) == {"Mint", "Withdraw", "reset"}
    assert by_name["Mint"].guarded is False
    assert by_name["Mint"].writes_state is True
    assert by_name["Mint"].contract == "Jetton"
    assert by_name["Withdraw"].guarded is True
    assert by_name["reset"].guarded is False


def test_empty_tree_has_no_handlers(tmp_path):
    _write(tmp_path, "a.tact", "contract A {}")
    surface = scan_tact(str(tmp_path))
    assert surface.handlers == []
    assert surface.contracts == ["A"]


def test_unmodelled_is_reported(tmp_path):
    _write(tmp_path, "a.tact", SAMPLE)
    assert scan_tact(str(tmp_path)).unmodelled
