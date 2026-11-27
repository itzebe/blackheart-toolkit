"""value_lead: an unprivileged actor receives native ETH it did not put in (real EVM)."""

from blackheart.evmworld import Account, World
from blackheart.probe import SUCCESS, UNPRIVILEGED, probe_world

_ADDR = 0xD00D
_OTHER = 0xBEEF
_DRAIN = bytes([0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x47, 0x33, 0x5A, 0xF1, 0x00])
_PAY_OTHER = (bytes([0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x47, 0x73])
              + _OTHER.to_bytes(20, "big") + bytes([0x5A, 0xF1, 0x00]))


def test_value_lead_true_when_caller_drains_contract_eth():
    w = World({_ADDR: Account(code=_DRAIN, balance=5)})
    r = probe_world(w, _ADDR, "0x00000000", sender=UNPRIVILEGED)
    assert r.outcome == SUCCESS and r.value_lead is True


def test_value_lead_false_when_contract_pays_someone_else():
    w = World({_ADDR: Account(code=_PAY_OTHER, balance=5)})
    r = probe_world(w, _ADDR, "0x00000000", sender=UNPRIVILEGED)
    assert r.outcome == SUCCESS and r.value_lead is False


def test_value_lead_false_on_noop():
    w = World({_ADDR: Account(code=bytes([0x00]), balance=5)})
    r = probe_world(w, _ADDR, "0x00000000", sender=UNPRIVILEGED)
    assert r.outcome == SUCCESS and r.value_lead is False


_SLOT = 3
# credit storage[_SLOT] by 100: PUSH1 _SLOT, SLOAD, PUSH1 100, ADD, PUSH1 _SLOT, SSTORE, STOP
_CREDIT = bytes([0x60, 0x03, 0x54, 0x60, 0x64, 0x01, 0x60, 0x03, 0x55, 0x00])


def test_value_lead_true_on_token_credit_via_value_slot():
    w = World({_ADDR: Account(code=_CREDIT)})
    r = probe_world(w, _ADDR, "0x00000000", sender=UNPRIVILEGED, value_slot=_SLOT)
    assert r.outcome == SUCCESS and r.token_gain == 100 and r.value_lead is True


def test_value_lead_false_when_token_slot_unchanged():
    w = World({_ADDR: Account(code=bytes([0x00]))})
    r = probe_world(w, _ADDR, "0x00000000", sender=UNPRIVILEGED, value_slot=_SLOT)
    assert r.outcome == SUCCESS and r.token_gain == 0 and r.value_lead is False
