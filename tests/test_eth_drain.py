"""The EVM must move native value on CALL, so a reentrancy drain is provable.

Before this, ``CALL`` did not transfer balance (only ``CREATE`` did), so a vault
that sends ETH before zeroing its ledger could not be drained in the model. These
guards pin the correct semantics: transfer on CALL, undo on child failure, fail
without transferring when the balance is short.
"""

from __future__ import annotations

from blackheart.evmworld import Account, World
from blackheart.probe import mapping_slot, probe_world

VAULT = 0x3000
ATTACKER = 0x4000

# withdraw(): balances[caller] is read, sent to the caller, then zeroed -- the
# classic send-before-zero bug. The CALL carries the stored balance as value.
_WITHDRAW = bytes([
    0x33, 0x60, 0x00, 0x52, 0x60, 0x00, 0x60, 0x20, 0x52, 0x60, 0x40, 0x60, 0x00, 0x20,
    0x80, 0x60, 0x40, 0x52, 0x54, 0x60, 0x60, 0x52,
    0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x60, 0x00,
    0x60, 0x60, 0x51, 0x33, 0x5A, 0xF1, 0x50,
    0x60, 0x40, 0x51, 0x60, 0x00, 0x90, 0x55, 0x00,
])
# attacker fallback: re-enter withdraw() once.
_ATTACKER = (bytes([0x60, 0x00, 0x54, 0x60, 0x2D, 0x57, 0x60, 0x01, 0x60, 0x00, 0x55,
                    0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x73])
             + VAULT.to_bytes(20, "big") + bytes([0x5A, 0xF1, 0x50, 0x5B, 0x00]))


def _call_site(value_bytecode_value: int = 0x01) -> bytes:
    return bytes([0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x60, 0x00,
                  0x60, value_bytecode_value, 0x33, 0x5A, 0xF1, 0x50, 0x00])


def test_call_transfers_value_to_a_codeless_target():
    w = World({VAULT: Account(code=_call_site(), balance=10), ATTACKER: Account(code=b"", balance=0)})
    probe_world(w, VAULT, "0x00000000", sender=ATTACKER)
    assert w.accounts[VAULT].balance == 9
    assert w.accounts[ATTACKER].balance == 1


def test_reentrancy_drains_eth_over_entitlement():
    slot = mapping_slot(ATTACKER, 0)
    w = World({VAULT: Account(code=_WITHDRAW, storage={slot: 1}, balance=10),
               ATTACKER: Account(code=_ATTACKER, balance=0)})
    r = probe_world(w, VAULT, "0x00000000", sender=ATTACKER)
    gain = sum(c["balance_to"] - c["balance_from"]
               for c in r.state_diff if int(c["address"], 16) == ATTACKER)
    assert gain == 2
    assert gain > 1  # two withdrawals for a one-wei entitlement


def test_call_with_insufficient_balance_fails_without_transfer():
    w = World({VAULT: Account(code=_call_site(), balance=0), ATTACKER: Account(code=b"", balance=0)})
    probe_world(w, VAULT, "0x00000000", sender=ATTACKER)
    assert w.accounts[VAULT].balance == 0
    assert w.accounts[ATTACKER].balance == 0


def test_reverted_child_returns_the_value():
    reverter = 0x5000
    code = (bytes([0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x60, 0x01, 0x73])
            + reverter.to_bytes(20, "big") + bytes([0x5A, 0xF1, 0x50, 0x00]))
    w = World({VAULT: Account(code=code, balance=5), reverter: Account(code=bytes([0x60, 0x00, 0x60, 0x00, 0xFD]))})
    probe_world(w, VAULT, "0x00000000", sender=ATTACKER)
    assert w.accounts[VAULT].balance == 5  # unchanged: the child reverted
    assert w.accounts[reverter].balance == 0
