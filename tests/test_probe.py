"""Acceptance bar for the unprivileged-surface probe.

Grounded in real hunts: the probe must classify reachability from an
unprivileged EOA and report the state a call actually changes, so a
caller-source self-service is never mistaken for cross-account theft.
"""

from __future__ import annotations

from blackheart.probe import REVERT, SUCCESS, UNPRIVILEGED, probe, probe_selector

# Selector dispatch: selector == 0x11111111 -> STOP; anything else -> REVERT.
# 60 00 35 60 E0 1c 63 11111111 14 60 14 57 60 00 60 00 fd 5b 00
_DISPATCH = bytes([
    0x60, 0x00, 0x35, 0x60, 0xE0, 0x1C, 0x63, 0x11, 0x11, 0x11, 0x11, 0x14,
    0x60, 0x14, 0x57, 0x60, 0x00, 0x60, 0x00, 0xFD, 0x5B, 0x00,
])


def test_selectors_are_classified_from_an_unprivileged_caller():
    results = probe(_DISPATCH, ["0x11111111", "0x22222222"])
    assert [r.outcome for r in results] == [SUCCESS, REVERT]
    # Only the non-reverting reach is a lead; the revert is not.
    assert results[0].is_lead is True
    assert results[1].is_lead is False
    assert results[1].halt == "REVERT"


def test_a_state_writing_call_reports_the_slot_it_changed():
    # SSTORE(0, 1); STOP -- the exact shape a fund-moving write takes.
    store_one = bytes([0x60, 0x01, 0x60, 0x00, 0x55, 0x00])
    result = probe_selector(store_one, "0x00000000")
    assert result.outcome == SUCCESS
    slots = [s for change in result.state_diff for s in change["storage"]]
    assert slots and slots[0]["to"] == 1


def test_a_reverting_call_carries_no_state_change():
    # REVERT with empty data: state is unwound, nothing is attributed.
    result = probe_selector(bytes([0x60, 0x00, 0x60, 0x00, 0xFD]), "0x00000000")
    assert result.outcome == REVERT
    assert result.state_diff == []


def test_the_default_caller_is_unprivileged():
    assert UNPRIVILEGED == 0x000000000000000000000000000000000000dEaD
    result = probe_selector(_DISPATCH, "0x11111111")
    assert result.selector == "0x11111111"
