"""Acceptance bar for the task budget ledger."""

from __future__ import annotations

import pytest

from blackheart.budget import Budget


def test_uncapped_axis_never_blocks():
    b = Budget()
    assert b.remaining_tokens is None
    assert b.remaining_turns is None
    assert not b.wrapped_up
    assert not b.exhausted
    assert b.can_start(tokens=10_000_000, turns=10_000_000)


def test_token_cap_and_wrapup_reserve():
    b = Budget(max_tokens=100, reserve_tokens=20)
    b.charge_tokens(50)
    assert b.remaining_tokens == 50
    assert not b.wrapped_up
    b.charge_tokens(40)  # 90 used, 10 left <= 20 reserve -> wrap up
    assert b.wrapped_up
    assert not b.exhausted
    assert not b.can_start(tokens=50)  # cannot cover a worker past the reserve
    b.charge_tokens(10)  # 100 used
    assert b.exhausted


def test_turn_cap():
    b = Budget(max_turns=3, reserve_turns=1)
    b.charge_turn()
    b.charge_turn()
    assert b.remaining_turns == 1
    assert b.wrapped_up  # 1 <= reserve 1
    assert not b.can_start(turns=2)
    assert not b.can_start(turns=1)  # inside the reserve, no new worker starts


def test_negative_charge_rejected():
    with pytest.raises(ValueError):
        Budget().charge_tokens(-1)
