"""A minimizer must shrink a reproducer and never invent one."""

from __future__ import annotations

from blackheart.symbolic.minimize import minimize_calldata


def _word(value: int) -> bytes:
    return value.to_bytes(32, "big")


def test_a_signal_word_survives_and_the_noise_around_it_is_removed():
    original = _word(0) + _word(5) + _word(0)
    result = minimize_calldata(original, lambda data: _word(5) in data)
    assert result.minimized == _word(5)
    assert result.reduced is True


def test_a_partial_last_word_keeps_its_width():
    original = b"\x00" * 32 + b"\x05" * 8
    result = minimize_calldata(original, lambda data: data.endswith(b"\x05" * 8))
    assert result.minimized == b"\x05" * 8


def test_a_predicate_that_raises_is_treated_as_not_satisfied():
    def predicate(_data: bytes) -> bool:
        raise RuntimeError("the candidate broke the runner")

    original = _word(1) + _word(2)
    result = minimize_calldata(original, predicate)
    assert result.minimized == original
    assert result.accepted == 0
    assert result.attempts > 0


def test_the_attempt_budget_is_respected():
    original = _word(1) + _word(2) + _word(3)
    result = minimize_calldata(original, lambda data: True, max_attempts=1)
    assert result.attempts <= 1


def test_the_search_is_deterministic():
    original = _word(9) + _word(7) + _word(5)
    predicate = lambda data: _word(7) in data  # noqa: E731
    first = minimize_calldata(original, predicate)
    second = minimize_calldata(original, predicate)
    assert first.to_dict() == second.to_dict()
