"""Acceptance bar for the target noise governor."""

from __future__ import annotations

from blackheart.noise import PROFILES, NoiseGovernor, NoiseProfile


class FakeClock:
    """A clock that only advances when the governor sleeps."""

    def __init__(self) -> None:
        self.now = 0.0

    def clock(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.now += max(0.0, seconds)


def _governor(profile: NoiseProfile) -> tuple[NoiseGovernor, FakeClock]:
    fc = FakeClock()
    return NoiseGovernor(profile, clock=fc.clock, sleep=fc.sleep), fc


def test_burst_is_immediate_then_rate_paces():
    # AGGRESSIVE has jitter 0, so the burst is exactly free (no jitter drift)
    gov, fc = _governor(NoiseProfile.AGGRESSIVE)  # burst 10 @ 20 req/s
    burst = PROFILES[NoiseProfile.AGGRESSIVE].burst
    start = fc.now
    for _ in range(burst):
        with gov.acquire("h"):
            pass
    assert fc.now == start  # whole burst is free
    # next request must wait ~1/rate before a token is available
    start = fc.now
    with gov.acquire("h"):
        pass
    assert fc.now > start


def test_backoff_on_429_after_release():
    gov, fc = _governor(NoiseProfile.AGGRESSIVE)  # jitter 0, base backoff 1s
    with gov.acquire("h") as slot:
        slot.report(429)
    # after a 429 the governor must hold off for at least the backoff
    start = fc.now
    with gov.acquire("h"):
        pass
    assert fc.now - start >= PROFILES[NoiseProfile.AGGRESSIVE].base_backoff


def test_hosts_are_independent():
    gov, fc = _governor(NoiseProfile.AGGRESSIVE)  # jitter 0
    burst = PROFILES[NoiseProfile.AGGRESSIVE].burst
    for _ in range(burst):
        with gov.acquire("a"):
            pass
    # host "a" is now drained; host "b" still has its full burst
    start = fc.now
    with gov.acquire("b"):
        pass
    assert fc.now == start


def test_profile_resolution_from_string():
    gov = NoiseGovernor("aggressive")
    assert gov.profile is NoiseProfile.AGGRESSIVE
