"""Target noise governor (adapted from ARTEX's noise governor).

A live target is a shared resource. Hammering it is a denial of service even
when the requests are "just" recon, and the country's engagement policies say so
plainly ("make every effort not to damage or restrict availability"). This module
paces requests per host so the operation stays inside that rule: a token bucket
for the rate, a burst allowance, an in-flight cap, jitter on the wait, and
exponential backoff on 429/503.

It is a pure pacer. The caller acquires a slot before a request and reports the
outcome after it; the governor never makes a request itself. It is safe to share
across threads (a lock guards each host's bucket) and its clock/sleep are
injectable so it is testable without real waiting.

Profiles (per host):
    quiet       1 req/s, burst 2,  1 in flight, jitter 0.10
    balanced    5 req/s, burst 5,  2 in flight, jitter 0.05
    aggressive 20 req/s, burst 10, 4 in flight, jitter 0.00
"""

from __future__ import annotations

import random
import threading
import time
from dataclasses import dataclass
from enum import Enum


class NoiseProfile(str, Enum):
    QUIET = "quiet"
    BALANCED = "balanced"
    AGGRESSIVE = "aggressive"


@dataclass(frozen=True)
class NoisePolicy:
    rate_per_sec: float
    burst: int
    in_flight: int
    jitter: float = 0.0
    base_backoff: float = 1.0
    max_backoff: float = 60.0


PROFILES: dict[NoiseProfile, NoisePolicy] = {
    NoiseProfile.QUIET: NoisePolicy(1.0, 2, 1, 0.10),
    NoiseProfile.BALANCED: NoisePolicy(5.0, 5, 2, 0.05),
    NoiseProfile.AGGRESSIVE: NoisePolicy(20.0, 10, 4, 0.00),
}


class _Bucket:
    """A token bucket plus in-flight counter and backoff state for one host."""

    def __init__(self, policy: NoisePolicy) -> None:
        self.policy = policy
        self.tokens: float = float(policy.burst)
        self.updated: float = time.monotonic()
        self.in_flight: int = 0
        self.backoff_until: float = 0.0
        self.backoff: float = policy.base_backoff


class NoiseGovernor:
    """Per-host request pacer. ``acquire(host)`` returns a context manager."""

    def __init__(
        self,
        profile: NoiseProfile | str = NoiseProfile.BALANCED,
        *,
        clock=time.monotonic,
        sleep=time.sleep,
        rng: random.Random | None = None,
    ) -> None:
        self.profile = NoiseProfile(profile)
        self.policy = PROFILES[self.profile]
        self._clock = clock
        self._sleep = sleep
        self._rng = rng or random.Random()
        self._lock = threading.Lock()
        self._buckets: dict[str, _Bucket] = {}

    def _bucket(self, host: str) -> _Bucket:
        bucket = self._buckets.get(host)
        if bucket is None:
            bucket = _Bucket(self.policy)
            bucket.updated = self._clock()
            self._buckets[host] = bucket
        return bucket

    def _refill(self, bucket: _Bucket, now: float) -> None:
        elapsed = max(0.0, now - bucket.updated)
        bucket.tokens = min(bucket.policy.burst, bucket.tokens + elapsed * bucket.policy.rate_per_sec)
        bucket.updated = now

    def acquire(self, host: str):
        return _Slot(self, host)

    # -- the mechanics, kept separate so tests can drive the clock -------- #
    def _wait_for_slot(self, host: str) -> None:
        with self._lock:
            bucket = self._bucket(host)
            while True:
                now = self._clock()
                if now < bucket.backoff_until:
                    self._sleep(min(bucket.backoff_until - now, bucket.policy.max_backoff))
                    continue
                if bucket.in_flight >= bucket.policy.in_flight:
                    self._sleep(0.01)
                    continue
                self._refill(bucket, now)
                if bucket.tokens >= 1.0:
                    bucket.tokens -= 1.0
                    bucket.in_flight += 1
                    if bucket.policy.jitter:
                        self._sleep(self._rng.uniform(0.0, bucket.policy.jitter))
                    return
                deficit = (1.0 - bucket.tokens) / bucket.policy.rate_per_sec
                self._sleep(max(0.001, deficit))

    def _release(self, host: str, status: int | None) -> None:
        with self._lock:
            bucket = self._bucket(host)
            bucket.in_flight = max(0, bucket.in_flight - 1)
            if status in (429, 503):
                bucket.backoff_until = self._clock() + bucket.backoff
                bucket.backoff = min(bucket.policy.max_backoff, bucket.backoff * 2.0)
            elif status is not None and status < 500 and status != 429:
                # a healthy response relaxes the backoff toward the base
                bucket.backoff = bucket.policy.base_backoff
                bucket.backoff_until = 0.0


class _Slot:
    """Context manager: wait for a slot, run, then report the status."""

    def __init__(self, governor: NoiseGovernor, host: str) -> None:
        self._governor = governor
        self._host = host
        self._status: int | None = None

    def __enter__(self) -> "_Slot":
        self._governor._wait_for_slot(self._host)
        return self

    def report(self, status: int) -> None:
        self._status = status

    def __exit__(self, exc_type, exc, tb) -> bool:
        self._governor._release(self._host, self._status)
        return False
