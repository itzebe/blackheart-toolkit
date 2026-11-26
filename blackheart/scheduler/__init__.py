"""Durable autonomous execution scheduler.

BLACKHEART provides the research engine, the resumable state and the CLI; until
now it did not provide the *scheduler* that keeps that work running unattended
(``docs/RESEARCH_ENGINE.md`` §8 named the gap). This package is that scheduler,
and nothing more: it does not implement research, it dispatches real jobs into the
existing engine and guarantees each one runs exactly as the engine would run it.

The properties the mission demands, enforced in code:

  * **Durable and restart-safe.** State is an append-only, hash-chained JSONL log
    (the same discipline as :mod:`blackheart.investigation`), rebuilt by replay.
    A process killed mid-write loses at most the truncated final line, which is
    reported rather than hidden.
  * **Explicit lifecycle.** A job moves only along the transitions in
    :data:`TRANSITIONS`; an illegal transition is refused, never coerced.
  * **Lease ownership with fencing.** A claim grants a time-bounded lease and an
    epoch. Every heartbeat and completion must present the current epoch, so a
    worker whose lease was reclaimed cannot later "complete" the job it no longer
    owns -- duplicate dispatch and ambiguous retries cannot corrupt the record.
  * **Stale-worker recovery.** A lease that expires without a heartbeat is
    reclaimed and the job re-queued, with its attempt history preserved.
  * **Bounded retry with backoff.** A failed attempt schedules a deterministic
    bounded-exponential retry; a job that exhausts its budget is dead-lettered,
    never retried forever.
  * **Misfire recovery.** A job whose scheduled time passed while nothing was
    running is recorded as a misfire and executed once, deterministically.
  * **Idempotency and trigger deduplication.** Submitting the same idempotency /
    dedupe key returns the existing job instead of creating a second one.
  * **Authorization at every boundary.** The recorded authorization is re-checked
    immediately before execution *and* again after recovery; a job whose scope no
    longer passes is BLOCKED, never run.

It is a *dispatcher*: the work itself is the engine's, reached through
:mod:`blackheart.scheduler.executors`.
"""

from __future__ import annotations

from .jobs import (
    TERMINAL,
    TRANSITIONS,
    InvalidTransition,
    Job,
    JobState,
    Lease,
    RetryPolicy,
    transition_allowed,
)
from .store import JobStore
from .engine import Scheduler, SchedulerConfig

__all__ = [
    "Job", "JobState", "Lease", "RetryPolicy", "InvalidTransition",
    "TRANSITIONS", "TERMINAL", "transition_allowed",
    "JobStore", "Scheduler", "SchedulerConfig",
]
