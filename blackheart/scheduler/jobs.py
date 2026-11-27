"""The job record, its lifecycle, and the lease that guards ownership.

A job is a durable request to run one unit of BLACKHEART research. It carries
everything needed to re-run it after a restart -- the target, the asset, the
recorded authorization, the kind of work, and the idempotency key that stops a
duplicate from being enqueued -- plus the mutable execution state (attempts,
lease, backoff, history) that the store appends as events.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Optional

from ..models import utcnow


class JobState:
    """The lifecycle states of a scheduled job.

    ``PENDING``    -- enqueued and runnable now (or at ``not_before``).
    ``LEASED``     -- claimed by a worker holding a live lease.
    ``RETRYING``   -- a prior attempt failed; waiting out backoff.
    ``BLOCKED``    -- authorization no longer passes; must not run.
    ``SUCCEEDED``  -- terminal, the job completed its work.
    ``FAILED``     -- terminal, attempts exhausted (dead-letter).
    ``CANCELLED``  -- terminal, cancelled by an operator before completion.
    """

    PENDING = "PENDING"
    LEASED = "LEASED"
    RETRYING = "RETRYING"
    BLOCKED = "BLOCKED"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


TERMINAL = frozenset({JobState.SUCCEEDED, JobState.FAILED, JobState.CANCELLED})

#: The only legal state transitions. A transition not listed here is refused.
#: ``LEASED -> PENDING`` is stale-worker recovery (lease reclaimed); it is legal
#: only from an expired lease, which the scheduler enforces before calling it.
TRANSITIONS: dict[str, frozenset[str]] = {
    JobState.PENDING: frozenset({
        JobState.LEASED,      # claimed
        JobState.BLOCKED,     # authorization failed at dispatch
        JobState.CANCELLED,   # cancelled before running
    }),
    JobState.LEASED: frozenset({
        JobState.SUCCEEDED,   # worker completed the work
        JobState.RETRYING,    # worker reported a retryable failure
        JobState.FAILED,      # worker reported a terminal failure / budget spent
        JobState.PENDING,     # lease expired -> reclaimed (stale worker)
        JobState.BLOCKED,     # authorization withdrawn while the worker was down
        JobState.CANCELLED,   # cancelled while leased
    }),
    JobState.RETRYING: frozenset({
        JobState.LEASED,      # backoff elapsed, claimed again
        JobState.BLOCKED,     # authorization failed on retry dispatch
        JobState.CANCELLED,
        JobState.FAILED,      # budget exhausted while waiting
    }),
    JobState.BLOCKED: frozenset({
        JobState.PENDING,     # authorization re-established by an operator
        JobState.CANCELLED,
    }),
    JobState.SUCCEEDED: frozenset(),
    JobState.FAILED: frozenset(),
    JobState.CANCELLED: frozenset(),
}


class InvalidTransition(RuntimeError):
    """Raised when a job is asked to move along a transition it may not take."""


def transition_allowed(current: str, target: str) -> bool:
    return target in TRANSITIONS.get(current, frozenset())


@dataclass
class RetryPolicy:
    """Bounded exponential backoff.

    ``max_attempts`` is the total number of execution attempts (the first try
    included). ``base_seconds`` and ``max_seconds`` bound the delay between them;
    ``factor`` multiplies the delay each attempt. All arithmetic is deterministic
    -- no jitter -- so a recovered job computes the same ``not_before``.
    """

    max_attempts: int = 5
    base_seconds: float = 2.0
    factor: float = 2.0
    max_seconds: float = 300.0

    def delay_for(self, attempt: int) -> float:
        """Seconds to wait after *attempt* failed (attempt is 1-based)."""
        if attempt <= 0:
            return 0.0
        raw = self.base_seconds * (self.factor ** (attempt - 1))
        return float(min(raw, self.max_seconds))

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "RetryPolicy":
        known = {f for f in cls.__dataclass_fields__}  # type: ignore[attr-defined]
        return cls(**{k: v for k, v in d.items() if k in known})


@dataclass
class Lease:
    """A time-bounded, fenced ownership grant.

    ``epoch`` increments on every claim. A worker presents the epoch it was
    granted; a stale worker (whose lease expired and was reclaimed) presents an
    old epoch and its heartbeat/completion is refused. This is what makes an
    ambiguous retry safe: only the current lease-holder can write the outcome.
    """

    owner: str
    epoch: int
    expires_at: str          # ISO-8601 UTC

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> Optional["Lease"]:
        if not d:
            return None
        known = {f for f in cls.__dataclass_fields__}  # type: ignore[attr-defined]
        return cls(**{k: v for k, v in d.items() if k in known})


@dataclass
class Job:
    """One durable unit of scheduled research work."""

    job_id: str
    kind: str                      # the executor to run (see executors.py)
    target: str
    asset: str
    authz: dict                    # AuthorizationRecord as a dict (re-checked)
    payload: dict = field(default_factory=dict)   # executor-specific arguments
    idempotency_key: str = ""      # dedupe on submit (falls back to job_id)
    priority: int = 0
    state: str = JobState.PENDING
    retry: RetryPolicy = field(default_factory=RetryPolicy)
    attempts: int = 0              # completed execution attempts
    max_attempts: int = 5
    lease: Optional[Lease] = None
    epoch: int = 0                 # monotonic claim counter (fencing token source)
    not_before: str = ""           # earliest time the job may run (backoff/misfire)
    last_error: str = ""
    result: dict = field(default_factory=dict)
    misfires: int = 0
    scope_reference: str = ""
    history: list[str] = field(default_factory=list)
    created_at: str = field(default_factory=utcnow)
    updated_at: str = field(default_factory=utcnow)

    # -- derived ------------------------------------------------------- #
    def is_terminal(self) -> bool:
        return self.state in TERMINAL

    def budget_spent(self) -> bool:
        return self.attempts >= self.max_attempts

    def dedupe_key(self) -> str:
        return self.idempotency_key or self.job_id

    # -- serialisation -------------------------------------------------- #
    def to_dict(self) -> dict:
        d = asdict(self)
        d["retry"] = self.retry.to_dict()
        d["lease"] = self.lease.to_dict() if self.lease else None
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "Job":
        known = {f for f in cls.__dataclass_fields__}  # type: ignore[attr-defined]
        data = {k: v for k, v in d.items() if k in known}
        data["retry"] = RetryPolicy.from_dict(d.get("retry") or {})
        data["lease"] = Lease.from_dict(d.get("lease") or {})
        data.setdefault("payload", {})
        data.setdefault("result", {})
        data.setdefault("history", [])
        return cls(**data)


__all__ = [
    "Job", "JobState", "Lease", "RetryPolicy",
    "InvalidTransition", "TRANSITIONS", "TERMINAL", "transition_allowed",
]
