"""The scheduler: claim, lease, heartbeat, recover, retry, and run.

This is the durable autonomous execution loop. It owns *policy* only; the work is
done by an executor (:mod:`blackheart.scheduler.executors`) and the state is kept
by a :class:`~blackheart.scheduler.store.JobStore`. Every method is synchronous and
deterministic -- time is injected as a clock -- so a restart replays to the same
decisions and the adversarial tests are reproducible.

Lifecycle in one line: ``PENDING -> LEASED -> (SUCCEEDED | RETRYING | FAILED)``,
with ``LEASED -> PENDING`` only when a lease expires (stale-worker recovery),
``-> BLOCKED`` when authorization fails, and ``-> CANCELLED`` on operator cancel.

The two safety properties that matter most:

  * **Fencing.** A claim returns a :class:`~blackheart.scheduler.jobs.Lease` with an
    epoch. ``heartbeat`` and ``complete`` require the current epoch; a worker whose
    lease expired and was reclaimed presents a stale epoch and is refused. That is
    what makes a duplicate dispatch or an ambiguous retry harmless: a superseded
    worker can never overwrite the outcome.
  * **Authorization at every boundary.** The executor re-checks authorization
    before running, and the scheduler re-checks it again when a job is reclaimed
    after recovery; a job whose scope no longer passes goes BLOCKED, never run.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Callable, Optional

from ..authz import authorize_active_testing
from ..models import AuthorizationRecord, utcnow
from .executors import ExecContext, ExecOutcome, get_executor
from .jobs import (
    TRANSITIONS,
    InvalidTransition,
    Job,
    JobState,
    Lease,
    transition_allowed,
)
from .store import JobStore


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _parse(ts: str) -> Optional[datetime]:
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts)
    except ValueError:
        return None


@dataclass
class SchedulerConfig:
    """Tunables. Deterministic; a clock may be injected for tests."""

    lease_seconds: float = 1800.0   # a real hunt/investigate run takes minutes
    default_max_attempts: int = 5
    #: The clock. Defaults to wall-clock UTC; tests inject a controllable one.
    clock: Callable[[], datetime] = _now
    #: Optional live authorization source. When set, a job's *current* authorization
    #: is read from here at claim and execution time instead of trusting the copy
    #: snapshotted at enqueue. Without it, a scope withdrawal recorded after a job
    #: was queued cannot block that job -- the snapshot still says AUTHORIZED. The
    #: trigger receiver supplies this so a live revocation is honoured.
    authz_provider: Optional[Callable[[str], Optional[AuthorizationRecord]]] = None


class Scheduler:
    def __init__(
        self, store: JobStore, *, config: Optional[SchedulerConfig] = None,
        workdir: str = "",
    ) -> None:
        self.store = store
        self.config = config or SchedulerConfig()
        self.workdir = workdir

    # -- helpers -------------------------------------------------------- #
    def _now(self) -> datetime:
        return self.config.clock()

    def _transition(self, job: Job, target: str, note: str) -> Job:
        if not transition_allowed(job.state, target):
            allowed = sorted(TRANSITIONS.get(job.state, ()))
            raise InvalidTransition(
                f"job {job.job_id}: illegal transition {job.state} -> {target} "
                f"(allowed: {allowed})"
            )
        job.state = target
        job.updated_at = utcnow()
        job.history.append(f"{target}: {note}")
        self.store.save(job)
        return job

    # -- submission ----------------------------------------------------- #
    def submit(self, job: Job) -> Job:
        """Persist a new job, deduplicating on its idempotency key.

        Submitting the same ``idempotency_key`` (or ``job_id`` when none is set)
        twice returns the first job unchanged -- a repeated trigger never creates a
        second unit of work.
        """
        # The dedupe read and the append must be one atomic step: otherwise two
        # concurrent submissions of one idempotency key both read "no existing job"
        # and each persists one, which is exactly the duplicate work the key exists
        # to prevent. The log lock is re-entrant, so a caller already inside a
        # transaction is unaffected.
        with self.store.log.transaction():
            existing = self.store.by_dedupe_key(job.dedupe_key())
            if existing is not None:
                return existing
            job.state = JobState.PENDING
            job.attempts = 0
            job.max_attempts = job.max_attempts or self.config.default_max_attempts
            job.lease = None
            job.created_at = job.created_at or utcnow()
            job.updated_at = utcnow()
            job.history.append(f"submitted: kind={job.kind} target={job.target}")
            self.store.save(job)
            return job

    def enqueue(self, *, kind: str, target: str, asset: str,
                authz: AuthorizationRecord, payload: Optional[dict] = None,
                idempotency_key: str = "", priority: int = 0,
                scope_reference: str = "", job_id: str = "") -> Job:
        """Convenience constructor + submit. ``idempotency_key`` dedupes."""
        job = Job(
            job_id=job_id or f"JOB-{uuid.uuid4().hex[:12]}",
            kind=kind, target=target, asset=asset, authz=authz.to_dict(),
            payload=payload or {}, idempotency_key=idempotency_key,
            priority=priority, scope_reference=scope_reference,
            max_attempts=self.config.default_max_attempts,
        )
        return self.submit(job)

    # -- authorization -------------------------------------------------- #
    def _live_authz(self, job: Job) -> tuple[bool, Optional[AuthorizationRecord]]:
        """``(provider_configured, current_record)`` for ``job``'s asset.

        The two are deliberately separate. "No provider configured" means the
        caller may fall back to the snapshot the job carries. "Provider configured
        but no record" is a *failure to establish current authorization* and must
        block the job -- otherwise deleting or corrupting the authorization file
        would silently authorize a job the operator withdrew scope from. A provider
        that raises is treated the same as one returning ``None``: unavailable.
        """
        provider = self.config.authz_provider
        if provider is None:
            return False, None
        try:
            return True, provider(job.asset)
        except Exception:  # noqa: BLE001 -- a broken provider must not authorize
            return True, None

    def _authorization_ok(self, job: Job) -> tuple[bool, str]:
        try:
            record = AuthorizationRecord.from_dict(job.authz)
        except Exception as exc:  # noqa: BLE001
            return False, f"authorization record unreadable: {exc}"
        configured, live = self._live_authz(job)
        if configured:
            if live is None:
                # Fail closed: a live provider exists but could not produce the
                # current record (file deleted, unreadable, or the provider
                # errored). Falling back to the enqueue-time snapshot would run a
                # job whose scope may have been withdrawn.
                return False, ("live authorization record is unavailable; refusing "
                               "to run on the enqueue-time snapshot")
            record = live
        decision = authorize_active_testing(record, job.asset)
        if not decision.allowed:
            return False, "; ".join(decision.blockers)
        return True, ""

    # -- claiming ------------------------------------------------------- #
    def _is_runnable(self, job: Job) -> bool:
        if job.state not in (JobState.PENDING, JobState.RETRYING):
            return False
        if job.budget_spent():
            return False
        nb = _parse(job.not_before)
        return nb is None or self._now() >= nb

    def claim(self, owner: str, *, job_id: str = "") -> Optional[Job]:
        """Claim the highest-priority runnable job for *owner*, granting a lease.

        Authorization is re-checked here, at the dispatch boundary: a job whose
        scope no longer passes is moved to BLOCKED and skipped, never handed to a
        worker. A claim always bumps the lease epoch, so a stale worker from an
        earlier claim cannot act on this one.
        """
        candidates = [j for j in self.store.all()
                      if (j.job_id == job_id if job_id else True) and self._is_runnable(j)]
        candidates.sort(key=lambda j: (-j.priority, j.created_at))
        for job in candidates:
            ok, reason = self._authorization_ok(job)
            if not ok:
                if transition_allowed(job.state, JobState.BLOCKED):
                    self._transition(job, JobState.BLOCKED, f"authorization: {reason}")
                continue
            return self._lease(job, owner)
        return None

    def _lease(self, job: Job, owner: str) -> Job:
        # The epoch is a monotonic counter on the job, not derived from the
        # current lease: recovery clears the lease, so deriving the epoch from it
        # would let a reclaimed job reuse an epoch and defeat the fence.
        job.epoch += 1
        job.attempts += 1          # an attempt begins now, not at completion:
        # a worker that dies mid-run never reports, so counting at completion
        # would let a crash-looping job be reclaimed forever without a dead-letter.
        expires = self._now() + timedelta(seconds=self.config.lease_seconds)
        target = JobState.LEASED
        # PENDING or RETRYING may both be claimed; both transitions are legal.
        if not transition_allowed(job.state, target):
            raise InvalidTransition(
                f"job {job.job_id}: cannot claim from state {job.state}"
            )
        job.state = target
        job.lease = Lease(owner=owner, epoch=job.epoch, expires_at=expires.isoformat())
        job.updated_at = utcnow()
        job.history.append(f"LEASED: owner={owner} epoch={job.epoch}")
        self.store.save(job)
        return job

    # -- lease maintenance ---------------------------------------------- #
    def _owns(self, job: Job, owner: str, epoch: int) -> bool:
        return (job.state == JobState.LEASED and job.lease is not None
                and job.lease.owner == owner and job.lease.epoch == epoch)

    def heartbeat(self, job_id: str, owner: str, epoch: int) -> bool:
        """Renew the lease. Returns False (and changes nothing) if not the owner.

        A stale worker -- one whose lease already expired and was reclaimed --
        presents an old epoch and is refused here, so it learns it no longer owns
        the job before it does any further work.
        """
        job = self.store.get(job_id)
        if job is None or not self._owns(job, owner, epoch):
            return False
        job.lease.expires_at = (
            self._now() + timedelta(seconds=self.config.lease_seconds)
        ).isoformat()
        job.updated_at = utcnow()
        job.history.append(f"HEARTBEAT: owner={owner} epoch={epoch}")
        self.store.save(job)
        return True

    def lease_expired(self, job: Job) -> bool:
        if job.state != JobState.LEASED or job.lease is None:
            return False
        exp = _parse(job.lease.expires_at)
        return exp is not None and self._now() >= exp

    def recover_stale(self) -> list[str]:
        """Reclaim every expired lease and re-queue the job for another attempt.

        Recovery is *safe*: the reclaimed job keeps its attempt count and history,
        and authorization is re-checked before it becomes runnable again (the
        dispatch claim will refuse it if the scope changed). Returns the job ids
        that were recovered.
        """
        recovered: list[str] = []
        for job in self.store.all():
            if not self.lease_expired(job):
                continue
            ok, reason = self._authorization_ok(job)
            if not ok:
                if transition_allowed(job.state, JobState.BLOCKED):
                    self._transition(job, JobState.BLOCKED,
                                     f"authorization failed on recovery: {reason}")
                    continue
            job.lease = None
            # The lost attempt was counted at claim time. If the budget is now
            # spent, dead-letter instead of re-queuing: a job that reliably kills
            # its worker must stop, not loop forever.
            if job.budget_spent():
                self._transition(
                    job, JobState.FAILED,
                    "stale worker: lease expired, attempt budget spent",
                )
                continue
            job.history.append("STALE: lease expired, reclaimed")
            self._transition(job, JobState.PENDING, "stale-worker recovery")
            recovered.append(job.job_id)
        return recovered

    # -- completion ----------------------------------------------------- #
    def complete(self, job_id: str, owner: str, epoch: int,
                 outcome: ExecOutcome) -> Job:
        """Record the outcome of an attempt, fenced by (owner, epoch).

        A stale worker (wrong epoch) is refused: its result is discarded, so a
        duplicate dispatch cannot corrupt the record. On a retryable failure the
        job is rescheduled with bounded backoff; when the attempt budget is spent
        it is dead-lettered (FAILED), never retried forever.
        """
        job = self.store.get(job_id)
        if job is None:
            raise KeyError(f"job {job_id!r} not found")
        if not self._owns(job, owner, epoch):
            raise InvalidTransition(
                f"job {job_id}: worker {owner!r} epoch {epoch} does not own the "
                f"lease (current: {job.lease.owner if job.lease else None!r} "
                f"epoch {job.lease.epoch if job.lease else None}); stale result refused"
            )
        job.lease = None

        if outcome.ok:
            job.result = outcome.result
            job.last_error = ""
            return self._transition(job, JobState.SUCCEEDED, outcome.summary or "ok")

        job.last_error = outcome.error or outcome.summary or "failed"
        if outcome.blocked:
            # An authorization refusal is not a failure and must not consume the
            # attempt budget into a terminal dead-letter. Move to BLOCKED, which a
            # re-established scope can return to PENDING -- the same state a
            # withdrawal observed at claim or recovery produces.
            if transition_allowed(job.state, JobState.BLOCKED):
                return self._transition(job, JobState.BLOCKED,
                                        f"authorization: {job.last_error}")
        if outcome.retryable and not job.budget_spent():
            delay = job.retry.delay_for(job.attempts)
            job.not_before = (self._now() + timedelta(seconds=delay)).isoformat()
            return self._transition(
                job, JobState.RETRYING,
                f"attempt {job.attempts} failed, retry in {delay:.0f}s: {job.last_error}",
            )
        # Terminal: a deterministic failure, or the budget is spent.
        return self._transition(job, JobState.FAILED, job.last_error)

    # -- misfires ------------------------------------------------------- #
    def handle_misfire(self, job_id: str) -> bool:
        """Detect a job whose scheduled time passed while nothing was running.

        A runnable job with a ``not_before`` in the past is a misfire (downtime
        swallowed the scheduled moment). We record it and clear ``not_before`` so
        it runs exactly once now, deterministically -- never twice, never skipped.
        Returns True if a misfire was recorded.
        """
        job = self.store.get(job_id)
        if job is None or job.state not in (JobState.PENDING, JobState.RETRYING):
            return False
        nb = _parse(job.not_before)
        if nb is None or self._now() < nb:
            return False
        job.misfires += 1
        job.not_before = ""
        job.history.append(f"MISFIRE: scheduled moment {nb.isoformat()} passed while down")
        job.updated_at = utcnow()
        self.store.save(job)
        return True

    # -- cancellation --------------------------------------------------- #
    def cancel(self, job_id: str, reason: str = "cancelled by operator") -> Job:
        """Cancel a non-terminal job. Idempotent on an already-terminal job."""
        job = self.store.get(job_id)
        if job is None:
            raise KeyError(f"job {job_id!r} not found")
        if job.is_terminal():
            return job
        job.lease = None
        return self._transition(job, JobState.CANCELLED, reason)

    # -- execution ------------------------------------------------------ #
    def run_once(self, owner: str) -> Optional[Job]:
        """Claim one job, run it through its executor, and record the outcome.

        This is the whole loop for one unit: recover any stale leases first (so a
        dead worker's job is not lost), then claim, execute, and complete. The
        executor re-checks authorization; the scheduler already checked it at
        claim time.
        """
        self.recover_stale()
        job = self.claim(owner)
        if job is None:
            return None
        return self._execute(job, owner)

    def _execute(self, job: Job, owner: str) -> Job:
        authz_configured, live = self._live_authz(job)
        ctx = ExecContext(authorize=authorize_active_testing, workdir=self.workdir,
                          live_authz=live, live_authz_configured=authz_configured)
        try:
            executor = get_executor(job.kind)
        except KeyError as exc:
            outcome = ExecOutcome(ok=False, retryable=False, error=str(exc))
        else:
            try:
                outcome = executor(job, ctx)
            except Exception as exc:  # noqa: BLE001 -- executor bug is retryable
                outcome = ExecOutcome(ok=False, retryable=True,
                                      error=f"{type(exc).__name__}: {exc}")
        return self.complete(job.job_id, owner, job.lease.epoch, outcome)

    def run_pending(self, owner: str, *, max_jobs: int = 100) -> list[Job]:
        """Drain runnable jobs (bounded). Returns the jobs that reached a terminal
        or retry state, in the order they were processed."""
        done: list[Job] = []
        for _ in range(max_jobs):
            job = self.run_once(owner)
            if job is None:
                break
            done.append(job)
        return done

    # -- observability -------------------------------------------------- #
    def history(self, job_id: str) -> list[str]:
        job = self.store.get(job_id)
        return list(job.history) if job else []

    def summary(self) -> dict:
        counts: dict[str, int] = {}
        for job in self.store.all():
            counts[job.state] = counts.get(job.state, 0) + 1
        return {"total": sum(counts.values()), "by_state": counts}


__all__ = ["Scheduler", "SchedulerConfig"]
