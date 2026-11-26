"""Executors: how a scheduled job becomes real BLACKHEART work.

An executor is a plain callable ``(job, context) -> ExecOutcome``. It does not
schedule, retry, or persist -- the :class:`~blackheart.scheduler.engine.Scheduler`
owns all of that. An executor's only job is to run the *engine* for one job and
report honestly what happened, including whether a failure is worth retrying.

Keeping the executors thin is deliberate: the scheduler must never invent a
result, so an executor returns the engine's own verdict verbatim, and a missing
dependency or an environment failure is classified ``retryable`` rather than
being dressed up as a clean run.

Two real executors are provided:

  * ``"hunt"`` -- runs :func:`blackheart.hunt.hunt` (every engine in order) on the
    job's target and records its honest verdict.
  * ``"investigate"`` -- drives the P3 investigation lifecycle for the job's
    hypothesis payload and records its stage/verdict.

A registry maps ``kind -> executor`` so the CLI and tests can dispatch by name and
so a future capability adds an executor without touching the scheduler core.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from ..models import AuthorizationRecord


@dataclass
class ExecOutcome:
    """What one execution attempt produced.

    ``ok`` is the *only* signal the scheduler trusts for success. ``retryable``
    says whether a failed attempt should be retried (a transient/environmental
    failure) or is terminal (a deterministic error, a bad payload, an exhausted
    budget). ``result`` is the engine's own payload, stored verbatim.
    """

    ok: bool
    retryable: bool = False
    summary: str = ""
    result: dict = field(default_factory=dict)
    error: str = ""
    #: True when the attempt was refused by the authorization gate rather than
    #: failing. The job moves to ``BLOCKED`` (recoverable once scope is
    #: re-established), not to the terminal ``FAILED`` dead-letter, so a withdrawal
    #: is never confused with a spent attempt budget.
    blocked: bool = False


@dataclass
class ExecContext:
    """Everything an executor may use, injected so it stays testable."""

    #: Re-check authorization for the job's asset right before running. Provided
    #: by the scheduler so the executor cannot skip the gate.
    authorize: Callable[[AuthorizationRecord, str], Any]
    #: Directory for engine output/evidence, if the executor writes any.
    workdir: str = ""
    #: The job's *live* authorization record, when the scheduler has a provider.
    #: The executor must authorize against this, not the snapshot on the job, or a
    #: scope withdrawal between enqueue and execution would go unnoticed.
    live_authz: Optional[AuthorizationRecord] = None
    #: True when the scheduler *has* a live provider. Combined with a ``None``
    #: ``live_authz`` this means "the current record could not be read", which must
    #: block the job rather than silently authorizing the enqueue-time snapshot.
    live_authz_configured: bool = False


def _authorized(job, ctx: ExecContext) -> Optional[ExecOutcome]:
    """Return a BLOCKING outcome if the job's authorization no longer passes."""
    try:
        record = AuthorizationRecord.from_dict(job.authz)
    except Exception as exc:  # noqa: BLE001 -- an unreadable record cannot authorize
        return ExecOutcome(ok=False, retryable=False,
                           error=f"authorization record unreadable: {exc}")
    if ctx.live_authz_configured:
        if ctx.live_authz is None:
            return ExecOutcome(
                ok=False, retryable=False, blocked=True,
                error="live authorization record is unavailable; refusing to run "
                      "on the enqueue-time snapshot",
                result={"blocked": True, "asset": job.asset, "status": "unavailable"},
            )
        record = ctx.live_authz
    decision = ctx.authorize(record, job.asset)
    if not decision.allowed:
        return ExecOutcome(
            ok=False, retryable=False, blocked=True,
            error="authorization failed: " + "; ".join(decision.blockers),
            result={"blocked": True, "asset": job.asset,
                    "status": getattr(decision.status, "value", str(decision.status))},
        )
    return None


def hunt_executor(job, ctx: ExecContext) -> ExecOutcome:
    """Run the universal hunt on the job's target -- a real engine run."""
    blocked = _authorized(job, ctx)
    if blocked is not None:
        return blocked
    try:
        from ..hunt import HuntConfig, hunt
    except Exception as exc:  # noqa: BLE001
        return ExecOutcome(ok=False, retryable=True,
                           error=f"hunt engine unavailable: {exc}")

    payload = dict(job.payload or {})
    try:
        # Authorization was re-checked by ``_authorized`` immediately above, so
        # these flags record a gate that genuinely passed -- they are not a bypass.
        cfg = HuntConfig(
            seed=int(payload.get("seed", 0)),
            certify_depth=int(payload.get("certify_depth", 3)),
            in_scope=True,
            scope_reference=job.scope_reference,
            authorization_gate_passed=True,
        )
        result = hunt(job.target, cfg)
    except Exception as exc:  # noqa: BLE001 -- a stage crash is a transient fault
        return ExecOutcome(ok=False, retryable=True,
                           error=f"{type(exc).__name__}: {exc}")

    body = result.to_dict()
    return ExecOutcome(ok=True, retryable=False, summary=body.get("verdict", ""),
                       result={"verdict": body.get("verdict", ""),
                               "verified": len(result.verified),
                               "candidates": len(result.candidates),
                               "certified": len(result.certified)})


def investigate_executor(job, ctx: ExecContext) -> ExecOutcome:
    """Drive the P3 investigation lifecycle for the job's hypothesis payload."""
    blocked = _authorized(job, ctx)
    if blocked is not None:
        return blocked
    payload = dict(job.payload or {})
    hypothesis = payload.get("hypothesis")
    if not hypothesis:
        return ExecOutcome(ok=False, retryable=False,
                           error="investigate job has no 'hypothesis' payload")
    try:
        from ..hypothesis.generation import GeneratedHypothesis
        from ..investigation import InvestigationEngine, InvestigationStore

        store = InvestigationStore(ctx.workdir or ".blackheart/scheduler/investigations")
        record = AuthorizationRecord.from_dict(job.authz)
        engine = InvestigationEngine(store, authorization=record)
        hyp = GeneratedHypothesis(**{
            k: v for k, v in hypothesis.items()
            if k in GeneratedHypothesis.__dataclass_fields__
        })
        state = engine.start(hyp, scope_reference=job.scope_reference)
    except Exception as exc:  # noqa: BLE001
        return ExecOutcome(ok=False, retryable=True,
                           error=f"{type(exc).__name__}: {exc}")
    return ExecOutcome(ok=True, retryable=False,
                       summary=f"investigation {state.investigation_id} at {state.stage}",
                       result={"investigation_id": state.investigation_id,
                               "stage": state.stage, "status": state.status})


#: Registry of executor kind -> callable. Add a capability here, not in the core.
EXECUTORS: dict[str, Callable[[Any, ExecContext], ExecOutcome]] = {
    "hunt": hunt_executor,
    "investigate": investigate_executor,
}


def get_executor(kind: str) -> Callable[[Any, ExecContext], ExecOutcome]:
    if kind not in EXECUTORS:
        raise KeyError(f"unknown job kind {kind!r}; known: {sorted(EXECUTORS)}")
    return EXECUTORS[kind]


__all__ = [
    "ExecOutcome", "ExecContext", "EXECUTORS", "get_executor",
    "hunt_executor", "investigate_executor",
]
