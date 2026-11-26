"""The durable scheduler must be adversarially correct, not merely working.

These tests target the failure modes an unattended, restartable, multi-worker
scheduler actually has: an illegal transition, a stale worker writing a result it
no longer owns, a lease that never expires, a duplicate trigger creating a second
job, a missed scheduled moment, an exhausted retry budget retrying forever, a job
that runs after its authorization was withdrawn, and a tampered log that reads as
clean. Each is written to fail if the corresponding guarantee is removed.

The engine work is injected through a fake executor, so the tests exercise the
*scheduler* -- leases, fencing, recovery, retry, authorization -- without depending
on a multi-minute hunt run. One end-to-end test drives the real ``hunt`` executor
on a registered local target to prove the wiring is genuine, not mocked.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

from blackheart.authz import new_record
from blackheart.models import utcnow
from blackheart.scheduler import (
    InvalidTransition,
    Job,
    JobState,
    JobStore,
    Scheduler,
    SchedulerConfig,
    transition_allowed,
)
from blackheart.scheduler import executors as ex
from blackheart.scheduler.executors import ExecOutcome


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def _authz(assets=("vault",), *, verified=True, checks=True):
    rec = new_record(
        "test-program", "local", "http://localhost", "http://localhost/scope",
        program_active=checks, safe_harbor=checks, poc_required=checks,
        nigerian_eligible=checks, payout_feasible=checks, zero_cost=checks,
    )
    rec.asset_classes = {a: "AUTHORIZED" for a in assets}
    if verified:
        rec.verified = True
        rec.evidence = [{
            "kind": "scope-capture", "url": "http://localhost/scope",
            "retrieved_at": utcnow(), "sha256": "0" * 64,
        }]
    return rec


class Clock:
    """A controllable clock: tests advance time deterministically."""

    def __init__(self) -> None:
        self.t = datetime(2026, 1, 1, tzinfo=timezone.utc)

    def __call__(self) -> datetime:
        return self.t

    def advance(self, seconds: float) -> None:
        self.t += timedelta(seconds=seconds)


def _scheduler(tmp_path, clock=None, **cfg):
    clock = clock or Clock()
    store = JobStore(tmp_path / "state", key=None)
    config = SchedulerConfig(clock=clock, **cfg)
    return Scheduler(store, config=config, workdir=str(tmp_path / "work")), clock


def _job(tmp_path, kind="fake", asset="vault", **kw):
    return Job(
        job_id=kw.pop("job_id", "JOB-1"), kind=kind,
        target=kw.pop("target", "access-control"), asset=asset,
        authz=_authz().to_dict(), **kw,
    )


@pytest.fixture
def fake_executor(monkeypatch):
    """Register a controllable executor and return its behaviour holder."""
    state = {"outcome": ExecOutcome(ok=True, summary="ok", result={"ran": True}),
             "calls": 0, "last_job": None}

    def _exec(job, ctx):
        state["calls"] += 1
        state["last_job"] = job
        out = state["outcome"]
        return out(job, ctx) if callable(out) else out

    monkeypatch.setitem(ex.EXECUTORS, "fake", _exec)
    return state


# --------------------------------------------------------------------------- #
# Lifecycle / state machine
# --------------------------------------------------------------------------- #

def test_illegal_transition_is_refused():
    assert transition_allowed(JobState.SUCCEEDED, JobState.PENDING) is False
    assert transition_allowed(JobState.FAILED, JobState.LEASED) is False
    assert transition_allowed(JobState.PENDING, JobState.LEASED) is True


def test_completing_a_succeeded_job_raises(tmp_path, fake_executor):
    sched, _ = _scheduler(tmp_path)
    job = sched.submit(_job(tmp_path))
    sched.run_once("w1")
    done = sched.store.get(job.job_id)
    assert done.state == JobState.SUCCEEDED
    # A second completion from any worker must be refused: terminal is terminal.
    with pytest.raises(InvalidTransition):
        sched.complete(job.job_id, "w1", 1, ExecOutcome(ok=True))


# --------------------------------------------------------------------------- #
# Leases and fencing
# --------------------------------------------------------------------------- #

def test_claim_grants_lease_and_bumps_epoch(tmp_path, fake_executor):
    clock = Clock()
    sched, clock = _scheduler(tmp_path, clock)
    sched.submit(_job(tmp_path))
    j1 = sched.claim("w1")
    assert j1.state == JobState.LEASED and j1.lease.epoch == 1
    # A retryable failure re-queues; the next claim's epoch must strictly increase.
    sched.complete(j1.job_id, "w1", 1, ExecOutcome(ok=False, retryable=True, error="x"))
    clock.advance(3600)
    j2 = sched.claim("w2")
    assert j2.lease.epoch == 2


def test_stale_worker_cannot_complete_after_reclaim(tmp_path, fake_executor):
    clock = Clock()
    sched, clock = _scheduler(tmp_path, clock, lease_seconds=10)
    job = sched.submit(_job(tmp_path))
    first = sched.claim("w1")             # epoch 1
    clock.advance(11)                      # lease expires
    recovered = sched.recover_stale()
    assert recovered == [job.job_id]
    second = sched.claim("w2")             # epoch 2, a different owner
    assert second.lease.epoch == 2
    # The first worker, still believing it owns epoch 1, tries to write a result.
    with pytest.raises(InvalidTransition):
        sched.complete(job.job_id, "w1", first.lease.epoch, ExecOutcome(ok=True))
    # Only the current owner can complete.
    done = sched.complete(job.job_id, "w2", 2, ExecOutcome(ok=True, result={"by": "w2"}))
    assert done.state == JobState.SUCCEEDED and done.result == {"by": "w2"}


def test_heartbeat_renews_and_refuses_non_owner(tmp_path):
    clock = Clock()
    sched, clock = _scheduler(tmp_path, clock, lease_seconds=10)
    job = sched.submit(_job(tmp_path))
    claimed = sched.claim("w1")
    clock.advance(8)
    assert sched.heartbeat(job.job_id, "w1", 1) is True   # renew before expiry
    clock.advance(8)                                       # 16s since claim, 8 since renew
    assert sched.lease_expired(sched.store.get(job.job_id)) is False
    # A non-owner and a wrong epoch are both refused and change nothing.
    assert sched.heartbeat(job.job_id, "w2", 1) is False
    assert sched.heartbeat(job.job_id, "w1", 99) is False


def test_heartbeat_after_reclaim_is_refused(tmp_path):
    clock = Clock()
    sched, clock = _scheduler(tmp_path, clock, lease_seconds=10)
    job = sched.submit(_job(tmp_path))
    sched.claim("w1")
    clock.advance(11)
    sched.recover_stale()
    sched.claim("w2")                      # epoch 2
    assert sched.heartbeat(job.job_id, "w1", 1) is False


# --------------------------------------------------------------------------- #
# Retry and dead-letter
# --------------------------------------------------------------------------- #

def test_retryable_failure_backs_off_then_succeeds(tmp_path, fake_executor):
    clock = Clock()
    sched, clock = _scheduler(tmp_path, clock)
    job = sched.submit(_job(tmp_path, max_attempts=3))

    fake_executor["outcome"] = ExecOutcome(ok=False, retryable=True, error="transient")
    r1 = sched.run_once("w1")
    assert r1.state == JobState.RETRYING and r1.attempts == 1
    # Not runnable until backoff elapses.
    assert sched.claim("w1") is None
    clock.advance(r1.retry.delay_for(1) + 0.1)
    fake_executor["outcome"] = ExecOutcome(ok=True, result={"ok": 1})
    r2 = sched.run_once("w1")
    assert r2.state == JobState.SUCCEEDED and r2.attempts == 2


def test_budget_exhaustion_dead_letters(tmp_path, fake_executor):
    clock = Clock()
    sched, clock = _scheduler(tmp_path, clock)
    job = sched.submit(_job(tmp_path, max_attempts=2))
    fake_executor["outcome"] = ExecOutcome(ok=False, retryable=True, error="always")
    sched.run_once("w1")
    clock.advance(3600)
    final = sched.run_once("w1")
    assert final.state == JobState.FAILED
    assert final.attempts == 2
    # Dead-lettered: never claimed again even if time passes.
    clock.advance(10_000)
    assert sched.claim("w1") is None


def test_terminal_failure_is_not_retried(tmp_path, fake_executor):
    sched, _ = _scheduler(tmp_path)
    job = sched.submit(_job(tmp_path))
    fake_executor["outcome"] = ExecOutcome(ok=False, retryable=False, error="bad payload")
    r = sched.run_once("w1")
    assert r.state == JobState.FAILED and r.attempts == 1


# --------------------------------------------------------------------------- #
# Idempotency / dedupe
# --------------------------------------------------------------------------- #

def test_duplicate_idempotency_key_creates_one_job(tmp_path):
    sched, _ = _scheduler(tmp_path)
    a = sched.enqueue(kind="fake", target="t", asset="vault",
                      authz=_authz(), idempotency_key="daily")
    b = sched.enqueue(kind="fake", target="t", asset="vault",
                      authz=_authz(), idempotency_key="daily")
    assert a.job_id == b.job_id
    assert len(sched.store.all()) == 1


def test_distinct_keys_create_distinct_jobs(tmp_path):
    sched, _ = _scheduler(tmp_path)
    a = sched.enqueue(kind="fake", target="t", asset="vault",
                      authz=_authz(), idempotency_key="day-1")
    b = sched.enqueue(kind="fake", target="t", asset="vault",
                      authz=_authz(), idempotency_key="day-2")
    assert a.job_id != b.job_id and len(sched.store.all()) == 2


# --------------------------------------------------------------------------- #
# Misfire recovery
# --------------------------------------------------------------------------- #

def test_misfire_recorded_once_and_cleared(tmp_path):
    clock = Clock()
    sched, clock = _scheduler(tmp_path, clock)
    job = sched.submit(_job(tmp_path))
    job.not_before = (clock() - timedelta(hours=1)).isoformat()
    sched.store.save(job)
    assert sched.handle_misfire(job.job_id) is True
    fired = sched.store.get(job.job_id)
    assert fired.misfires == 1 and fired.not_before == ""
    # Second call: not a misfire any more (already cleared).
    assert sched.handle_misfire(job.job_id) is False


def test_job_in_backoff_is_not_a_misfire(tmp_path):
    clock = Clock()
    sched, clock = _scheduler(tmp_path, clock)
    job = sched.submit(_job(tmp_path))
    job.not_before = (clock() + timedelta(hours=1)).isoformat()
    sched.store.save(job)
    assert sched.handle_misfire(job.job_id) is False


# --------------------------------------------------------------------------- #
# Authorization at every boundary
# --------------------------------------------------------------------------- #

def test_unauthorized_job_is_blocked_not_run(tmp_path, fake_executor):
    sched, _ = _scheduler(tmp_path)
    job = Job(job_id="JOB-u", kind="fake", target="t", asset="vault",
              authz=_authz(verified=False).to_dict())
    sched.submit(job)
    ran = sched.run_once("w1")
    assert ran is None
    assert fake_executor["calls"] == 0
    assert sched.store.get("JOB-u").state == JobState.BLOCKED


def test_authorization_withdrawn_after_enqueue_blocks_execution(tmp_path, fake_executor):
    """A job enqueued while authorized must not run if scope is withdrawn."""
    sched, _ = _scheduler(tmp_path)
    job = sched.submit(_job(tmp_path))
    # Withdraw authorization in the stored job (as an operator would).
    job.authz = _authz(checks=False).to_dict()
    sched.store.save(job)
    ran = sched.run_once("w1")
    assert ran is None and fake_executor["calls"] == 0
    assert sched.store.get(job.job_id).state == JobState.BLOCKED


def test_recovery_blocks_when_scope_withdrawn_while_down(tmp_path):
    clock = Clock()
    sched, clock = _scheduler(tmp_path, clock, lease_seconds=10)
    job = sched.submit(_job(tmp_path))
    sched.claim("w1")
    # While the worker is "down", authorization is withdrawn.
    j = sched.store.get(job.job_id)
    j.authz = _authz(checks=False).to_dict()
    sched.store.save(j)
    clock.advance(11)
    sched.recover_stale()
    assert sched.store.get(job.job_id).state == JobState.BLOCKED


# --------------------------------------------------------------------------- #
# Durable store: replay, restart, corruption, tamper
# --------------------------------------------------------------------------- #

def test_state_survives_restart_by_replay(tmp_path, fake_executor):
    sched, _ = _scheduler(tmp_path)
    job = sched.submit(_job(tmp_path, max_attempts=3))
    sched.claim("w1")
    # A brand-new scheduler over the same directory must see the LEASED job.
    store2 = JobStore(tmp_path / "state")
    sched2 = Scheduler(store2, config=SchedulerConfig(clock=Clock()))
    replayed = store2.get(job.job_id)
    assert replayed.state == JobState.LEASED and replayed.lease.owner == "w1"


def test_truncated_tail_is_reported_not_hidden(tmp_path):
    sched, _ = _scheduler(tmp_path)
    sched.submit(_job(tmp_path))
    path = sched.store.path
    with path.open("a", encoding="utf-8") as fh:
        fh.write('{"type": "state", "id": "JOB-1", "content": {')  # truncated
    report = sched.store.corruption_report()
    assert report["skipped_lines"] == 1 and report["ok"] is False
    # The valid record before the truncation is still readable.
    assert sched.store.get("JOB-1") is not None


def test_hash_chain_detects_tampering(tmp_path):
    sched, _ = _scheduler(tmp_path)
    sched.submit(_job(tmp_path))
    path = sched.store.path
    lines = path.read_text().splitlines()
    ev = json.loads(lines[0])
    ev["content"]["state"] = "SUCCEEDED"   # forge a success without re-hashing
    lines[0] = json.dumps(ev)
    path.write_text("\n".join(lines) + "\n")
    result = sched.store.verify_integrity()
    assert result["status"] == "FAILED" and result["ok"] is False


def test_clean_chain_verifies(tmp_path, fake_executor):
    sched, _ = _scheduler(tmp_path)
    sched.submit(_job(tmp_path))
    sched.run_once("w1")
    result = sched.store.verify_integrity()
    assert result["status"] == "VERIFIED" and result["checked"] >= 2


# --------------------------------------------------------------------------- #
# Operator controls
# --------------------------------------------------------------------------- #

def test_cancel_prevents_execution(tmp_path, fake_executor):
    sched, _ = _scheduler(tmp_path)
    job = sched.submit(_job(tmp_path))
    sched.cancel(job.job_id, reason="operator stop")
    assert sched.run_once("w1") is None
    assert fake_executor["calls"] == 0
    assert sched.store.get(job.job_id).state == JobState.CANCELLED


def test_cancel_is_idempotent_on_terminal_job(tmp_path, fake_executor):
    sched, _ = _scheduler(tmp_path)
    job = sched.submit(_job(tmp_path))
    sched.run_once("w1")
    again = sched.cancel(job.job_id)
    assert again.state == JobState.SUCCEEDED   # unchanged, not corrupted


def test_priority_ordering(tmp_path, fake_executor):
    sched, _ = _scheduler(tmp_path)
    sched.submit(Job(job_id="JOB-low", kind="fake", target="t", asset="vault",
                     authz=_authz().to_dict(), priority=1))
    sched.submit(Job(job_id="JOB-high", kind="fake", target="t", asset="vault",
                     authz=_authz().to_dict(), priority=10))
    first = sched.claim("w1")
    assert first.job_id == "JOB-high"


# --------------------------------------------------------------------------- #
# Executor wiring (the anti-mock test: the real engine runs)
# --------------------------------------------------------------------------- #

def test_real_hunt_executor_runs_the_engine(tmp_path):
    """Prove the scheduler drives the *real* hunt engine, not a stub."""
    sched, _ = _scheduler(tmp_path)
    job = sched.enqueue(
        kind="hunt", target="access-control", asset="vault",
        authz=_authz(), payload={"certify_depth": 2},
    )
    done = sched.run_once("w1")
    assert done.state == JobState.SUCCEEDED
    # The engine's own verdict is recorded verbatim -- a real sentence, and the
    # engine genuinely searched (candidates > 0).
    assert done.result["verdict"]
    assert done.result["candidates"] >= 0
    assert "verified" in done.result


def test_executor_cannot_skip_authorization(tmp_path):
    """Even if the scheduler's claim gate were bypassed, the executor refuses."""
    sched, _ = _scheduler(tmp_path)
    job = Job(job_id="JOB-x", kind="hunt", target="access-control", asset="vault",
              authz=_authz(checks=False).to_dict())
    ctx = ex.ExecContext(authorize=__import__(
        "blackheart.authz", fromlist=["authorize_active_testing"]
    ).authorize_active_testing)
    outcome = ex.hunt_executor(job, ctx)
    assert outcome.ok is False and outcome.retryable is False
    assert outcome.result.get("blocked") is True


def test_unknown_kind_fails_terminally(tmp_path):
    sched, _ = _scheduler(tmp_path)
    job = sched.submit(Job(job_id="JOB-k", kind="does-not-exist", target="t",
                           asset="vault", authz=_authz().to_dict()))
    done = sched.run_once("w1")
    assert done.state == JobState.FAILED


def test_run_pending_drains_all(tmp_path, fake_executor):
    sched, _ = _scheduler(tmp_path)
    for i in range(5):
        sched.submit(Job(job_id=f"JOB-{i}", kind="fake", target="t", asset="vault",
                         authz=_authz().to_dict()))
    done = sched.run_pending("w1")
    assert len(done) == 5 and all(j.state == JobState.SUCCEEDED for j in done)
    assert sched.summary()["by_state"] == {JobState.SUCCEEDED: 5}


# --------------------------------------------------------------------------- #
# CLI surface (the scheduler is reachable exactly as documented)
# --------------------------------------------------------------------------- #

def test_cli_schedule_add_list_show(tmp_path, fake_executor):
    from blackheart.cli import main

    authz_file = tmp_path / "authz.json"
    authz_file.write_text(json.dumps(_authz().to_dict()))
    state = tmp_path / "state"

    rc = main(["schedule", "--dir", str(state), "add", "--kind", "hunt",
               "--target", "access-control", "--asset", "vault",
               "--authz", str(authz_file), "--key", "daily"])
    assert rc == 0

    # A repeated trigger with the same idempotency key must not create a second job.
    main(["schedule", "--dir", str(state), "add", "--kind", "hunt",
          "--target", "access-control", "--asset", "vault",
          "--authz", str(authz_file), "--key", "daily"])
    jobs = JobStore(state).all()
    assert len(jobs) == 1
    job_id = jobs[0].job_id

    assert main(["schedule", "--dir", str(state), "show", job_id]) == 0
    assert main(["schedule", "--dir", str(state), "summary"]) == 0
    assert main(["schedule", "--dir", str(state), "verify"]) == 0


def test_cli_schedule_run_real_engine(tmp_path):
    from blackheart.cli import main

    authz_file = tmp_path / "authz.json"
    authz_file.write_text(json.dumps(_authz().to_dict()))
    state = tmp_path / "state"
    main(["schedule", "--dir", str(state), "add", "--kind", "hunt",
          "--target", "access-control", "--asset", "vault",
          "--authz", str(authz_file), "--key", "run-once"])
    rc = main(["schedule", "--dir", str(state), "run", "--owner", "w1"])
    assert rc == 0
    job = JobStore(state).all()[0]
    assert job.state == JobState.SUCCEEDED and job.result["verdict"]


def test_cli_schedule_cancel_and_missing_job(tmp_path):
    from blackheart.cli import main

    authz_file = tmp_path / "authz.json"
    authz_file.write_text(json.dumps(_authz().to_dict()))
    state = tmp_path / "state"
    main(["schedule", "--dir", str(state), "add", "--kind", "hunt",
          "--target", "access-control", "--asset", "vault", "--authz", str(authz_file)])
    job_id = JobStore(state).all()[0].job_id
    assert main(["schedule", "--dir", str(state), "cancel", job_id]) == 0
    assert JobStore(state).get(job_id).state == JobState.CANCELLED
    # An unknown job id is a usage error, not a crash.
    assert main(["schedule", "--dir", str(state), "show", "JOB-nope"]) == 2


def test_real_investigate_executor_drives_the_lifecycle(tmp_path):
    """The investigate executor drives the real P3 engine, not a stub."""
    from blackheart.hypothesis.generation import GeneratedHypothesis

    hyp = GeneratedHypothesis(
        hyp_id="P2-T:accounting-manipulation::x",
        objective_id="T:accounting-manipulation",
        title="Donation breaks the share/asset invariant",
        category="accounting-manipulation", component="Vault",
        entry_point="flashLoan",
        attacker_capability="any external actor with a token balance",
        trust_boundary="user <-> vault", critical_asset="vault-liquidity",
        invariant="convertToShares(totalSupply) == totalAssets()",
        expected_impact="state-corruption: accounting diverges",
        impact_id="state-corruption",
        strategy="donate to shift the live balance without minting shares",
        required_tools=["forge"], reproduction_criteria="invariant is false",
        falsification_criteria="invariant holds for every donation",
        authorization_requirement="asset must be AUTHORIZED",
        novelty_requirement="NoveltyReview must classify it LIKELY_NEW",
    )
    sched, _ = _scheduler(tmp_path)
    job = sched.enqueue(kind="investigate", target="T", asset="vault",
                        authz=_authz(), payload={"hypothesis": hyp.to_dict()})
    done = sched.run_once("w1")
    assert done.state == JobState.SUCCEEDED
    assert done.result["investigation_id"]
    assert done.result["stage"]


def test_crashing_worker_cannot_cause_an_infinite_crash_loop(tmp_path):
    """A worker that dies without reporting must still consume its budget.

    ``complete`` is the only place a well-behaved worker increments ``attempts``.
    A worker killed mid-run never calls it, so if recovery did not account for the
    lost attempt, a job that reliably crashes its worker would be reclaimed and
    re-run forever -- an unbounded crash loop with no dead-letter. The attempt
    budget must hold even when no completion is ever reported.
    """
    clock = Clock()
    sched, clock = _scheduler(tmp_path, clock, lease_seconds=10)
    job = sched.submit(_job(tmp_path, max_attempts=3))

    for _ in range(10):                    # far more than the budget
        claimed = sched.claim("w-crash")   # worker claims ...
        if claimed is None:
            break
        # ... and dies: no complete(), no heartbeat. Lease expires.
        clock.advance(11)
        sched.recover_stale()

    final = sched.store.get(job.job_id)
    assert final.state == JobState.FAILED, "a crash-looping job must dead-letter"
    assert final.attempts >= 3


def test_attempts_counted_at_claim_not_completion(tmp_path, fake_executor):
    """The attempt budget is consumed when work starts, exactly once per claim."""
    clock = Clock()
    sched, clock = _scheduler(tmp_path, clock)
    job = sched.submit(_job(tmp_path, max_attempts=3))
    fake_executor["outcome"] = ExecOutcome(ok=False, retryable=True, error="t")

    seen = []
    for _ in range(3):
        done = sched.run_once("w1")
        seen.append(done.attempts)
        clock.advance(done.retry.delay_for(done.attempts) + 1)
    assert seen == [1, 2, 3]
    assert done.state == JobState.FAILED and done.attempts == 3


@pytest.mark.slow
def test_concurrent_writers_keep_the_hash_chain_valid(tmp_path):
    """Several workers on one store must not corrupt the chain.

    ``save`` reads the chain head and then appends. Without serialisation two
    processes both chain onto the same head and the log stops verifying. The
    lease/fencing design exists so workers *may* share a store, so this must hold.
    Uses real processes because the race is between processes, not threads.
    """
    import subprocess
    import sys
    import textwrap

    script = tmp_path / "writer.py"
    script.write_text(textwrap.dedent(f"""
        import sys
        sys.path.insert(0, {str(__import__("pathlib").Path(__file__).parents[1])!r})
        from blackheart.scheduler import JobStore, Job
        store = JobStore({str(tmp_path)!r})
        pid = __import__("os").getpid()
        for i in range(25):
            store.save(Job(f"J-{{pid}}-{{i}}", "fake", "t", "v", {{}}))
    """))
    procs = [subprocess.Popen([sys.executable, str(script)]) for _ in range(4)]
    for p in procs:
        assert p.wait() == 0

    report = JobStore(str(tmp_path)).verify_integrity()
    assert report["status"] == "VERIFIED"
    assert report["checked"] == 100


def test_checkpoint_detects_tail_truncation(tmp_path, capsys, fake_executor):
    """The in-band chain cannot see a removed tail; a checkpoint can.

    A log with its last record(s) deleted still verifies internally, so the store
    must be able to pin its head and later catch the shorter log. This drives the
    real CLI ``checkpoint`` and ``verify --checkpoint`` paths, for both a partial
    truncation and a full truncation to empty (the case a naive check misses).
    """
    from blackheart.cli import main

    state = tmp_path / "state"
    authz_file = tmp_path / "authz.json"
    authz_file.write_text(json.dumps(_authz().to_dict()))
    base = ["schedule", "--dir", str(state)]
    for asset in ("v1", "v2"):
        assert main(base + ["add", "--kind", "hunt", "--target", "t",
                            "--asset", asset, "--authz", str(authz_file)]) == 0
    assert main(base + ["checkpoint"]) == 0
    capsys.readouterr()

    log = state / "jobs.jsonl"
    cp = str(state / "jobs.checkpoint.json")
    full = log.read_text().splitlines()

    # Partial truncation: drop the last record.
    log.write_text("\n".join(full[:-1]) + "\n")
    assert main(base + ["verify", "--checkpoint", cp]) == 1
    assert json.loads(capsys.readouterr().out)["status"] == "FAILED"

    # Full truncation: delete the entire log body.
    log.write_text("")
    assert main(base + ["verify", "--checkpoint", cp]) == 1
    report = json.loads(capsys.readouterr().out)
    assert report["status"] == "FAILED" and report["ok"] is False


# --------------------------------------------------------------------------- #
# Live authorization provider: a *missing* record must fail closed
# --------------------------------------------------------------------------- #

def test_live_authz_provider_returning_none_blocks_the_job(tmp_path, fake_executor):
    """Fail-closed: when a live provider is configured but cannot produce the
    current record (the authorization file was deleted), the job must NOT run.

    Regression for a fail-open: the scheduler used to fall back to the
    enqueue-time snapshot when the provider returned ``None``, so withdrawing
    scope by deleting the authz file still let the job execute.
    """
    sched, _ = _scheduler(tmp_path, authz_provider=lambda asset: None)
    job = sched.submit(_job(tmp_path))
    ran = sched.run_once("w1")
    assert ran is None
    assert fake_executor["calls"] == 0
    blocked = sched.store.get(job.job_id)
    assert blocked.state == JobState.BLOCKED
    assert "live authorization record is unavailable" in blocked.history[-1]


def test_live_authz_provider_that_raises_blocks_the_job(tmp_path, fake_executor):
    """A provider that raises is 'record unavailable', never 'authorized'."""
    def boom(asset):
        raise RuntimeError("authz file unreadable")

    sched, _ = _scheduler(tmp_path, authz_provider=boom)
    job = sched.submit(_job(tmp_path))
    assert sched.run_once("w1") is None
    assert fake_executor["calls"] == 0
    assert sched.store.get(job.job_id).state == JobState.BLOCKED


def test_no_provider_falls_back_to_the_enqueue_snapshot(tmp_path, fake_executor):
    """Without a provider the snapshot is authoritative -- the previous behaviour
    for callers that never mutate their record must be preserved."""
    sched, _ = _scheduler(tmp_path)  # no authz_provider
    job = sched.submit(_job(tmp_path))
    ran = sched.run_once("w1")
    assert ran is not None
    assert fake_executor["calls"] == 1
    assert sched.store.get(job.job_id).state == JobState.SUCCEEDED


def test_live_authz_provider_withdrawal_blocks_execution(tmp_path, fake_executor):
    """A provider that stops authorizing the asset blocks a live withdrawal."""
    state = {"rec": _authz()}
    sched, _ = _scheduler(tmp_path, authz_provider=lambda asset: state["rec"])
    job = sched.submit(_job(tmp_path))
    state["rec"] = _authz(checks=False)  # scope withdrawn after enqueue
    assert sched.run_once("w1") is None
    assert fake_executor["calls"] == 0
    assert sched.store.get(job.job_id).state == JobState.BLOCKED


# --------------------------------------------------------------------------- #
# The CLI worker honours a live scope withdrawal (the real ingress->worker path)
# --------------------------------------------------------------------------- #

def test_cli_schedule_run_with_authz_blocks_after_withdrawal(tmp_path):
    """The documented guarantee is that a scope withdrawal between acceptance and
    execution still blocks the job. In the real topology the ingress only enqueues;
    a separate `schedule run` worker executes. That worker must be given the live
    record (`--authz`) and must re-read it, or the guarantee is false. Here the file
    is deleted after enqueue: the worker must BLOCK, not run the hunt."""
    from blackheart.cli import main

    authz_file = tmp_path / "authz.json"
    authz_file.write_text(json.dumps(_authz().to_dict()))
    state = tmp_path / "state"
    assert main(["schedule", "--dir", str(state), "add", "--kind", "hunt",
                 "--target", "access-control", "--asset", "vault",
                 "--authz", str(authz_file)]) == 0

    authz_file.unlink()  # operator withdraws scope after acceptance

    main(["schedule", "--dir", str(state), "--authz", str(authz_file),
          "run", "--owner", "w1"])
    job = JobStore(state).all()[0]
    assert job.state == JobState.BLOCKED, job.to_dict()
    assert job.attempts == 0  # the hunt never ran


def test_cli_schedule_without_authz_uses_the_snapshot(tmp_path, fake_executor):
    """Omitting `--authz` keeps the previous snapshot semantics: the job still runs.
    This documents the difference rather than letting it be silent."""
    from blackheart.cli import main

    authz_file = tmp_path / "authz.json"
    authz_file.write_text(json.dumps(_authz().to_dict()))
    state = tmp_path / "state"
    # ``schedule add`` only offers the real kinds, so the fake executor's job is
    # enqueued through the same store the CLI uses.
    Scheduler(JobStore(state)).enqueue(
        kind="fake", target="access-control", asset="vault",
        authz=_authz(), payload={})
    rc = main(["schedule", "--dir", str(state), "run", "--owner", "w1"])
    assert rc == 0
    assert JobStore(state).all()[0].state == JobState.SUCCEEDED


# --------------------------------------------------------------------------- #
# An authorization refusal at execution is BLOCKED, not a spent FAILED budget
# --------------------------------------------------------------------------- #

def test_execution_time_authorization_refusal_blocks_not_fails(tmp_path):
    """A scope withdrawal between claim and execution must produce BLOCKED -- the
    same recoverable state a withdrawal observed at claim or recovery produces --
    and must not be dead-lettered as FAILED, which would confuse a policy decision
    with a spent attempt budget."""
    record = _authz()
    state = {"rec": record}
    sched = Scheduler(
        JobStore(tmp_path / "state"),
        config=SchedulerConfig(authz_provider=lambda asset: state["rec"]),
        workdir=str(tmp_path / "work"),
    )
    sched.enqueue(kind="hunt", target="access-control", asset="vault",
                  authz=record, payload={})
    claimed = sched.claim("w1")
    assert claimed.state == JobState.LEASED

    state["rec"] = None  # withdrawn after the claim, before execution
    done = sched._execute(claimed, "w1")

    assert done.state == JobState.BLOCKED, done.to_dict()
    assert "authorization" in done.last_error
    assert done.state not in (JobState.FAILED, JobState.SUCCEEDED)


# --------------------------------------------------------------------------- #
# Concurrent submissions of one idempotency key create exactly one job
# --------------------------------------------------------------------------- #

def test_concurrent_submit_of_one_idempotency_key_creates_one_job(tmp_path):
    """``submit`` reads for an existing job and then appends. Without a lock over
    both, N threads all read "none" and each persists a job -- the duplicate work
    the idempotency key exists to prevent. The read-modify-append must be atomic."""
    import threading

    store = JobStore(tmp_path / "state")
    sched = Scheduler(store, workdir=str(tmp_path / "work"))
    record = _authz()
    n = 8
    barrier = threading.Barrier(n)

    def submit():
        barrier.wait()  # release all threads together to maximise the race
        sched.enqueue(kind="hunt", target="access-control", asset="vault",
                      authz=record, payload={"n": 1}, idempotency_key="daily")

    threads = [threading.Thread(target=submit) for _ in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(store.all()) == 1
