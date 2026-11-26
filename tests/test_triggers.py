"""Trigger monitoring must be adversarially correct, not merely working.

Every test here attacks one specific control: a forged signature, an expired
timestamp, a replay, a duplicate, a tampered payload, an injected authorization
field, a scope that does not authorize, a flood, an oversized body, a crash
between acceptance and dispatch, and a trigger record that would lie about what
happened to the work. Each is written to fail if the control it exercises is
removed.

The end-to-end test drives a *real* trigger through a *real* scheduler into a
*real* engine executor on a registered local target, so the wiring is proven
genuine rather than mocked.
"""

from __future__ import annotations

import json
import time

import pytest

from blackheart.authz import new_record
from blackheart.models import utcnow
from blackheart.scheduler import JobStore, Scheduler, SchedulerConfig
from blackheart.scheduler import executors as ex
from blackheart.scheduler.executors import ExecOutcome
from blackheart.triggers import (
    ManualTriggerSource,
    RecurringTrigger,
    TriggerError,
    TriggerLedger,
    TriggerPolicy,
    TriggerReceiver,
    TriggerState,
    WebhookTriggerSource,
    validate_payload,
)


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

SECRET = b"test-webhook-secret-0123456789"


def _authz(assets=("vault",), *, checks=True):
    rec = new_record(
        "test-program", "local", "http://localhost", "http://localhost/scope",
        program_active=checks, safe_harbor=checks, poc_required=checks,
        nigerian_eligible=checks, payout_feasible=checks, zero_cost=checks,
    )
    rec.asset_classes = {a: "AUTHORIZED" for a in assets}
    rec.verified = True
    rec.evidence = [{
        "kind": "scope-capture", "url": "http://localhost/scope",
        "retrieved_at": utcnow(), "sha256": "0" * 64,
    }]
    return rec


class FakeClock:
    def __init__(self, t: float = 1_700_000_000.0) -> None:
        self.t = t

    def __call__(self) -> float:
        return self.t

    def advance(self, s: float) -> None:
        self.t += s


class DtClock:
    """A datetime clock for the scheduler, whose epoch form feeds the receiver."""

    def __init__(self) -> None:
        from datetime import datetime, timezone
        self.t = datetime(2026, 1, 1, tzinfo=timezone.utc)

    def __call__(self):
        return self.t

    def advance(self, seconds: float) -> None:
        from datetime import timedelta
        self.t += timedelta(seconds=seconds)


def _receiver(tmp_path, *, scheduler=None, clock=None, authz=None, **policy):
    ledger = TriggerLedger(tmp_path / "triggers")
    pol = TriggerPolicy(authz=authz or _authz(), **policy)
    return TriggerReceiver(ledger, pol, scheduler=scheduler,
                           clock=clock or FakeClock()), ledger


def _scheduler(tmp_path, clock=None, **cfg):
    store = JobStore(tmp_path / "state")
    config = SchedulerConfig(clock=(lambda: _dt(clock)) if clock else None, **cfg)
    return Scheduler(store, config=config, workdir=str(tmp_path / "work"))


def _dt(fake_clock):
    from datetime import datetime, timezone
    return datetime.fromtimestamp(fake_clock.t, tz=timezone.utc)


def _sign(source: WebhookTriggerSource, body: bytes, ts: int, delivery: str = "d-1"):
    return {
        source.signature_header: source.expected_signature(str(ts), body),
        source.timestamp_header: str(ts),
        "X-Blackheart-Delivery": delivery,
    }


def _payload(**kw):
    p = {"kind": "hunt", "target": "access-control", "asset": "vault"}
    p.update(kw)
    return json.dumps(p).encode("utf-8")


# --------------------------------------------------------------------------- #
# Authentication
# --------------------------------------------------------------------------- #

def test_valid_signature_is_accepted(tmp_path):
    rx, ledger = _receiver(tmp_path)
    src = WebhookTriggerSource(SECRET)
    now = 1_700_000_000
    body = _payload()
    d = rx.handle(src, body, _sign(src, body, now))
    assert d.state == TriggerState.AUTHENTICATED
    assert d.created_job is False          # no scheduler attached
    assert len(ledger.all()) == 1


def test_forged_signature_is_rejected(tmp_path):
    rx, ledger = _receiver(tmp_path)
    src = WebhookTriggerSource(SECRET)
    body = _payload()
    headers = _sign(src, body, 1_700_000_000)
    headers[src.signature_header] = "sha256=" + "0" * 64
    d = rx.handle(src, body, headers)
    assert d.state == TriggerState.REJECTED
    assert "signature" in d.reason
    assert ledger.all()[0].state == TriggerState.REJECTED


def test_wrong_secret_is_rejected(tmp_path):
    rx, _ = _receiver(tmp_path)
    signer = WebhookTriggerSource(b"attacker-secret")
    verifier = WebhookTriggerSource(SECRET)
    body = _payload()
    d = rx.handle(verifier, body, _sign(signer, body, 1_700_000_000))
    assert d.state == TriggerState.REJECTED


def test_expired_timestamp_is_rejected(tmp_path):
    clock = FakeClock(1_700_000_000)
    rx, _ = _receiver(tmp_path, clock=clock)
    src = WebhookTriggerSource(SECRET, max_skew_seconds=300)
    body = _payload()
    # Signed 10 minutes in the past: outside the window.
    d = rx.handle(src, body, _sign(src, body, int(clock.t) - 600))
    assert d.state == TriggerState.REJECTED
    assert "skew" in d.reason


def test_missing_headers_are_rejected(tmp_path):
    rx, _ = _receiver(tmp_path)
    src = WebhookTriggerSource(SECRET)
    assert rx.handle(src, _payload(), {}).state == TriggerState.REJECTED


# --------------------------------------------------------------------------- #
# Replay / duplicate delivery
# --------------------------------------------------------------------------- #

def test_replay_with_same_delivery_id_is_refused(tmp_path):
    rx, ledger = _receiver(tmp_path, scheduler=_scheduler(tmp_path))
    src = WebhookTriggerSource(SECRET)
    body = _payload()
    headers = _sign(src, body, 1_700_000_000, delivery="fixed-id")
    first = rx.handle(src, body, headers)
    assert first.state == TriggerState.ACCEPTED
    second = rx.handle(src, body, headers)          # exact replay
    assert second.state == TriggerState.DUPLICATE
    assert second.job_id == first.job_id
    # Exactly one job exists.
    assert len(rx.scheduler.store.all()) == 1
    # The original ACCEPTED record must survive the replay: the replay is recorded
    # under its own id, so the ledger still proves the first delivery created work.
    assert ledger.get("fixed-id").state == TriggerState.ACCEPTED
    states = sorted(r.state for r in ledger.all())
    assert states == [TriggerState.ACCEPTED, TriggerState.DUPLICATE]


def test_resend_with_new_nonce_dedupes_on_payload(tmp_path):
    rx, _ = _receiver(tmp_path, scheduler=_scheduler(tmp_path))
    src = WebhookTriggerSource(SECRET)
    body = _payload()
    first = rx.handle(src, body, _sign(src, body, 1_700_000_000, delivery="d-a"))
    second = rx.handle(src, body, _sign(src, body, 1_700_000_001, delivery="d-b"))
    assert first.state == TriggerState.ACCEPTED
    assert second.state == TriggerState.DUPLICATE
    assert second.job_id == first.job_id
    assert len(rx.scheduler.store.all()) == 1


# --------------------------------------------------------------------------- #
# Payload validation
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("payload,needle", [
    ({"kind": "hunt", "target": "t"}, "missing required field: asset"),
    ({"kind": "hunt", "target": "t", "asset": "a", "extra": 1}, "unknown payload field"),
    ({"kind": "exec", "target": "t", "asset": "a"}, "unknown trigger kind"),
    ({"kind": "investigate", "target": "t", "asset": "a"}, "requires a 'hypothesis'"),
    ({"kind": "hunt", "target": "", "asset": "a"}, "must not be empty"),
    ({"kind": "hunt", "target": "t", "asset": "a", "seed": "x"}, "must be an integer"),
])
def test_payload_schema_rejects_bad_input(payload, needle):
    with pytest.raises(TriggerError) as exc:
        validate_payload(payload)
    assert needle in str(exc.value)


def test_malformed_json_is_rejected(tmp_path):
    rx, _ = _receiver(tmp_path)
    src = WebhookTriggerSource(SECRET)
    body = b"{not json"
    d = rx.handle(src, body, _sign(src, body, 1_700_000_000))
    assert d.state == TriggerState.REJECTED


def test_oversized_body_is_rejected(tmp_path):
    rx, _ = _receiver(tmp_path)
    src = WebhookTriggerSource(SECRET, max_bytes=200)
    body = _payload(note="x" * 500)
    d = rx.handle(src, body, _sign(src, body, 1_700_000_000))
    assert d.state == TriggerState.REJECTED
    assert "too large" in d.reason


def test_payload_cannot_supply_authorization(tmp_path):
    """A payload that tries to assert its own scope is rejected by the schema."""
    with pytest.raises(TriggerError):
        validate_payload({"kind": "hunt", "target": "t", "asset": "a",
                          "authz": {"verified": True}})
    with pytest.raises(TriggerError):
        validate_payload({"kind": "hunt", "target": "t", "asset": "a",
                          "scope": {"assets": {"a": "AUTHORIZED"}}})


# --------------------------------------------------------------------------- #
# Authorization enforcement
# --------------------------------------------------------------------------- #

def test_unauthorized_asset_creates_no_job(tmp_path):
    sched = _scheduler(tmp_path)
    rx, ledger = _receiver(tmp_path, scheduler=sched, authz=_authz(assets=("vault",)))
    src = WebhookTriggerSource(SECRET)
    body = _payload(asset="someone-elses-contract")
    d = rx.handle(src, body, _sign(src, body, 1_700_000_000))
    assert d.state == TriggerState.REJECTED
    assert "authorization failed" in d.reason
    assert sched.store.all() == []          # no job was created


def test_scope_withdrawn_after_acceptance_blocks_job(tmp_path):
    """Acceptance checks scope; the scheduler re-checks it at claim time."""
    sched = _scheduler(tmp_path)
    rx, _ = _receiver(tmp_path, scheduler=sched, authz=_authz(assets=("vault",)))
    src = WebhookTriggerSource(SECRET)
    body = _payload()
    d = rx.handle(src, body, _sign(src, body, 1_700_000_000))
    assert d.state == TriggerState.ACCEPTED
    job = sched.store.get(d.job_id)
    # Withdraw authorization on the stored job, as an operator would.
    job.authz["verified"] = False
    sched.store.save(job)
    claimed = sched.claim("w1")
    assert claimed is None
    assert sched.store.get(d.job_id).state == "BLOCKED"


def test_stale_evidence_blocks_trigger(tmp_path):
    from datetime import timedelta
    rec = _authz()
    old = "2020-01-01T00:00:00+00:00"
    rec.evidence = [{"kind": "scope-capture", "url": "http://localhost/scope",
                     "retrieved_at": old, "sha256": "0" * 64}]
    rec.checked_at = old
    rx, _ = _receiver(tmp_path, scheduler=_scheduler(tmp_path), authz=rec)
    src = WebhookTriggerSource(SECRET)
    body = _payload()
    d = rx.handle(src, body, _sign(src, body, 1_700_000_000))
    assert d.state == TriggerState.REJECTED
    assert "stale" in d.reason


# --------------------------------------------------------------------------- #
# Rate limiting / flood
# --------------------------------------------------------------------------- #

def test_flood_is_rate_limited(tmp_path):
    clock = FakeClock(1_700_000_000)
    sched = _scheduler(tmp_path)
    rx, _ = _receiver(tmp_path, scheduler=sched, clock=clock,
                      max_accepted_per_window=3, window_seconds=60)
    src = WebhookTriggerSource(SECRET)
    states = []
    for i in range(6):
        body = _payload(note=f"job-{i}")     # distinct payloads -> distinct work
        d = rx.handle(src, body, _sign(src, body, int(clock.t), delivery=f"d{i}"))
        states.append(d.state)
    assert states[:3] == [TriggerState.ACCEPTED] * 3
    assert all(s == TriggerState.REJECTED for s in states[3:])
    assert len(sched.store.all()) == 3


def test_rate_limit_window_slides(tmp_path):
    clock = FakeClock(1_700_000_000)
    rx, _ = _receiver(tmp_path, scheduler=_scheduler(tmp_path), clock=clock,
                      max_accepted_per_window=1, window_seconds=60)
    src = WebhookTriggerSource(SECRET)
    b1 = _payload(note="a")
    assert rx.handle(src, b1, _sign(src, b1, int(clock.t), "d1")).state == TriggerState.ACCEPTED
    b2 = _payload(note="b")
    assert rx.handle(src, b2, _sign(src, b2, int(clock.t), "d2")).state == TriggerState.REJECTED
    clock.advance(61)
    b3 = _payload(note="c")
    assert rx.handle(src, b3, _sign(src, b3, int(clock.t), "d3")).state == TriggerState.ACCEPTED


# --------------------------------------------------------------------------- #
# Observability: a trigger must not lie about what happened
# --------------------------------------------------------------------------- #

def test_trigger_state_tracks_the_real_job(tmp_path):
    clock = DtClock()
    store = JobStore(tmp_path / "state")
    sched = Scheduler(store, config=SchedulerConfig(clock=clock), workdir=str(tmp_path))
    rx, _ = _receiver(tmp_path, scheduler=sched,
                      clock=lambda: clock.t.timestamp())
    src = WebhookTriggerSource(SECRET)
    body = _payload()
    d = rx.handle(src, body, _sign(src, body, int(clock.t.timestamp())))
    assert d.state == TriggerState.ACCEPTED

    # Claim the job: the trigger must become DISPATCHED, not COMPLETED.
    job = sched.claim("w1")
    rx.sync_states()
    assert rx.ledger.get(d.delivery_id).state == TriggerState.DISPATCHED

    # Complete the job: the trigger becomes COMPLETED, but only now.
    sched.complete(job.job_id, "w1", job.lease.epoch,
                   ExecOutcome(ok=True, summary="done", result={"verdict": "x"}))
    rx.sync_states()
    assert rx.ledger.get(d.delivery_id).state == TriggerState.COMPLETED


def test_accepted_trigger_is_not_reported_executed(tmp_path):
    sched = _scheduler(tmp_path)
    rx, _ = _receiver(tmp_path, scheduler=sched)
    src = WebhookTriggerSource(SECRET)
    body = _payload()
    d = rx.handle(src, body, _sign(src, body, 1_700_000_000))
    rec = rx.ledger.get(d.delivery_id)
    assert rec.state == TriggerState.ACCEPTED
    assert rec.state != TriggerState.EXECUTED
    assert rec.state != TriggerState.COMPLETED


# --------------------------------------------------------------------------- #
# Recurring triggers
# --------------------------------------------------------------------------- #

def test_recurring_trigger_fires_on_interval(tmp_path):
    clock = FakeClock(1_700_000_000)
    sched = _scheduler(tmp_path)
    rx, _ = _receiver(tmp_path, scheduler=sched, clock=clock)
    trig = RecurringTrigger("daily", interval_seconds=3600,
                            payload={"kind": "hunt", "target": "access-control",
                                     "asset": "vault"})
    assert len(rx.tick([trig])) == 1                 # due immediately (last_fired=0)
    assert trig.last_fired == clock.t
    assert rx.tick([trig]) == []                     # not due yet
    clock.advance(3601)
    assert len(rx.tick([trig])) == 1                 # due again


def test_recurring_trigger_creates_a_new_job_each_interval(tmp_path):
    """A recurring trigger must not become a fire-once trigger via payload dedupe."""
    clock = FakeClock(1_700_000_000)
    sched = _scheduler(tmp_path)
    rx, _ = _receiver(tmp_path, scheduler=sched, clock=clock)
    trig = RecurringTrigger("t", interval_seconds=60,
                            payload={"kind": "hunt", "target": "access-control",
                                     "asset": "vault"})
    first = rx.tick([trig])[0]
    assert first.created_job is True
    clock.advance(61)
    second = rx.tick([trig])[0]
    assert second.created_job is True                # a fresh run, not a duplicate
    assert second.job_id != first.job_id
    assert len(sched.store.all()) == 2               # two distinct jobs really exist


def test_recurring_trigger_respects_scope(tmp_path):
    clock = FakeClock(1_700_000_000)
    rx, _ = _receiver(tmp_path, scheduler=_scheduler(tmp_path), clock=clock,
                      authz=_authz(assets=("vault",)))
    trig = RecurringTrigger("t", interval_seconds=60,
                            payload={"kind": "hunt", "target": "x", "asset": "not-in-scope"})
    out = rx.tick([trig])
    assert out[0].state == TriggerState.REJECTED
    assert out[0].created_job is False


# --------------------------------------------------------------------------- #
# Ledger integrity
# --------------------------------------------------------------------------- #

def test_trigger_ledger_is_hash_chained(tmp_path):
    rx, ledger = _receiver(tmp_path, scheduler=_scheduler(tmp_path))
    src = WebhookTriggerSource(SECRET)
    for i in range(5):
        body = _payload(note=f"n{i}")
        rx.handle(src, body, _sign(src, body, 1_700_000_000, delivery=f"d{i}"))
    assert ledger.verify_integrity()["status"] == "VERIFIED"


def test_rejected_record_never_contains_the_secret(tmp_path):
    rx, ledger = _receiver(tmp_path)
    src = WebhookTriggerSource(SECRET)
    body = _payload()
    headers = _sign(src, body, 1_700_000_000)
    headers[src.signature_header] = "sha256=" + "0" * 64
    rx.handle(src, body, headers)
    raw = (tmp_path / "triggers" / "triggers.jsonl").read_text()
    assert SECRET.decode() not in raw


# --------------------------------------------------------------------------- #
# End to end: real trigger -> real scheduler -> real engine
# --------------------------------------------------------------------------- #

def test_end_to_end_real_research(tmp_path):
    """A signed webhook becomes a durable job the real engine executes.

    The ``hunt`` executor runs the genuine universal hunt on a registered local
    target. We assert the chain of custody: trigger -> job -> real verdict.
    """
    clock = DtClock()
    store = JobStore(tmp_path / "state")
    sched = Scheduler(store, config=SchedulerConfig(clock=clock, lease_seconds=3600),
                      workdir=str(tmp_path / "work"))
    rx, ledger = _receiver(tmp_path, scheduler=sched,
                           clock=lambda: clock.t.timestamp())
    src = WebhookTriggerSource(SECRET)

    body = json.dumps({"kind": "hunt", "target": "access-control",
                       "asset": "vault", "scope_reference": "local://test",
                       "seed": 7}).encode()
    d = rx.handle(src, body, _sign(src, body, int(clock.t.timestamp())))
    assert d.state == TriggerState.ACCEPTED

    # The scheduler claims and the real engine runs.
    done = sched.run_pending("worker-1")
    assert len(done) == 1
    job = store.get(d.job_id)
    assert job.state in ("SUCCEEDED", "FAILED")   # the engine ran for real
    assert job.attempts == 1

    # Trigger provenance: the trigger is linked to the job and its real outcome.
    rx.sync_states()
    rec = ledger.get(d.delivery_id)
    assert rec.job_id == d.job_id
    assert rec.state == TriggerState.COMPLETED
    # The job payload carries the delivery id: provenance survives to execution.
    assert job.payload.get("delivery_id") == d.delivery_id
    assert job.scope_reference == "local://test"
    # The ledger is intact after real work.
    assert ledger.verify_integrity()["status"] == "VERIFIED"


# --------------------------------------------------------------------------- #
# Crash / restart between acceptance and dispatch
# --------------------------------------------------------------------------- #

def test_crash_after_acceptance_recovers(tmp_path):
    """A job accepted but never claimed survives a restart and runs once."""
    store = JobStore(tmp_path / "state")
    sched = Scheduler(store, workdir=str(tmp_path))
    rx, _ = _receiver(tmp_path, scheduler=sched)
    src = WebhookTriggerSource(SECRET)
    body = _payload()
    d = rx.handle(src, body, _sign(src, body, 1_700_000_000))
    assert d.state == TriggerState.ACCEPTED

    # Simulate a crash: build a brand-new scheduler over the same store.
    sched2 = Scheduler(JobStore(tmp_path / "state"), workdir=str(tmp_path))
    assert sched2.store.get(d.job_id).state == "PENDING"
    done = sched2.run_pending("worker-2")
    assert [j.job_id for j in done] == [d.job_id]


def test_failed_job_is_visible_in_the_trigger_reason(tmp_path):
    """A trigger whose job FAILED must not read as a bare successful COMPLETED."""
    from blackheart.scheduler.jobs import JobState
    sched = _scheduler(tmp_path)
    rx, ledger = _receiver(tmp_path, scheduler=sched)
    d = rx.handle(ManualTriggerSource(),
                  b'{"kind":"hunt","target":"access-control","asset":"vault"}', {})
    job = sched.store.get(d.job_id)
    job.state = JobState.FAILED
    job.attempts = 1
    sched.store.save(job)
    rx.sync_states()
    rec = ledger.get(d.delivery_id)
    assert rec.state == TriggerState.COMPLETED
    assert "FAILED" in rec.reason           # the outcome is visible, not hidden
    assert any("FAILED" in h for h in rec.history)


# --------------------------------------------------------------------------- #
# Concurrency: duplicate job creation under simultaneous delivery
# --------------------------------------------------------------------------- #

def test_concurrent_identical_deliveries_create_exactly_one_job(tmp_path):
    """N simultaneous resends of one payload must create ONE job, not N.

    The dedupe is a read-modify-append over the ledger. Without holding the ledger
    lock across the whole gate sequence, every thread reads "no duplicate" and each
    creates a job -- this reproduced 3 jobs from 24 threads before the fix, so the
    assertion fails if the transaction is removed.
    """
    import threading

    clock = FakeClock()
    sched = _scheduler(tmp_path, clock=clock)
    rx, ledger = _receiver(tmp_path, scheduler=sched, clock=clock,
                           max_accepted_per_window=500)
    src = WebhookTriggerSource(SECRET)
    body = _payload()
    ts = int(clock.t)
    sig = src.expected_signature(str(ts), body)
    errors: list[str] = []

    def deliver(i: int) -> None:
        try:
            rx.handle(src, body, {
                "X-Blackheart-Signature": sig, "X-Blackheart-Timestamp": str(ts),
                # distinct delivery ids, identical payload: pure payload dedupe
                "X-Blackheart-Delivery": f"concurrent-{i}",
            })
        except Exception as exc:  # noqa: BLE001 - a raise here is itself a failure
            errors.append(repr(exc))

    threads = [threading.Thread(target=deliver, args=(i,)) for i in range(24)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert errors == []
    assert len(sched.store.all()) == 1
    assert ledger.verify_integrity()["status"] == "VERIFIED"


def test_concurrent_same_delivery_id_creates_one_job_and_one_accept(tmp_path):
    """A concurrent replay of the *same* delivery id must create one job and keep
    exactly one ACCEPTED record; the rest are recorded as duplicates."""
    import threading

    clock = FakeClock()
    sched = _scheduler(tmp_path, clock=clock)
    rx, ledger = _receiver(tmp_path, scheduler=sched, clock=clock,
                           max_accepted_per_window=500)
    src = WebhookTriggerSource(SECRET)
    body = _payload()
    ts = int(clock.t)
    headers = {"X-Blackheart-Signature": src.expected_signature(str(ts), body),
               "X-Blackheart-Timestamp": str(ts),
               "X-Blackheart-Delivery": "one-and-only"}

    def deliver() -> None:
        rx.handle(src, body, headers)

    threads = [threading.Thread(target=deliver) for _ in range(16)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(sched.store.all()) == 1
    accepted = [r for r in ledger.all() if r.state == TriggerState.ACCEPTED]
    assert len(accepted) == 1
    # The original ACCEPTED record survives under its real id.
    assert ledger.get("one-and-only").state == TriggerState.ACCEPTED
    assert ledger.verify_integrity()["status"] == "VERIFIED"


# --------------------------------------------------------------------------- #
# Live authorization provider: a missing record must reject the delivery
# --------------------------------------------------------------------------- #

def test_live_authz_provider_none_rejects_the_delivery(tmp_path):
    """A configured provider that cannot produce the current record (file deleted)
    must reject the delivery. Falling back to the policy snapshot would accept
    work against scope the operator may have withdrawn.
    """
    recv, ledger = _receiver(tmp_path, authz_provider=lambda asset: None,
                             scheduler=_scheduler(tmp_path))
    src = WebhookTriggerSource(SECRET)
    body = _payload()
    headers = _sign(src, body, 1_700_000_000)
    d = recv.handle(src, body, headers)
    assert d.state == "REJECTED"
    assert "live authorization record is unavailable" in d.reason
    assert all(r.state != "ACCEPTED" for r in ledger.all())


def test_live_authz_provider_that_raises_rejects_the_delivery(tmp_path):
    def boom(asset):
        raise OSError("authz file unreadable")

    recv, _ = _receiver(tmp_path, authz_provider=boom,
                        scheduler=_scheduler(tmp_path))
    src = WebhookTriggerSource(SECRET)
    body = _payload()
    d = recv.handle(src, body, _sign(src, body, 1_700_000_000))
    assert d.state == "REJECTED"


def test_live_authz_provider_failure_does_not_enqueue_a_job(tmp_path):
    store = JobStore(tmp_path / "state")
    sched = Scheduler(store, config=SchedulerConfig(), workdir=str(tmp_path / "w"))
    recv, _ = _receiver(tmp_path, authz_provider=lambda asset: None, scheduler=sched)
    src = WebhookTriggerSource(SECRET)
    body = _payload()
    recv.handle(src, body, _sign(src, body, 1_700_000_000))
    assert store.all() == []


def test_enqueue_snapshots_the_record_authorization_was_granted_against(tmp_path):
    """The job must carry the record the receiver actually authorized against, not
    the policy's stale configured record -- a scheduler later recovering the job
    with no live provider trusts that snapshot."""
    fresh = _authz()                     # the live record (authoritative)
    stale = _authz(assets=())            # configured snapshot: authorizes nothing
    sched = _scheduler(tmp_path)
    recv, _ = _receiver(tmp_path, authz=stale, scheduler=sched,
                        authz_provider=lambda asset: fresh)
    src = WebhookTriggerSource(SECRET)
    body = _payload()
    d = recv.handle(src, body, _sign(src, body, 1_700_000_000))
    assert d.state == "ACCEPTED"
    from blackheart.models import AuthorizationRecord as AR
    job = sched.store.get(d.job_id)
    snap = AR.from_dict(job.authz)
    assert snap.asset_classes.get("vault") == "AUTHORIZED"
