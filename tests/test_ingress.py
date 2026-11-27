"""The live HTTP ingress must be real, hostile-input-safe, and honest.

Every test here runs an actual ``ThreadingHTTPServer`` on a loopback port and
speaks real HTTP to it -- no mocks of the server, the socket, or the receiver.
The end-to-end test drives a signed HTTP request all the way through the
receiver, the durable scheduler, and the *real* research engine, then asserts the
trigger -> job -> verdict chain of custody.

Each control is tested by attacking it: a forged signature, an expired or future
timestamp, a replay, concurrent duplicates, a wrong content type, an oversized
body, malformed JSON, an unauthorized target, and a shutdown mid-flight. The
tests are written to fail if the control they exercise is removed.
"""

from __future__ import annotations

import json
import socket
import threading
import time
import urllib.error
import urllib.request

import pytest

from blackheart.authz import new_record
from blackheart.ingress import IngressConfig, IngressError, IngressServer
from blackheart.models import utcnow
from blackheart.scheduler import JobStore, Scheduler, SchedulerConfig
from blackheart.triggers import (
    TriggerLedger,
    TriggerPolicy,
    TriggerReceiver,
    TriggerState,
    WebhookTriggerSource,
)

SECRET = b"ingress-test-secret-abcdefghijklmnop"


# --------------------------------------------------------------------------- #
# Fixtures and helpers
# --------------------------------------------------------------------------- #

class FakeClock:
    def __init__(self, t: float = 1_700_000_000.0) -> None:
        self.t = t

    def __call__(self) -> float:
        return self.t

    def advance(self, s: float) -> None:
        self.t += s


def _authz(assets=("vault",)):
    rec = new_record(
        "ingress-program", "local", "http://localhost", "http://localhost/scope",
        program_active=True, safe_harbor=True, poc_required=True,
        nigerian_eligible=True, payout_feasible=True, zero_cost=True,
    )
    rec.asset_classes = {a: "AUTHORIZED" for a in assets}
    rec.verified = True
    rec.evidence = [{
        "kind": "scope-capture", "url": "http://localhost/scope",
        "retrieved_at": utcnow(), "sha256": "0" * 64,
    }]
    return rec


def _dt(clock: FakeClock):
    from datetime import datetime, timezone
    return datetime.fromtimestamp(clock.t, tz=timezone.utc)


def _build(tmp_path, *, with_scheduler=True, clock=None, **cfg):
    clock = clock or FakeClock()
    store = JobStore(tmp_path / "state")
    # The record is shared by the policy and the scheduler's live provider, so a
    # test can withdraw scope after acceptance and have both boundaries see it.
    record = _authz()
    sched = Scheduler(
        store,
        config=SchedulerConfig(clock=lambda: _dt(clock),
                               authz_provider=lambda asset: record),
        workdir=str(tmp_path / "work"),
    ) if with_scheduler else None
    ledger = TriggerLedger(tmp_path / "triggers")
    receiver = TriggerReceiver(
        ledger,
        TriggerPolicy(authz=record, max_accepted_per_window=500,
                      authz_provider=lambda asset: record),
        scheduler=sched, clock=clock,
    )
    source = WebhookTriggerSource(SECRET)
    config = IngressConfig(port=0, **cfg)
    server = IngressServer(receiver, source, config=config, clock=clock).start()
    return server, receiver, ledger, sched, source, clock


@pytest.fixture
def ingress(tmp_path):
    server, receiver, ledger, sched, source, clock = _build(tmp_path)
    try:
        yield server, receiver, ledger, sched, source, clock
    finally:
        server.stop(drain_timeout=2.0)


def _payload(**kw) -> bytes:
    p = {"kind": "hunt", "target": "access-control", "asset": "vault"}
    p.update(kw)
    return json.dumps(p).encode("utf-8")


def _post(server, body: bytes, *, headers=None, path="/trigger",
          content_type="application/json"):
    url = server.base_url + path
    hdrs = {"Content-Type": content_type}
    hdrs.update(headers or {})
    req = urllib.request.Request(url, data=body, headers=hdrs, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8") or "{}"
        try:
            return exc.code, json.loads(raw)
        except json.JSONDecodeError:
            return exc.code, {"raw": raw}


def _get(server, path):
    url = server.base_url + path
    try:
        with urllib.request.urlopen(url, timeout=10) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode("utf-8") or "{}")


def _signed(source, body, clock, delivery="d-1"):
    ts = int(clock.t)
    return {
        "X-Blackheart-Signature": source.expected_signature(str(ts), body),
        "X-Blackheart-Timestamp": str(ts),
        "X-Blackheart-Delivery": delivery,
    }


# --------------------------------------------------------------------------- #
# Real end-to-end: signed HTTP request -> real engine execution
# --------------------------------------------------------------------------- #

def test_signed_http_request_runs_real_research(tmp_path):
    """The whole chain over real HTTP: authenticate -> authorize -> durable job ->
    scheduler dispatch -> the real hunt engine runs -> honest final status."""
    server, receiver, ledger, sched, source, clock = _build(tmp_path)
    try:
        body = _payload(scope_reference="local://ingress", seed=3)
        status, resp = _post(server, body, headers=_signed(source, body, clock))
        assert status == 202, resp
        assert resp["state"] == TriggerState.ACCEPTED
        assert resp["created_job"] is True
        job_id = resp["job_id"]

        # 202 must NOT mean "research finished" -- the job is still pending.
        assert sched.store.get(job_id).state == "PENDING"

        # The real scheduler runs the real engine.
        done = sched.run_pending("worker-ingress")
        assert [j.job_id for j in done] == [job_id]
        job = sched.store.get(job_id)
        assert job.state in ("SUCCEEDED", "FAILED")   # the engine actually ran
        assert job.attempts == 1

        # Provenance: the job carries the delivery id; the trigger reports the truth.
        assert job.payload.get("delivery_id") == resp["delivery_id"]
        assert job.scope_reference == "local://ingress"
        receiver.sync_states()
        rec = ledger.get(resp["delivery_id"])
        assert rec.job_id == job_id
        assert rec.state == TriggerState.COMPLETED
        assert ledger.verify_integrity()["status"] == "VERIFIED"
    finally:
        server.stop(drain_timeout=2.0)


# --------------------------------------------------------------------------- #
# Authentication attacks
# --------------------------------------------------------------------------- #

def test_forged_signature_is_400_and_creates_no_job(ingress):
    server, receiver, ledger, sched, source, clock = ingress
    body = _payload()
    headers = _signed(source, body, clock)
    headers["X-Blackheart-Signature"] = "sha256=" + "0" * 64
    status, resp = _post(server, body, headers=headers)
    assert status == 400
    assert sched.store.all() == []


def test_missing_signature_is_rejected(ingress):
    server, receiver, ledger, sched, source, clock = ingress
    body = _payload()
    status, resp = _post(server, body, headers={"X-Blackheart-Delivery": "x"})
    assert status == 400
    assert sched.store.all() == []


def test_expired_timestamp_is_rejected(ingress):
    server, receiver, ledger, sched, source, clock = ingress
    body = _payload()
    old = int(clock.t) - 10_000
    headers = {
        "X-Blackheart-Signature": source.expected_signature(str(old), body),
        "X-Blackheart-Timestamp": str(old),
        "X-Blackheart-Delivery": "old",
    }
    status, resp = _post(server, body, headers=headers)
    assert status == 400
    assert sched.store.all() == []


def test_future_timestamp_is_rejected(ingress):
    server, receiver, ledger, sched, source, clock = ingress
    body = _payload()
    future = int(clock.t) + 10_000
    headers = {
        "X-Blackheart-Signature": source.expected_signature(str(future), body),
        "X-Blackheart-Timestamp": str(future),
        "X-Blackheart-Delivery": "future",
    }
    status, resp = _post(server, body, headers=headers)
    assert status == 400
    assert sched.store.all() == []


def test_signature_over_different_body_is_rejected(ingress):
    """A signature for body A must not authenticate body B (exact-bytes signing)."""
    server, receiver, ledger, sched, source, clock = ingress
    signed_body = _payload(seed=1)
    headers = _signed(source, signed_body, clock)
    tampered = _payload(seed=2)
    status, resp = _post(server, tampered, headers=headers)
    assert status == 400
    assert sched.store.all() == []


def test_replayed_delivery_id_creates_no_second_job(ingress):
    server, receiver, ledger, sched, source, clock = ingress
    body = _payload()
    headers = _signed(source, body, clock, delivery="replay-me")
    s1, r1 = _post(server, body, headers=headers)
    assert s1 == 202 and r1["created_job"] is True
    s2, r2 = _post(server, body, headers=headers)
    assert s2 == 200 and r2["state"] == TriggerState.DUPLICATE
    assert len(sched.store.all()) == 1


def test_concurrent_duplicate_http_deliveries_create_one_job(ingress):
    server, receiver, ledger, sched, source, clock = ingress
    body = _payload()
    ts = int(clock.t)
    sig = source.expected_signature(str(ts), body)
    results: list[int] = []
    lock = threading.Lock()

    def deliver(i):
        status, _ = _post(server, body, headers={
            "X-Blackheart-Signature": sig, "X-Blackheart-Timestamp": str(ts),
            "X-Blackheart-Delivery": f"conc-{i}",
        })
        with lock:
            results.append(status)

    threads = [threading.Thread(target=deliver, args=(i,)) for i in range(16)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(sched.store.all()) == 1
    assert results.count(202) == 1
    assert results.count(200) == 15


# --------------------------------------------------------------------------- #
# Transport-level attacks
# --------------------------------------------------------------------------- #

def test_wrong_content_type_is_415(ingress):
    server, receiver, ledger, sched, source, clock = ingress
    body = _payload()
    status, resp = _post(server, body, headers=_signed(source, body, clock),
                         content_type="text/plain")
    assert status == 415
    assert sched.store.all() == []


def test_json_content_type_with_charset_is_accepted(ingress):
    server, receiver, ledger, sched, source, clock = ingress
    body = _payload()
    status, resp = _post(server, body, headers=_signed(source, body, clock),
                         content_type="application/json; charset=utf-8")
    assert status == 202


def test_oversized_body_is_413(tmp_path):
    server, receiver, ledger, sched, source, clock = _build(
        tmp_path, max_body_bytes=512)
    try:
        body = _payload(note="x" * 4000)
        status, resp = _post(server, body, headers=_signed(source, body, clock))
        assert status == 413
        assert sched.store.all() == []
    finally:
        server.stop(drain_timeout=2.0)


def test_malformed_json_is_400(ingress):
    server, receiver, ledger, sched, source, clock = ingress
    body = b"{not json at all"
    status, resp = _post(server, body, headers=_signed(source, body, clock))
    assert status == 400
    assert sched.store.all() == []


def test_schema_violation_is_400(ingress):
    """An unknown field, or a payload that asserts its own authz, is refused."""
    server, receiver, ledger, sched, source, clock = ingress
    body = json.dumps({"kind": "hunt", "target": "access-control",
                       "asset": "vault", "authz": "AUTHORIZED"}).encode()
    status, resp = _post(server, body, headers=_signed(source, body, clock))
    assert status == 400
    assert sched.store.all() == []


def test_unauthorized_target_is_refused(ingress):
    """A valid signature is not target authorization: an out-of-scope asset is 403."""
    server, receiver, ledger, sched, source, clock = ingress
    body = _payload(asset="not-in-scope")
    status, resp = _post(server, body, headers=_signed(source, body, clock))
    assert status == 403
    assert sched.store.all() == []


def test_get_on_trigger_path_is_405(ingress):
    server, *_ = ingress
    status, resp = _get(server, "/trigger")
    assert status == 405


def test_unknown_path_is_404(ingress):
    server, *_ = ingress
    status, resp = _get(server, "/nope")
    assert status == 404


# --------------------------------------------------------------------------- #
# Health and readiness (and what they must NOT leak)
# --------------------------------------------------------------------------- #

def test_health_is_liveness_only(ingress):
    server, *_ = ingress
    status, body = _get(server, "/health")
    assert status == 200 and body["ok"] is True
    # No configuration, secret, evidence or job contents.
    blob = json.dumps(body).lower()
    for forbidden in ("secret", "authz", "evidence", "job", "asset"):
        assert forbidden not in blob


def test_readiness_reports_scheduler_attachment(tmp_path):
    server, receiver, ledger, sched, source, clock = _build(
        tmp_path, with_scheduler=False)
    try:
        status, body = _get(server, "/ready")
        assert status == 503 and body["ready"] is False
        assert body["scheduler_attached"] is False
    finally:
        server.stop(drain_timeout=2.0)


def test_readiness_true_when_scheduler_attached(ingress):
    server, *_ = ingress
    status, body = _get(server, "/ready")
    assert status == 200 and body["ready"] is True


# --------------------------------------------------------------------------- #
# Lifecycle: shutdown, restart recovery
# --------------------------------------------------------------------------- #

def test_shutdown_refuses_new_deliveries_and_closes(tmp_path):
    server, receiver, ledger, sched, source, clock = _build(tmp_path)
    body = _payload()
    s1, r1 = _post(server, body, headers=_signed(source, body, clock))
    assert s1 == 202
    server.stop(drain_timeout=2.0)
    assert server.is_serving() is False
    # The port is closed: a further request cannot connect.
    with pytest.raises((urllib.error.URLError, ConnectionError, socket.timeout)):
        _post(server, body, headers=_signed(source, body, clock))


def test_restart_recovers_pending_job_and_serves_again(tmp_path):
    """A job accepted over HTTP survives a full stop/start and still runs once."""
    clock = FakeClock()
    server, receiver, ledger, sched, source, _ = _build(tmp_path, clock=clock)
    body = _payload(seed=11)
    status, resp = _post(server, body, headers=_signed(source, body, clock))
    assert status == 202
    job_id = resp["job_id"]
    server.stop(drain_timeout=2.0)

    # Rebuild the whole stack over the same directories, as a real restart does.
    server2, receiver2, ledger2, sched2, source2, _ = _build(tmp_path, clock=clock)
    try:
        assert sched2.store.get(job_id).state == "PENDING"
        done = sched2.run_pending("worker-restart")
        assert [j.job_id for j in done] == [job_id]
        # The ledger survived intact across the restart.
        assert ledger2.verify_integrity()["status"] == "VERIFIED"
    finally:
        server2.stop(drain_timeout=2.0)


def test_ambiguous_response_does_not_duplicate_work(tmp_path):
    """If the client never sees the 202 (connection dropped), a resend is idempotent."""
    server, receiver, ledger, sched, source, clock = _build(tmp_path)
    try:
        body = _payload()
        headers = _signed(source, body, clock, delivery="ambiguous-1")
        # First delivery succeeds server-side.
        s1, r1 = _post(server, body, headers=headers)
        assert s1 == 202
        # Client "did not see it" and resends the identical signed request.
        s2, r2 = _post(server, body, headers=headers)
        assert s2 == 200 and r2["state"] == TriggerState.DUPLICATE
        assert r2["job_id"] == r1["job_id"]
        assert len(sched.store.all()) == 1
    finally:
        server.stop(drain_timeout=2.0)


# --------------------------------------------------------------------------- #
# Configuration validation
# --------------------------------------------------------------------------- #

def test_public_bind_requires_explicit_opt_in():
    with pytest.raises(IngressError):
        IngressConfig(host="0.0.0.0").validate()


def test_invalid_port_is_refused():
    with pytest.raises(IngressError):
        IngressConfig(port=99999).validate()


def test_secret_never_appears_in_error_bodies(ingress):
    server, receiver, ledger, sched, source, clock = ingress
    body = _payload()
    headers = _signed(source, body, clock)
    headers["X-Blackheart-Signature"] = "sha256=deadbeef"
    status, resp = _post(server, body, headers=headers)
    assert status == 400
    assert SECRET.decode() not in json.dumps(resp)


# --------------------------------------------------------------------------- #
# Scope change between HTTP acceptance and execution
# --------------------------------------------------------------------------- #

def test_scope_revoked_between_accept_and_execution_blocks_the_job(tmp_path):
    """A delivery accepted over HTTP must be re-authorized at execution time.

    The signature was valid and the asset was in scope when the job was created.
    Authorization is then withdrawn (scope changed). The scheduler must re-check the
    gate immediately before running and BLOCK the job rather than attack a target
    that is no longer authorized. This proves the HTTP layer did not become a
    one-time authorization bypass.
    """
    server, receiver, ledger, sched, source, clock = _build(tmp_path)
    try:
        body = _payload(asset="vault")
        status, resp = _post(server, body, headers=_signed(source, body, clock))
        assert status == 202
        job_id = resp["job_id"]
        assert sched.store.get(job_id).state == "PENDING"

        # Scope is withdrawn after acceptance: the asset is no longer AUTHORIZED.
        record = receiver.policy.authz
        record.asset_classes = {"vault": "OUT_OF_SCOPE"}
        record.verified = False

        sched.run_pending("worker-scope-change")
        job = sched.store.get(job_id)
        assert job.state == "BLOCKED", job.state
        # The trigger tells the truth: it did not claim the research completed.
        receiver.sync_states()
        assert ledger.get(resp["delivery_id"]).state != TriggerState.COMPLETED
    finally:
        server.stop(drain_timeout=2.0)


# --------------------------------------------------------------------------- #
# Operational: real subprocess serves, drains on SIGTERM, and recovers
# --------------------------------------------------------------------------- #

def test_cli_serve_subprocess_accepts_and_stops_gracefully(tmp_path):
    """Start the real ``blackheart ingress serve`` process, deliver over HTTP, and
    stop it with SIGTERM -- proving the CLI wiring, not just the library.

    A SIGTERM must drain and exit 0; the accepted job must survive the restart and
    still be PENDING on disk, ready for a scheduler to pick up.
    """
    import os
    import signal
    import subprocess
    import sys as _sys

    authz_path = tmp_path / "authz.json"
    authz_path.write_text(json.dumps(_authz().to_dict()), encoding="utf-8")
    port = _free_port()
    env = dict(os.environ)
    env["BLACKHEART_TRIGGER_SECRET"] = SECRET.decode()
    proc = subprocess.Popen(
        [_sys.executable, "-m", "blackheart", "ingress",
         "--dir", str(tmp_path / "state"), "--authz", str(authz_path),
         "--port", str(port), "serve"],
        cwd=str(_repo_root()), env=env,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )
    try:
        _wait_until_listening(port, proc)
        body = _payload(seed=99)
        ts = int(time.time())
        status, resp = _post_url(
            f"http://127.0.0.1:{port}/trigger", body,
            {"Content-Type": "application/json",
             "X-Blackheart-Signature": _sig(SECRET, ts, body),
             "X-Blackheart-Timestamp": str(ts),
             "X-Blackheart-Delivery": "subproc-1"},
        )
        assert status == 202, resp
        job_id = resp["job_id"]
    finally:
        proc.send_signal(signal.SIGTERM)
        try:
            rc = proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            proc.kill()
            raise
    assert rc == 0

    # The accepted job survived the process exit and is still runnable.
    store = JobStore(tmp_path / "state")
    job = store.get(job_id)
    assert job is not None and job.state == "PENDING"


def _repo_root():
    from pathlib import Path
    return Path(__file__).resolve().parent.parent


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_until_listening(port: int, proc, timeout: float = 20.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if proc.poll() is not None:
            raise AssertionError(f"server exited early: {proc.stdout.read()}")
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=1):
                return
        except (urllib.error.URLError, ConnectionError):
            time.sleep(0.1)
    raise AssertionError("server did not start listening")


def _sig(secret: bytes, ts: int, body: bytes) -> str:
    import hashlib
    import hmac
    return "sha256=" + hmac.new(secret, str(ts).encode() + b"." + body,
                                hashlib.sha256).hexdigest()


def _post_url(url, body, headers):
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode("utf-8") or "{}")


# --------------------------------------------------------------------------- #
# Request-smuggling / desync: a rejection that does not read the body must close
# --------------------------------------------------------------------------- #

def test_undrained_rejection_closes_connection_instead_of_desyncing(ingress):
    """A 415 is sent before the body is read. If the connection stayed open, the
    unread body would be parsed as the next request on a keep-alive socket -- a
    classic request-smuggling desync. The server must answer ``Connection: close``
    and drop the socket, so the next request is a *fresh* one.

    A regression here shows up as the second request being answered with 501 (the
    stdlib default handler, i.e. the leftover body was parsed as a request line).
    """
    import http.client

    server, receiver, ledger, sched, source, clock = ingress
    conn = http.client.HTTPConnection("127.0.0.1", server.port, timeout=5)
    body = _payload()
    try:
        conn.request("POST", "/trigger", body=body,
                     headers={"Content-Type": "text/plain"})
        first = conn.getresponse()
        assert first.status == 415
        assert first.getheader("Connection", "").lower() == "close"
        first.read()

        # http.client transparently reconnects because of Connection: close, so
        # this is a genuinely new request -- unsigned, and therefore a clean 400,
        # never a 501 from a desynchronised socket.
        conn.request("POST", "/trigger", body=body,
                     headers={"Content-Type": "application/json"})
        second = conn.getresponse()
        assert second.status == 400, second.read()
    finally:
        conn.close()


def test_oversized_body_rejection_closes_connection(tmp_path):
    import http.client

    server, receiver, ledger, sched, source, clock = _build(
        tmp_path, max_body_bytes=256)
    try:
        conn = http.client.HTTPConnection("127.0.0.1", server.port, timeout=5)
        try:
            conn.request("POST", "/trigger", body=b"x" * 4096,
                         headers={"Content-Type": "application/json"})
            resp = conn.getresponse()
            assert resp.status == 413
            assert resp.getheader("Connection", "").lower() == "close"
        finally:
            conn.close()
    finally:
        server.stop(drain_timeout=2.0)


# --------------------------------------------------------------------------- #
# Slow-loris / resource exhaustion: the listener must bound concurrency
# --------------------------------------------------------------------------- #

def test_connection_cap_refuses_excess_connections(tmp_path):
    """Open more raw sockets than the cap allows and hold them. Each accepted
    connection occupies a thread; the server must refuse beyond the cap with 503
    instead of spawning unbounded threads (a slow-loris DoS otherwise)."""
    server, receiver, ledger, sched, source, clock = _build(
        tmp_path, max_concurrent_connections=2)
    held: list[socket.socket] = []
    try:
        refused = 0
        for _ in range(6):
            s = socket.create_connection(("127.0.0.1", server.port), timeout=2)
            # Send a partial request line and stall: this holds a worker thread.
            s.sendall(b"GET /health HTTP/1.1\r\nHost: x\r\n")
            held.append(s)
        time.sleep(0.4)
        # Read whatever each socket got; some must carry a 503.
        for s in held:
            s.settimeout(0.5)
            try:
                data = s.recv(200)
            except (socket.timeout, ConnectionError):
                continue
            if b"503" in data:
                refused += 1
        assert refused >= 1, "server never refused an excess connection"
    finally:
        for s in held:
            try:
                s.close()
            except OSError:
                pass
        server.stop(drain_timeout=2.0)


# --------------------------------------------------------------------------- #
# Framing ambiguity: pipelining and transfer codings cannot desync the socket
# --------------------------------------------------------------------------- #

def _raw_exchange(port: int, request: bytes, *, wait: float = 0.4) -> bytes:
    """Send raw bytes, read until the peer closes, return everything received."""
    s = socket.create_connection(("127.0.0.1", port), timeout=3)
    try:
        s.sendall(request)
        time.sleep(wait)
        data = b""
        s.settimeout(1.5)
        try:
            while True:
                chunk = s.recv(65536)
                if not chunk:
                    break
                data += chunk
        except (socket.timeout, ConnectionError):
            pass
        return data
    finally:
        try:
            s.close()
        except OSError:
            pass


def test_get_with_a_body_cannot_smuggle_a_second_request(tmp_path):
    """A GET carrying a body used to leave those bytes on the socket, which were
    then parsed as the next request ('HELLOGET ...' -> 501). Every response now
    closes, so the socket carries exactly one response and the pipelined bytes are
    never interpreted."""
    server, *_ = _build(tmp_path)
    try:
        req = (b"GET /trigger HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nHELLO"
               b"GET /health HTTP/1.1\r\nHost: x\r\n\r\n")
        out = _raw_exchange(server.port, req)
        assert out.count(b"HTTP/1.1") == 1, out
        assert b'"serving"' not in out, "a smuggled /health request was served"
    finally:
        server.stop(drain_timeout=2.0)


def test_trailing_bytes_after_a_signed_post_are_not_parsed_as_a_request(tmp_path):
    """The realistic smuggling case: a *valid* signed delivery whose declared
    Content-Length is shorter than the bytes sent. The leftover bytes must not be
    parsed as a second request."""
    import time as _time

    server, receiver, ledger, sched, source, clock = _build(tmp_path)
    try:
        body = _payload()
        ts = str(int(_time.time()))
        sig = source.expected_signature(ts, body)
        smuggled = b"GET /health HTTP/1.1\r\nHost: x\r\n\r\n"
        req = (
            b"POST /trigger HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n"
            b"X-Blackheart-Signature: " + sig.encode() + b"\r\n"
            b"X-Blackheart-Timestamp: " + ts.encode() + b"\r\n"
            b"X-Blackheart-Delivery: d-smuggle\r\n"
            b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n"
            + body + smuggled
        )
        out = _raw_exchange(server.port, req)
        assert out.count(b"HTTP/1.1") == 1, out
        assert b'"serving"' not in out, "trailing bytes were parsed as a request"
        assert b"Connection: close" in out
    finally:
        server.stop(drain_timeout=2.0)


def test_transfer_encoding_is_rejected(tmp_path):
    """A body framed with Transfer-Encoding is a CL.TE/TE.CL ambiguity; the server
    reads a fixed Content-Length only, so it must refuse the coding outright."""
    server, *_ = _build(tmp_path)
    try:
        req = (b"POST /trigger HTTP/1.1\r\nHost: x\r\n"
               b"Content-Type: application/json\r\n"
               b"Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n")
        out = _raw_exchange(server.port, req)
        assert out.split(b"\r\n", 1)[0] == b"HTTP/1.1 400 Bad Request", out
        assert b"Transfer-Encoding" in out
        assert out.count(b"HTTP/1.1") == 1
    finally:
        server.stop(drain_timeout=2.0)


def test_every_response_closes_the_connection(tmp_path):
    """The desync class is removed by construction: no response keeps the socket
    alive, so pipelined bytes can never become a request."""
    import http.client

    server, *_ = _build(tmp_path)
    try:
        conn = http.client.HTTPConnection("127.0.0.1", server.port, timeout=5)
        try:
            conn.request("GET", "/health")
            resp = conn.getresponse()
            assert resp.status == 200
            assert resp.getheader("Connection", "").lower() == "close"
            resp.read()
        finally:
            conn.close()
    finally:
        server.stop(drain_timeout=2.0)


def test_header_phase_slow_loris_is_closed_by_the_connection_timeout(tmp_path):
    """A client that opens a connection and never finishes the request line/headers
    used to hold a worker thread forever: the timeout was applied only around the
    body read, not during ``rfile.readline`` for the headers. The socket must be
    bounded for the whole request, so the server closes it after
    ``request_timeout`` seconds."""
    import time as _time

    server, *_ = _build(tmp_path, request_timeout=0.4)
    try:
        s = socket.create_connection(("127.0.0.1", server.port), timeout=3)
        try:
            s.sendall(b"POST /trigger HTTP/1.1\r\n")  # stall mid-headers
            t0 = _time.monotonic()
            s.settimeout(3)
            data = b""
            try:
                data = s.recv(200)
            except socket.timeout:
                pass
            elapsed = _time.monotonic() - t0
            assert data == b"", f"server did not close the stalled socket: {data!r}"
            assert elapsed < 2.0, f"timeout not applied during header read ({elapsed:.2f}s)"
        finally:
            s.close()
    finally:
        server.stop(drain_timeout=2.0)
