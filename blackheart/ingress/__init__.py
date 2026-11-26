"""Authenticated live HTTP ingress: a real listener in front of the trigger receiver.

This is transport only. It parses an HTTP request into ``(raw body, headers)`` and
hands it to the *existing* :class:`~blackheart.triggers.TriggerReceiver`, which
owns authentication, dedupe, rate limiting, authorization and job creation. The
ingress therefore adds no second execution path and cannot bypass a gate -- the
receiver's gate order is unchanged, and the scheduler it already holds does the
dispatch. Read :mod:`blackheart.triggers` for the security model; this module only
guarantees that a hostile HTTP request cannot get past the receiver or exhaust the
process before the receiver ever sees it.

What the transport itself enforces (each tested in ``tests/test_ingress.py``):

  * **Body cap before allocation.** ``Content-Length`` is rejected outright when it
    exceeds the cap, and the socket read is bounded so a lying or absent
    ``Content-Length`` cannot stream an unbounded body into memory.
  * **Content type.** ``application/json`` (optionally with ``; charset=...``) is
    required; anything else is 415 and never reaches the receiver.
  * **Method and path.** Only ``POST /trigger`` (and ``GET /health``,
    ``GET /ready``) exist; everything else is 404/405 with an ``Allow`` header.
  * **Timeouts.** A per-connection socket timeout closes a stalled or slow-loris
    client without holding a worker thread forever.
  * **Honest status codes.** ``202 Accepted`` means *the receiver accepted the
    delivery and a durable job exists* -- it never implies the research ran.
    A rejected delivery is ``400``/``403`` as appropriate, and a duplicate is
    ``200`` with ``state=DUPLICATE`` (idempotent success, no new job).
  * **No secrets in responses or logs.** Error bodies carry the receiver's safe
    reason; the structured log records method, path, status, delivery id and
    duration -- never the body, the signature, or the secret.
  * **Readiness is separate from liveness.** ``/ready`` reports whether the
    scheduler is attached (so a delivery would be dispatched); ``/health`` is
    liveness only. Neither exposes configuration, evidence, or job contents.

Authorization is still the receiver's: a valid HMAC signature proves *who sent*
the request, never *that the target may be attacked*. The receiver re-checks
:func:`blackheart.authz.authorize_active_testing` against its configured record,
and the scheduler re-checks it again at claim and execution time.

Standard library only. Binds loopback by default; a non-loopback bind is allowed
but is the operator's explicit choice (and TLS/proxying is theirs to terminate).
"""

from __future__ import annotations

import json
import logging
import socket
import sys
import threading
import time
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Callable, Optional

from ..triggers import (
    TriggerDispatch,
    TriggerError,
    TriggerReceiver,
    TriggerState,
    WebhookTriggerSource,
)

__all__ = [
    "IngressConfig",
    "IngressServer",
    "IngressError",
    "STATUS_FOR_STATE",
]

log = logging.getLogger("blackheart.ingress")

#: The receiver state -> HTTP status. 202 is the honest "accepted, work queued"
#: answer: a 200/201 would imply the research finished, and it has not.
STATUS_FOR_STATE: dict[str, int] = {
    TriggerState.ACCEPTED: 202,
    TriggerState.AUTHENTICATED: 202,   # authenticated but no scheduler attached
    TriggerState.DUPLICATE: 200,       # idempotent: no new job, not an error
    TriggerState.REJECTED: 403,        # gate failed (signature/timestamp/scope/rate)
}

#: Reasons that are really *client* errors, not authorization failures.
_CLIENT_ERROR_HINTS = (
    "signature", "timestamp", "body", "payload", "json", "content",
    "too large", "header", "field", "kind",
)


class IngressError(RuntimeError):
    """A configuration or lifecycle error. Safe to show; never contains a secret."""


@dataclass
class IngressConfig:
    """Everything the listener needs. Validated at construction, not at request time."""

    host: str = "127.0.0.1"
    port: int = 8787
    #: Hard cap on the request body. The receiver also enforces one; this is the
    #: earlier, cheaper gate that protects the process before parsing.
    max_body_bytes: int = 64 * 1024
    #: Socket timeout for a single connection, in seconds (slow-loris defence).
    request_timeout: float = 15.0
    #: Path that accepts a signed delivery.
    trigger_path: str = "/trigger"
    #: Refuse to start on a non-loopback interface unless the operator opts in.
    allow_public_bind: bool = False
    #: Require ``application/json`` on the delivery endpoint.
    require_json_content_type: bool = True
    #: Maximum concurrent connections served at once. ``ThreadingHTTPServer``
    #: spawns one thread per connection with no ceiling, so without this a
    #: slow-loris opens sockets until the process runs out of threads/memory. A
    #: connection beyond the cap is refused with 503 rather than accepted.
    max_concurrent_connections: int = 128

    def validate(self) -> None:
        if not isinstance(self.port, int) or not (0 <= self.port <= 65535):
            raise IngressError(f"port must be 0..65535, got {self.port!r}")
        if self.max_body_bytes <= 0:
            raise IngressError("max_body_bytes must be positive")
        if self.request_timeout <= 0:
            raise IngressError("request_timeout must be positive")
        if self.max_concurrent_connections <= 0:
            raise IngressError("max_concurrent_connections must be positive")
        if not self.trigger_path.startswith("/"):
            raise IngressError("trigger_path must start with '/'")
        loopback = self.host in ("127.0.0.1", "localhost", "::1")
        if not loopback and not self.allow_public_bind:
            raise IngressError(
                f"refusing to bind non-loopback host {self.host!r} without "
                "allow_public_bind=True; terminate TLS and authentication in front "
                "of a public listener"
            )


def _is_json_content_type(value: str) -> bool:
    """Accept ``application/json`` with optional parameters (e.g. ``; charset=utf-8``).

    Anything else -- including a bare ``text/plain`` smuggling JSON, or a missing
    type -- is refused so the receiver is never fed a body the client did not
    declare as JSON.
    """
    if not value:
        return False
    main = value.split(";", 1)[0].strip().lower()
    return main == "application/json"


class _BoundedThreadingHTTPServer(ThreadingHTTPServer):
    """``ThreadingHTTPServer`` with a hard ceiling on concurrent connections.

    The stdlib server spawns an unbounded thread per accepted connection, so a
    client that opens many half-open sockets (slow loris) can exhaust the process.
    This refuses a connection past the cap -- it closes it immediately with a 503
    instead of spawning a thread for it -- which bounds memory and threads.
    """

    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, addr, handler, *, max_connections: int):
        self._max_connections = max_connections
        self._active = 0
        self._active_lock = threading.Lock()
        super().__init__(addr, handler)

    def process_request(self, request, client_address):
        with self._active_lock:
            if self._active >= self._max_connections:
                over = True
            else:
                over = False
                self._active += 1
        if over:
            # Refuse without spawning a thread. Write a minimal 503 and close.
            try:
                request.settimeout(1.0)
                body = b'{"error": "too many connections"}'
                request.sendall(
                    b"HTTP/1.1 503 Service Unavailable\r\n"
                    b"Content-Type: application/json\r\n"
                    b"Content-Length: " + str(len(body)).encode() + b"\r\n"
                    b"Connection: close\r\n\r\n" + body
                )
            except OSError:
                pass
            finally:
                self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            with self._active_lock:
                self._active -= 1
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            with self._active_lock:
                self._active -= 1

    def handle_error(self, request, client_address):
        """Log a handler failure in the structured form instead of dumping a
        traceback to stderr. A client that disconnects mid-response is routine
        (``ConnectionResetError``/``BrokenPipeError``) and is not an error; anything
        else is logged by type so it is visible without leaking the request body.
        """
        exc = sys.exc_info()[1]
        if isinstance(exc, (ConnectionResetError, BrokenPipeError, TimeoutError)):
            return
        log.error(json.dumps({
            "event": "ingress_handler_error",
            "client": client_address[0] if client_address else "?",
            "error": type(exc).__name__ if exc else "unknown",
        }))


class IngressServer:
    """A real ``ThreadingHTTPServer`` that drives one :class:`TriggerReceiver`.

    Lifecycle is explicit: :meth:`start` binds and serves, :meth:`stop` drains and
    closes. The handler closes over this instance, so the receiver and its ledger
    are the only stateful things -- restart recovery is the receiver's (it replays
    the ledger), not the transport's.
    """

    def __init__(
        self, receiver: TriggerReceiver, source: WebhookTriggerSource,
        *, config: Optional[IngressConfig] = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.receiver = receiver
        self.source = source
        self.config = config or IngressConfig()
        self.config.validate()
        self.clock = clock
        self._httpd: Optional[ThreadingHTTPServer] = None
        self._thread: Optional[threading.Thread] = None
        self._in_flight = 0
        self._in_flight_lock = threading.Lock()
        self._stopping = threading.Event()
        self._started_at = 0.0

    # -- lifecycle ------------------------------------------------------- #
    def start(self) -> "IngressServer":
        handler = self._make_handler()
        self._httpd = _BoundedThreadingHTTPServer(
            (self.config.host, self.config.port), handler,
            max_connections=self.config.max_concurrent_connections,
        )
        self.config.port = self._httpd.server_address[1]
        self._started_at = self.clock()
        self._thread = threading.Thread(
            target=self._httpd.serve_forever, kwargs={"poll_interval": 0.2},
            name="blackheart-ingress", daemon=True,
        )
        self._thread.start()
        log.info(json.dumps({
            "event": "ingress_started", "host": self.config.host,
            "port": self.config.port, "trigger_path": self.config.trigger_path,
        }))
        return self

    def stop(self, *, drain_timeout: float = 10.0) -> None:
        """Stop accepting, wait (bounded) for in-flight deliveries, then close."""
        self._stopping.set()
        if self._httpd is not None:
            self._httpd.shutdown()
            self._httpd.server_close()
            self._httpd = None
        if self._thread is not None:
            self._thread.join(timeout=drain_timeout)
            self._thread = None
        deadline = time.monotonic() + drain_timeout
        while time.monotonic() < deadline:
            with self._in_flight_lock:
                if self._in_flight == 0:
                    break
            time.sleep(0.01)
        log.info(json.dumps({"event": "ingress_stopped", "port": self.config.port}))

    def __enter__(self) -> "IngressServer":
        return self.start()

    def __exit__(self, *exc) -> None:
        self.stop()

    @property
    def port(self) -> int:
        return self.config.port

    @property
    def base_url(self) -> str:
        host = self.config.host
        if ":" in host:  # IPv6 literal
            host = f"[{host}]"
        return f"http://{host}:{self.config.port}"

    def is_serving(self) -> bool:
        return self._httpd is not None

    # -- observability (never leaks configuration or evidence) ----------- #
    def health(self) -> dict:
        return {
            "ok": True,
            "serving": self.is_serving(),
            "uptime_seconds": round(self.clock() - self._started_at, 3)
            if self._started_at else 0.0,
        }

    def readiness(self) -> dict:
        """Ready only if a delivery would actually be dispatched.

        A receiver with no scheduler authenticates and records but cannot run work,
        so it is *not* ready -- reporting otherwise would let a caller believe a
        job will execute when it will not.
        """
        ready = self.is_serving() and self.receiver.scheduler is not None
        return {
            "ready": ready,
            "scheduler_attached": self.receiver.scheduler is not None,
            "stopping": self._stopping.is_set(),
        }

    # -- request handling ------------------------------------------------ #
    def _make_handler(self):
        server = self

        class _Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"
            server_version = "blackheart-ingress"
            sys_version = ""

            def log_message(self, *args):  # we emit structured logs ourselves
                pass

            def setup(self):
                # Bound the socket for the *whole* request, not just the body read.
                # ``rfile.readline`` for the request line and headers would otherwise
                # block forever on a client that opens a connection and sends
                # nothing (or a partial header block) -- the header-phase
                # slow-loris. Setting it here covers every read and write.
                super().setup()
                try:
                    self.connection.settimeout(server.config.request_timeout)
                except OSError:
                    pass

            # -- helpers ------------------------------------------------ #
            def _send_json(self, status: int, body: dict,
                           extra_headers: Optional[dict] = None,
                           *, close: bool = True) -> None:
                data = json.dumps(body).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.send_header("X-Content-Type-Options", "nosniff")
                if close:
                    # A response sent without draining the request body leaves the
                    # socket out of sync: the next bytes on a keep-alive connection
                    # would be parsed as a new request. Closing is the only safe
                    # answer when the body was not read. Every response closes: a
                    # webhook ingress gains nothing from keep-alive, and refusing to
                    # pipeline requests removes the whole desync class by
                    # construction rather than auditing each early return.
                    self.close_connection = True
                    self.send_header("Connection", "close")
                for k, v in (extra_headers or {}).items():
                    self.send_header(k, v)
                self.end_headers()
                try:
                    self.wfile.write(data)
                except (BrokenPipeError, ConnectionResetError):
                    pass

            def _client_ip(self) -> str:
                return self.client_address[0] if self.client_address else "?"

            def _log(self, status: int, started: float, **extra) -> None:
                # Never log the body, the signature, or the secret.
                payload = {
                    "event": "ingress_request", "method": self.command,
                    "path": self.path.split("?", 1)[0], "status": status,
                    "client": self._client_ip(),
                    "duration_ms": round((server.clock() - started) * 1000, 2),
                }
                payload.update(extra)
                log.info(json.dumps(payload))

            # -- GET: liveness / readiness only ------------------------- #
            def do_GET(self):  # noqa: N802 (http.server API)
                started = server.clock()
                path = self.path.split("?", 1)[0]
                if path == "/health":
                    self._send_json(200, server.health())
                    self._log(200, started)
                    return
                if path == "/ready":
                    body = server.readiness()
                    self._send_json(200 if body["ready"] else 503, body)
                    self._log(200 if body["ready"] else 503, started)
                    return
                if path == server.config.trigger_path:
                    self._send_json(405, {"error": "use POST"}, {"Allow": "POST"})
                    self._log(405, started)
                    return
                self._send_json(404, {"error": "not found"})
                self._log(404, started)

            def do_POST(self):  # noqa: N802
                started = server.clock()
                path = self.path.split("?", 1)[0]
                if path != server.config.trigger_path:
                    # The request body was not read; close so the socket cannot be
                    # desynchronised by the leftover bytes.
                    self._send_json(404, {"error": "not found"}, close=True)
                    self._log(404, started)
                    return
                if server._stopping.is_set():
                    self._send_json(503, {"error": "server is shutting down"},
                                    {"Retry-After": "1"}, close=True)
                    self._log(503, started)
                    return
                self._handle_delivery(started)

            def _handle_delivery(self, started: float) -> None:
                cfg = server.config
                # 0. Framing. The body is read with a fixed Content-Length, so any
                # transfer coding is a framing ambiguity we refuse outright. A
                # request carrying both Content-Length and Transfer-Encoding is the
                # classic CL.TE/TE.CL smuggling vector: two hops can disagree about
                # where the body ends, and the bytes left over become a second
                # request. Rejecting it here is stricter than trying to reconcile it.
                if self.headers.get("Transfer-Encoding"):
                    self._send_json(400, {"error": "Transfer-Encoding is not supported; "
                                                   "send Content-Length"},
                                    close=True)
                    self._log(400, started, reason="transfer_encoding")
                    return

                # 1. Content type.
                ctype = self.headers.get("Content-Type", "")
                if cfg.require_json_content_type and not _is_json_content_type(ctype):
                    self._send_json(415, {"error": "Content-Type must be application/json"},
                                    close=True)
                    self._log(415, started, reason="content_type")
                    return

                # 2. Body size, before reading a single body byte.
                raw_len = self.headers.get("Content-Length")
                if raw_len is None:
                    # A body without a length is not something we can bound safely.
                    self._send_json(411, {"error": "Content-Length required"},
                                    close=True)
                    self._log(411, started, reason="no_content_length")
                    return
                try:
                    length = int(raw_len)
                except ValueError:
                    self._send_json(400, {"error": "invalid Content-Length"},
                                    close=True)
                    self._log(400, started, reason="bad_content_length")
                    return
                if length < 0 or length > cfg.max_body_bytes:
                    self._send_json(
                        413, {"error": f"body exceeds {cfg.max_body_bytes} bytes"},
                        close=True,
                    )
                    self._log(413, started, reason="body_too_large")
                    return

                # 3. Bounded read. rfile is wrapped with the socket timeout set
                # below, so a client that stalls mid-body cannot hold the thread.
                try:
                    self.connection.settimeout(cfg.request_timeout)
                    body = self.rfile.read(length)
                except socket.timeout:
                    self._send_json(408, {"error": "request timeout"}, close=True)
                    self._log(408, started, reason="timeout")
                    return
                except (ConnectionResetError, BrokenPipeError):
                    self._log(499, started, reason="client_closed")
                    return
                if len(body) != length:
                    self._send_json(400, {"error": "incomplete body"})
                    self._log(400, started, reason="short_body")
                    return

                # 4. Hand the exact bytes to the receiver. Headers are copied to a
                # plain dict so the receiver cannot reach back into the socket.
                headers = {k: v for k, v in self.headers.items()}
                with server._in_flight_lock:
                    server._in_flight += 1
                try:
                    dispatch = server.receiver.handle(server.source, body, headers)
                except TriggerError as exc:  # defensive: a source may raise directly
                    self._send_json(400, {"error": str(exc)})
                    self._log(400, started, reason="trigger_error")
                    return
                finally:
                    with server._in_flight_lock:
                        server._in_flight -= 1

                status = self._status_for(dispatch)
                extra = {"X-Blackheart-Delivery": dispatch.delivery_id} \
                    if dispatch.delivery_id else None
                self._send_json(status, dispatch.to_dict(), extra)
                self._log(status, started, delivery=dispatch.delivery_id,
                          state=dispatch.state)

            def _status_for(self, dispatch: TriggerDispatch) -> int:
                if dispatch.state == TriggerState.REJECTED:
                    reason = (dispatch.reason or "").lower()
                    if any(h in reason for h in _CLIENT_ERROR_HINTS):
                        return 400
                    return 403
                return STATUS_FOR_STATE.get(dispatch.state, 500)

        return _Handler
