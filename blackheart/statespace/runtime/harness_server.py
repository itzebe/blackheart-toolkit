"""A loopback HTTP server that runs a harness application.

The server exposes a tiny, uniform protocol over a
:class:`~blackheart.statespace.runtime.harness_apps` app so the HTTP execution
adapter can drive it:

  * ``GET  /health``  -> ``{"ok": true}``
  * ``GET  /state``   -> ``{"state": <observed state>}``
  * ``POST /reset``   -> return the app to its known initial state
  * ``POST /<op>``    -> dispatch operation ``<op>`` for the caller identity

The caller identity is taken from the ``X-Blackheart-Actor`` header; the server
enforces the operation's declared roles at the boundary (an actor whose roles do
not permit the operation gets 403). The app's own handlers enforce the
application-level authorization (grants, ownership) -- that is where the flaws
live, and the server must not paper over them.

The server binds to ``127.0.0.1`` only. It is standard-library only and is started
by the evaluation harness; it is never started implicitly by the engine.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Optional

from .harness_apps import AppInvariant, Op, make_app


class HarnessServer:
    """Serve one harness app on a loopback port; drive it from a test/benchmark."""

    def __init__(self, app_name: str, host: str = "127.0.0.1", port: int = 0) -> None:
        self.app = make_app(app_name)
        self.host = host
        self.port = port
        self._state: dict = self.app.initial_state()
        self._lock = threading.Lock()
        self._ops: dict[str, Op] = {op.name: op for op in self.app.ops()}
        self._httpd: Optional[ThreadingHTTPServer] = None
        self._thread: Optional[threading.Thread] = None

    # -- lifecycle ------------------------------------------------------- #

    def start(self) -> "HarnessServer":
        handler = self._make_handler()
        self._httpd = ThreadingHTTPServer((self.host, self.port), handler)
        self._httpd.daemon_threads = True
        self.port = self._httpd.server_address[1]
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        if self._httpd is not None:
            self._httpd.shutdown()
            self._httpd.server_close()
            self._httpd = None

    def __enter__(self):
        return self.start()

    def __exit__(self, *exc) -> None:
        self.stop()

    @property
    def base_url(self) -> str:
        return f"http://{self.host}:{self.port}"

    def identities(self) -> dict[str, dict[str, str]]:
        return {a: {"X-Blackheart-Actor": a} for a in self.app.roles()}

    def invariants(self) -> list[AppInvariant]:
        return self.app.invariants()

    def snapshot(self) -> dict:
        with self._lock:
            return self.app.snapshot(self._state)

    # -- request handling ------------------------------------------------ #

    def _make_handler(self):
        server = self

        class _Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *args):  # keep test output clean
                pass

            def _send(self, status: int, body: dict) -> None:
                data = json.dumps(body).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def _read_params(self) -> dict:
                length = int(self.headers.get("Content-Length", "0") or 0)
                if not length:
                    return {}
                raw = self.rfile.read(length)
                try:
                    return json.loads(raw.decode("utf-8")) or {}
                except (ValueError, UnicodeDecodeError):
                    return {}

            def do_GET(self):  # noqa: N802
                path = self.path.split("?", 1)[0]
                if path == "/health":
                    return self._send(200, {"ok": True, "app": server.app.name})
                if path == "/state":
                    return self._send(200, {"state": server.snapshot()})
                return self._send(404, {"error": "not found"})

            def do_POST(self):  # noqa: N802
                path = self.path.split("?", 1)[0].lstrip("/")
                actor = self.headers.get("X-Blackheart-Actor", "")
                if path == "reset":
                    with server._lock:
                        server._state = server.app.initial_state()
                    return self._send(200, {"reset": True})
                op = server._ops.get(path)
                if op is None:
                    return self._send(404, {"error": f"unknown operation {path!r}"})
                # boundary role check
                actor_roles = server.app.roles().get(actor, ())
                if op.roles and not (set(op.roles) & set(actor_roles)):
                    return self._send(403, {"error": "role not permitted"})
                params = self._read_params()
                with server._lock:
                    try:
                        status, body = op.handler(server._state, actor, params)
                    except Exception as exc:  # a handler fault is a 500, recorded as evidence
                        return self._send(500, {"error": f"{type(exc).__name__}: {exc}"})
                return self._send(status, body)

        return _Handler


def serve(app_name: str, host: str = "127.0.0.1", port: int = 0) -> HarnessServer:
    return HarnessServer(app_name, host=host, port=port).start()
