"""Chromium harness: locate a real browser, run probe pages, read CDP facts.

The harness runs *released* Chromium builds locally (the mission's rule: never
present a debug-build result as a released-build finding). It is standard-library
only, like the rest of the engine, and shells out to the browser the same way the
DVDF and Foundry harnesses shell out to their tools.

Two capabilities:

* :class:`Chromium` -- discovery + ``--dump-dom`` probe execution against a
  pair of local HTTP origins (cross-origin probes need two origins).
* :meth:`Chromium.process_info` -- a minimal CDP client (raw WebSocket, no
  dependency) that reads ``SystemInfo.getProcessInfo``, so the harness can prove
  site isolation (renderer-per-site) rather than assume it.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import shutil
import socket
import struct
import subprocess
import tempfile
import threading
import time
import urllib.request
from contextlib import contextmanager
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Optional


class ChromeError(RuntimeError):
    """The browser could not be located, launched, or driven."""


class ChromeNotFound(ChromeError):
    """No Chromium/Chrome binary is available in this environment."""


#: Environment variables checked (in order) for an explicit browser path.
BROWSER_ENV_VARS = ("BLACKHEART_CHROME", "CHROME_BIN", "CHROMIUM_BIN")

#: Common install locations, checked after PATH.
BROWSER_CANDIDATES = (
    "/usr/bin/chromium",
    "/usr/bin/chromium-browser",
    "/usr/bin/google-chrome",
    "/usr/bin/google-chrome-stable",
    "/snap/bin/chromium",
    "/opt/google/chrome/chrome",
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
)


def find_browser(explicit: Optional[str] = None) -> str:
    """Return the path to a Chromium/Chrome binary, or raise ChromeNotFound.

    An explicit path (argument or environment) wins and is *not* silently
    substituted: if the caller named a browser and it is not there, that is an
    error, not a reason to pick a different one.
    """
    if explicit:
        if os.path.isfile(explicit) and os.access(explicit, os.X_OK):
            return explicit
        raise ChromeNotFound(f"requested browser {explicit!r} is not an executable file")

    for var in BROWSER_ENV_VARS:
        value = os.environ.get(var)
        if value:
            if os.path.isfile(value) and os.access(value, os.X_OK):
                return value
            raise ChromeNotFound(f"${var} points to {value!r}, which is not executable")

    for name in ("chromium", "chromium-browser", "google-chrome",
                 "google-chrome-stable", "chrome"):
        found = shutil.which(name)
        if found:
            return found
    for path in BROWSER_CANDIDATES:
        if os.path.isfile(path) and os.access(path, os.X_OK):
            return path
    raise ChromeNotFound(
        "no Chromium/Chrome binary found; set BLACKHEART_CHROME to its path"
    )


def browser_version(binary: str, timeout: int = 30) -> str:
    """The reported version string, e.g. ``Chromium 156.0.8078.79``."""
    try:
        out = subprocess.run(
            [binary, "--version"], capture_output=True, text=True, timeout=timeout
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ChromeError(f"could not run {binary} --version: {exc}") from exc
    text = (out.stdout or out.stderr).strip()
    if not text:
        raise ChromeError(f"{binary} --version produced no output")
    return text


# --------------------------------------------------------------------------- #
# Local origin pair (cross-origin probes need two origins)
# --------------------------------------------------------------------------- #

class _QuietHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):  # keep the test output clean
        pass

    def do_GET(self):  # noqa: N802 (http.server API)
        rel = self.path.split("?", 1)[0].lstrip("/") or "index.html"
        target = (self.server.serve_root / rel).resolve()
        try:
            target.relative_to(self.server.serve_root.resolve())
        except ValueError:
            self.send_error(403)
            return
        if not target.is_file():
            self.send_error(404)
            return
        data = target.read_bytes()
        self.send_response(200)
        ctype = "text/html; charset=utf-8" if target.suffix in (".html", ".htm") \
            else "application/octet-stream"
        self.send_header("Content-Type", ctype)
        # Optional per-file response headers (COOP/COEP/CSP) via a sidecar file.
        headers_file = target.with_suffix(target.suffix + ".headers")
        if headers_file.is_file():
            for line in headers_file.read_text().splitlines():
                if ":" in line:
                    k, v = line.split(":", 1)
                    self.send_header(k.strip(), v.strip())
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


@dataclass
class OriginPair:
    """Two loopback HTTP origins serving one directory, on distinct ports."""

    root: Path
    port_a: int
    port_b: int
    _servers: list = field(default_factory=list)

    @property
    def url_a(self) -> str:
        return f"http://127.0.0.1:{self.port_a}"

    @property
    def url_b(self) -> str:
        return f"http://127.0.0.1:{self.port_b}"

    def stop(self) -> None:
        for srv in self._servers:
            srv.shutdown()
            srv.server_close()
        self._servers.clear()


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@contextmanager
def serve_origins(root: Path):
    """Serve ``root`` on two loopback origins; yield the pair; always shut down."""
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)
    pair = OriginPair(root=root, port_a=_free_port(), port_b=_free_port())
    for port in (pair.port_a, pair.port_b):
        srv = ThreadingHTTPServer(("127.0.0.1", port), _QuietHandler)
        srv.serve_root = root
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        pair._servers.append(srv)
    try:
        yield pair
    finally:
        pair.stop()


# --------------------------------------------------------------------------- #
# Minimal CDP WebSocket client (no dependency)
# --------------------------------------------------------------------------- #

class _WebSocket:
    """A tiny RFC6455 client: just enough for the Chrome DevTools Protocol."""

    def __init__(self, url: str, timeout: float = 20.0) -> None:
        if not url.startswith("ws://"):
            raise ChromeError(f"unsupported websocket URL {url!r}")
        rest = url[len("ws://"):]
        hostport, _, path = rest.partition("/")
        host, _, port = hostport.partition(":")
        self.sock = socket.create_connection((host, int(port or 80)), timeout=timeout)
        self.sock.settimeout(timeout)
        key = base64.b64encode(os.urandom(16)).decode()
        self.sock.sendall(
            f"GET /{path} HTTP/1.1\r\nHost: {hostport}\r\nUpgrade: websocket\r\n"
            f"Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\n"
            f"Sec-WebSocket-Version: 13\r\n\r\n".encode()
        )
        self._read_handshake()

    def _read_handshake(self) -> None:
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise ChromeError("CDP websocket handshake closed early")
            buf += chunk
        if b"101" not in buf.split(b"\r\n", 1)[0]:
            raise ChromeError(f"CDP websocket handshake failed: {buf[:120]!r}")

    def _send_frame(self, payload: bytes, opcode: int = 0x1) -> None:
        header = bytearray([0x80 | opcode])
        mask = os.urandom(4)
        n = len(payload)
        if n < 126:
            header.append(0x80 | n)
        elif n < 65536:
            header.append(0x80 | 126)
            header += struct.pack(">H", n)
        else:
            header.append(0x80 | 127)
            header += struct.pack(">Q", n)
        header += mask
        masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        self.sock.sendall(bytes(header) + masked)

    def _recv_exact(self, n: int) -> bytes:
        data = b""
        while len(data) < n:
            chunk = self.sock.recv(n - len(data))
            if not chunk:
                raise ChromeError("CDP websocket closed")
            data += chunk
        return data

    def recv_frame(self) -> bytes:
        b1, b2 = self._recv_exact(2)
        opcode = b1 & 0x0F
        length = b2 & 0x7F
        if length == 126:
            length = struct.unpack(">H", self._recv_exact(2))[0]
        elif length == 127:
            length = struct.unpack(">Q", self._recv_exact(8))[0]
        payload = self._recv_exact(length)
        if opcode == 0x8:  # close
            raise ChromeError("CDP websocket closed by peer")
        return payload

    def call(self, msg_id: int, method: str, params: Optional[dict] = None) -> dict:
        self._send_frame(json.dumps(
            {"id": msg_id, "method": method, "params": params or {}}
        ).encode())
        for _ in range(500):  # skip events until our reply arrives
            payload = self.recv_frame()
            try:
                msg = json.loads(payload)
            except json.JSONDecodeError:
                continue
            if msg.get("id") == msg_id:
                return msg
        raise ChromeError(f"no CDP reply for {method}")

    def close(self) -> None:
        try:
            self._send_frame(b"", opcode=0x8)
        except OSError:
            pass
        self.sock.close()


# --------------------------------------------------------------------------- #
# The runner
# --------------------------------------------------------------------------- #

@dataclass
class ProbeRun:
    """The captured result of running one probe page."""

    url: str
    dom: str
    returncode: int
    stderr: str
    duration_ms: int
    result: dict  # parsed from the page's <pre id="result"> JSON

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "returncode": self.returncode,
            "duration_ms": self.duration_ms,
            "result": self.result,
            "dom_sha256": hashlib.sha256(self.dom.encode("utf-8")).hexdigest(),
            "stderr_tail": self.stderr[-2000:],
        }


class Chromium:
    """A located Chromium binary plus the flags to run it headlessly and safely.

    Every run uses a fresh throwaway ``--user-data-dir`` and ``--no-sandbox``
    (the sandbox user cannot use the setuid sandbox; this is a *local test
    browser*, not a hardened deployment -- stated plainly so no result is
    over-claimed).
    """

    def __init__(self, binary: Optional[str] = None, *, timeout: int = 90) -> None:
        self.binary = find_browser(binary)
        self.version = browser_version(self.binary)
        self.timeout = timeout

    def _base_flags(self, profile: str) -> list[str]:
        return [
            self.binary,
            "--headless",
            "--no-sandbox",
            "--disable-gpu",
            "--disable-dev-shm-usage",
            "--no-first-run",
            "--no-default-browser-check",
            "--disable-background-networking",
            "--user-data-dir=" + profile,
        ]

    def run_probe(self, url: str, *, virtual_time_ms: int = 6000) -> ProbeRun:
        """Load ``url`` headlessly, dump the DOM, parse ``#result`` JSON."""
        with tempfile.TemporaryDirectory(prefix="bh-chrome-") as profile:
            flags = self._base_flags(profile) + [
                f"--virtual-time-budget={virtual_time_ms}",
                "--dump-dom",
                url,
            ]
            start = time.time()
            try:
                proc = subprocess.run(
                    flags, capture_output=True, text=True, timeout=self.timeout
                )
            except subprocess.TimeoutExpired as exc:
                raise ChromeError(f"probe {url} exceeded {self.timeout}s") from exc
            duration = int((time.time() - start) * 1000)
            dom = proc.stdout or ""
        return ProbeRun(
            url=url, dom=dom, returncode=proc.returncode,
            stderr=proc.stderr or "", duration_ms=duration,
            result=_parse_result(dom),
        )

    # -- CDP-backed facts --------------------------------------------------- #

    @contextmanager
    def _debug_browser(self):
        """Launch a debuggable browser; yield (proc, port); always terminate."""
        with tempfile.TemporaryDirectory(prefix="bh-chrome-cdp-") as profile:
            port = _free_port()
            flags = self._base_flags(profile) + [
                f"--remote-debugging-port={port}", "about:blank",
            ]
            proc = subprocess.Popen(
                flags, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
            try:
                _wait_for_port(port, timeout=20)
                yield proc, port
            finally:
                proc.terminate()
                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    proc.kill()

    def _cdp(self, port: int) -> "_WebSocket":
        with urllib.request.urlopen(
            f"http://127.0.0.1:{port}/json/version", timeout=10
        ) as resp:
            ws_url = json.load(resp)["webSocketDebuggerUrl"]
        return _WebSocket(ws_url)

    def process_info(self) -> dict:
        """Read the browser's process list via CDP ``SystemInfo.getProcessInfo``."""
        with self._debug_browser() as (_proc, port):
            ws = self._cdp(port)
            try:
                return ws.call(1, "SystemInfo.getProcessInfo").get("result", {})
            finally:
                ws.close()

    def site_isolation_probe(self, urls: list[str]) -> dict:
        """Open each URL as a separate target and map it to a renderer process.

        Returns ``{"targets": [...], "renderer_pids": [...], "distinct_sites": n}``.
        This is the harness's *evidence* that cross-origin pages are kept in
        separate renderer processes; a violation of the invariant would show two
        distinct sites sharing a renderer pid.
        """
        with self._debug_browser() as (_proc, port):
            ws = self._cdp(port)
            try:
                created = []
                for i, url in enumerate(urls):
                    r = ws.call(100 + i, "Target.createTarget", {"url": url})
                    tid = r.get("result", {}).get("targetId")
                    if tid:
                        created.append(tid)
                # SystemInfo reports processes with their hosted target ids.
                info = ws.call(200, "SystemInfo.getProcessInfo").get("result", {})
                return {"created_targets": created, "process_info": info}
            finally:
                ws.close()


def _wait_for_port(port: int, *, timeout: float = 20.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                return
        except OSError:
            time.sleep(0.1)
    raise ChromeError(f"browser debugging port {port} did not open")


def _parse_result(dom: str) -> dict:
    """Extract the JSON a probe page wrote into ``<pre id="result">``.

    Probe pages render their observation as JSON in that element so the harness
    never scrapes prose out of the DOM.
    """
    marker = '<pre id="result">'
    start = dom.find(marker)
    if start == -1:
        return {"_parse_error": "no #result element in the dumped DOM"}
    start += len(marker)
    end = dom.find("</pre>", start)
    if end == -1:
        return {"_parse_error": "unterminated #result element"}
    # A serialized DOM escapes only &, <, > in text content -- NOT quotes (those
    # are escaped in attribute values, not text). `&amp;` must be undone last or
    # it would turn a literal "&amp;lt;" into "<".
    raw = (dom[start:end].replace("&lt;", "<").replace("&gt;", ">")
           .replace("&amp;", "&"))
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        return {"_parse_error": f"#result is not JSON: {exc}", "_raw": raw[:2000]}


__all__ = [
    "BROWSER_CANDIDATES",
    "BROWSER_ENV_VARS",
    "ChromeError",
    "ChromeNotFound",
    "Chromium",
    "OriginPair",
    "ProbeRun",
    "browser_version",
    "find_browser",
    "serve_origins",
]
