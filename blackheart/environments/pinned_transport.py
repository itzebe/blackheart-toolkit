"""A urllib transport that connects to a *validated address*, not to a hostname.

``urllib`` normally hands a hostname to the socket layer, which resolves it again
at connect time. That second resolution is the time-of-check/time-of-use gap: the
address validated by :mod:`blackheart.environments.destination` need not be the
address the socket reaches. Pinning removes the second resolution entirely.

How pinning works without breaking TLS:

* ``HTTPConnection.connect`` is replaced so the socket is opened to the pinned
  ``(ip, port)`` -- no hostname ever reaches ``getaddrinfo`` at connect time.
* ``self.host`` keeps the **hostname**, so ``http.client`` builds the ``Host``
  header from the real name and ``ssl`` uses it for SNI and certificate
  verification via ``server_hostname``. The IP is only the socket destination.

That separation is the whole point: the name is what we authenticate, the address
is what we contact, and the policy validated the latter against the former.
"""

from __future__ import annotations

import http.client
import ssl
import threading
import urllib.request
from typing import Iterable, Optional


class PinnedHTTPSConnection(http.client.HTTPSConnection):
    """An HTTPS connection whose socket goes to ``pinned_ip``, not the hostname."""

    def __init__(self, host: str, *, pinned_ip: str, timeout: float = 15.0,
                 context: Optional[ssl.SSLContext] = None, **kwargs):
        # `host` may be "name:port"; http.client splits it, and `self.port` is then
        # authoritative. We keep `self.host` as the name so SNI/Host stay correct.
        super().__init__(host, timeout=timeout, context=context, **kwargs)
        self._pinned_ip = pinned_ip

    def connect(self) -> None:  # noqa: D102 - documented in the module docstring
        # Deliberately NOT calling super().connect(): that would resolve `self.host`.
        sock = _open_pinned_socket(self._pinned_ip, self.port, self.timeout)
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)
        # Record the peer actually reached, so the audit trail proves the pin.
        self._peer_address = self.sock.getpeername()


class PinnedHTTPConnection(http.client.HTTPConnection):
    """The plaintext equivalent. No TLS, so pinning is the only control."""

    def __init__(self, host: str, *, pinned_ip: str, timeout: float = 15.0,
                 **kwargs):
        super().__init__(host, timeout=timeout, **kwargs)
        self._pinned_ip = pinned_ip

    def connect(self) -> None:  # noqa: D102
        sock = _open_pinned_socket(self._pinned_ip, self.port, self.timeout)
        self.sock = sock
        self._peer_address = sock.getpeername()


#: The peer address of the most recent pinned connection *in this thread*.
#: ``urllib`` wraps the response socket closely enough that digging it back out of
#: a finished response is unreliable; ``connect()`` is the one place the peer is
#: definitely knowable, so it is recorded there and read back here. Thread-local:
#: a process-global would let one concurrent probe read another's peer.
_PEER = threading.local()


class LAST_PEER:
    """Thread-local peer-address cell, read with .address."""

    @staticmethod
    def address() -> str:
        return getattr(_PEER, "address", "")

    @staticmethod
    def set(address: str) -> None:
        _PEER.address = address


def _open_pinned_socket(ip: str, port: int, timeout: float):
    """Open a TCP socket to exactly ``ip:port``, with no name resolution."""
    import socket

    family = socket.AF_INET6 if ":" in ip else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((ip, port))
    except OSError:
        sock.close()
        raise
    try:
        LAST_PEER.set(str(sock.getpeername()[0]))
    except OSError:  # pragma: no cover - defensive
        LAST_PEER.set(ip)
    return sock


class _PinnedHTTPHandler(urllib.request.HTTPHandler):
    def __init__(self, pinned_ip: str, timeout: float):
        super().__init__()
        self._pinned_ip = pinned_ip
        self._timeout = timeout

    def http_open(self, req):
        return self.do_open(
            lambda host, **kw: PinnedHTTPConnection(
                host, pinned_ip=self._pinned_ip, timeout=self._timeout,
            ),
            req,
        )


class _PinnedHTTPSHandler(urllib.request.HTTPSHandler):
    def __init__(self, pinned_ip: str, timeout: float, context: ssl.SSLContext):
        super().__init__(context=context)
        self._pinned_ip = pinned_ip
        self._timeout = timeout

    def https_open(self, req):
        def factory(host, **kw):
            return PinnedHTTPSConnection(
                host, pinned_ip=self._pinned_ip, timeout=self._timeout,
                context=self._context,
            )

        return self.do_open(factory, req)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse to follow redirects at the transport level.

    Redirect handling lives in the caller, where each hop is a fresh
    authorization + resolution + pin decision. A transport that followed
    redirects would silently contact a destination no policy approved.
    """

    def redirect_request(self, *args, **kwargs):
        return None


def build_pinned_opener(pinned_ip: str, scheme: str, *,
                        timeout: float = 15.0,
                        context: Optional[ssl.SSLContext] = None,
                        handlers: Iterable[urllib.request.BaseHandler] = ()):
    """An opener that can only reach ``pinned_ip``, and never follows a redirect.

    ``context`` defaults to a verifying context: certificate and hostname checks
    stay on. Passing ``CERT_NONE`` is possible but no code path in this package
    does, and ``verify_tls`` is reported in the audit record either way.
    """
    if context is None:
        context = ssl.create_default_context()
    chain = [
        _NoRedirect(),
        urllib.request.ProxyHandler({}),  # a proxy would route around the pin
    ]
    if scheme == "https":
        chain.append(_PinnedHTTPSHandler(pinned_ip, timeout, context))
    else:
        chain.append(_PinnedHTTPHandler(pinned_ip, timeout))
    chain.extend(handlers)
    return urllib.request.build_opener(*chain)


def tls_verification_enabled(context: ssl.SSLContext) -> bool:
    """Report honestly whether a context verifies certificates and hostnames."""
    return bool(context.verify_mode == ssl.CERT_REQUIRED and context.check_hostname)
