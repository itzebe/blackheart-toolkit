"""One canonical destination, and the address policy that decides if it may be contacted.

The problem this module exists to solve, stated plainly: *a hostname passing an
authorization check proves nothing about the address the socket will reach.*
``internal.example.com`` may be authorized and may resolve to ``127.0.0.1`` or
``169.254.169.254``. Mission 5 closed the "authorized asset A, fetched URL B"
gap; this closes the "authorized hostname, internal address" gap, and the
time-of-check/time-of-use gap that follows from it.

Three pieces, in the order the connection uses them:

1. :func:`canonicalize` -- turn a URL into exactly one :class:`Destination`.
   Every field that could be reinterpreted downstream (scheme, userinfo, host,
   port, trailing dot, IPv4/IPv6 literal form, IPv4-mapped IPv6) is resolved
   *here*, once. Nothing downstream re-parses the original string.

2. :class:`AddressPolicy` -- classify one resolved IP as permitted or not.
   Fail-closed: an address is refused unless it is positively global-unicast and
   not in any special-use range. Multicast is called out because
   ``ipaddress.is_global`` is **True** for ``224.0.0.1`` and ``ff02::1``, so
   ``is_global`` alone is not a safe test.

3. :class:`SecureResolver` -- resolve the canonical host, normalise every answer,
   and refuse the whole resolution if *any* answer is prohibited. It returns the
   validated addresses so the connection layer can pin to one of them.

The invariant: the address this module validated is the address the socket
connects to. :mod:`blackheart.environments.http_service` enforces that by never
handing a hostname to the socket layer.
"""

from __future__ import annotations

import ipaddress
import socket
import urllib.parse
from dataclasses import dataclass
from typing import Iterable, Optional

_IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address

_DEFAULT_PORTS = {"http": 80, "https": 443}

#: Ranges that must never be contacted, independent of ``is_global``. IPv4 and
#: IPv6 are listed separately because a v4-mapped v6 address is unwrapped first.
_PROHIBITED_V4 = tuple(ipaddress.IPv4Network(n) for n in (
    "0.0.0.0/8",          # "this network"; 0.0.0.0 itself is unspecified
    "10.0.0.0/8",         # RFC1918 private
    "100.64.0.0/10",      # RFC6598 carrier-grade NAT (also cloud metadata)
    "127.0.0.0/8",        # loopback
    "169.254.0.0/16",     # link-local, incl. 169.254.169.254 cloud metadata
    "172.16.0.0/12",      # RFC1918 private
    "192.0.0.0/24",       # IETF protocol assignments
    "192.0.2.0/24",       # TEST-NET-1
    "192.88.99.0/24",     # deprecated 6to4 relay anycast
    "192.168.0.0/16",     # RFC1918 private
    "198.18.0.0/15",      # benchmarking
    "198.51.100.0/24",    # TEST-NET-2
    "203.0.113.0/24",     # TEST-NET-3
    "224.0.0.0/4",        # multicast (is_global is True here -- must be explicit)
    "240.0.0.0/4",        # reserved, incl. 255.255.255.255 broadcast
))

_PROHIBITED_V6 = tuple(ipaddress.IPv6Network(n) for n in (
    "::/128",             # unspecified
    "::1/128",            # loopback
    "64:ff9b::/96",       # NAT64 -- unwrap risk; refused rather than reinterpreted
    "100::/64",           # discard-only
    "2001:db8::/32",      # documentation
    "fc00::/7",           # unique-local (incl. fd00:ec2::254 AWS IMDSv6)
    "fe80::/10",          # link-local
    "ff00::/8",           # multicast (is_global is True here -- must be explicit)
))

#: Addresses that are metadata services rather than ordinary endpoints. Most are
#: already covered above; naming them makes the audit record say *why*.
_METADATA = frozenset({
    "169.254.169.254",    # AWS/GCP/Azure/OpenStack IMDS
    "169.254.170.2",      # ECS task metadata
    "100.100.100.200",    # Alibaba Cloud metadata
    "fd00:ec2::254",      # AWS IMDSv6
})


class DestinationError(ValueError):
    """A URL that cannot be turned into exactly one safe, unambiguous destination."""


@dataclass(frozen=True)
class Destination:
    """Exactly one interpretation of a URL. Downstream code reads only this.

    ``host`` is the canonical hostname used for authorization, TLS verification
    and the ``Host`` header. ``ip`` is set only when the URL named a literal
    address; a hostname destination resolves later, under policy.
    """

    scheme: str
    host: str
    port: int
    path: str
    #: The literal IP the URL named, if it named one. Never set for a hostname.
    ip: Optional[_IPAddress] = None
    #: True when the URL host was a literal address rather than a name.
    is_ip_literal: bool = False
    #: Non-default port present in the URL, which affects the Host header.
    explicit_port: bool = False
    #: Notes on canonicalisation (trailing dot removed, IDNA applied, ...).
    normalizations: tuple[str, ...] = ()

    @property
    def is_default_port(self) -> bool:
        return self.port == _DEFAULT_PORTS.get(self.scheme)

    @property
    def host_header(self) -> str:
        """The ``Host`` header value: include the port only when non-default.

        An IPv6 literal must be bracketed here (RFC 3986 §3.2.2). Without the
        brackets the authority cannot be parsed back -- ``http://::1/x`` is not a
        URL -- so a literal v6 destination would be rejected by the transport
        rather than contacted.
        """
        host = f"[{self.host}]" if ":" in self.host else self.host
        return host if self.is_default_port else f"{host}:{self.port}"

    @property
    def tls_server_name(self) -> str:
        """What certificate verification and SNI must use: the bare host.

        ``ssl`` wants an unbracketed name -- for a literal IP that is the IP
        itself, which is what a certificate for an IP address is issued against.
        """
        return self.host

    def to_dict(self) -> dict:
        return {
            "scheme": self.scheme, "host": self.host, "port": self.port,
            "path": self.path, "is_ip_literal": self.is_ip_literal,
            "ip": str(self.ip) if self.ip else None,
            "host_header": self.host_header,
            "normalizations": list(self.normalizations),
        }


def _strip_trailing_dot(host: str) -> tuple[str, bool]:
    """``example.com.`` is the same host as ``example.com`` (RFC 1034 §3.1)."""
    if host.endswith(".") and len(host) > 1:
        return host[:-1], True
    return host, False


def _canonical_host(raw: str) -> tuple[str, Optional[_IPAddress], tuple[str, ...]]:
    """Normalise a URL host into ``(hostname, literal_ip, notes)``."""
    notes: list[str] = []
    if not raw:
        raise DestinationError("empty host")
    if any(c.isspace() or ord(c) < 0x20 or ord(c) == 0x7F for c in raw):
        raise DestinationError(f"host contains whitespace or control characters: {raw!r}")

    host = raw.lower()
    # An IPv6 literal arrives bracketed from urlsplit's netloc but bare from
    # `.hostname`; accept both and parse it as an address.
    candidate = host.strip("[]")
    try:
        addr = ipaddress.ip_address(candidate)
    except ValueError:
        addr = None
    if addr is not None:
        if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
            # ::ffff:127.0.0.1 is loopback wearing an IPv6 costume. Unwrap it so
            # policy sees the real destination instead of the wrapper.
            notes.append(f"unwrapped IPv4-mapped IPv6 {addr} -> {addr.ipv4_mapped}")
            addr = addr.ipv4_mapped
        return str(addr), addr, tuple(notes)

    if host.startswith("["):
        raise DestinationError(f"malformed bracketed host: {raw!r}")
    if ":" in host:
        # A colon in a non-literal host is either a port that leaked in or junk.
        raise DestinationError(f"host contains ':' but is not a valid IPv6 literal: {raw!r}")

    host, stripped = _strip_trailing_dot(host)
    if stripped:
        notes.append("removed trailing dot")
    if not host:
        raise DestinationError("empty host after normalisation")

    if not host.isascii():
        # Reject rather than silently reinterpret: IDNA2003 in the stdlib maps
        # some labels differently from IDNA2008 browsers use, and a mismatch
        # between what we authorize and what we connect to is the whole risk.
        try:
            host = host.encode("idna").decode("ascii").lower()
            notes.append("IDNA-encoded non-ASCII host")
        except UnicodeError as exc:
            raise DestinationError(f"non-ASCII host cannot be IDNA-encoded: {raw!r}") from exc
    if not host.isascii() or any(c in host for c in "/\\@?#"):
        raise DestinationError(f"host contains characters that change URL meaning: {raw!r}")
    if host.startswith("-") or host.endswith("-") or ".." in host:
        raise DestinationError(f"malformed hostname: {raw!r}")
    return host, None, tuple(notes)


def canonicalize(url: str) -> Destination:
    """Turn ``url`` into the single :class:`Destination` it is allowed to mean.

    Anything ambiguous is refused rather than guessed at. In particular:
    userinfo (``user:pass@host``) is rejected outright -- it is a credential leak
    vector and makes "which host is this?" ambiguous for downstream readers.
    """
    if not isinstance(url, str) or not url.strip():
        raise DestinationError("empty URL")
    if any(c.isspace() for c in url.strip()):
        raise DestinationError(f"URL contains whitespace: {url!r}")
    try:
        parts = urllib.parse.urlsplit(url.strip())
    except ValueError as exc:
        raise DestinationError(f"URL cannot be parsed: {exc}") from exc

    scheme = (parts.scheme or "").lower()
    if scheme not in _DEFAULT_PORTS:
        raise DestinationError(f"scheme {scheme!r} is not http/https")
    if "@" in parts.netloc:
        raise DestinationError("URL contains userinfo (user:pass@); refused")
    if not parts.netloc:
        raise DestinationError("URL has no host")

    try:
        raw_port = parts.port
    except ValueError as exc:
        raise DestinationError(f"invalid port: {exc}") from exc
    host, literal, notes = _canonical_host(parts.hostname or "")
    port = raw_port if raw_port is not None else _DEFAULT_PORTS[scheme]
    if not 1 <= port <= 65535:
        raise DestinationError(f"port {port} is out of range")

    path = parts.path or "/"
    if parts.query:
        path = f"{path}?{parts.query}"
    if not path.startswith("/"):
        raise DestinationError(f"path does not start with '/': {path!r}")

    return Destination(
        scheme=scheme, host=host, port=port, path=path, ip=literal,
        is_ip_literal=literal is not None, explicit_port=raw_port is not None,
        normalizations=notes,
    )


@dataclass(frozen=True)
class AddressVerdict:
    """Whether one resolved address may be contacted, and why."""

    address: str
    allowed: bool
    reason: str

    def to_dict(self) -> dict:
        return {"address": self.address, "allowed": self.allowed, "reason": self.reason}


@dataclass
class DestinationPolicy:
    """Decides which resolved addresses may be contacted.

    Defaults to deny: only global-unicast addresses outside every special-use
    range pass. ``allow_private`` exists for a deliberate local engagement and is
    recorded in the audit trail; it is never inferred.
    """

    #: Permit private/loopback/link-local destinations. Explicit opt-in only, and
    #: every permitted-by-exception address is recorded with its reason.
    allow_private: bool = False
    #: Extra addresses to permit even though the default policy would refuse them.
    allowed_addresses: tuple[str, ...] = ()
    #: Extra hostnames permitted to resolve to non-global addresses.
    allowed_private_hosts: tuple[str, ...] = ()

    def classify(self, address: _IPAddress, *, host: str = "") -> AddressVerdict:
        """Classify one address. Fail-closed: refuse unless positively safe."""
        addr = address
        if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
            addr = addr.ipv4_mapped
        text = str(addr)

        if text in self.allowed_addresses:
            return AddressVerdict(str(address), True, "explicitly allowed address")

        # Metadata is refused *before* the private-destination opt-in. An operator
        # enabling loopback for a local engagement must not thereby expose the
        # cloud instance's credential endpoint: "may reach 127.0.0.1" is a much
        # narrower grant than "may reach any non-public address", and the two are
        # exactly the addresses `allow_private` covers. Only a per-address
        # allowlist entry, which names this endpoint specifically, can permit it.
        if text in _METADATA:
            return AddressVerdict(str(address), False, "cloud metadata endpoint")

        if self.allow_private:
            return AddressVerdict(str(address), True, "operator enabled private destinations")
        if host and host in self.allowed_private_hosts:
            return AddressVerdict(str(address), True, f"host {host} is allowed a private address")
        if isinstance(addr, ipaddress.IPv4Address):
            for net in _PROHIBITED_V4:
                if addr in net:
                    return AddressVerdict(str(address), False, f"prohibited range {net}")
        else:
            for net in _PROHIBITED_V6:
                if addr in net:
                    return AddressVerdict(str(address), False, f"prohibited range {net}")

        # Belt and braces: a non-global address that no explicit rule named is
        # still refused, because "not in my table" must not mean "probably fine".
        if not addr.is_global:
            return AddressVerdict(str(address), False, "not a global-unicast address")
        if addr.is_multicast or addr.is_reserved or addr.is_unspecified:
            return AddressVerdict(str(address), False, "multicast/reserved/unspecified")
        return AddressVerdict(str(address), True, "global unicast")


class ResolutionError(RuntimeError):
    """A destination could not be resolved to a set of permitted addresses."""


@dataclass
class Resolution:
    """The validated result of resolving one destination.

    ``addresses`` holds only addresses that passed the policy, in the order the
    resolver returned them. ``rejected`` records every refused answer with its
    reason, so the audit trail shows what was thrown away and why.
    """

    host: str
    port: int
    addresses: tuple[_IPAddress, ...]
    verdicts: tuple[AddressVerdict, ...] = ()
    rejected: tuple[AddressVerdict, ...] = ()
    from_literal: bool = False

    @property
    def primary(self) -> _IPAddress:
        if not self.addresses:
            raise ResolutionError(f"{self.host} resolved to no permitted address")
        return self.addresses[0]

    def to_dict(self) -> dict:
        return {
            "host": self.host, "port": self.port, "from_literal": self.from_literal,
            "addresses": [str(a) for a in self.addresses],
            "verdicts": [v.to_dict() for v in self.verdicts],
            "rejected": [v.to_dict() for v in self.rejected],
        }


class SecureResolver:
    """Resolve a canonical destination and validate every answer before use."""

    def __init__(self, policy: DestinationPolicy | None = None,
                 *, resolver=None, timeout_s: float = 10.0):
        self.policy = policy or DestinationPolicy()
        #: Injectable for tests: ``(host, port) -> Iterable[str]``.
        self._resolver = resolver
        self._timeout = timeout_s

    def _raw_addresses(self, host: str, port: int) -> list[str]:
        if self._resolver is not None:
            return list(self._resolver(host, port))
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
        return [info[4][0] for info in infos]

    def resolve(self, dest: Destination) -> Resolution:
        """Return only permitted addresses, or raise. Never partially succeeds.

        If *any* answer is prohibited the whole resolution fails: discarding the
        unsafe answer and connecting to the safe one would make the outcome depend
        on resolver ordering, which is exactly the rebinding primitive.
        """
        if dest.is_ip_literal and dest.ip is not None:
            verdict = self.policy.classify(dest.ip, host=dest.host)
            if not verdict.allowed:
                raise ResolutionError(
                    f"destination {dest.host} is a literal address refused by policy: "
                    f"{verdict.reason}"
                )
            return Resolution(host=dest.host, port=dest.port,
                              addresses=(dest.ip,), verdicts=(verdict,),
                              from_literal=True)

        try:
            raw = self._raw_addresses(dest.host, dest.port)
        except (socket.gaierror, OSError) as exc:
            raise ResolutionError(f"DNS resolution failed for {dest.host}: {exc}") from exc
        if not raw:
            raise ResolutionError(f"DNS returned no addresses for {dest.host}")

        permitted: list[_IPAddress] = []
        verdicts: list[AddressVerdict] = []
        rejected: list[AddressVerdict] = []
        seen: set[str] = set()
        for text in raw:
            try:
                addr = ipaddress.ip_address(text)
            except ValueError:
                rejected.append(AddressVerdict(str(text), False, "unparseable DNS answer"))
                continue
            key = str(addr)
            if key in seen:
                continue
            seen.add(key)
            verdict = self.policy.classify(addr, host=dest.host)
            verdicts.append(verdict)
            if verdict.allowed:
                permitted.append(addr)
            else:
                rejected.append(verdict)

        if rejected:
            reasons = "; ".join(f"{v.address} ({v.reason})" for v in rejected[:4])
            raise ResolutionError(
                f"{dest.host} resolved to a prohibited address: {reasons}. "
                "A mixed answer is refused as a whole, not filtered."
            )
        if not permitted:
            raise ResolutionError(f"{dest.host} resolved to no usable address")
        return Resolution(host=dest.host, port=dest.port,
                          addresses=tuple(permitted), verdicts=tuple(verdicts))


def classify_all(addresses: Iterable[str], policy: DestinationPolicy,
                 *, host: str = "") -> list[AddressVerdict]:
    """Classify a list of address strings. Convenience for audit and tests."""
    out: list[AddressVerdict] = []
    for text in addresses:
        try:
            addr = ipaddress.ip_address(text)
        except ValueError:
            out.append(AddressVerdict(str(text), False, "unparseable address"))
            continue
        out.append(policy.classify(addr, host=host))
    return out
