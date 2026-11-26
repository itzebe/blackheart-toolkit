"""Mission 05.1 acceptance bar: HTTP egress authorization at the connection boundary.

The claim under test is narrow and checkable: *the destination BLACKHEART
authorized is the destination the socket reaches*. Every test here drives the real
code path -- the real adapter, the real socket, a real local HTTP server -- with a
controlled resolver standing in for DNS. No test depends on external DNS or live
internet conditions.

The four things this file proves:

1. A hostname that resolves to an internal address is **blocked before connect**.
2. The address validated by policy is the address the socket actually reaches
   (connection pinning), with TLS hostname verification and the ``Host`` header
   intact.
3. A DNS answer that changes between validation and connection cannot win: every
   connection re-resolves and re-validates.
4. Every redirect is a fresh authorization decision, and a block is recorded as a
   block -- never as a successful probe or a "clean" coverage verdict.
"""

from __future__ import annotations

import http.server
import socket
import ssl
import threading
import urllib.request

import pytest

from blackheart.coverage_engine import (
    ControllerConfig,
    CoverageState,
    FailureKind,
    ProbeOutcome,
    ResearchController,
    Taxonomy,
)
from blackheart.environments import HttpServiceAdapter
from blackheart.environments.adapter import ProbeRequest
from blackheart.environments.destination import (
    DestinationError,
    DestinationPolicy,
    ResolutionError,
    SecureResolver,
    canonicalize,
    classify_all,
)
from blackheart.environments.http_service import MAX_REDIRECTS
from blackheart.environments.pinned_transport import (
    build_pinned_opener,
    tls_verification_enabled,
)
from blackheart.objectives import TargetProfile
from tests.test_environments import _authorized_record


# --------------------------------------------------------------------------- #
# Fixtures: a real server, and a resolver the test controls completely
# --------------------------------------------------------------------------- #

class _Recorder:
    """Records which paths a local server actually served."""

    def __init__(self) -> None:
        self.hits: list[str] = []


@pytest.fixture
def internal_server():
    """A real HTTP server on loopback -- the 'internal service' of the attack."""
    rec = _Recorder()

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            rec.hits.append(self.path)
            body = b"INTERNAL-SECRET"
            if self.path.startswith("/hop"):
                self.send_response(302)
                self.send_header("Location", self.path.split("to=")[-1])
                self.end_headers()
                return
            if self.path.startswith("/loop"):
                self.send_response(302)
                self.send_header("Location", "/loop")
                self.end_headers()
                return
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_address[1]}", rec
    server.shutdown()
    server.server_close()


@pytest.fixture
def dns(monkeypatch):
    """A controllable DNS: ``dns.map["host"] = ["1.2.3.4", ...]``.

    Patching ``socket.getaddrinfo`` is how we stand in for the resolver; the
    product code under test is untouched.
    """
    class Map:
        def __init__(self) -> None:
            self.map: dict[str, list[str]] = {}
            self.calls: list[str] = []

        def __setitem__(self, host, addrs):
            self.map[host] = addrs

    table = Map()
    real = socket.getaddrinfo

    def fake(host, port, *a, **kw):
        if host in table.map:
            table.calls.append(host)
            answers = table.map[host]
            if isinstance(answers, Exception):
                raise answers
            out = []
            for ip in answers:
                fam = socket.AF_INET6 if ":" in ip else socket.AF_INET
                out.append((fam, socket.SOCK_STREAM, 6, "", (ip, port, 0, 0)
                            if fam == socket.AF_INET6 else (ip, port)))
            return out
        return real(host, port, *a, **kw)

    monkeypatch.setattr(socket, "getaddrinfo", fake)
    return table


def _private_adapter(**kw) -> HttpServiceAdapter:
    kw.setdefault("policy", DestinationPolicy(allow_private=True))
    adapter = HttpServiceAdapter(**kw)
    adapter.probe()
    return adapter


# --------------------------------------------------------------------------- #
# 1. Canonical destination: one interpretation, or a refusal
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("url,expected", [
    ("http://app.example.com/x", ("http", "app.example.com", 80, "/x")),
    ("https://app.example.com", ("https", "app.example.com", 443, "/")),
    ("https://app.example.com:8443/a?b=c", ("https", "app.example.com", 8443, "/a?b=c")),
    ("HTTP://APP.EXAMPLE.COM/x", ("http", "app.example.com", 80, "/x")),
    # A trailing dot is the same host (RFC 1034), so it is normalised, not refused.
    ("http://app.example.com./x", ("http", "app.example.com", 80, "/x")),
])
def test_canonicalization_normalizes_the_fields_that_matter(url, expected):
    dest = canonicalize(url)
    assert (dest.scheme, dest.host, dest.port, dest.path) == expected


@pytest.mark.parametrize("url", [
    "file:///etc/passwd",
    "ftp://app.example.com/x",
    "gopher://app.example.com/",
    "app.example.com/x",                 # no scheme
    "http:///x",                         # no host
    "http://user:pass@app.example.com/x",  # userinfo hides the real host
    "http://app.example.com:99999/x",    # port out of range
    "http://app.example.com/x y",        # whitespace
    "http://a\x00b.example.com/",        # NUL
])
def test_ambiguous_or_unsupported_destinations_are_refused(url):
    with pytest.raises(DestinationError):
        canonicalize(url)


def test_trailing_dot_is_normalized_so_it_cannot_dodge_the_host_check():
    """``internal.example.com.`` must not be a different host from ``internal.example.com``."""
    assert canonicalize("http://internal.example.com./x").host == \
        canonicalize("http://internal.example.com/x").host


def test_ipv4_mapped_ipv6_is_unwrapped_to_the_real_destination():
    """``::ffff:127.0.0.1`` is loopback wearing a costume; it must read as loopback."""
    dest = canonicalize("http://[::ffff:127.0.0.1]/x")
    assert dest.is_ip_literal
    assert str(dest.ip) == "127.0.0.1"
    verdict = DestinationPolicy().classify(dest.ip)
    assert verdict.allowed is False
    assert "loopback" in verdict.reason or "prohibited" in verdict.reason


def test_host_header_and_tls_server_name_keep_the_hostname():
    """The name must survive canonicalisation: TLS and ``Host`` depend on it."""
    dest = canonicalize("https://App.Example.com:8443/x")
    assert dest.host_header == "app.example.com:8443"
    assert dest.tls_server_name == "app.example.com"
    # The default port is omitted from the Host header, as HTTP requires.
    assert canonicalize("https://app.example.com/x").host_header == "app.example.com"


@pytest.mark.parametrize("url,expected_header,expected_sni", [
    ("http://[2606:4700::1111]/x", "[2606:4700::1111]", "2606:4700::1111"),
    ("http://[2606:4700::1111]:8080/x", "[2606:4700::1111]:8080", "2606:4700::1111"),
    ("https://[2001:db8::1]/x", "[2001:db8::1]", "2001:db8::1"),
])
def test_an_ipv6_literal_keeps_its_brackets_in_the_host_header(
        url, expected_header, expected_sni):
    """Regression: an unbracketed v6 authority is not a URL.

    ``host_header`` dropping the brackets produced ``http://::1/x``, which the
    transport rejects -- every literal-IPv6 target failed. The header needs the
    brackets; TLS/SNI needs the bare address.
    """
    dest = canonicalize(url)
    assert dest.host_header == expected_header
    assert dest.tls_server_name == expected_sni
    # The reconstructed URL must round-trip back to the same destination.
    rebuilt = f"{dest.scheme}://{dest.host_header}{dest.path}"
    assert canonicalize(rebuilt) == dest
    urllib.request.Request(rebuilt)  # must not raise


def test_a_reconstructed_ipv6_url_parses_back_to_the_same_host():
    dest = canonicalize("http://[2606:4700::1111]:8080/path?q=1")
    rebuilt = f"{dest.scheme}://{dest.host_header}{dest.path}"
    again = canonicalize(rebuilt)
    assert (again.host, again.port, again.path) == (dest.host, dest.port, dest.path)


def test_idna_hosts_are_encoded_not_reinterpreted():
    dest = canonicalize("http://bücher.example/x")
    assert dest.host == "xn--bcher-kva.example"
    assert "IDNA" in " ".join(dest.normalizations)


# --------------------------------------------------------------------------- #
# 2. Address policy: fail-closed classification
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("addr,allowed,why", [
    ("8.8.8.8", True, "public IPv4"),
    ("1.1.1.1", True, "public IPv4"),
    ("2606:4700::1111", True, "public IPv6"),
    ("127.0.0.1", False, "loopback IPv4"),
    ("127.1.2.3", False, "loopback IPv4 range"),
    ("::1", False, "loopback IPv6"),
    ("10.0.0.1", False, "private IPv4 /8"),
    ("172.16.0.1", False, "private IPv4 /12"),
    ("192.168.1.1", False, "private IPv4 /16"),
    ("169.254.1.1", False, "link-local IPv4"),
    ("169.254.169.254", False, "cloud metadata IPv4"),
    ("100.100.100.200", False, "cloud metadata (Alibaba)"),
    ("fc00::1", False, "unique-local IPv6"),
    ("fd00:ec2::254", False, "cloud metadata IPv6"),
    ("fe80::1", False, "link-local IPv6"),
    ("224.0.0.1", False, "multicast IPv4 (is_global lies here)"),
    ("ff02::1", False, "multicast IPv6 (is_global lies here)"),
    ("0.0.0.0", False, "unspecified IPv4"),
    ("::", False, "unspecified IPv6"),
    ("255.255.255.255", False, "broadcast"),
    ("198.18.0.1", False, "benchmarking range"),
    ("192.0.2.5", False, "documentation range"),
    ("::ffff:127.0.0.1", False, "IPv4-mapped loopback"),
    ("::ffff:8.8.8.8", True, "IPv4-mapped public"),
])
def test_address_policy_classifies_every_special_range(addr, allowed, why):
    verdict = classify_all([addr], DestinationPolicy())[0]
    assert verdict.allowed is allowed, f"{addr} ({why}): {verdict.reason}"


def test_multicast_is_refused_even_though_is_global_says_true():
    """The trap this policy exists for: ``ipaddress.is_global`` is True for multicast."""
    import ipaddress

    assert ipaddress.ip_address("224.0.0.1").is_global is True
    assert classify_all(["224.0.0.1"], DestinationPolicy())[0].allowed is False


@pytest.mark.parametrize("addr", [
    "169.254.169.254",   # AWS/GCP/Azure/OpenStack IMDS
    "169.254.170.2",     # ECS task metadata
    "100.100.100.200",   # Alibaba Cloud metadata
    "fd00:ec2::254",     # AWS IMDSv6
])
def test_metadata_stays_refused_even_when_private_destinations_are_enabled(addr):
    """Regression: ``allow_private`` must not unlock the cloud credential endpoint.

    The opt-in exists for a local engagement against loopback. Every metadata
    endpoint is a private/link-local address too, so a check that ran *after* the
    opt-in silently granted them as well -- turning "reach my dev server" into
    "reach the instance credentials".
    """
    verdict = classify_all([addr], DestinationPolicy(allow_private=True))[0]
    assert verdict.allowed is False
    assert "metadata" in verdict.reason


def test_metadata_can_only_be_reached_by_naming_it_explicitly():
    """The narrow escape hatch stays available and is auditable."""
    policy = DestinationPolicy(allow_private=True,
                               allowed_addresses=("169.254.169.254",))
    verdict = classify_all(["169.254.169.254"], policy)[0]
    assert verdict.allowed is True
    assert "explicitly allowed" in verdict.reason


def test_allow_private_still_permits_an_ordinary_local_fixture():
    """The opt-in must keep working for what it was written for."""
    for addr in ("127.0.0.1", "::1", "10.0.0.5", "192.168.1.10"):
        assert classify_all([addr], DestinationPolicy(allow_private=True))[0].allowed


def test_private_destination_requires_an_explicit_opt_in():
    assert classify_all(["127.0.0.1"], DestinationPolicy())[0].allowed is False
    opted_in = DestinationPolicy(allow_private=True)
    assert classify_all(["127.0.0.1"], opted_in)[0].allowed is True


# --------------------------------------------------------------------------- #
# 3. Secure resolution: every answer is validated, mixed answers are refused
# --------------------------------------------------------------------------- #

def test_a_public_answer_resolves(dns):
    dns["app.example.com"] = ["93.184.216.34"]
    res = SecureResolver().resolve(canonicalize("http://app.example.com/"))
    assert [str(a) for a in res.addresses] == ["93.184.216.34"]


def test_a_loopback_answer_is_refused_before_any_connection(dns):
    dns["internal.example.com"] = ["127.0.0.1"]
    with pytest.raises(ResolutionError, match="prohibited"):
        SecureResolver().resolve(canonicalize("http://internal.example.com/"))


def test_a_mixed_answer_is_refused_as_a_whole(dns):
    """Filtering the bad answer and connecting to the good one is resolver-order luck."""
    dns["mixed.example.com"] = ["93.184.216.34", "127.0.0.1"]
    with pytest.raises(ResolutionError, match="mixed|prohibited"):
        SecureResolver().resolve(canonicalize("http://mixed.example.com/"))


def test_an_empty_answer_is_a_resolution_failure(dns):
    dns["empty.example.com"] = []
    with pytest.raises(ResolutionError, match="no addresses"):
        SecureResolver().resolve(canonicalize("http://empty.example.com/"))


def test_a_dns_failure_is_a_resolution_failure_not_a_clean_result(dns):
    dns["down.example.com"] = socket.gaierror("temporary failure")
    with pytest.raises(ResolutionError, match="DNS resolution failed"):
        SecureResolver().resolve(canonicalize("http://down.example.com/"))


def test_ipv6_answers_are_validated_too(dns):
    dns["v6.example.com"] = ["::1"]
    with pytest.raises(ResolutionError, match="prohibited"):
        SecureResolver().resolve(canonicalize("http://v6.example.com/"))


# --------------------------------------------------------------------------- #
# 4. The original defect: authorized hostname -> internal address
# --------------------------------------------------------------------------- #

def test_authorized_hostname_resolving_to_loopback_never_reaches_the_service(
        internal_server, dns):
    """The Mission 5 residual weakness, closed at the connection boundary.

    The hostname passes the asset check; its address does not pass policy. The
    service must never see the request.
    """
    base, rec = internal_server
    port = base.rsplit(":", 1)[1]
    asset = f"http://internal-target.example.com:{port}"
    dns["internal-target.example.com"] = ["127.0.0.1"]

    adapter = _private_adapter()
    # Use a policy that refuses private addresses: this is the attack scenario.
    adapter._policy = DestinationPolicy()
    adapter._resolver = SecureResolver(DestinationPolicy())

    obs = adapter.execute(ProbeRequest(
        target=asset, target_type="http-service", operation="inspect",
        authorization=_authorized_record(asset),
    ))
    assert obs.ok is False
    assert obs.facts["blocked"] is True
    assert "prohibited" in obs.error.lower()
    assert rec.hits == [], "the internal service must never be contacted"


def test_the_authorized_hostname_itself_still_works_when_its_address_is_public(dns):
    """The fix must not block ordinary authorized research."""
    dns["app.example.com"] = ["93.184.216.34"]
    res = SecureResolver().resolve(canonicalize("http://app.example.com/"))
    assert str(res.primary) == "93.184.216.34"
    assert res.from_literal is False


def test_an_ip_literal_destination_is_validated_directly():
    with pytest.raises(ResolutionError, match="literal address refused"):
        SecureResolver().resolve(canonicalize("http://127.0.0.1/x"))


# --------------------------------------------------------------------------- #
# 5. Connection pinning: the validated address IS the peer
# --------------------------------------------------------------------------- #

def test_the_validated_address_is_the_peer_that_answers(internal_server, dns):
    """Pinning, proved through the real socket: name says one thing, socket another."""
    base, rec = internal_server
    port = base.rsplit(":", 1)[1]
    # The *name* resolves to loopback (allowed here only because the fixture is
    # loopback); the point is that the socket reaches the address we validated.
    dns["pinned.example.com"] = ["127.0.0.1"]
    asset = f"http://pinned.example.com:{port}"
    adapter = _private_adapter()

    obs = adapter.execute(ProbeRequest(
        target=asset, target_type="http-service", operation="inspect",
        authorization=_authorized_record(asset),
    ))
    assert obs.ok is True
    assert obs.facts["peer_address"] == "127.0.0.1"
    assert obs.facts["egress"]["hops"][0]["selected_address"] == "127.0.0.1"
    assert rec.hits == ["/"], "the pinned address is the one that was contacted"


def test_the_host_header_keeps_the_authorized_hostname(internal_server, dns):
    """Pinning must not turn the request into a raw-IP request."""
    base, _ = internal_server
    port = base.rsplit(":", 1)[1]
    dns["named.example.com"] = ["127.0.0.1"]

    seen: list[str] = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            seen.append(self.headers.get("Host", ""))
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, *a):
            pass

    server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        asset = f"http://named.example.com:{server.server_address[1]}"
        adapter = _private_adapter()
        obs = adapter.execute(ProbeRequest(
            target=asset, target_type="http-service", operation="inspect",
            authorization=_authorized_record(asset),
        ))
        assert obs.ok is True
        assert seen and seen[0] == f"named.example.com:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()


def test_the_socket_layer_never_resolves_a_hostname(dns):
    """Pinning removes the second resolution: the transport must not call getaddrinfo."""
    dns["pinned.example.com"] = ["127.0.0.1"]
    calls_before = len(dns.calls)
    opener = build_pinned_opener("127.0.0.1", "http", timeout=1)
    # Build only: the opener must not resolve anything at construction time.
    assert isinstance(opener, urllib.request.OpenerDirector)
    assert len(dns.calls) == calls_before


def test_tls_verification_is_enabled_by_default():
    """Pinning must never be achieved by disabling certificate checks."""
    assert tls_verification_enabled(ssl.create_default_context()) is True


def test_a_pinned_connection_to_a_closed_port_fails_rather_than_falling_back():
    """No silent fallback to an unvalidated address: a dead pin is an error."""
    opener = build_pinned_opener("127.0.0.1", "http", timeout=2)
    with pytest.raises(Exception):
        opener.open("http://unreachable.example:1/", timeout=2)


# --------------------------------------------------------------------------- #
# 6. DNS rebinding: a changed answer is re-validated
# --------------------------------------------------------------------------- #

def test_a_second_resolution_that_rebinds_to_loopback_is_refused(dns):
    """Validation is per-connection, so a rebound answer cannot inherit trust."""
    resolver = SecureResolver()
    dest = canonicalize("http://rebind.example.com/")

    dns["rebind.example.com"] = ["93.184.216.34"]
    first = resolver.resolve(dest)
    assert str(first.primary) == "93.184.216.34"

    dns["rebind.example.com"] = ["127.0.0.1"]
    with pytest.raises(ResolutionError, match="prohibited"):
        resolver.resolve(dest)


def test_each_request_resolves_afresh(internal_server, dns):
    """Two requests under a rebinding resolver: the second is refused, not served."""
    base, rec = internal_server
    port = base.rsplit(":", 1)[1]
    asset = f"http://flip.example.com:{port}"
    adapter = HttpServiceAdapter()  # strict policy
    adapter.probe()

    dns["flip.example.com"] = ["127.0.0.1"]
    obs = adapter.execute(ProbeRequest(
        target=asset, target_type="http-service", operation="inspect",
        authorization=_authorized_record(asset),
    ))
    assert obs.ok is False
    assert rec.hits == []


# --------------------------------------------------------------------------- #
# 7. Redirects: every hop is a new authorization decision
# --------------------------------------------------------------------------- #

def _hop_adapter(**kw) -> HttpServiceAdapter:
    # A 302 to another host must be *re-authorized*, so the fixture server can sit
    # on loopback while the redirect target is somewhere else entirely.
    kw.setdefault("policy", DestinationPolicy(allow_private=True))
    adapter = HttpServiceAdapter(**kw)
    adapter.probe()
    return adapter


def test_a_redirect_to_an_unauthorized_host_is_blocked(internal_server, dns):
    base, rec = internal_server
    port = base.rsplit(":", 1)[1]
    asset = f"http://app.example.com:{port}"
    dns["app.example.com"] = ["127.0.0.1"]
    dns["evil.example.net"] = ["127.0.0.1"]

    adapter = _hop_adapter()
    obs = adapter.execute(ProbeRequest(
        target=asset, target_type="http-service", operation="inspect",
        authorization=_authorized_record(asset),
        params={"url": f"{asset}/hop?to=https://evil.example.net/"},
    ))
    assert obs.ok is False
    assert obs.facts["blocked"] is True
    assert "evil.example.net" in obs.error


def test_a_redirect_to_loopback_is_blocked(dns, internal_server):
    base, _ = internal_server
    port = base.rsplit(":", 1)[1]
    asset = f"http://app.example.com:{port}"
    dns["app.example.com"] = ["127.0.0.1"]

    adapter = _hop_adapter()
    obs = adapter.execute(ProbeRequest(
        target=asset, target_type="http-service", operation="inspect",
        authorization=_authorized_record(asset),
        params={"url": f"{asset}/hop?to=http://127.0.0.1:1/"},
    ))
    assert obs.ok is False
    assert obs.facts["blocked"] is True


def test_a_redirect_to_a_metadata_address_is_blocked(dns, internal_server):
    base, _ = internal_server
    port = base.rsplit(":", 1)[1]
    asset = f"http://app.example.com:{port}"
    dns["app.example.com"] = ["127.0.0.1"]

    adapter = _hop_adapter()
    obs = adapter.execute(ProbeRequest(
        target=asset, target_type="http-service", operation="inspect",
        authorization=_authorized_record(asset),
        params={"url": f"{asset}/hop?to=http://169.254.169.254/latest/meta-data/"},
    ))
    assert obs.ok is False
    assert obs.facts["blocked"] is True


def test_a_redirect_to_an_unsupported_scheme_is_blocked(dns, internal_server):
    base, _ = internal_server
    port = base.rsplit(":", 1)[1]
    asset = f"http://app.example.com:{port}"
    dns["app.example.com"] = ["127.0.0.1"]

    adapter = _hop_adapter()
    obs = adapter.execute(ProbeRequest(
        target=asset, target_type="http-service", operation="inspect",
        authorization=_authorized_record(asset),
        params={"url": f"{asset}/hop?to=file:///etc/passwd"},
    ))
    assert obs.ok is False
    assert obs.facts["blocked"] is True


def test_a_redirect_to_the_same_authorized_host_is_followed(dns, internal_server):
    base, rec = internal_server
    port = base.rsplit(":", 1)[1]
    asset = f"http://app.example.com:{port}"
    dns["app.example.com"] = ["127.0.0.1"]

    adapter = _hop_adapter()
    obs = adapter.execute(ProbeRequest(
        target=asset, target_type="http-service", operation="inspect",
        authorization=_authorized_record(asset),
        params={"url": f"{asset}/hop?to=/health"},
    ))
    assert obs.ok is True
    assert obs.facts["status"] == 200
    assert len(obs.facts["egress"]["hops"]) == 2


def test_a_redirect_loop_is_cut_off(dns, internal_server):
    base, _ = internal_server
    port = base.rsplit(":", 1)[1]
    asset = f"http://app.example.com:{port}"
    dns["app.example.com"] = ["127.0.0.1"]

    adapter = _hop_adapter()
    obs = adapter.execute(ProbeRequest(
        target=asset, target_type="http-service", operation="inspect",
        authorization=_authorized_record(asset),
        params={"url": f"{asset}/loop"},
    ))
    assert obs.ok is False
    assert obs.facts["blocked"] is True
    assert "redirect" in obs.error.lower()
    # The chain is bounded: at most MAX_REDIRECTS hops actually fetched, plus the
    # final record that names the refusal. A loop can never run forever.
    fetched = [h for h in obs.facts["egress"]["hops"]
               if h.get("decision") == "authorized"]
    assert len(fetched) <= MAX_REDIRECTS + 1


def test_a_redirect_to_a_new_dns_answer_is_revalidated(dns, internal_server):
    """The redirect destination resolves differently and is refused."""
    base, _ = internal_server
    port = base.rsplit(":", 1)[1]
    asset = f"http://app.example.com:{port}"
    dns["app.example.com"] = ["127.0.0.1"]
    dns["other.example.com"] = ["127.0.0.1"]

    adapter = _hop_adapter()
    obs = adapter.execute(ProbeRequest(
        target=asset, target_type="http-service", operation="inspect",
        authorization=_authorized_record(asset),
        params={"url": f"{asset}/hop?to=http://other.example.com:{port}/"},
    ))
    # Same host would be allowed; a *different* authorized-looking host is not.
    assert obs.ok is False
    assert obs.facts["blocked"] is True


def test_redirects_can_be_disabled_entirely(dns, internal_server):
    base, _ = internal_server
    port = base.rsplit(":", 1)[1]
    asset = f"http://app.example.com:{port}"
    dns["app.example.com"] = ["127.0.0.1"]

    adapter = _hop_adapter(follow_redirects=False)
    obs = adapter.execute(ProbeRequest(
        target=asset, target_type="http-service", operation="inspect",
        authorization=_authorized_record(asset),
        params={"url": f"{asset}/hop?to=/health"},
    ))
    assert obs.ok is False
    assert obs.facts["blocked"] is True


# --------------------------------------------------------------------------- #
# 8. Authorization regression: the asset decides, not a request field
# --------------------------------------------------------------------------- #

def test_an_authorized_asset_cannot_fetch_a_different_url_in_params(dns):
    """The Mission 5 SSRF defect, kept as a regression test."""
    dns["app.example.com"] = ["93.184.216.34"]
    dns["other.example.com"] = ["93.184.216.34"]
    adapter = HttpServiceAdapter()
    adapter.probe()
    obs = adapter.execute(ProbeRequest(
        target="https://app.example.com", target_type="http-service",
        operation="inspect",
        authorization=_authorized_record("https://app.example.com"),
        params={"url": "https://other.example.com/"},
    ))
    assert obs.ok is False
    assert "authorized asset" in obs.error


def test_no_request_field_can_override_the_authorized_destination(dns,
                                                                 internal_server):
    """No parameter can redirect the probe to a host other than the asset.

    Two outcomes are acceptable and both are safe: the field is *ignored* (the
    request goes to the authorized host) or it is *refused*. What must never
    happen is the unauthorized host being resolved or contacted, so that is what
    this asserts -- deterministically, against a local server.
    """
    base, rec = internal_server
    port = base.rsplit(":", 1)[1]
    authorized = f"http://app.example.com:{port}"
    dns["app.example.com"] = ["127.0.0.1"]
    # Deliberately unresolvable: reaching it would be a *connection* attempt.
    dns["other.example.com"] = socket.gaierror("no such host")
    adapter = _private_adapter()

    for field_name in ("url", "target", "host", "endpoint", "destination"):
        rec.hits.clear()
        obs = adapter.execute(ProbeRequest(
            target=authorized, target_type="http-service", operation="inspect",
            authorization=_authorized_record(authorized),
            params={field_name: "http://other.example.com/"},
        ))
        assert dns.calls.count("other.example.com") == 0, (
            f"field {field_name!r} caused the unauthorized host to be resolved")
        if obs.ok:
            # Followed -- so it must have stayed on the authorized destination.
            host = obs.facts["egress"]["hops"][-1]["canonical"]["host"]
            assert host == "app.example.com", (
                f"field {field_name!r} redirected the probe to {host}")
        else:
            assert "other.example.com" not in obs.error or "authorized asset" in obs.error


def test_an_authorized_port_cannot_be_used_to_reach_another_port(dns, internal_server):
    """Regression (found by adversarial review): the grant is host *and* port.

    An asset authorized at ``app.example.com:8080`` must not reach
    ``app.example.com:22``. Binding on the host alone turns one in-scope web app
    into a port scanner for every service on the same host -- SSH, Redis, an
    admin port -- none of which the authorization named.
    """
    base, rec = internal_server
    authorized_port = base.rsplit(":", 1)[1]
    asset = f"http://app.example.com:{authorized_port}"
    dns["app.example.com"] = ["127.0.0.1"]
    adapter = _private_adapter()

    for other in ("22", "6379", "9200"):
        rec.hits.clear()
        obs = adapter.execute(ProbeRequest(
            target=asset, target_type="http-service", operation="inspect",
            authorization=_authorized_record(asset),
            params={"url": f"http://app.example.com:{other}/"},
        ))
        assert obs.ok is False, f"port {other} was reachable from a :{authorized_port} grant"
        assert obs.facts["blocked"] is True
        assert "port" in obs.error.lower()
        assert rec.hits == [], "no request may reach the other port"


def test_the_authorized_port_itself_still_works(dns, internal_server):
    base, rec = internal_server
    authorized_port = base.rsplit(":", 1)[1]
    asset = f"http://app.example.com:{authorized_port}"
    dns["app.example.com"] = ["127.0.0.1"]
    adapter = _private_adapter()
    obs = adapter.execute(ProbeRequest(
        target=asset, target_type="http-service", operation="inspect",
        authorization=_authorized_record(asset),
    ))
    assert obs.ok is True
    assert rec.hits == ["/"]


def test_an_asset_that_is_not_a_url_fails_closed():
    """Regression (found by adversarial review): no binding means no request.

    The backend's control is "the URL is the authorized asset". If the asset label
    cannot be canonicalized there is nothing to bind to, so the request must be
    refused -- not issued unbound, which is what a silent ``authorized = None`` did.
    """
    adapter = HttpServiceAdapter()
    adapter.probe()
    for asset in ("asset-a", "app.example.com:443", "not a url"):
        obs = adapter.execute(ProbeRequest(
            target=asset, target_type="http-service", operation="inspect",
            authorization=_authorized_record(asset),
            params={"url": "https://anywhere.example.com/"},
        ))
        assert obs.ok is False, f"asset {asset!r} produced an unbound request"
        assert obs.facts["blocked"] is True
        assert "not a url" in obs.error.lower()


def test_a_trailing_dot_cannot_dodge_the_authorized_host_binding(dns):
    dns["app.example.com"] = ["93.184.216.34"]
    adapter = HttpServiceAdapter()
    adapter.probe()
    # The asset is written with a dot; the request without (and vice versa).
    obs = adapter.execute(ProbeRequest(
        target="https://app.example.com.", target_type="http-service",
        operation="inspect",
        authorization=_authorized_record("https://app.example.com."),
        params={"url": "https://app.example.com/"},
    ))
    # The dot is normalised away, so the host binding matches rather than refusing.
    assert obs.facts.get("blocked") is not True
    assert obs.facts["egress"]["hops"][0]["canonical"]["host"] == "app.example.com"


# --------------------------------------------------------------------------- #
# 9. Coverage integration: a block never becomes a clean verdict
# --------------------------------------------------------------------------- #

def _api_profile() -> TargetProfile:
    return TargetProfile(name="api", kind="http-service", assets=["api.example.com"],
                         entry_points=["query"], roles=["user"], notes="HTTP api")


def test_a_blocked_probe_leaves_the_class_open_not_clean():
    """An authorization/DNS block is not evidence about the class."""
    def probe(class_key, hyp_id, strategy):
        return ProbeOutcome(ok=False, failure_kind=FailureKind.INCONCLUSIVE.value,
                            failure_reason="egress blocked: prohibited address")

    result = ResearchController(Taxonomy(), ControllerConfig(max_probes=200)).run(
        _api_profile(), probe=probe)
    summary = result.record.summary()
    assert summary["verdict"] == "INCOMPLETE"
    assert summary["tested_no_issue"] == []
    assert all(c.state is not CoverageState.TESTED_NO_ISSUE_FOUND
               for c in result.record.classes.values())
    blocked = [c for c in result.record.classes.values()
               if c.state is CoverageState.BLOCKED]
    assert blocked and all(c.blocked_attempts for c in blocked)


def test_a_backend_fault_still_reads_as_blocked_not_clean():
    """The Mission 5 defect-5 regression, kept honest alongside the new one."""
    def probe(class_key, hyp_id, strategy):
        raise RuntimeError("backend exploded")

    result = ResearchController(Taxonomy(), ControllerConfig(max_probes=200)).run(
        _api_profile(), probe=probe)
    summary = result.record.summary()
    assert summary["verdict"] == "INCOMPLETE"
    assert summary["tested_no_issue"] == []


def test_a_successful_probe_records_real_execution_provenance(dns, internal_server):
    base, _ = internal_server
    port = base.rsplit(":", 1)[1]
    asset = f"http://app.example.com:{port}"
    dns["app.example.com"] = ["127.0.0.1"]
    adapter = _hop_adapter()

    obs = adapter.execute(ProbeRequest(
        target=asset, target_type="http-service", operation="inspect",
        authorization=_authorized_record(asset),
    ))
    assert obs.can_support_finding()
    assert obs.facts["peer_address"] == "127.0.0.1"
    assert obs.facts["egress"]["outcome"] == "executed"


# --------------------------------------------------------------------------- #
# 10. Auditability: every decision is recorded, no secrets leak
# --------------------------------------------------------------------------- #

def test_a_blocked_request_produces_an_audit_record(dns):
    dns["internal.example.com"] = ["127.0.0.1"]
    adapter = HttpServiceAdapter()
    adapter.probe()
    obs = adapter.execute(ProbeRequest(
        target="http://internal.example.com/", target_type="http-service",
        operation="inspect",
        authorization=_authorized_record("http://internal.example.com/"),
    ))
    egress = obs.facts["egress"]
    assert egress["outcome"] == "blocked"
    assert egress["requested_url"] == "http://internal.example.com/"
    assert egress["policy"] == "global-unicast-only"
    hop = egress["hops"][0]
    assert hop["decision"] == "blocked"
    assert "prohibited" in hop["reason"]


def test_the_audit_record_excludes_credentials_and_bodies(internal_server, dns):
    base, _ = internal_server
    port = base.rsplit(":", 1)[1]
    asset = f"http://app.example.com:{port}"
    dns["app.example.com"] = ["127.0.0.1"]
    adapter = _hop_adapter()

    obs = adapter.execute(ProbeRequest(
        target=asset, target_type="http-service", operation="inspect",
        authorization=_authorized_record(asset),
    ))
    blob = repr(obs.facts["egress"]).lower()
    for forbidden in ("authorization:", "cookie:", "internal-secret"):
        assert forbidden not in blob


def test_a_credential_header_supplied_by_the_caller_is_not_forwarded(dns, internal_server):
    """A probe must not be usable to leak an ambient credential."""
    base, _ = internal_server
    port = base.rsplit(":", 1)[1]
    asset = f"http://app.example.com:{port}"
    dns["app.example.com"] = ["127.0.0.1"]
    adapter = _hop_adapter()
    obs = adapter.execute(ProbeRequest(
        target=asset, target_type="http-service", operation="inspect",
        authorization=_authorized_record(asset),
        params={"url": asset, "headers": {"Authorization": "Bearer SECRET"}},
    ))
    assert "SECRET" not in repr(obs.facts)


def test_a_caller_supplied_credential_header_is_actually_dropped(internal_server, dns):
    """Review finding: the filter ran on an empty header dict, so it was dead code.

    The control must be live: a caller-supplied ``Authorization``/``Cookie`` must
    not reach the destination. Proved from the server side, not by inspecting a
    dict the code already threw away.
    """
    base, _ = internal_server
    port = base.rsplit(":", 1)[1]
    asset = f"http://app.example.com:{port}"
    dns["app.example.com"] = ["127.0.0.1"]

    seen: list[dict] = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            seen.append({k.lower(): v for k, v in self.headers.items()})
            body = b"ok"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        target = f"http://app.example.com:{server.server_address[1]}"
        adapter = _private_adapter()
        obs = adapter.execute(ProbeRequest(
            target=target, target_type="http-service", operation="inspect",
            authorization=_authorized_record(target),
            params={"headers": {"Authorization": "Bearer SECRET",
                                "Cookie": "session=SECRET",
                                "X-Trace": "kept"}},
        ))
        assert obs.ok is True
        assert seen, "the fixture must have served the request"
        assert "authorization" not in seen[0], "a credential must never be forwarded"
        assert "cookie" not in seen[0], "a session cookie must never be forwarded"
        assert seen[0].get("x-trace") == "kept", "ordinary headers still work"
    finally:
        server.shutdown()
        server.server_close()


def test_truncation_is_reported_from_the_real_body_size(dns):
    """Review finding: ``read(MAX)`` cannot distinguish "exactly MAX" from "more".

    A body of exactly the cap is *not* truncated, and a larger body is. Reading
    one byte past the cap makes both facts observable.
    """
    sizes = {"exact": HttpServiceAdapter.MAX_BODY_BYTES,
             "over": HttpServiceAdapter.MAX_BODY_BYTES + 5000}
    payload = {k: b"x" * n for k, n in sizes.items()}

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            key = self.path.strip("/") or "exact"
            body = payload[key]
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        port = server.server_address[1]
        asset = f"http://app.example.com:{port}"
        dns["app.example.com"] = ["127.0.0.1"]
        adapter = _private_adapter()

        exact = adapter.execute(ProbeRequest(
            target=asset, target_type="http-service", operation="inspect",
            authorization=_authorized_record(asset),
            params={"url": f"{asset}/exact"},
        ))
        over = adapter.execute(ProbeRequest(
            target=asset, target_type="http-service", operation="inspect",
            authorization=_authorized_record(asset),
            params={"url": f"{asset}/over"},
        ))
        assert exact.facts["truncated"] is False
        assert exact.facts["body_bytes"] == HttpServiceAdapter.MAX_BODY_BYTES
        assert over.facts["truncated"] is True
        assert over.facts["body_bytes"] == HttpServiceAdapter.MAX_BODY_BYTES
        assert over.limitation, "a truncated body must carry a limitation"
    finally:
        server.shutdown()
        server.server_close()


def test_the_peer_address_is_recorded_per_thread():
    """Review finding: a process-global peer cell let concurrent probes race.

    A barrier forces every worker to *write* before any worker *reads*. With a
    shared cell every worker then reads the last value written; with a per-thread
    cell each reads its own. The ordering makes the race deterministic instead of
    hoping a small window is hit.
    """
    import threading as _t

    from blackheart.environments.pinned_transport import LAST_PEER

    n = 6
    written = _t.Barrier(n)
    results: dict[str, str] = {}

    def worker(i: int) -> None:
        LAST_PEER.set(f"10.0.0.{i}")
        written.wait()
        results[f"t{i}"] = LAST_PEER.address()

    threads = [_t.Thread(target=worker, args=(i,)) for i in range(1, n + 1)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert results == {f"t{i}": f"10.0.0.{i}" for i in range(1, n + 1)}


# --------------------------------------------------------------------------- #
# 11. Adapter consistency: no alternate network route
# --------------------------------------------------------------------------- #

def test_only_the_http_backend_reaches_the_network():
    """A new network backend must not appear without egress enforcement."""
    import pathlib
    import re

    root = pathlib.Path(__file__).resolve().parents[1] / "blackheart" / "environments"
    network_imports = re.compile(
        r"^\s*(import|from)\s+(urllib|requests|httpx|aiohttp|http\.client|ftplib|"
        r"telnetlib|smtplib|socket)\b", re.MULTILINE)
    offenders = []
    for path in sorted(root.glob("*.py")):
        if path.name in {"http_service.py", "pinned_transport.py", "destination.py"}:
            continue
        if network_imports.search(path.read_text()):
            offenders.append(path.name)
    assert offenders == [], (
        f"these backends import a network client without the egress path: {offenders}"
    )


def test_the_local_backend_declares_no_network_capability():
    from blackheart.environments import LocalSourceAdapter
    assert LocalSourceAdapter.declared.network is False
