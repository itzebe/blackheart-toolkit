"""A real HTTP/API backend: read-only requests against an authorized endpoint.

The third backend, and the only one that reaches the network. It is deliberately
minimal and read-only: a research probe can *inspect* an HTTP surface (status,
headers, a bounded body) so an API or web target can be reasoned about, but it
cannot send a state-changing request through this adapter.

Every request goes through one path, in this order, and no step is optional:

1. **Canonicalize** -- the URL becomes exactly one :class:`Destination`
   (:mod:`blackheart.environments.destination`). Scheme, host, port, path,
   userinfo, IDNA, IPv4/IPv6 literal form and IPv4-mapped IPv6 are resolved once,
   here. Downstream code never re-parses the original string.
2. **Bind to the authorized asset** -- the canonical host must be the authorized
   asset's host. An authorized asset may not be used to reach another host.
3. **Resolve under policy** -- the host is resolved and *every* answer is
   classified. A prohibited answer fails the whole resolution.
4. **Pin** -- the socket is opened to the validated address, so the address that
   was checked is the address contacted. The hostname is kept for TLS and Host.
5. **Re-authorize every redirect** -- each hop repeats 1-4 as a fresh decision.

The result carries an :class:`EgressRecord` describing exactly what happened, so a
blocked request is auditable and is never reported as a successful probe.
"""

from __future__ import annotations

import hashlib
import ssl
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Optional

from ..models import utcnow
from .adapter import (
    AdapterState,
    Capabilities,
    ExecutionAdapter,
    Observation,
    ProbeRequest,
    ProbeResult,
)
from .destination import (
    Destination,
    DestinationError,
    DestinationPolicy,
    ResolutionError,
    SecureResolver,
    canonicalize,
)
from .pinned_transport import LAST_PEER, build_pinned_opener, tls_verification_enabled

#: Headers that must never be inherited from the environment into a probe.
_NEVER_FORWARD = frozenset({"authorization", "cookie", "proxy-authorization"})

#: Methods this adapter allows. Read-only by construction.
_READ_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})

#: Redirect statuses. Each one is a *new* authorization decision, never a hop the
#: transport follows on its own.
_REDIRECT_CODES = frozenset({301, 302, 303, 307, 308})

#: A redirect chain longer than this is refused as a loop/livelock signal.
MAX_REDIRECTS = 5


@dataclass
class EgressRecord:
    """The audit trail for one HTTP execution decision.

    Deliberately excludes credentials, cookies and response bodies: it records
    *which destination was contacted and why it was allowed*, not what came back.
    """

    requested_url: str
    authorized_asset: str
    policy: str
    hops: list[dict[str, Any]] = field(default_factory=list)
    outcome: str = ""
    reason: str = ""
    created_at: str = field(default_factory=utcnow)

    def add_hop(self, **kw: Any) -> None:
        self.hops.append({"at": utcnow(), **kw})

    def to_dict(self) -> dict:
        return {
            "requested_url": self.requested_url,
            "authorized_asset": self.authorized_asset,
            "policy": self.policy,
            "hops": list(self.hops),
            "outcome": self.outcome,
            "reason": self.reason,
            "created_at": self.created_at,
        }


class HttpServiceAdapter(ExecutionAdapter):
    """Inspect an authorized HTTP/API endpoint, read-only, on a pinned connection."""

    name = "http-service"

    declared = Capabilities(
        target_types=("http-service", "web-application", "remote-service"),
        operations=("inspect", "enumerate", "capture", "execute"),
        network=True,
        state_control=False,
        transactions=False,
        snapshot_rollback=False,
        evidence_capture=True,
        evidence_tier="real-execution",
        limitations=[
            "read-only: GET/HEAD/OPTIONS only, never a state-changing request",
            "redirects are not followed by the transport; each hop is re-authorized",
            "response body capped; large or streaming endpoints are truncated",
            "no authenticated probing: never forwards ambient credentials",
        ],
        required_permissions=["network reachability to the authorized host"],
        safety_constraints=[
            "http/https only; every redirect re-authorized; body capped",
            "Authorization/Cookie headers never inherited from the environment",
            "every connection pinned to a policy-validated address",
        ],
    )

    MAX_BODY_BYTES = 512_000

    def __init__(self, *, timeout_s: float = 15.0, allow_hosts: tuple[str, ...] = (),
                 policy: Optional[DestinationPolicy] = None,
                 resolver: Optional[SecureResolver] = None,
                 follow_redirects: bool = True):
        self._timeout = timeout_s
        self._allow_hosts = tuple(h.lower() for h in allow_hosts)
        self._policy = policy or DestinationPolicy()
        self._resolver = resolver or SecureResolver(self._policy)
        #: Redirects are followed only as a sequence of fresh authorization
        #: decisions; the transport itself never follows one.
        self._follow_redirects = follow_redirects
        super().__init__()

    # -- probe --------------------------------------------------------- #

    def _probe(self) -> ProbeResult:
        try:
            urllib.request.build_opener()
        except Exception as exc:
            return ProbeResult(
                state=AdapterState.MISCONFIGURED,
                detail=f"urllib opener unavailable: {type(exc).__name__}: {exc}",
            )
        confirmed = Capabilities(
            target_types=self.declared.target_types,
            operations=self.declared.operations,
            tools={"urllib": True},
            network=True,
            state_control=False,
            transactions=False,
            snapshot_rollback=False,
            evidence_capture=True,
            evidence_tier="real-execution",
            limitations=list(self.declared.limitations),
            required_permissions=list(self.declared.required_permissions),
            safety_constraints=list(self.declared.safety_constraints),
        )
        if self._allow_hosts:
            confirmed.safety_constraints.append(
                f"restricted to hosts: {', '.join(self._allow_hosts)}"
            )
        if self._policy.allow_private:
            confirmed.safety_constraints.append(
                "operator enabled private destinations (recorded per request)"
            )
        return ProbeResult(state=AdapterState.READY, detail="stdlib urllib available",
                           confirmed=confirmed)

    # -- authorization helpers ----------------------------------------- #

    @staticmethod
    def _host_of(value: str) -> str:
        try:
            return canonicalize(value).host
        except DestinationError:
            return (urllib.parse.urlsplit(value).hostname or "").lower()

    def _authorize(self, dest: Destination, authorized: Optional[Destination]) -> Optional[str]:
        """Return a refusal reason, or ``None`` when the destination is allowed.

        The authorized *authority* is the host **and** the port. Binding on the
        host alone would let an asset granted at ``app.example.com:8080`` reach
        ``app.example.com:22`` -- a different service that was never in scope. The
        asset string is the grant, so the port it names is part of the grant.
        """
        if self._allow_hosts and dest.host not in self._allow_hosts:
            return (f"host '{dest.host}' is not in this backend's allowlist "
                    f"({', '.join(self._allow_hosts)})")
        if authorized is None:
            return None
        if dest.host != authorized.host:
            return (f"refusing to fetch '{dest.host}': the authorized asset is "
                    f"'{authorized.host}'; a probe may not widen scope")
        if dest.port != authorized.port:
            return (f"refusing to fetch '{dest.host}:{dest.port}': the authorized "
                    f"asset is '{authorized.host}:{authorized.port}'; a probe may "
                    "not widen scope to another port")
        return None

    # -- execution ------------------------------------------------------ #

    def _execute(self, request: ProbeRequest, caps: Capabilities) -> Observation:
        url = request.params.get("url") or request.target
        method = str(request.params.get("method", "GET")).upper()
        if method not in _READ_METHODS:
            return Observation(
                adapter=self.name, target=request.target, operation=request.operation,
                ok=False, evidence_tier=caps.evidence_tier,
                error=f"method '{method}' is not allowed; this backend is read-only",
            )

        record = EgressRecord(
            requested_url=str(url), authorized_asset=request.asset_id,
            policy=("allow_private" if self._policy.allow_private else "global-unicast-only"),
        )
        try:
            authorized = canonicalize(request.asset_id)
        except DestinationError as exc:
            # Fail closed. This backend's control is "the URL is the authorized
            # asset"; if the asset cannot be canonicalized there is nothing to bind
            # the request to, so no request may be issued. Dropping the binding and
            # proceeding would send an authorized-looking probe to any destination.
            record.outcome = "blocked"
            record.reason = f"authorized asset '{request.asset_id}' is not a URL: {exc}"
            record.add_hop(url=str(url), decision="blocked", reason=record.reason)
            return self._blocked(request, caps, record, record.reason)

        current = str(url)
        for _hop in range(MAX_REDIRECTS + 1):
            # 1. canonicalize -- one interpretation, or refuse.
            try:
                dest = canonicalize(current)
            except DestinationError as exc:
                record.outcome = "blocked"
                record.reason = f"destination rejected: {exc}"
                record.add_hop(url=current, decision="blocked", reason=str(exc))
                return self._blocked(request, caps, record, record.reason)

            # 2. authorization -- the asset decides, not the URL.
            refusal = self._authorize(dest, authorized)
            if refusal:
                record.outcome = "blocked"
                record.reason = refusal
                record.add_hop(url=current, canonical=dest.to_dict(),
                               decision="blocked", reason=refusal)
                return self._blocked(request, caps, record, refusal)

            # 3. resolve every answer under policy.
            try:
                resolution = self._resolver.resolve(dest)
            except ResolutionError as exc:
                record.outcome = "blocked"
                record.reason = str(exc)
                record.add_hop(url=current, canonical=dest.to_dict(),
                               decision="blocked", reason=str(exc))
                return self._blocked(request, caps, record, str(exc))

            # 4. pin -- connect to a validated address, keep the name for TLS.
            hop_record: dict[str, Any] = {
                "url": current,
                "canonical": dest.to_dict(),
                "decision": "authorized",
                "resolution": resolution.to_dict(),
                "selected_address": str(resolution.primary),
            }
            try:
                status, headers, body, peer = self._fetch(
                    dest, resolution, method,
                    request.params.get("headers"),
                )
            except _RedirectTo as redirect:
                hop_record.update(status=redirect.status,
                                  redirect_to=redirect.location)
                record.add_hop(**hop_record)
                if not self._follow_redirects:
                    record.outcome = "redirect_refused"
                    record.reason = f"redirect to {redirect.location} not followed"
                    return self._blocked(
                        request, caps, record,
                        f"server redirected to {redirect.location}; redirects are "
                        "disabled for this backend",
                    )
                if not redirect.location:
                    record.outcome = "blocked"
                    record.reason = "redirect without a Location header"
                    return self._blocked(request, caps, record, record.reason)
                current = urllib.parse.urljoin(current, redirect.location)
                continue
            except _EgressFailure as failure:
                hop_record.update(decision="failed", reason=str(failure))
                record.add_hop(**hop_record)
                record.outcome = "failed"
                record.reason = str(failure)
                return self._failed(request, caps, record, str(failure))

            hop_record.update(status=status, peer_address=peer,
                              tls_verified=dest.scheme == "https")
            record.add_hop(**hop_record)
            record.outcome = "executed"
            record.reason = f"HTTP {status} from {peer}"
            # One byte past the cap was requested, so this is a fact about the
            # response rather than an inference from a full buffer.
            truncated = len(body) > self.MAX_BODY_BYTES
            body = body[: self.MAX_BODY_BYTES]
            return Observation(
                adapter=self.name, target=request.target, operation=request.operation,
                ok=True, evidence_tier="real-execution",
                raw=body.decode("utf-8", "replace"),
                facts={
                    "url": current, "method": method, "status": status,
                    "headers": headers, "body_sha256": hashlib.sha256(body).hexdigest(),
                    "body_bytes": len(body), "truncated": truncated,
                    "peer_address": peer,
                    "canonical_host": dest.host,
                    "egress": record.to_dict(),
                },
                limitation="response body truncated" if truncated else "",
            )

        record.outcome = "blocked"
        record.reason = f"exceeded {MAX_REDIRECTS} redirects"
        record.add_hop(url=current, decision="blocked", reason="redirect limit")
        return self._blocked(request, caps, record, record.reason)

    # -- one pinned request --------------------------------------------- #

    def _fetch(self, dest: Destination, resolution, method: str,
               extra_headers: Optional[dict] = None):
        """Issue exactly one request to the pinned address. Raises on failure."""
        context = ssl.create_default_context()
        opener = build_pinned_opener(
            str(resolution.primary), dest.scheme,
            timeout=self._timeout, context=context,
        )
        if not tls_verification_enabled(context):  # pragma: no cover - defensive
            raise _EgressFailure("refusing to connect with TLS verification disabled")

        # The URL carries the canonical host, never the pinned IP: http.client
        # builds the Host header from it and ssl uses it for SNI/verification.
        # Only the socket destination is overridden, inside the opener.
        req = urllib.request.Request(f"{dest.scheme}://{dest.host_header}{dest.path}",
                                     method=method)
        for name, value in (extra_headers or {}).items():
            if name.strip().lower() in _NEVER_FORWARD:
                # A credential must never ride a probe: it would be an ambient
                # secret leaked to whatever the destination turns out to be.
                continue
            req.add_header(name, value)

        try:
            with opener.open(req, timeout=self._timeout) as resp:
                body = resp.read(self.MAX_BODY_BYTES + 1)
                status = resp.status
                headers = dict(resp.headers.items())
                peer = LAST_PEER.address() or _peer_of(resp)
        except urllib.error.HTTPError as exc:
            location = exc.headers.get("Location") if exc.headers else None
            if exc.code in _REDIRECT_CODES:
                raise _RedirectTo(exc.code, location) from None
            body = (exc.read(self.MAX_BODY_BYTES + 1)
                    if hasattr(exc, "read") else b"")
            return exc.code, dict(exc.headers.items()) if exc.headers else {}, body, \
                (LAST_PEER.address() or _peer_of(exc))
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise _EgressFailure(f"request failed: {type(exc).__name__}: {exc}") from exc
        return status, headers, body, peer

    # -- result constructors -------------------------------------------- #

    def _blocked(self, request: ProbeRequest, caps: Capabilities,
                 record: EgressRecord, reason: str) -> Observation:
        """A refusal is a BLOCKED outcome, never a successful probe."""
        return Observation(
            adapter=self.name, target=request.target, operation=request.operation,
            ok=False, evidence_tier=caps.evidence_tier,
            error=f"egress blocked: {reason}",
            facts={"egress": record.to_dict(), "blocked": True},
            limitation="request was not executed: egress policy refused it",
        )

    def _failed(self, request: ProbeRequest, caps: Capabilities,
                record: EgressRecord, reason: str) -> Observation:
        return Observation(
            adapter=self.name, target=request.target, operation=request.operation,
            ok=False, evidence_tier=caps.evidence_tier,
            error=f"request failed: {reason}",
            facts={"egress": record.to_dict(), "blocked": False},
            limitation="endpoint unreachable or timed out",
        )


class _RedirectTo(Exception):
    """Internal: the peer answered with a redirect that must be re-authorized."""

    def __init__(self, status: int, location: Optional[str]):
        super().__init__(f"redirect {status} -> {location}")
        self.status = status
        self.location = location


class _EgressFailure(Exception):
    """Internal: the request could not be completed."""


def _peer_of(response) -> str:
    """Best-effort peer address, for the audit trail."""
    try:
        sock = getattr(response, "fp", None)
        raw = getattr(sock, "raw", None)
        conn = getattr(raw, "_sock", None)
        if conn is not None:
            return str(conn.getpeername()[0])
    except Exception:
        pass
    return ""
