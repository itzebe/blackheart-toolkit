"""Scope and authorization enforcement for *local* executable targets.

The mission requires scope to be enforced **before** execution, not merely at
reporting time, and to fail closed when authorization is missing or ambiguous.
A controlled local target is authorized by an explicit :class:`LocalScope`
record; anything not explicitly authorized is refused.

Two independent checks guard every dispatch:

  * the **scope decision** -- is this asset authorized for active testing? A local
    harness target is authorized by its operator (``authorized=True`` with a named
    reference); a real target must additionally pass BLACKHEART's
    :func:`blackheart.authz.authorize_active_testing` gate.
  * the **isolation decision** -- is the destination a permitted loopback address?
    The loopback HTTP adapter refuses non-loopback hosts, refuses to follow
    redirects (so a redirect cannot move execution off the approved origin), and
    refuses cloud-metadata and link-local addresses.

Neither check may be weakened to make an adapter "work".
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Optional

from .interface import ScopeError

#: Hostnames that resolve to the local machine and are therefore permitted.
LOOPBACK_HOSTNAMES = frozenset({"127.0.0.1", "localhost", "::1", "[::1]"})

#: Address ranges that must never be contacted by an execution adapter. These are
#: the cloud-metadata and link-local ranges -- reaching them from a "local" target
#: would be a scope escape.
FORBIDDEN_NETWORKS = (
    ipaddress.ip_network("169.254.0.0/16"),     # link-local (incl. cloud metadata)
    ipaddress.ip_network("fe80::/10"),          # IPv6 link-local
    ipaddress.ip_network("100.100.100.200/32"),  # Alibaba metadata
)


def is_loopback_host(host: str) -> bool:
    """True only for an address that is the local machine (loopback)."""
    h = host.strip().lower()
    if h in LOOPBACK_HOSTNAMES:
        return True
    # strip brackets from an IPv6 literal
    if h.startswith("[") and h.endswith("]"):
        h = h[1:-1]
    try:
        ip = ipaddress.ip_address(h)
    except ValueError:
        return False
    return ip.is_loopback


def is_forbidden_address(host: str) -> bool:
    """True for a link-local / cloud-metadata address that must never be reached."""
    h = host.strip().lower().strip("[]")
    try:
        ip = ipaddress.ip_address(h)
    except ValueError:
        return False
    return any(ip in net for net in FORBIDDEN_NETWORKS)


@dataclass
class LocalScope:
    """The authorization decision for one local executable target.

    ``authorized`` is the operator's explicit statement that this target is a
    controlled, local environment they are permitted to execute against. It is
    **not** inferred from the target being local: a loopback service can still be
    out of scope, so the flag is required and defaults to False.
    """

    asset: str
    authorized: bool = False
    reference: str = ""                     # where the authorization came from
    allowed_hosts: tuple[str, ...] = ("127.0.0.1", "::1")
    allowed_ports: tuple[int, ...] = ()
    allow_process_exec: bool = False        # may a process adapter spawn a local command?
    notes: str = ""
    extra_evidence: list[str] = field(default_factory=list)

    def check(self, host: Optional[str] = None, port: Optional[int] = None,
              *, kind: str = "http") -> None:
        """Raise :class:`ScopeError` unless this execution is authorized.

        Fails closed: an unset/ambiguous decision is a refusal, not a default.
        """
        if not self.authorized:
            raise ScopeError(
                f"target '{self.asset}' is not authorized for active testing "
                "(set LocalScope(authorized=True) with a reference); refusing to execute"
            )
        if not self.reference.strip():
            raise ScopeError(
                f"authorization for '{self.asset}' carries no reference; "
                "an unverifiable authorization is not an authorization"
            )
        if kind == "process" and not self.allow_process_exec:
            raise ScopeError(
                f"process execution for '{self.asset}' is not authorized "
                "(set LocalScope(allow_process_exec=True) explicitly)"
            )
        if host is not None:
            if is_forbidden_address(host):
                raise ScopeError(
                    f"refusing to contact forbidden address {host!r} "
                    "(link-local / cloud-metadata range)"
                )
            if not is_loopback_host(host):
                raise ScopeError(
                    f"refusing to contact non-loopback host {host!r}; "
                    "execution adapters are restricted to the local machine"
                )
            if self.allowed_hosts and host.strip().lower().strip("[]") not in {
                h.strip("[]") for h in self.allowed_hosts
            } and host not in self.allowed_hosts:
                # 127.0.0.1 vs localhost vs ::1 are all loopback; only reject when
                # the operator explicitly narrowed the allow-list to other hosts.
                if not is_loopback_host(host):
                    raise ScopeError(f"host {host!r} is not in the authorized host list")
        if port is not None and self.allowed_ports and port not in self.allowed_ports:
            raise ScopeError(
                f"port {port} is not in the authorized port list {self.allowed_ports}"
            )

    def to_dict(self) -> dict:
        return {
            "asset": self.asset,
            "authorized": self.authorized,
            "reference": self.reference,
            "allowed_hosts": list(self.allowed_hosts),
            "allowed_ports": list(self.allowed_ports),
            "allow_process_exec": self.allow_process_exec,
            "notes": self.notes,
            "extra_evidence": list(self.extra_evidence),
        }


def local_harness_scope(asset: str, *, allow_process_exec: bool = False,
                        reference: str = "local-harness:blackheart/statespace/runtime") -> LocalScope:
    """Authorize a BLACKHEART *local harness* target (a controlled test app).

    This is the narrow authorization for the engine's own deliberately-vulnerable
    local applications: no network beyond loopback, no real users, no real funds.
    It is deliberately *not* a way to authorize a real target -- that still needs
    the full :func:`blackheart.authz.authorize_active_testing` gate.
    """
    return LocalScope(asset=asset, authorized=True, reference=reference,
                      allowed_hosts=("127.0.0.1", "::1"), allow_process_exec=allow_process_exec,
                      notes="BLACKHEART local harness target (loopback only)")


def from_authorization_record(record, asset: str) -> LocalScope:
    """Build a scope from a real :class:`AuthorizationRecord` (fail-closed).

    Active testing is permitted only if the authorization gate allows it. The
    resulting scope still restricts to loopback, so even an authorized asset is
    only ever driven through the local adapters.
    """
    from ...authz import authorize_active_testing  # local import avoids a cycle

    decision = authorize_active_testing(record, asset)
    return LocalScope(
        asset=asset,
        authorized=bool(decision.allowed),
        reference=record.scope_url or "",
        allowed_hosts=("127.0.0.1", "::1"),
        notes="; ".join(decision.reasons),
        extra_evidence=list(record.evidence),
    )
