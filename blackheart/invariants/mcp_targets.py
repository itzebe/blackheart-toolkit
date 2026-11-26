"""Executable targets for the MCP-server attack class.

A remote MCP server is an *authorization* surface before it is a tool surface:
an OAuth 2.1 protected resource whose tools act on a user's data with that
user's privileges. The classes below are the ones a bug-bounty program for an
MCP server actually accepts, modelled so the engine can *break* them rather than
describe them.

Two are executable here:

  * ``mcp-cors-credentials`` -- a protected resource that reflects an arbitrary
    ``Origin`` while also sending ``Access-Control-Allow-Credentials: true``.
    Any web origin (and ``Origin: null`` from a sandboxed iframe or ``file://``)
    may then read authenticated cross-origin responses, so a token a browser
    attaches is readable by the attacker's page. The guarded twin binds the
    response to an allowlist and refuses to pair a wildcard origin with
    credentials.

  * ``mcp-token-audience`` -- a verifier that checks a bearer token's signature
    and expiry but not its **audience** (which resource it was minted for) or
    its **tenant** (which cloudId/site it is bound to). A token issued for one
    resource -- or one tenant -- is then accepted by another. This is the
    audience/tenant-confusion class that appears whenever two resource versions
    or two issuers coexist (here, a legacy ``/v1`` resource and a ``/v2`` one,
    or a shared issuer serving many sites). The guarded twin binds the token to
    ``(audience, tenant)`` and rejects any other.

Three further accepted classes are **not** executed, and are recorded as such in
:mod:`blackheart.invariants.coverage` rather than faked: cross-tenant data
disclosure through tool calls, scope overreach (a granted scope reaching data it
should not), and resource-owner impersonation. They need a live tenant, a real
token, and a consent grant, so a model here would be theatre. The report names
them as hypotheses with a test plan, never as coverage.

Everything below is deterministic: no I/O, no network, no credentials, no funds.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .engine import InvariantSpec, OpSpec, PureState, Target


# --------------------------------------------------------------------------- #
# 1. CORS: reflected origin + allow-credentials
# --------------------------------------------------------------------------- #

@dataclass
class CorsState:
    #: Origins that received a credentialed cross-origin read of user data.
    leaked_to: set[str] = field(default_factory=set)
    #: The protected resource's allowlist (the intended readership).
    allowlist: set[str] = field(default_factory=set)
    requests: int = 0


class CorsResource(PureState, Target):
    """A protected resource that reflects any ``Origin`` with credentials allowed."""

    name = "mcp-cors-credentials"
    ACTORS = ["attacker", "victim"]
    #: ``null`` is a real, attacker-reachable origin (sandboxed iframe / file://).
    ORIGINS = ["https://evil.example", "null", "https://app.atlassian.com"]

    def reset(self) -> CorsState:
        return CorsState(allowlist={"https://app.atlassian.com"})

    def ops(self) -> list[OpSpec]:
        return [
            OpSpec("fetch_authenticated", self.ACTORS, {"origin": self.ORIGINS},
                   weight=6, description="browser GET of the resource with the user's token"),
            OpSpec("fetch_anonymous", self.ACTORS, {"origin": self.ORIGINS},
                   weight=2, description="browser GET with no credentials attached"),
        ]

    # -- the single control the guarded twin restores -- #
    def _allowed(self, origin: str) -> bool:
        """Vulnerable: every origin is allowed, including ``null``."""
        return True

    def step(self, st: CorsState, op_name: str, actor: str, params: dict[str, Any]) -> None:
        origin = params["origin"]
        st.requests += 1
        if not self._allowed(origin):
            return
        # A browser only exposes the *credentialed* body to a page script when the
        # response allows credentials; this resource always does.
        if op_name == "fetch_authenticated":
            st.leaked_to.add(origin)

    def invariants(self) -> list[InvariantSpec]:
        return [
            InvariantSpec(
                "no-cross-origin-credential-read",
                "no origin outside the resource's allowlist can read an authenticated "
                "cross-origin response",
                lambda st: not (st.leaked_to - st.allowlist),
                severity_if_broken="high",
            ),
            InvariantSpec(
                "no-null-origin-trust",
                "the opaque origin 'null' is never granted a credentialed read",
                lambda st: "null" not in st.leaked_to,
                severity_if_broken="high",
            ),
        ]

    def snapshot(self, st: CorsState) -> dict[str, Any]:
        return {"requests": st.requests, "leaked_to": sorted(st.leaked_to)}


class GuardedCorsResource(CorsResource):
    """The allowlist restored: only a listed origin, and never ``null``."""

    name = "mcp-cors-guarded"

    def _allowed(self, origin: str) -> bool:
        return origin != "null" and origin in self.reset().allowlist


# --------------------------------------------------------------------------- #
# 2. Token audience / tenant binding
# --------------------------------------------------------------------------- #

@dataclass
class TokenState:
    #: (audience, tenant) pairs the verifier accepted a token for.
    accepted_for: set[tuple[str, str]] = field(default_factory=set)
    #: Tenants whose data was actually returned.
    disclosed: set[str] = field(default_factory=set)
    #: Tenants the caller legitimately holds a grant for.
    entitled: set[str] = field(default_factory=set)
    calls: int = 0


class AudienceConfusedVerifier(PureState, Target):
    """A verifier that checks signature and expiry, but not audience or tenant."""

    name = "mcp-token-audience"
    ACTORS = ["attacker", "victim"]
    AUDIENCES = ["https://mcp.example/v1/mcp", "https://mcp.example/v2/mcp"]
    TENANTS = ["site-a", "site-b"]
    RESOURCE_AUDIENCE = "https://mcp.example/v1/mcp"

    def reset(self) -> TokenState:
        # The attacker legitimately holds a grant for site-a only. Everything
        # else is not theirs.
        return TokenState(entitled={"site-a"})

    def ops(self) -> list[OpSpec]:
        return [
            # Present a token minted for one (audience, tenant) to this resource.
            OpSpec("present_token", self.ACTORS,
                   {"audience": self.AUDIENCES, "tenant": self.TENANTS},
                   weight=6, description="call a tool with a bearer token"),
            OpSpec("list_tools", self.ACTORS, {"audience": self.AUDIENCES},
                   weight=1, description="tools/list on the resource"),
        ]

    # -- the single control the guarded twin restores -- #
    def _token_valid(self, audience: str, tenant: str) -> bool:
        """Vulnerable: signature+expiry were already checked upstream; no binding."""
        return True

    def step(self, st: TokenState, op_name: str, actor: str, params: dict[str, Any]) -> None:
        st.calls += 1
        if op_name != "present_token":
            return
        audience, tenant = params["audience"], params["tenant"]
        if not self._token_valid(audience, tenant):
            return
        st.accepted_for.add((audience, tenant))
        # Accepted means the tool executes with the token's privileges against
        # that tenant's data -- which is the disclosure.
        st.disclosed.add(tenant)

    def invariants(self) -> list[InvariantSpec]:
        return [
            InvariantSpec(
                "no-cross-tenant-disclosure",
                "no caller receives data from a tenant they hold no grant for",
                lambda st: not (st.disclosed - st.entitled),
                severity_if_broken="critical",
            ),
            InvariantSpec(
                "token-bound-to-resource",
                "a token is only accepted by the resource (audience) it was minted for",
                lambda st: all(aud == self.RESOURCE_AUDIENCE
                               for aud, _ in st.accepted_for),
                severity_if_broken="high",
            ),
        ]

    def snapshot(self, st: TokenState) -> dict[str, Any]:
        return {"calls": st.calls, "disclosed": sorted(st.disclosed)}


class GuardedAudienceVerifier(AudienceConfusedVerifier):
    """The binding restored: the token must match this resource *and* a granted tenant."""

    name = "mcp-token-guarded"

    def _token_valid(self, audience: str, tenant: str) -> bool:
        return audience == self.RESOURCE_AUDIENCE and tenant in self.reset().entitled
