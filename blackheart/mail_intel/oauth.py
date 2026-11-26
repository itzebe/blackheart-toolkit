"""Least-privilege OAuth scope policy for read-only Gmail intelligence.

The integration is read-only by construction, and this module is where that is
enforced rather than promised. It states the *only* scope BLACKHEART will ever
request, refuses any broader one, and records the current Google requirement that
makes the narrowest read scope a **restricted** scope.

Verified against Google's published documentation (retrieved 2026-11-19):

  * ``https://developers.google.com/workspace/gmail/api/auth/scopes`` lists
    ``https://www.googleapis.com/auth/gmail.readonly`` ("View your email messages
    and settings") under **Restricted scopes**.
  * ``https://support.google.com/cloud/answer/9110914`` states that apps requesting
    restricted scopes must complete OAuth app verification (and restricted scopes
    require annual re-verification and, per Google's policy, a third-party security
    assessment).
  * ``https://developers.google.com/identity/protocols/oauth2`` states that a
    project with an External consent screen in "Testing" publishing status issues
    refresh tokens that expire in **7 days** (unless only basic profile scopes are
    requested).

Consequences, recorded honestly:

  * A live, unattended, long-lived Gmail integration requires Google verification
    of a restricted scope -- which in practice means a security assessment. That is
    a real deployment blocker for a no-cost, no-card setup. BLACKHEART does not
    bypass it and does not request a broader scope to avoid it.
  * In "Testing" mode the integration works for the owner's own account/test users,
    with a 7-day refresh-token lifetime the operator must renew.
  * Therefore a first-class **manual-import fallback** (:mod:`blackheart.mail_intel.manual_import`)
    exists so opportunity intake works with zero OAuth dependency.

Nothing here fetches the network or stores a token. It is the policy layer.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

#: The one and only scope BLACKHEART may request for this feature.
GMAIL_READONLY_SCOPE = "https://www.googleapis.com/auth/gmail.readonly"

#: Scopes that are explicitly forbidden: anything that can compose, send, modify,
#: delete, insert, or read broader settings. Requesting any of these is refused.
FORBIDDEN_SCOPES = frozenset({
    "https://mail.google.com/",
    "https://www.googleapis.com/auth/gmail.modify",
    "https://www.googleapis.com/auth/gmail.compose",
    "https://www.googleapis.com/auth/gmail.send",
    "https://www.googleapis.com/auth/gmail.insert",
    "https://www.googleapis.com/auth/gmail.labels",
    "https://www.googleapis.com/auth/gmail.settings.basic",
    "https://www.googleapis.com/auth/gmail.settings.sharing",
    "https://www.googleapis.com/auth/gmail.addons.current.action.compose",
})

#: Google's scope classification, recorded so the operator sees the cost of the
#: least-privilege choice rather than discovering it during verification.
GMAIL_SCOPE_CLASS = {
    GMAIL_READONLY_SCOPE: "restricted",
    "https://www.googleapis.com/auth/gmail.metadata": "restricted",
    "https://www.googleapis.com/auth/gmail.modify": "restricted",
    "https://www.googleapis.com/auth/gmail.send": "sensitive",
}

#: The facts that constrain deployment, with their sources. Kept as data so a
#: doc string cannot drift from what the code enforces.
OAUTH_FACTS = {
    "readonly_is_restricted": True,
    "verification_required_for_restricted": True,
    "annual_reverification_required": True,
    "testing_mode_refresh_token_days": 7,
    "sources": (
        "https://developers.google.com/workspace/gmail/api/auth/scopes",
        "https://support.google.com/cloud/answer/9110914",
        "https://developers.google.com/identity/protocols/oauth2",
    ),
    "retrieved": "2026-11-19",
}


class ScopeError(ValueError):
    """Raised when a requested scope set is broader than read-only."""


class GrantState(str, Enum):
    """The lifecycle of a Gmail grant, as observed -- never assumed."""

    NOT_CONFIGURED = "NOT_CONFIGURED"  # no client/credentials present
    CONFIGURED = "CONFIGURED"          # client present, no verified grant yet
    GRANTED = "GRANTED"                # a token exchange succeeded
    EXPIRED = "EXPIRED"                # refresh failed / token rejected
    REVOKED = "REVOKED"                # the operator revoked access
    FAILED = "FAILED"                  # an unrecoverable OAuth error


@dataclass
class ScopeValidation:
    """The result of validating a requested scope set."""

    ok: bool
    granted: list[str] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"ok": self.ok, "granted": list(self.granted),
                "problems": list(self.problems)}


def validate_scopes(requested: list[str]) -> ScopeValidation:
    """Refuse any request broader than read-only, and require the read scope.

    * Any forbidden scope -> fail.
    * A scope outside the allowlist -> fail (fail closed: an unknown scope may be
      broader than it looks).
    * The read-only scope must be present -> otherwise fail (nothing to do).
    """
    problems: list[str] = []
    for scope in requested:
        if scope in FORBIDDEN_SCOPES:
            problems.append(f"forbidden write/settings scope requested: {scope}")
        elif scope != GMAIL_READONLY_SCOPE:
            problems.append(f"scope outside the read-only allowlist: {scope}")
    if GMAIL_READONLY_SCOPE not in requested:
        problems.append("the read-only Gmail scope is required and was not requested")
    return ScopeValidation(ok=not problems, granted=[GMAIL_READONLY_SCOPE] if not problems
                           else [], problems=problems)


@dataclass
class OAuthStatus:
    """An honest, current status of the Gmail integration for the operator."""

    state: GrantState
    detail: str = ""
    #: Why a live integration is (or is not) possible here, in plain terms.
    blocker: str = ""
    #: When a live integration cannot run, the fallback that does.
    fallback: str = "manual-import"
    scopes: list[str] = field(default_factory=lambda: [GMAIL_READONLY_SCOPE])

    def to_dict(self) -> dict:
        return {
            "state": self.state.value, "detail": self.detail, "blocker": self.blocker,
            "fallback": self.fallback, "scopes": list(self.scopes),
            "oauth_facts": dict(OAUTH_FACTS),
        }


def describe_requirement() -> dict:
    """The documented Google requirement, for docs and the CLI."""
    return {
        "requested_scope": GMAIL_READONLY_SCOPE,
        "classification": GMAIL_SCOPE_CLASS.get(GMAIL_READONLY_SCOPE, "restricted"),
        "verification_required": OAUTH_FACTS["verification_required_for_restricted"],
        "annual_reverification": OAUTH_FACTS["annual_reverification_required"],
        "testing_mode_refresh_token_days": OAUTH_FACTS["testing_mode_refresh_token_days"],
        "blocker": (
            "A live unattended integration requires Google verification of a "
            "restricted Gmail scope (security assessment). BLACKHEART does not "
            "bypass verification. Use the owner's test-user grant (7-day refresh "
            "token, renewed by the operator) or the manual-import fallback."
        ),
        "sources": list(OAUTH_FACTS["sources"]),
    }
