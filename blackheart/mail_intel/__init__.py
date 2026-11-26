"""Secure, read-only Gmail intelligence for opportunity intake.

The integration brings relevant bounty-program messages (new programs, invitations,
scope changes, policy updates, known-issue updates, disclosures, deadlines, replies)
into BLACKHEART's **existing** authorized research workflow. It is read-only by
construction and never grants authority.

Components:

  * :mod:`~blackheart.mail_intel.oauth` -- the least-privilege scope policy. The
    only scope requested is ``gmail.readonly``, which Google classifies as
    *restricted*; the resulting verification requirement is recorded as a real
    blocker, not bypassed.
  * :mod:`~blackheart.mail_intel.trust` -- the trust boundary. A message is
    untrusted data; injection and authority-override text is flagged, never obeyed.
  * :mod:`~blackheart.mail_intel.gmail_client` -- a bounded, paginating, read-only
    client that fails honestly (a token that cannot be refreshed is ``EXPIRED``, not
    an empty mailbox).
  * :mod:`~blackheart.mail_intel.intake` -- extraction, dedupe, and delivery of an
    *opportunity candidate* through the existing :class:`TriggerReceiver`. An email
    never authorizes; the receiver still resolves scope against BLACKHEART's own
    records.
  * :mod:`~blackheart.mail_intel.manual_import` -- the zero-OAuth fallback that
    works today.

No operation here sends, forwards, modifies, deletes, submits, or announces
anything, and no message content can change authorization.
"""

from __future__ import annotations

from .gmail_client import GmailError, GmailReadOnlyClient, MessagePage, RawMessage
from .intake import Opportunity, OpportunityIntake
from .manual_import import ImportedMessage, ManualImporter
from .oauth import (
    FORBIDDEN_SCOPES,
    GMAIL_READONLY_SCOPE,
    GrantState,
    OAuthStatus,
    ScopeError,
    ScopeValidation,
    describe_requirement,
    validate_scopes,
)
from .trust import (
    ClaimKind,
    EmailClaim,
    MessageFacts,
    SourceTrust,
    classify_message,
    extract_links,
    fence_email,
    sender_domain,
)

__all__ = [
    "ClaimKind",
    "EmailClaim",
    "FORBIDDEN_SCOPES",
    "GMAIL_READONLY_SCOPE",
    "GmailError",
    "GmailReadOnlyClient",
    "GrantState",
    "ImportedMessage",
    "ManualImporter",
    "MessageFacts",
    "MessagePage",
    "OAuthStatus",
    "Opportunity",
    "OpportunityIntake",
    "RawMessage",
    "ScopeError",
    "ScopeValidation",
    "SourceTrust",
    "classify_message",
    "describe_requirement",
    "extract_links",
    "fence_email",
    "sender_domain",
    "validate_scopes",
]
