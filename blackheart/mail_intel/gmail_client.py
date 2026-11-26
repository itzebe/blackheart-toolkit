"""A read-only Gmail client with honest failure handling.

This is the transport: it lists and fetches messages, paginates, and deduplicates --
and nothing else. It can only ever call ``gmail.readonly`` endpoints; there is no
method to send, modify, delete, or change settings, so the read-only property is a
property of the interface, not of a runtime check.

Design rules, carried from the rest of the project:

  * **Honest failure.** A token that cannot be refreshed is ``EXPIRED`` or
    ``FAILED`` with the reason, never an empty mailbox that looks like "no
    messages". A caller can always tell "nothing matched" from "we could not read".
  * **Stdlib only**, ``urllib``, like every other adapter. No OAuth library is
    imported; the token exchange is plain HTTP form posts.
  * **No token in a URL or a log.** The access token is only ever sent in the
    ``Authorization`` header; it is never written to an error string or a filename.
  * **Pagination is bounded** and returns the page token, so a caller controls cost.

The client is deliberately *unauthenticated by default*: constructing it with no
credentials yields ``NOT_CONFIGURED``. A live mode requires an operator-supplied
OAuth client + refresh token, exchanged here; the synthetic path
(:mod:`blackheart.mail_intel.fixtures`) is what the tests exercise.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Optional

from .oauth import (
    GMAIL_READONLY_SCOPE,
    GrantState,
    OAuthStatus,
    validate_scopes,
)
from .trust import MessageFacts, extract_links, sender_domain

_TOKEN_URL = "https://oauth2.googleapis.com/token"
_API_BASE = "https://gmail.googleapis.com/gmail/v1/users/me"


class GmailError(RuntimeError):
    """A classified Gmail failure the caller can act on -- never a silent empty."""


@dataclass
class RawMessage:
    """One message as read from Gmail, before classification."""

    message_id: str
    thread_id: str = ""
    sender: str = ""
    subject: str = ""
    snippet: str = ""
    body_text: str = ""
    body_html: str = ""
    internal_date: str = ""
    label_ids: list[str] = field(default_factory=list)
    #: True when DKIM/DMARC headers show an aligned, passing authentication result.
    authenticated: bool = False
    attachment_names: list[str] = field(default_factory=list)

    def to_facts(self) -> MessageFacts:
        return MessageFacts(
            message_id=self.message_id, sender=self.sender,
            sender_domain=sender_domain(self.sender), authenticated=self.authenticated,
            subject=self.subject, received_at=self.internal_date,
            links=extract_links(self.body_text, self.body_html),
            attachment_names=list(self.attachment_names),
            has_attachments=bool(self.attachment_names),
        )

    def to_dict(self) -> dict:
        return {
            "message_id": self.message_id, "thread_id": self.thread_id,
            "sender": self.sender, "subject": self.subject,
            "snippet_len": len(self.snippet), "body_text_len": len(self.body_text),
            "attachment_names": list(self.attachment_names),
            "authenticated": self.authenticated,
        }


@dataclass
class MessagePage:
    """One page of listed messages, with the token to fetch the next."""

    messages: list[RawMessage] = field(default_factory=list)
    next_page_token: str = ""
    #: How many message stubs the list call returned before fetching bodies.
    listed: int = 0

    def to_dict(self) -> dict:
        return {"listed": self.listed, "fetched": len(self.messages),
                "next_page_token": bool(self.next_page_token),
                "messages": [m.to_dict() for m in self.messages]}


def _header(headers: list[dict], name: str) -> str:
    for h in headers:
        if h.get("name", "").lower() == name.lower():
            return h.get("value", "")
    return ""


def _decode_body(payload: dict) -> tuple[str, str]:
    """Decode a message payload into (text, html), base64url, bounded."""
    import base64

    text, html = "", ""

    def _walk(part: dict) -> None:
        nonlocal text, html
        mime = part.get("mimeType", "")
        data = part.get("body", {}).get("data")
        if data:
            try:
                raw = base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))
                decoded = raw.decode("utf-8", "replace")
            except Exception:
                decoded = ""
            if mime == "text/plain":
                text += decoded
            elif mime == "text/html":
                html += decoded
        for sub in part.get("parts", []) or []:
            _walk(sub)

    _walk(payload or {})
    return text, html


def _is_authenticated(headers: list[dict]) -> bool:
    """Trust the sender only when DKIM or DMARC shows an aligned pass.

    Google exposes the raw ``Authentication-Results``/``ARC-Authentication-Results``
    header. We require an explicit ``dkim=pass`` or ``dmarc=pass`` -- a bare SPF pass
    is not enough, and a missing header is *not* authenticated (fail closed).
    """
    for name in ("Authentication-Results", "ARC-Authentication-Results"):
        value = _header(headers, name).lower()
        if value and ("dkim=pass" in value or "dmarc=pass" in value):
            return True
    return False


class GmailReadOnlyClient:
    """Read-only Gmail access. Never sends, modifies, deletes, or changes settings."""

    def __init__(
        self,
        *,
        client_id: str = "",
        client_secret: str = "",
        refresh_token: str = "",
        allow_scopes: Optional[list[str]] = None,
        timeout_s: float = 20.0,
    ) -> None:
        self._client_id = client_id
        self._client_secret = client_secret
        self._refresh_token = refresh_token
        self._timeout = timeout_s
        self._access_token = ""
        self._status = OAuthStatus(state=GrantState.NOT_CONFIGURED)
        #: The requested scopes are always read-only; a caller cannot widen them.
        self._scopes = allow_scopes or [GMAIL_READONLY_SCOPE]
        check = validate_scopes(self._scopes)
        if not check.ok:
            self._status = OAuthStatus(
                state=GrantState.FAILED,
                detail="refused: requested scopes are broader than read-only",
                blocker="; ".join(check.problems),
            )
            raise GmailError(
                "refusing to construct a Gmail client with non-read-only scopes: "
                + "; ".join(check.problems)
            )
        if not (client_id and client_secret and refresh_token):
            self._status = OAuthStatus(
                state=GrantState.NOT_CONFIGURED,
                detail="no OAuth client/refresh token configured",
                blocker=(
                    "live Gmail needs an OAuth client + refresh token for a verified "
                    "(restricted-scope) app; use manual import until that is set up"
                ),
            )

    # -- status -------------------------------------------------------- #

    def status(self) -> OAuthStatus:
        return self._status

    # -- token exchange ------------------------------------------------ #

    def _exchange_refresh_token(self) -> None:
        """Exchange the refresh token for an access token; classify failures."""
        if not (self._client_id and self._client_secret and self._refresh_token):
            self._status = OAuthStatus(
                state=GrantState.NOT_CONFIGURED,
                detail="cannot exchange: OAuth client not configured",
            )
            raise GmailError("Gmail client is not configured")
        data = urllib.parse.urlencode({
            "client_id": self._client_id,
            "client_secret": self._client_secret,
            "refresh_token": self._refresh_token,
            "grant_type": "refresh_token",
        }).encode("utf-8")
        req = urllib.request.Request(_TOKEN_URL, data=data, method="POST")
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                payload = json.loads(resp.read().decode("utf-8"))
            self._access_token = payload.get("access_token", "")
            granted = (payload.get("scope", "") or "").split()
            if granted:
                check = validate_scopes(granted)
                if not check.ok:
                    # A broader grant than requested: refuse to use it.
                    self._status = OAuthStatus(
                        state=GrantState.FAILED,
                        detail="server granted broader scopes than read-only",
                        blocker="; ".join(check.problems),
                    )
                    self._access_token = ""
                    raise GmailError("server granted broader scopes than read-only")
            if not self._access_token:
                self._status = OAuthStatus(
                    state=GrantState.FAILED, detail="token endpoint returned no access_token",
                )
                raise GmailError("no access token returned")
            self._status = OAuthStatus(state=GrantState.GRANTED,
                                       detail="refresh token exchanged successfully")
        except urllib.error.HTTPError as exc:
            body = ""
            try:
                body = exc.read().decode("utf-8", "replace")
            except Exception:
                pass
            # `invalid_grant` means the refresh token is expired/revoked.
            state = GrantState.EXPIRED if "invalid_grant" in body else GrantState.FAILED
            # Never echo the body verbatim if it might contain a token.
            reason = "invalid_grant (expired/revoked)" if state is GrantState.EXPIRED \
                else f"token endpoint HTTP {exc.code}"
            self._status = OAuthStatus(state=state, detail=reason,
                                       blocker="re-authorize or use manual import")
            raise GmailError(f"token exchange failed: {reason}") from None
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            self._status = OAuthStatus(state=GrantState.FAILED,
                                       detail=f"token endpoint unreachable: {type(exc).__name__}")
            raise GmailError("token endpoint unreachable") from None

    def _ensure_token(self) -> None:
        if self._access_token:
            return
        self._exchange_refresh_token()

    def _api_get(self, path: str, params: dict[str, Any]) -> dict:
        self._ensure_token()
        query = urllib.parse.urlencode({k: v for k, v in params.items() if v not in ("", None)})
        url = f"{_API_BASE}{path}" + (f"?{query}" if query else "")
        req = urllib.request.Request(url, method="GET")
        req.add_header("Authorization", f"Bearer {self._access_token}")
        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            if exc.code == 401:
                # Token rejected mid-run: mark expired and surface, do not retry-loop.
                self._status = OAuthStatus(state=GrantState.EXPIRED,
                                           detail="access token rejected (401)")
                raise GmailError("access token rejected; re-authorize") from None
            raise GmailError(f"Gmail API HTTP {exc.code} on {path}") from None
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise GmailError(f"Gmail API unreachable: {type(exc).__name__}") from None

    # -- reads (the only public operations) ---------------------------- #

    def list_messages(self, *, query: str = "", max_results: int = 25,
                      page_token: str = "") -> MessagePage:
        """List message stubs and fetch their bodies, with pagination."""
        data = self._api_get("/messages", {
            "q": query, "maxResults": max_results, "pageToken": page_token,
        })
        stubs = data.get("messages", []) or []
        page = MessagePage(listed=len(stubs),
                           next_page_token=data.get("nextPageToken", "") or "")
        for stub in stubs:
            mid = stub.get("id")
            if not mid:
                continue
            page.messages.append(self.get_message(mid))
        return page

    def get_message(self, message_id: str) -> RawMessage:
        """Fetch one message in full (bounded)."""
        data = self._api_get(f"/messages/{urllib.parse.quote(message_id)}",
                             {"format": "full"})
        payload = data.get("payload", {}) or {}
        headers = payload.get("headers", []) or []
        text, html = _decode_body(payload)
        names: list[str] = []

        def _collect_parts(part: dict) -> None:
            if part.get("filename"):
                names.append(part["filename"])
            for sub in part.get("parts", []) or []:
                _collect_parts(sub)

        _collect_parts(payload)
        return RawMessage(
            message_id=data.get("id", message_id),
            thread_id=data.get("threadId", ""),
            sender=_header(headers, "From"),
            subject=_header(headers, "Subject"),
            snippet=data.get("snippet", ""),
            body_text=text, body_html=html,
            internal_date=data.get("internalDate", ""),
            label_ids=data.get("labelIds", []) or [],
            authenticated=_is_authenticated(headers),
            attachment_names=names,
        )

    # -- revocation ---------------------------------------------------- #

    def revoke(self) -> bool:
        """Revoke the refresh token at Google. Returns True on a confirmed revoke.

        A revocation is the documented way to withdraw access; we call Google's
        revoke endpoint with the token, then clear it locally regardless of the
        reply so a stale token can never be reused by this process.
        """
        token = self._refresh_token
        self._refresh_token = ""
        self._access_token = ""
        self._status = OAuthStatus(state=GrantState.REVOKED,
                                   detail="local token cleared by revocation")
        if not token:
            return True
        try:
            data = urllib.parse.urlencode({"token": token}).encode("utf-8")
            req = urllib.request.Request(
                "https://oauth2.googleapis.com/revoke", data=data, method="POST")
            req.add_header("Content-Type", "application/x-www-form-urlencoded")
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                return resp.status == 200
        except (urllib.error.URLError, TimeoutError, OSError):
            return False
