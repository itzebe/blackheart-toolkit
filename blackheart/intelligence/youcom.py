"""You.com client for BLACKHEART's external intelligence layer.

Implements the three You.com REST APIs BLACKHEART needs, with the project's
honesty, key-safety, and cost-safety rules:

  * **Web Search API**  -- ``POST https://ydc-index.io/v1/search``  (snippets are
    the default and are not billed as page extraction; requesting highlights or
    full-page content turns on paid extraction).
  * **Contents API**    -- ``POST https://ydc-index.io/v1/contents`` (paid: fetches
    the Markdown/HTML of given URLs).
  * **Research API**    -- ``POST https://api.you.com/v1/research``  (paid: a
    citation-backed answer synthesised from multiple searches).

Authentication is the ``X-API-Key`` header (the Inference Router uses a Bearer
token instead; that is a different layer and is not used here).

Cost safety: the paid paths refuse to run unless ``allow_paid=True``, and the
client enforces a hard per-instance cap (``max_paid_calls``). The refusal is a
distinct :class:`CostRefusal`, so a caller can never mistake "I chose not to
spend" for "the service failed".

Key safety: the key is read from ``YDC_API_KEY`` (or passed in), sent only in the
``X-API-Key`` header, and scrubbed from every error message before it is returned.

Untrusted input: every result is external data. It is returned as data, framed
with the attacker question, and never executed or treated as an instruction.
"""

from __future__ import annotations

import json
import os
import re
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Optional

from ..mindset import ATTACKER_QUESTION, LEVERS, OUTCOMES

#: Endpoints (from https://you.com/docs/guides/search, /contents, /research).
SEARCH_URL = "https://ydc-index.io/v1/search"
CONTENTS_URL = "https://ydc-index.io/v1/contents"
RESEARCH_URL = "https://api.you.com/v1/research"

#: The environment variable the key is read from (the documented convention).
KEY_ENV = "YDC_API_KEY"

#: Provenance tag attached to every result this client produces.
PROVIDER_NAME = "you.com"

#: Sent on every request. api.you.com rejects the default urllib UA (403/1010).
USER_AGENT = "blackheart-intelligence/1.0"

#: Research effort levels, cheapest first. ``frontier`` is background-only.
RESEARCH_EFFORTS = ("lite", "standard", "deep", "exhaustive", "frontier")

MAX_INPUT_CHARS = 40_000

#: Generic shape of a You.com API key. Used to scrub a key from any message
#: even when the exact value is not known to the redactor (e.g. a proxy or
#: upstream that echoes the credential back in its error body).
_KEY_PATTERN = re.compile(r"\bydc-[A-Za-z0-9_\-]{8,}\b")


def redact_secrets(text: str, *, api_key: str = "") -> str:
    """Scrub the API key (exact value if known, and any ``ydc-`` token) from text.

    This is the single redactor for the whole module: the client uses it on every
    message it builds, and :class:`YouComError` uses it on construction, so no
    error can carry a key even if a caller forgets to scrub it first.
    """
    if not text:
        return text
    if api_key:
        text = text.replace(api_key, "<redacted>")
    return _KEY_PATTERN.sub("<redacted>", text)


class ErrorKind:
    """Why a request failed, as a value a caller can branch on.

    Mission requirement: unavailable credentials, invalid credentials, missing
    scope, rate limits, network errors, and service errors must be
    distinguishable -- a caller that wants to fall back (or not) needs to know
    *which* failure it hit, not just that something failed.
    """

    MISSING_KEY = "missing_key"                # no key configured at all
    INVALID_KEY = "invalid_key"                # HTTP 401
    INSUFFICIENT_SCOPE = "insufficient_scope"  # HTTP 403 (may be Cloudflare 1010)
    PAYMENT_REQUIRED = "payment_required"      # HTTP 402
    RATE_LIMITED = "rate_limited"              # HTTP 429
    INVALID_REQUEST = "invalid_request"        # HTTP 400/422
    SERVER_ERROR = "server_error"              # HTTP 5xx (after retries)
    NETWORK = "network"                        # timeout / DNS / connection reset
    UNKNOWN = "unknown"


class YouComError(RuntimeError):
    """A You.com request failed. The message never contains the API key.

    The redaction is enforced here, not left to callers: the message is scrubbed
    on construction (exact key when supplied, and any ``ydc-`` token), so the
    promise holds even for a caller that raises with an unscrubbed upstream body.

    ``kind`` is one of :class:`ErrorKind`; ``status`` is the HTTP status when the
    failure was an HTTP error, else ``0``.
    """

    def __init__(self, message: str, *, kind: str = ErrorKind.UNKNOWN,
                 status: int = 0, api_key: str = "") -> None:
        super().__init__(redact_secrets(message, api_key=api_key))
        self.kind = kind
        self.status = status


def kind_for_status(status: int) -> str:
    """Map an HTTP status to an :class:`ErrorKind`."""
    if status == 401:
        return ErrorKind.INVALID_KEY
    if status == 403:
        return ErrorKind.INSUFFICIENT_SCOPE
    if status == 402:
        return ErrorKind.PAYMENT_REQUIRED
    if status == 429:
        return ErrorKind.RATE_LIMITED
    if status in (400, 422):
        return ErrorKind.INVALID_REQUEST
    if 500 <= status < 600:
        return ErrorKind.SERVER_ERROR
    return ErrorKind.UNKNOWN


class CostRefusal(RuntimeError):
    """A paid You.com call was attempted without explicit permission.

    This is *not* a service failure: it is BLACKHEART declining to spend. It is a
    separate type so callers never conflate the two.
    """


@dataclass
class Source:
    """One external source (a search result or a research citation).

    ``provider`` records *which* provider supplied this source, so an agent can
    attribute a claim to its origin and a merged multi-provider result set keeps
    each source's provenance intact (mission requirement: provider provenance).
    """

    url: str
    title: str = ""
    snippets: list[str] = field(default_factory=list)
    description: str = ""
    page_age: str = ""
    provider: str = ""

    def to_dict(self) -> dict:
        return {"url": self.url, "title": self.title,
                "snippets": list(self.snippets),
                "description": self.description, "page_age": self.page_age,
                "provider": self.provider}


@dataclass
class Document:
    """A fetched page's content."""

    url: str
    title: str = ""
    markdown: str = ""
    html: str = ""

    def to_dict(self) -> dict:
        return {"url": self.url, "title": self.title,
                "markdown": self.markdown, "html": self.html}


@dataclass
class IntelResult:
    """The honest result of one intelligence operation.

    ``ok`` is the single success flag. ``paid`` records whether the call was a
    billable one. ``sources``/``documents``/``text`` carry whatever the service
    returned; ``warnings`` carries the service's own warnings verbatim.
    """

    operation: str                    # search | contents | research | health
    ok: bool = False
    error: str = ""
    error_kind: str = ""              # an ErrorKind value, when the call failed
    text: str = ""                    # research answer (Markdown), when present
    content_type: str = ""            # text | object
    sources: list[Source] = field(default_factory=list)
    documents: list[Document] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    paid: bool = False
    latency_ms: float = 0.0
    raw_status: int = 0
    query: str = ""
    provider: str = ""                # which provider answered (provenance)

    def to_dict(self) -> dict:
        return {
            "operation": self.operation, "ok": self.ok, "error": self.error,
            "error_kind": self.error_kind,
            "text": self.text, "content_type": self.content_type,
            "sources": [s.to_dict() for s in self.sources],
            "documents": [d.to_dict() for d in self.documents],
            "warnings": list(self.warnings), "paid": self.paid,
            "latency_ms": round(self.latency_ms, 1), "raw_status": self.raw_status,
            "query": self.query, "provider": self.provider,
        }


def frame_question() -> dict:
    """The attacker lens, attached to every intelligence result.

    External intelligence is only useful to BLACKHEART if it is read through the
    one question. This returns the canonical question, the three outcomes, and
    the five levers, so a caller can frame findings without restating them.
    """
    return {
        "question": ATTACKER_QUESTION,
        "outcomes": list(OUTCOMES),
        "levers": list(LEVERS),
    }


class YouComClient:
    """A minimal, honest You.com REST client (standard library only)."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        *,
        allow_paid: bool = False,
        max_paid_calls: int = 0,
        timeout: int = 30,
        max_retries: int = 2,
    ) -> None:
        self._api_key = (api_key if api_key is not None
                         else os.environ.get(KEY_ENV, "")).strip()
        self.allow_paid = allow_paid
        # A cap of 0 with allow_paid=False means "no paid calls". A caller that
        # opts in must also set a positive cap; 0 stays the safe default.
        self.max_paid_calls = max_paid_calls
        self.timeout = timeout
        self.max_retries = max_retries
        self._paid_calls = 0

    # -- capability / safety --------------------------------------------- #
    @property
    def key_present(self) -> bool:
        return bool(self._api_key)

    @property
    def paid_calls(self) -> int:
        return self._paid_calls

    def _redact(self, text: str) -> str:
        """Scrub the API key (and any ydc- token) from a string."""
        return redact_secrets(text, api_key=self._api_key)

    def _authorize_paid(self, operation: str) -> Optional[str]:
        """Return a refusal reason, or None when the paid call may proceed."""
        if not self.allow_paid:
            return (f"{operation} is a paid You.com operation and paid calls are "
                    "disabled (set allow_paid=True to permit it)")
        if self._paid_calls >= self.max_paid_calls:
            return (f"{operation} refused: paid-call cap reached "
                    f"({self._paid_calls}/{self.max_paid_calls})")
        return None

    # -- transport -------------------------------------------------------- #
    def _post(self, url: str, body: dict, *, paid: bool) -> tuple[dict, int]:
        if not self._api_key:
            raise YouComError(
                f"no You.com API key in ${KEY_ENV} (and none passed in); "
                f"set it and re-run, or use a free fallback provider",
                kind=ErrorKind.MISSING_KEY)
        data = json.dumps(body).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "X-API-Key": self._api_key,
            # api.you.com (Research/Answer) sits behind Cloudflare and rejects the
            # default urllib User-Agent with a 403 (error 1010). A plain, honest
            # UA is required; ydc-index.io does not care but is unaffected.
            "User-Agent": USER_AGENT,
        }
        attempt = 0
        last_error = ""
        while attempt <= self.max_retries:
            req = urllib.request.Request(url, data=data, headers=headers, method="POST")
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    payload = json.loads(resp.read().decode("utf-8"))
                if paid:
                    self._paid_calls += 1
                return payload, resp.status
            except urllib.error.HTTPError as exc:
                status = exc.code
                detail = ""
                try:
                    detail = exc.read().decode("utf-8")[:400]
                except Exception:  # pragma: no cover - body may be unreadable
                    pass
                last_error = self._redact(f"HTTP {status}: {detail}")
                # 401/403/402/422 are caller problems, not transient: no retry.
                if status == 429 or 500 <= status < 600:
                    retry_after = exc.headers.get("Retry-After") if exc.headers else None
                    attempt += 1
                    if attempt <= self.max_retries:
                        time.sleep(self._backoff(attempt, retry_after))
                        continue
                raise YouComError(last_error, kind=kind_for_status(status),
                                  status=status, api_key=self._api_key)
            except (urllib.error.URLError, TimeoutError, OSError) as exc:
                last_error = self._redact(f"{type(exc).__name__}: {exc}")
                attempt += 1
                if attempt <= self.max_retries:
                    time.sleep(self._backoff(attempt, None))
                    continue
                raise YouComError(last_error or "unknown transport error",
                                  kind=ErrorKind.NETWORK, api_key=self._api_key)
        raise YouComError(last_error or "unknown transport error",
                          kind=ErrorKind.NETWORK, api_key=self._api_key)

    @staticmethod
    def _backoff(attempt: int, retry_after: Optional[str]) -> float:
        if retry_after:
            try:
                return min(float(retry_after), 30.0)
            except ValueError:
                pass
        return min(2.0 ** (attempt - 1), 8.0)

    # -- Web Search API --------------------------------------------------- #
    def search(
        self,
        query: str,
        *,
        count: int = 10,
        freshness: str = "",
        country: str = "",
        language: str = "",
        safesearch: str = "",
        include_domains: Optional[list[str]] = None,
        exclude_domains: Optional[list[str]] = None,
        extract: str = "",
    ) -> IntelResult:
        """Search the web. Snippets by default; ``extract`` turns on paid extraction.

        ``extract`` is one of ``""`` (snippets, no page fetch), ``"highlights"``
        (query-relevant passages), or ``"full_page"``. The latter two are billed,
        so they require ``allow_paid``.
        """
        result = IntelResult(operation="search", query=query,
                             provider=PROVIDER_NAME)
        if not query.strip():
            result.error = "empty query"
            return result
        if extract not in ("", "highlights", "full_page"):
            result.error = f"unknown extract mode {extract!r}"
            return result
        paid = extract in ("highlights", "full_page")
        if paid:
            refusal = self._authorize_paid(f"search extraction ({extract})")
            if refusal is not None:
                raise CostRefusal(refusal)
        body: dict[str, Any] = {"query": query, "count": max(1, min(count, 100))}
        if freshness:
            body["freshness"] = freshness
        if country:
            body["country"] = country
        if language:
            body["language"] = language
        if safesearch:
            body["safesearch"] = safesearch
        if include_domains and exclude_domains:
            result.error = "include_domains and exclude_domains cannot be combined"
            return result
        if include_domains:
            body["include_domains"] = include_domains
        if exclude_domains:
            body["exclude_domains"] = exclude_domains
        if extract:
            body["extraction"] = {"extraction_mode": extract}

        start = time.monotonic()
        try:
            payload, status = self._post(SEARCH_URL, body, paid=paid)
        except CostRefusal:
            raise
        except YouComError as exc:
            result.error = str(exc)
            result.error_kind = exc.kind
            result.latency_ms = (time.monotonic() - start) * 1000
            return result
        result.latency_ms = (time.monotonic() - start) * 1000
        result.raw_status = status
        result.paid = paid
        result.ok = True
        result.sources = self._parse_web_results(payload)
        return result

    @staticmethod
    def _parse_web_results(payload: dict) -> list[Source]:
        results = (payload or {}).get("results") or {}
        web = results.get("web") or []
        sources: list[Source] = []
        for item in web:
            if not isinstance(item, dict):
                continue
            url = str(item.get("url") or "").strip()
            if not url:
                continue
            snippets = item.get("snippets") or []
            if not isinstance(snippets, list):
                snippets = [str(snippets)]
            sources.append(Source(
                url=url,
                title=str(item.get("title") or ""),
                snippets=[str(s) for s in snippets],
                description=str(item.get("description") or ""),
                page_age=str(item.get("page_age") or ""),
                provider=PROVIDER_NAME,
            ))
        return sources

    # -- Contents API ----------------------------------------------------- #
    def contents(self, urls: list[str], *,
                 formats: Optional[list[str]] = None,
                 crawl_timeout: int = 10) -> IntelResult:
        """Fetch the content of given URLs. Paid: requires ``allow_paid``."""
        result = IntelResult(operation="contents", provider=PROVIDER_NAME)
        refusal = self._authorize_paid("Contents API")
        if refusal is not None:
            raise CostRefusal(refusal)
        clean = [u.strip() for u in (urls or []) if u and u.strip()]
        if not clean:
            result.error = "no urls given"
            return result
        body: dict[str, Any] = {"urls": clean}
        if formats:
            body["formats"] = formats
        body["crawl_timeout"] = max(1, min(int(crawl_timeout), 60))

        start = time.monotonic()
        try:
            payload, status = self._post(CONTENTS_URL, body, paid=True)
        except CostRefusal:
            raise
        except YouComError as exc:
            result.error = str(exc)
            result.error_kind = exc.kind
            result.latency_ms = (time.monotonic() - start) * 1000
            return result
        result.latency_ms = (time.monotonic() - start) * 1000
        result.raw_status = status
        result.paid = True
        result.ok = True
        docs: list[Document] = []
        items = payload if isinstance(payload, list) else []
        for item in items:
            if not isinstance(item, dict):
                continue
            docs.append(Document(
                url=str(item.get("url") or ""),
                title=str(item.get("title") or ""),
                markdown=str(item.get("markdown") or ""),
                html=str(item.get("html") or ""),
            ))
        result.documents = docs
        return result

    # -- Research API ----------------------------------------------------- #
    def research(self, question: str, *, effort: str = "standard",
                 output_schema: Optional[dict] = None) -> IntelResult:
        """Ask a research question and get a citation-backed answer. Paid.

        ``frontier`` effort is background-only and is refused here; use the
        synchronous levels (lite/standard/deep/exhaustive).
        """
        result = IntelResult(operation="research", query=question,
                             provider=PROVIDER_NAME)
        refusal = self._authorize_paid("Research API")
        if refusal is not None:
            raise CostRefusal(refusal)
        if not question.strip():
            result.error = "empty research question"
            return result
        if len(question) > MAX_INPUT_CHARS:
            result.error = f"input exceeds {MAX_INPUT_CHARS} characters"
            return result
        if effort not in RESEARCH_EFFORTS:
            result.error = f"unknown research effort {effort!r}"
            return result
        if effort == "frontier":
            result.error = "research_effort='frontier' requires background mode, "
            "which is not implemented; use lite/standard/deep/exhaustive"
            return result
        if output_schema is not None and effort == "lite":
            result.error = "output_schema is not supported with effort='lite'"
            return result
        body: dict[str, Any] = {"input": question, "research_effort": effort}
        if output_schema is not None:
            body["output_schema"] = output_schema

        start = time.monotonic()
        try:
            payload, status = self._post(RESEARCH_URL, body, paid=True)
        except CostRefusal:
            raise
        except YouComError as exc:
            result.error = str(exc)
            result.error_kind = exc.kind
            result.latency_ms = (time.monotonic() - start) * 1000
            return result
        result.latency_ms = (time.monotonic() - start) * 1000
        result.raw_status = status
        result.paid = True
        result.ok = True

        output = (payload or {}).get("output") or {}
        content = output.get("content")
        content_type = str(output.get("content_type") or "")
        result.content_type = content_type
        if content_type == "object" or isinstance(content, dict):
            result.text = json.dumps(content, indent=2, default=str)
        else:
            result.text = str(content or "")
        sources = output.get("sources") or []
        parsed: list[Source] = []
        for item in sources:
            if not isinstance(item, dict):
                continue
            snippets = item.get("snippets") or []
            if not isinstance(snippets, list):
                snippets = [str(snippets)]
            parsed.append(Source(
                url=str(item.get("url") or ""),
                title=str(item.get("title") or ""),
                snippets=[str(s) for s in snippets],
                provider=PROVIDER_NAME,
            ))
        result.sources = parsed
        warnings = (payload or {}).get("warnings") or []
        result.warnings = [str(w) for w in warnings]
        return result

    # -- health ----------------------------------------------------------- #
    def health(self) -> IntelResult:
        """A cheap liveness probe: a one-result, snippets-only search.

        Snippets are the unbilled default, so the probe does not spend. It
        proves the key, the endpoint, and the network path all work.
        """
        result = self.search("security", count=1)
        result.operation = "health"
        return result
