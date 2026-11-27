"""External-intelligence provider abstraction with deterministic fallback.

BLACKHEART must not depend on a single external provider. This module gives the
intelligence layer a small, honest provider contract plus two **genuinely usable,
keyless** fallbacks, so a mission still gets external context when You.com is
unconfigured, rate-limited, or down.

Three providers are defined:

  * ``you.com``        -- the primary, keyed provider (:mod:`blackheart.intelligence.youcom`).
  * ``duckduckgo``     -- the keyless DuckDuckGo Instant Answer API. Returns an
                          abstract plus related topics for an entity/query; it is
                          **not** a general web index and returns nothing for many
                          queries, which is reported honestly rather than faked.
  * ``wikipedia``      -- the keyless Wikipedia search API. Returns article
                          titles and snippets; useful for background and prior
                          art on a technique or protocol.

Rules carried from the rest of the project:

  * **Provenance is preserved.** Every result carries the provider that answered,
    and every source carries its own provider tag, so a merged set can be
    attributed.
  * **Fallback only to a genuinely configured provider.** A provider with no key
    (when it needs one) is *unavailable*, not "empty"; the router never silently
    substitutes an unavailable provider, and it never fabricates a result.
  * **Disagreement is recorded, not resolved by fiat.** When two providers both
    answer, their differing URLs are reported as disagreement; the router does
    not pick a winner.
  * **No fabricated results.** A failed live request returns ``ok=False`` with a
    reason; a cached or invented answer is never presented as a live one.
  * **Standard library only** (``urllib``), matching the rest of the engine.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Optional, Protocol, runtime_checkable

from .youcom import (
    ErrorKind,
    IntelResult,
    Source,
    YouComClient,
)

#: A plain, honest User-Agent (some endpoints reject urllib's default).
USER_AGENT = "blackheart-intelligence/1.0"

#: Wikimedia's User-Agent policy (https://meta.wikimedia.org/wiki/User-Agent_policy)
#: asks for a *descriptive* UA that identifies the tool and a contact; its edge
#: rate-limits generic UAs with HTTP 429, so the Wikipedia provider sends this
#: instead of the generic one. This is the supported, non-evasive configuration.
WIKIMEDIA_USER_AGENT = (
    "BlackheartSecurityResearch/1.0 "
    "(https://github.com/itzebe/blackheart; security-research) urllib"
)

#: Default per-request timeout for the keyless providers.
DEFAULT_TIMEOUT = 20


@dataclass
class ProviderStatus:
    """What a provider is and whether it can currently be used.

    ``available`` is about *configuration* (a key is present when one is
    required), not about a live call. ``live_ok`` is set only by a probe.
    """

    name: str
    requires_key: bool
    key_present: bool
    paid: bool
    description: str
    live_ok: Optional[bool] = None
    live_status: int = 0
    live_error: str = ""
    live_error_kind: str = ""

    @property
    def available(self) -> bool:
        return (not self.requires_key) or self.key_present

    def to_dict(self) -> dict:
        return {
            "name": self.name, "requires_key": self.requires_key,
            "key_present": self.key_present, "paid": self.paid,
            "available": self.available, "description": self.description,
            "live_ok": self.live_ok, "live_status": self.live_status,
            "live_error": self.live_error, "live_error_kind": self.live_error_kind,
        }


@runtime_checkable
class SearchProvider(Protocol):
    """The contract every external-intelligence provider implements."""

    name: str
    requires_key: bool
    paid: bool

    def available(self) -> bool:  # pragma: no cover - structural
        ...

    def search(self, query: str, *, count: int = 10, **kwargs) -> IntelResult:
        ...


# --------------------------------------------------------------------------- #
# You.com provider (wraps the existing client, adds the provider contract)
# --------------------------------------------------------------------------- #

class YouComProvider:
    """The primary provider: wraps :class:`YouComClient` behind the contract."""

    name = "you.com"
    requires_key = True
    paid = False  # snippets search is free; paid paths are opt-in elsewhere

    def __init__(self, client: Optional[YouComClient] = None) -> None:
        self._client = client or YouComClient()

    @property
    def client(self) -> YouComClient:
        return self._client

    def available(self) -> bool:
        return self._client.key_present

    def search(self, query: str, *, count: int = 10, **kwargs) -> IntelResult:
        if not self.available():
            r = IntelResult(operation="search", query=query, provider=self.name)
            r.error = "YDC_API_KEY is not set"
            r.error_kind = ErrorKind.MISSING_KEY
            return r
        # The client's timeout is fixed at construction; drop any per-call
        # timeout the router passes so the provider contract stays uniform.
        kwargs.pop("timeout", None)
        return self._client.search(query, count=count, **kwargs)


# --------------------------------------------------------------------------- #
# Keyless fallbacks
# --------------------------------------------------------------------------- #

class _KeylessProvider:
    """Shared plumbing for the keyless providers (one GET, honest failure)."""

    name = ""
    requires_key = False
    paid = False
    description = ""

    def available(self) -> bool:
        return True

    def _get_json(self, url: str, *, timeout: int,
                  user_agent: str = USER_AGENT) -> tuple[Optional[dict], int, str, str]:
        """GET ``url`` and parse JSON.

        Returns ``(payload, status, error, error_kind)``. A non-2xx, a network
        failure, or an unparsable body yields ``payload=None`` with a reason --
        never a fabricated payload.
        """
        req = urllib.request.Request(url, headers={"User-Agent": user_agent})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = resp.read().decode("utf-8", "replace")
                status = resp.status
            try:
                return json.loads(body), status, "", ""
            except json.JSONDecodeError as exc:
                return None, status, f"unparsable JSON: {exc}", ErrorKind.UNKNOWN
        except urllib.error.HTTPError as exc:
            kind = ErrorKind.RATE_LIMITED if exc.code == 429 else ErrorKind.UNKNOWN
            if 500 <= exc.code < 600:
                kind = ErrorKind.SERVER_ERROR
            return None, exc.code, f"HTTP {exc.code}", kind
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            return None, 0, f"{type(exc).__name__}: {exc}", ErrorKind.NETWORK


class DuckDuckGoProvider(_KeylessProvider):
    """DuckDuckGo Instant Answer API (keyless).

    This endpoint answers *entity* and *definition* queries well (an abstract,
    an answer, and related topics) and returns an empty result set for many
    general queries. That limitation is surfaced, not hidden: an empty result is
    ``ok=True`` with zero sources and a note, because the call genuinely
    succeeded and simply had nothing -- the opposite of a failure.
    """

    name = "duckduckgo"
    description = "Keyless DuckDuckGo Instant Answer API (entities/definitions)."
    BASE = "https://api.duckduckgo.com/"

    def search(self, query: str, *, count: int = 10, timeout: int = DEFAULT_TIMEOUT,
               **kwargs) -> IntelResult:
        result = IntelResult(operation="search", query=query, provider=self.name)
        if not query.strip():
            result.error = "empty query"
            return result
        params = urllib.parse.urlencode({
            "q": query, "format": "json", "no_html": "1",
            "skip_disambig": "1", "t": "blackheart",
        })
        payload, status, error, kind = self._get_json(
            f"{self.BASE}?{params}", timeout=timeout)
        result.raw_status = status
        if payload is None:
            result.error = error
            result.error_kind = kind
            return result
        result.ok = True
        sources: list[Source] = []
        abstract_url = str(payload.get("AbstractURL") or "").strip()
        if abstract_url:
            sources.append(Source(
                url=abstract_url,
                title=str(payload.get("Heading") or payload.get("AbstractSource") or ""),
                snippets=[str(payload.get("AbstractText") or "")],
                description=str(payload.get("AbstractText") or ""),
                provider=self.name,
            ))
        for topic in payload.get("RelatedTopics") or []:
            if not isinstance(topic, dict):
                continue
            if "Topics" in topic:  # grouped results
                for sub in topic.get("Topics") or []:
                    self._append_topic(sources, sub)
            else:
                self._append_topic(sources, topic)
            if len(sources) >= count:
                break
        result.sources = sources[:count]
        if not result.sources:
            result.warnings = [
                "DuckDuckGo Instant Answer returned no abstract or related topics for this query (it is not a general web index)",
            ]
        return result

    @staticmethod
    def _append_topic(sources: list[Source], topic: object) -> None:
        if not isinstance(topic, dict):
            return
        url = str(topic.get("FirstURL") or "").strip()
        text = str(topic.get("Text") or "").strip()
        if not url or not text:
            return
        title = text.split(" - ", 1)[0][:120]
        sources.append(Source(url=url, title=title, snippets=[text],
                              description=text, provider="duckduckgo"))


class WikipediaProvider(_KeylessProvider):
    """Wikipedia search API (keyless).

    Good for background and prior art on a technique, protocol, or standard.
    Returns article titles with a plain-text snippet and a canonical URL.
    """

    name = "wikipedia"
    description = "Keyless Wikipedia search API (background/prior art)."
    BASE = "https://en.wikipedia.org/w/api.php"

    def search(self, query: str, *, count: int = 10, timeout: int = DEFAULT_TIMEOUT,
               **kwargs) -> IntelResult:
        result = IntelResult(operation="search", query=query, provider=self.name)
        if not query.strip():
            result.error = "empty query"
            return result
        params = urllib.parse.urlencode({
            "action": "query", "list": "search", "srsearch": query,
            "format": "json", "srlimit": max(1, min(count, 50)),
        })
        payload, status, error, kind = self._get_json(
            f"{self.BASE}?{params}", timeout=timeout,
            user_agent=WIKIMEDIA_USER_AGENT)
        result.raw_status = status
        if payload is None:
            result.error = error
            result.error_kind = kind
            return result
        result.ok = True
        hits = ((payload.get("query") or {}).get("search")) or []
        sources: list[Source] = []
        for hit in hits:
            if not isinstance(hit, dict):
                continue
            title = str(hit.get("title") or "")
            if not title:
                continue
            url = "https://en.wikipedia.org/wiki/" + urllib.parse.quote(
                title.replace(" ", "_"))
            snippet = _strip_html(str(hit.get("snippet") or ""))
            sources.append(Source(url=url, title=title, snippets=[snippet],
                                  description=snippet, provider=self.name))
        result.sources = sources
        if not sources:
            result.warnings = ["Wikipedia returned no matching articles"]
        return result


def _strip_html(text: str) -> str:
    """Remove the <span> highlight markup Wikipedia wraps matches in."""
    out, depth = [], 0
    for ch in text:
        if ch == "<":
            depth += 1
        elif ch == ">":
            depth = max(0, depth - 1)
        elif depth == 0:
            out.append(ch)
    return "".join(out).strip()


# --------------------------------------------------------------------------- #
# Registry
# --------------------------------------------------------------------------- #

class ProviderRegistry:
    """The set of known providers and which of them are usable right now.

    A project may specialise the registry through its ``.openhands/intelligence.json``
    (see :mod:`blackheart.intelligence.bootstrap`): it can disable a built-in
    provider only with an explicit, non-empty reason. The built-in providers are
    always present unless so disabled -- a project cannot silently remove the
    capability.
    """

    def __init__(self, *, youcom_client: Optional[YouComClient] = None,
                 project_root: Optional[str] = None) -> None:
        self._providers: dict[str, object] = {}
        self.register(YouComProvider(youcom_client))
        self.register(DuckDuckGoProvider())
        self.register(WikipediaProvider())
        self.disabled: dict[str, str] = {}
        if project_root is not None:
            self._apply_project_config(project_root)

    def _apply_project_config(self, project_root: str) -> None:
        from .bootstrap import load_project_config

        cfg = load_project_config(project_root)
        for name, reason in (cfg.get("disable") or {}).items():
            if name in self._providers:
                del self._providers[name]
                self.disabled[name] = reason

    def register(self, provider: object) -> None:
        self._providers[provider.name] = provider  # type: ignore[attr-defined]

    def get(self, name: str):
        if name not in self._providers:
            raise KeyError(f"unknown provider {name!r}; known: {', '.join(self._providers)}")
        return self._providers[name]

    def names(self) -> list[str]:
        return list(self._providers)

    def status(self, *, probe: bool = False, timeout: int = DEFAULT_TIMEOUT
               ) -> list[ProviderStatus]:
        """Report each provider's configuration state, optionally probing live.

        ``probe=True`` makes a real, cheap request per provider and records the
        result. A provider that is not configured is reported as unavailable and
        is *not* probed (there is nothing to prove).
        """
        out: list[ProviderStatus] = []
        for name, provider in self._providers.items():
            st = ProviderStatus(
                name=name,
                requires_key=getattr(provider, "requires_key", True),
                key_present=bool(provider.available()),
                paid=getattr(provider, "paid", False),
                description=getattr(provider, "description", ""),
            )
            if probe and st.available:
                r = provider.search("security", count=1, timeout=timeout)
                st.live_ok = r.ok
                st.live_status = r.raw_status
                st.live_error = r.error
                st.live_error_kind = r.error_kind
            out.append(st)
        return out


# --------------------------------------------------------------------------- #
# The router: deterministic preference + fallback + provenance + disagreement
# --------------------------------------------------------------------------- #

#: Default preference order. You.com first (best coverage), then the keyless
#: fallbacks. A caller may override with ``order=``.
DEFAULT_ORDER = ("you.com", "duckduckgo", "wikipedia")

#: The primary provider. When it is *configured*, it is the only provider the
#: router uses by default -- the keyless "generic" providers (DuckDuckGo IA,
#: Wikipedia) return thin or irrelevant results for the technical queries a hunt
#: makes, so falling through to them while the primary is up silently degrades the
#: intelligence. A caller that genuinely wants the fallbacks opts in with
#: ``allow_fallback=True``; the capability is preserved, it is just no longer the
#: silent default. When the primary is *not configured*, the keyless providers are
#: used -- honest degradation beats no context at all.
PRIMARY_PROVIDER = "you.com"


@dataclass
class RoutedSearch:
    """The result of a routed search: the answer, plus the full attempt log."""

    ok: bool
    provider: str
    result: Optional[IntelResult]
    attempts: list[dict] = field(default_factory=list)
    disagreements: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "ok": self.ok, "provider": self.provider,
            "result": self.result.to_dict() if self.result else None,
            "attempts": list(self.attempts),
            "disagreements": list(self.disagreements),
        }


class SearchRouter:
    """Route a search across providers with deterministic, primary-first policy.

    The policy, in order:

      1. **Enforce the primary provider.** When You.com is configured it is the
         whole order by default: a hunt never silently answers a technical query
         with a thin keyless result. Pass ``allow_fallback=True`` to opt back into
         the keyless fallbacks (their capability is preserved, not removed).
      2. When the primary is *not configured*, use the providers in ``order``
         (default :data:`DEFAULT_ORDER`) -- honest degradation to a keyless
         provider beats no context at all.
      3. Skip a provider that is not configured (it is *unavailable*, which is
         different from failing).
      4. On a provider that fails, record the attempt and fall through to the
         next configured provider.
      5. Return the first provider that returns ``ok``. If none does, return the
         last failure honestly (``ok=False``) with every attempt recorded.
      6. When ``cross_check=True`` and more than one provider is available, also
         query the others and record their URL sets as a **disagreement report**
         -- the router never silently picks one provider's answer over another's.

    Nothing is cached and nothing is fabricated: each call is a live request.
    """

    def __init__(self, registry: Optional[ProviderRegistry] = None) -> None:
        self.registry = registry or ProviderRegistry()

    def search(
        self,
        query: str,
        *,
        count: int = 10,
        order: tuple[str, ...] = DEFAULT_ORDER,
        cross_check: bool = False,
        allow_fallback: bool = False,
        timeout: int = DEFAULT_TIMEOUT,
    ) -> RoutedSearch:
        attempts: list[dict] = []
        first_ok: Optional[IntelResult] = None      # ok with at least one source
        first_empty: Optional[IntelResult] = None   # ok but no sources
        last_failure: Optional[IntelResult] = None

        # Enforce the primary provider: when it is configured, it is the whole
        # order unless the caller explicitly opted into the fallbacks. This is what
        # stops a hunt from silently answering with a generic keyless provider.
        effective = order
        if not allow_fallback and PRIMARY_PROVIDER in order:
            primary = self.registry.get(PRIMARY_PROVIDER)
            if primary.available():
                effective = (PRIMARY_PROVIDER,)

        for name in effective:
            provider = self.registry.get(name)
            if not provider.available():
                attempts.append({"provider": name, "skipped": True,
                                 "reason": "not configured"})
                continue
            start = time.monotonic()
            r = provider.search(query, count=count, timeout=timeout)
            attempts.append({
                "provider": name, "skipped": False, "ok": r.ok,
                "status": r.raw_status,
                "error": r.error, "error_kind": r.error_kind,
                "sources": len(r.sources),
                "latency_ms": round((time.monotonic() - start) * 1000, 1),
            })
            if r.ok and r.sources:
                first_ok = r
                break
            if r.ok and first_empty is None:
                # Keep looking: a provider that succeeded but returned nothing
                # is a worse answer than one that returns results. This is the
                # keyless-fallback case (e.g. DuckDuckGo IA has no entity for a
                # technical query, but Wikipedia may).
                first_empty = r
                continue
            if not r.ok:
                last_failure = r

        chosen = first_ok or first_empty
        if chosen is None:
            return RoutedSearch(ok=False, provider="",
                                result=last_failure, attempts=attempts)

        disagreements: list[dict] = []
        if cross_check:
            disagreements = self._cross_check(query, chosen, count, order, timeout)

        return RoutedSearch(ok=True, provider=chosen.provider, result=chosen,
                            attempts=attempts, disagreements=disagreements)

    def _cross_check(self, query: str, primary: IntelResult, count: int,
                     order: tuple[str, ...], timeout: int) -> list[dict]:
        """Query the other available providers and report URL-set differences.

        This is a *report*, not a merge: the caller sees that the providers
        disagree rather than receiving a silently chosen union.
        """
        primary_urls = {s.url for s in primary.sources}
        reports: list[dict] = []
        for name in order:
            if name == primary.provider:
                continue
            provider = self.registry.get(name)
            if not provider.available():
                continue
            r = provider.search(query, count=count, timeout=timeout)
            if not r.ok:
                reports.append({"provider": name, "ok": False,
                                "error": r.error, "error_kind": r.error_kind})
                continue
            other_urls = {s.url for s in r.sources}
            reports.append({
                "provider": name, "ok": True,
                "shared": sorted(primary_urls & other_urls),
                "only_in_primary": sorted(primary_urls - other_urls),
                "only_in_other": sorted(other_urls - primary_urls),
            })
        return reports
