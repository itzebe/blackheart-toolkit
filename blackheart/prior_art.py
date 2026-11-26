"""A free, documented prior-art source for the novelty gate: GitHub advisories.

A novelty review is only worth the search behind it. BLACKHEART's provider router
is the primary route, but every hosted search backend costs a key or a quota, and
when that quota is gone the gate silently has nothing to compare against. This
module gives the gate one source that is free, documented, machine-readable, and
usable without an account: the GitHub Advisory database, through the public REST
API (``GET /advisories``), authenticated only by the ``GITHUB_TOKEN`` the sandbox
already carries for git access.

**The endpoint's real contract was measured, not assumed.** ``GET /advisories``
ignores a free-text ``q`` parameter: ``q=reentrancy``, ``q=OpenZeppelin`` and
``q=solidity`` all return the same unfiltered global feed. Only these narrow the
result set, and each is exact:

* ``affects``  -- an **ecosystem package name** (``lodash``: yes; a protocol's own
  contract name: no).
* ``cve_id``   -- one exact CVE.
* ``ecosystem`` / ``severity`` -- coarseners, not searches.

So this source does **not** do free-text prior-art search, and it must not pretend
to. Its honest use is a *package* check: "does the library this candidate depends
on have a published advisory?" A candidate whose dependencies are clean gets an
empty result, which is recorded as *no advisory for these packages* -- never as
"novel". A query that is not a package name returns ``ok=False`` with the reason,
so the novelty gate sees a limitation rather than a silent zero.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Optional

__all__ = [
    "AdvisorySource",
    "AdvisorySearchResult",
    "GitHubAdvisorySearch",
    "advisory_search_fn",
    "looks_like_package",
]

_API = "https://api.github.com/advisories"
_PROVIDER = "github-advisories"

#: A conservative package-name shape. A query with spaces or Solidity-ish
#: punctuation is a sentence, not a package, and would return the unfiltered feed.
_PKG_OK = set("abcdefghijklmnopqrstuvwxyz0123456789._-@/")



@dataclass(frozen=True)
class AdvisorySource:
    """One advisory, reduced to the fields the novelty gate compares on."""

    url: str
    title: str = ""
    description: str = ""
    identifier: str = ""        # GHSA-xxxx-xxxx-xxxx
    severity: str = ""
    cve: str = ""
    published: str = ""
    provider: str = _PROVIDER


@dataclass
class AdvisorySearchResult:
    """The ``search_fn`` return shape: ``ok`` / ``provider`` / ``sources``."""

    ok: bool
    provider: str = _PROVIDER
    sources: list[AdvisorySource] = field(default_factory=list)
    error: str = ""


def _row_to_source(row: dict) -> Optional[AdvisorySource]:
    ghsa = row.get("ghsa_id") or ""
    html = row.get("html_url") or (f"https://github.com/advisories/{ghsa}" if ghsa else "")
    if not html:
        return None
    identifiers = row.get("identifiers") or []
    cve = next((i.get("value", "") for i in identifiers
                if isinstance(i, dict) and i.get("type") == "CVE"), "")
    return AdvisorySource(
        url=html,
        title=row.get("summary") or ghsa,
        description=(row.get("description") or "")[:2000],
        identifier=ghsa,
        severity=row.get("severity") or "",
        cve=cve,
        published=row.get("published_at") or "",
    )


def looks_like_package(query: str) -> bool:
    """Whether ``query`` could be an ecosystem package name, not a sentence."""
    q = query.strip().lower()
    return bool(q) and len(q) <= 100 and set(q) <= _PKG_OK


class GitHubAdvisorySearch:
    """Callable ``(query, count=...) -> AdvisorySearchResult`` over ``/advisories``.

    ``query`` must be an ecosystem package name or a CVE id; anything else is
    refused with ``ok=False`` because the API would silently return its global
    feed and the gate would compare a candidate against unrelated advisories.

    ``token`` falls back to ``$GITHUB_TOKEN``. Unauthenticated calls are allowed
    by GitHub but rate-limited hard (60/hr), so a missing token is reported in
    ``error`` rather than being treated as "no advisories exist" -- an empty
    result from an exhausted quota must never read as a clean novelty signal.
    """

    def __init__(self, token: Optional[str] = None, *, timeout: float = 20.0,
                 severity: str = "", ecosystem: str = "") -> None:
        self.token = token if token is not None else os.environ.get("GITHUB_TOKEN", "")
        self.timeout = timeout
        self.severity = severity
        self.ecosystem = ecosystem

    def _url(self, query: str, count: int) -> tuple[str, bool]:
        q = query.strip()
        is_cve = q.upper().startswith("CVE-")
        params = {"per_page": str(max(1, min(count, 100)))}
        if is_cve:
            params["cve_id"] = q.upper()
        else:
            params["affects"] = q.lower()
        if self.severity:
            params["severity"] = self.severity
        if self.ecosystem:
            params["ecosystem"] = self.ecosystem
        return f"{_API}?{urllib.parse.urlencode(params)}", is_cve

    def __call__(self, query: str, count: int = 5) -> AdvisorySearchResult:
        if not query.strip():
            return AdvisorySearchResult(ok=False, error="empty query")
        if not (looks_like_package(query) or query.strip().upper().startswith("CVE-")):
            return AdvisorySearchResult(
                ok=False,
                error=(f"{query!r} is not a package name or CVE id; /advisories "
                       "has no free-text search and would return its global feed"))
        url, _ = self._url(query, count)
        req = urllib.request.Request(url, method="GET")
        req.add_header("Accept", "application/vnd.github+json")
        req.add_header("X-GitHub-Api-Version", "2022-11-28")
        req.add_header("User-Agent", "blackheart-novelty")
        if self.token:
            req.add_header("Authorization", f"Bearer {self.token}")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                payload = json.loads(resp.read().decode("utf-8", errors="replace"))
        except urllib.error.HTTPError as e:
            # 403/429 is quota, not emptiness. Saying so keeps the caller honest.
            detail = "rate limited or forbidden" if e.code in (403, 429) else f"HTTP {e.code}"
            return AdvisorySearchResult(ok=False, error=f"{detail}: {e.reason}")
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as e:
            return AdvisorySearchResult(ok=False, error=f"{type(e).__name__}: {e}")

        if not isinstance(payload, list):
            return AdvisorySearchResult(ok=False, error="unexpected response shape")
        sources = [s for s in (_row_to_source(r) for r in payload if isinstance(r, dict))
                   if s is not None]
        return AdvisorySearchResult(ok=True, sources=sources)



def advisory_search_fn(token: Optional[str] = None, **kwargs) -> GitHubAdvisorySearch:
    """A ready-to-pass ``search_fn`` for :func:`novelty.collect_disclosures`."""
    return GitHubAdvisorySearch(token, **kwargs)
