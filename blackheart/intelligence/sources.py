"""Source-independence accounting for research results.

A novelty verdict is only as strong as the *independence* of the evidence behind
it. Four search results are not four sources when all four live on one
publisher, and a URL that differs only by scheme, ``www``, a tracking parameter,
a fragment, or a trailing slash is the same source, not a new one.

This module answers two questions honestly and testably:

  * **How many genuinely independent origins does a result set have?** -- by
    canonicalising each URL to its registrable domain and collapsing repeats
    (:func:`canonical_url`, :func:`registrable_domain`,
    :func:`independent_origins`).
  * **Is a source *primary* evidence or *secondary* commentary?** -- an official
    advisory, CVE record, or the repository's own issue/PR/commit is primary; a
    blog, news article, or documentation page is secondary
    (:func:`classify_evidence_tier`).

Nothing here performs network I/O; it is pure URL reasoning, so it is fully
deterministic and unit-testable.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

#: Query parameters that identify a *campaign*, not a *document*. Two URLs that
#: differ only by these are the same source.
_TRACKING_PARAMS = frozenset({
    "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
    "utm_id", "utm_name", "utm_reader", "utm_referrer",
    "gclid", "fbclid", "dclid", "msclkid", "mc_cid", "mc_eid",
    "ref", "referrer", "source", "src", "spm", "igshid", "_hsenc", "_hsmi",
    "yclid", "s_kwcid", "cmpid", "campaign_id", "trk", "trkcampaign",
})

#: Multi-label public suffixes that a naive "last two labels" rule would
#: truncate incorrectly. Not exhaustive (that needs the full PSL); it covers the
#: common registries so a domain is not mistaken for a bare suffix.
_COMPOUND_SUFFIXES = frozenset({
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "net.uk", "sch.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "co.jp", "or.jp", "ne.jp", "ac.jp", "go.jp",
    "co.in", "net.in", "org.in", "gen.in", "firm.in", "ind.in",
    "com.br", "net.br", "org.br", "gov.br",
    "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn",
    "co.nz", "net.nz", "org.nz", "govt.nz", "ac.nz",
    "co.za", "org.za", "net.za", "gov.za",
    "com.mx", "com.ar", "com.tr", "com.sg", "com.hk", "com.tw",
    "co.kr", "or.kr", "go.kr", "re.kr",
    "co.il", "co.id", "com.my", "com.ph", "com.vn", "com.pk",
})

#: Hosts that publish *primary* evidence: official advisories, CVE/NVD records,
#: OSV, vendor security pages, and a repository's own issues / PRs / commits.
_PRIMARY_HOST_SUFFIXES = (
    "nvd.nist.gov", "cve.org", "cve.mitre.org", "osv.dev",
    "github.com", "gitlab.com", "cisa.gov", "cert.org", "kb.cert.org",
    "security.snyk.io", "snyk.io", "hackerone.com", "bugcrowd.com",
)

#: Path fragments that mark a page as primary even off the hosts above.
_PRIMARY_PATH_MARKERS = (
    "/security/advisories/", "/advisories/", "/security-advisory",
    "/security/", "/vuln/", "/cve/", "/ghsa-", "/issues/", "/pull/",
    "/commit/", "/releases/tag/", "/blob/",
)


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _normalize_host(host: str) -> str:
    """Lowercase, punycode, and strip a trailing root dot from a hostname."""
    host = host.strip().lower().rstrip(".")
    if not host or _is_ip(host):
        return host
    try:
        # Encode IDN to punycode so ``münchen.de`` and ``xn--mnchen-3ya.de``
        # are recognised as the same origin.
        return host.encode("idna").decode("ascii")
    except (UnicodeError, ValueError):
        return host


def registrable_domain(url_or_host: str) -> str:
    """Return the registrable domain (eTLD+1) for a URL or bare host.

    ``https://www.Example.co.uk/x?utm_source=n`` -> ``example.co.uk``. IP
    addresses are returned unchanged. A bare single-label host is returned as-is.
    """
    host = url_or_host
    if "://" in host or "/" in host or "?" in host:
        host = urlsplit(host).hostname or ""
    host = _normalize_host(host)
    if not host or _is_ip(host):
        return host
    labels = host.split(".")
    if len(labels) <= 2:
        return host
    last_two = ".".join(labels[-2:])
    if last_two in _COMPOUND_SUFFIXES:
        return ".".join(labels[-3:])
    return last_two


def canonical_url(url: str) -> str:
    """Normalise a URL for de-duplication.

    Lowercases the host, drops ``www.``, collapses ``http``/``https`` (the same
    document over either scheme is the same source), drops the default port,
    removes the fragment, removes tracking-only query parameters, sorts the
    remaining query parameters, and strips a trailing slash from the path. The
    result is *not* a fetchable URL; it is a stable identity key.
    """
    if not url:
        return ""
    parts = urlsplit(url.strip())
    scheme = "https"  # identity only: http and https of one page are one source
    host = _normalize_host(parts.hostname or "")
    if host.startswith("www."):
        host = host[4:]
    netloc = host
    if parts.port and parts.port not in (80, 443):
        netloc = f"{host}:{parts.port}"
    path = parts.path or "/"
    if len(path) > 1 and path.endswith("/"):
        path = path.rstrip("/")
    query_pairs = [
        (k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True)
        if k.lower() not in _TRACKING_PARAMS
    ]
    query = urlencode(sorted(query_pairs))
    return urlunsplit((scheme, netloc, path, query, ""))


def classify_evidence_tier(url: str) -> str:
    """Return ``"primary"`` or ``"secondary"`` for a source URL.

    Primary evidence is an official advisory, a CVE/NVD/OSV record, a vendor
    security page, or a repository's own issue / pull request / commit. Anything
    else (a blog, a news article, a documentation page, a wiki) is secondary
    commentary.
    """
    if not url:
        return "secondary"
    parts = urlsplit(url)
    host = _normalize_host(parts.hostname or "")
    path = (parts.path or "").lower()
    if host.endswith(_PRIMARY_HOST_SUFFIXES):
        return "primary"
    if any(marker in path for marker in _PRIMARY_PATH_MARKERS):
        return "primary"
    return "secondary"


@dataclass
class SourceIndependence:
    """The independence profile of one result set."""

    total_urls: int = 0
    unique_urls: int = 0
    duplicates: int = 0
    origins: list[str] = field(default_factory=list)
    publisher_counts: dict[str, int] = field(default_factory=dict)
    primary_urls: list[str] = field(default_factory=list)
    secondary_urls: list[str] = field(default_factory=list)

    @property
    def independent_source_count(self) -> int:
        """The number of distinct publishers -- the honest source count."""
        return len(self.origins)

    @property
    def primary_count(self) -> int:
        return len(self.primary_urls)

    @property
    def secondary_count(self) -> int:
        return len(self.secondary_urls)

    def to_dict(self) -> dict:
        return {
            "total_urls": self.total_urls,
            "unique_urls": self.unique_urls,
            "duplicates": self.duplicates,
            "independent_source_count": self.independent_source_count,
            "origins": list(self.origins),
            "publisher_counts": dict(self.publisher_counts),
            "primary_count": self.primary_count,
            "secondary_count": self.secondary_count,
        }


def analyse(urls: list[str]) -> SourceIndependence:
    """Compute the independence profile of a list of source URLs."""
    rep = SourceIndependence(total_urls=len(urls))
    seen: dict[str, str] = {}  # canonical -> first original URL
    for url in urls:
        if not url:
            continue
        key = canonical_url(url)
        if not key:
            continue
        if key in seen:
            rep.duplicates += 1
            continue
        seen[key] = url
    rep.unique_urls = len(seen)
    counts: dict[str, int] = {}
    for key, original in seen.items():
        origin = registrable_domain(key)
        counts[origin] = counts.get(origin, 0) + 1
        if classify_evidence_tier(original) == "primary":
            rep.primary_urls.append(original)
        else:
            rep.secondary_urls.append(original)
    rep.origins = sorted(counts)
    rep.publisher_counts = counts
    return rep
