"""Deterministic scope matcher: URL / host / CIDR allow-deny decisions.

This module is an **adapted port** of the deterministic scope checker from
Agentic-Bug-Hunter (https://github.com/awarexone/Agentic-Bug-Hunter,
``bughunter/tools/scope_checker.py``, MIT License, Copyright (c) 2026 Claude Bug
Bounty Hunter Contributors). See ``THIRD_PARTY_NOTICES.md`` and the module
``LICENSE`` header below. It is adapted -- not vendored -- to BLACKHEART's
models and idioms: it keeps the upstream's fail-closed parsing and anchored
matching, and returns BLACKHEART's :class:`~blackheart.models.AssetStatus`
instead of the upstream's ad-hoc dict.

Why BLACKHEART needed it: the authorization gate
(:func:`blackheart.authz.classify_asset`) classifies an asset by **exact string
equality** against the recorded map. A real program's scope is expressed as
*patterns* -- ``*.target.com``, ``api.target.com:8443``, ``target.com/api/``,
``10.0.0.0/24`` -- and a test against ``sub.target.com`` must resolve against
those patterns, not against a hand-listed string. This matcher does that
deterministically and fails closed.

Supported allow/deny pattern forms (unchanged from upstream):

  - ``target.com``            exact host
  - ``*.target.com``          any subdomain (NOT the apex, NOT ``evil-target.com``)
  - ``api.target.com:8443``   host + port constraint
  - ``target.com/api/``       host + path-prefix constraint
  - ``10.0.0.0/24``           IPv4 CIDR range
  - ``10.0.0.5``              single IPv4 (a /32)
  - ``2001:db8::/32``         IPv6 CIDR range
  - ``2001:db8::1``           single IPv6

Fail-closed guarantees (the property this module exists to keep is "out-of-scope
traffic executed = 0"): anything empty, malformed, ambiguous, or unrecognized is
treated as OUT OF SCOPE. Anchored suffix matching (not ``fnmatch``) prevents
subdomain confusion; URL-level tricks (backslash, whitespace, control chars),
non-http(s) schemes, unicode hostnames, and alternate IP encodings are rejected.
Wildcards over a public suffix (``*.com``) are refused at construction so a
misconfiguration fails loudly rather than silently widening scope.

MIT License (upstream notice, preserved):

    Copyright (c) 2026 Claude Bug Bounty Hunter Contributors

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions: The above copyright
    notice and this permission notice shall be included in all copies or
    substantial portions of the Software. THE SOFTWARE IS PROVIDED "AS IS",
    WITHOUT WARRANTY OF ANY KIND.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlsplit

from ..models import AssetStatus


class ScopePatternError(ValueError):
    """A dangerous or unusable scope pattern.

    Raised at construction so a misconfigured scope fails loudly at config time
    instead of silently widening (or silently blocking everything) at request
    time. Subclasses ``ValueError`` so existing ``except ValueError`` sites still
    catch it.
    """


# Public suffixes we refuse to wildcard over. Not the full Public Suffix List --
# a pragmatic guard against the common "*.com" / "*.co.uk" footguns.
_PUBLIC_SUFFIXES = {
    "com", "net", "org", "io", "co", "dev", "app", "xyz", "info", "biz", "me",
    "ai", "gov", "edu", "mil", "int", "eu", "us", "uk", "de", "fr", "nl", "ru",
    "cn", "jp", "in", "br", "au", "ca", "es", "it", "se", "no", "fi", "pl",
    "co.uk", "org.uk", "gov.uk", "ac.uk", "com.au", "net.au", "org.au",
    "co.jp", "co.nz", "com.br", "co.in", "com.cn", "com.mx", "com.tr",
    "co.za", "com.sg", "com.hk", "com.tw",
}

# Post-lowercasing ASCII DNS label charset. Anything outside this (unicode
# homoglyphs, %, spaces) means "not a hostname we can reason about" -> reject.
_HOSTNAME_CHARS = re.compile(r"^[a-z0-9._-]+$")

# Control chars (incl. NUL/CR/LF/TAB), space, DEL/C1 range, and backslash.
# Backslash matters: browsers/curl treat "\" as "/" while urlparse does not, so
# "https://target.com\\@evil.com" would parse as target.com here but connect to
# evil.com. Reject the whole URL if present.
_FORBIDDEN_URL_CHARS = re.compile(r"[\x00-\x20\x7f-\x9f\\]")

_ALLOWED_SCHEMES = {"http", "https"}

_PORT_RE = re.compile(r"^[0-9]{1,5}$")


def _try_ip_network(text: str):
    """Return an ``ip_network`` for an IP or CIDR literal, else None.

    ``ipaddress`` rejects anything containing letters, so a domain like
    ``target.com`` correctly returns None. Wildcards are never IPs.
    """
    if not text or "*" in text:
        return None
    try:
        return ipaddress.ip_network(text, strict=False)
    except ValueError:
        return None


def _is_public_suffix(base: str) -> bool:
    return base in _PUBLIC_SUFFIXES


def _normalize_and_parse(url: str):
    """Canonicalize a URL/host string into a target tuple, or None (fail closed).

    Returns ``(kind, host, port, path, scheme)`` where ``kind`` is ``"ip"`` (host
    is an ipaddress object) or ``"domain"`` (host is a str). Returns None for
    anything empty, malformed, ambiguous, or unsupported. This is the ONE parser
    every scope decision goes through.
    """
    if not url or not isinstance(url, str):
        return None

    if _FORBIDDEN_URL_CHARS.search(url):
        return None

    # A bare IPv6 literal has no scheme and several colons; urlparse would mangle
    # it. Try it as an IP directly before treating the string as a URL.
    stripped = url.strip()
    if "://" not in stripped and stripped.count(":") >= 2:
        try:
            ip = ipaddress.ip_address(stripped)
        except ValueError:
            pass
        else:
            return ("ip", ip, None, "/", "https")

    candidate = url if "://" in url else f"https://{url}"

    try:
        parsed = urlsplit(candidate)
        scheme, netloc, path, _, _ = parsed
    except ValueError:
        return None

    if scheme not in _ALLOWED_SCHEMES:
        return None

    path = path or "/"
    if ":" not in netloc and "@" not in netloc and "[" not in netloc:
        hostname = netloc
        port = None
    else:
        try:
            hostname = parsed.hostname
            port = parsed.port
        except ValueError:
            return None

    if not hostname:
        return None

    host = hostname.lower()

    # Normalize a single trailing FQDN root dot: "target.com." == "target.com".
    if host[-1] == ".":
        host = host[:-1]
    if not host:
        return None

    if ":" in host:  # IPv6 literal (urlparse stripped the [] brackets)
        try:
            ip = ipaddress.IPv6Address(host)
        except ValueError:
            return None
        return ("ip", ip, port, path, scheme)

    if host[-1].isdecimal():  # try IPv4 before allocating the final label
        try:
            ip = ipaddress.IPv4Address(host)
        except ValueError:
            if host.rpartition(".")[2].isdecimal():
                return None
        else:
            return ("ip", ip, port, path, scheme)

    last = host.rpartition(".")[2]
    if not _HOSTNAME_CHARS.match(host):
        return None
    if not last or host[0] == "." or ".." in host:
        return None
    if last.startswith("0x"):  # hex-prefixed final labels are ambiguous IPs
        return None

    return ("domain", host, port, path, scheme)


def _domain_matches(hostname: str, pattern: str) -> bool:
    """Anchored domain matching -- prevents subdomain confusion.

    ``*.target.com`` matches ``sub.target.com`` but NOT ``target.com`` and NOT
    ``evil-target.com``; ``target.com`` matches exactly ``target.com``.
    """
    if pattern.startswith("*."):
        suffix = pattern[1:]  # ".target.com"
        return hostname.endswith(suffix) and hostname != suffix[1:]
    return hostname == pattern


def _exclusion_matches(hostname: str, pattern: str) -> bool:
    """Exclusions deny broadly: an exact exclusion covers the host AND its
    subdomains, so excluding ``blog.target.com`` also blocks
    ``cdn.blog.target.com`` (which a ``*.target.com`` allow would otherwise let
    back in). A wildcard exclusion keeps the anchored ``*.target.com`` semantics.
    """
    if pattern.startswith("*."):
        return _domain_matches(hostname, pattern)
    return hostname == pattern or hostname.endswith("." + pattern)


def _path_matches(url_path: str, pattern_path: Optional[str]) -> bool:
    """Prefix match with a path-segment boundary (``/api`` does not match
    ``/apixyz``). A pattern with no path (None or "/") matches any path."""
    if not pattern_path or pattern_path == "/":
        return True
    up = url_path or "/"
    if pattern_path.endswith("/"):
        return up == pattern_path[:-1] or up.startswith(pattern_path)
    return up == pattern_path or up.startswith(pattern_path + "/")


def _parse_pattern(raw: str) -> Optional[dict]:
    """Parse one scope pattern into a structured rule.

    Returns a rule dict, or None for an unusable pattern (skipped -- an unusable
    allow pattern simply never matches, which fails closed). Raises
    :class:`ScopePatternError` for a dangerous pattern (a wildcard over a public
    suffix) so the misconfiguration surfaces immediately.
    """
    if raw is None:
        return None
    p = raw.strip().lower()
    if not p:
        return None

    if "://" in p:
        p = p.split("://", 1)[1]

    net = _try_ip_network(p)
    if net is not None:
        return {"kind": "ip", "raw": raw, "network": net}

    host_port, sep, rest = p.partition("/")
    path = ("/" + rest) if sep else None

    host = host_port
    port: Optional[int] = None
    if ":" in host_port:
        host, _, port_s = host_port.rpartition(":")
        if not _PORT_RE.match(port_s) or int(port_s) > 65535:
            return None
        port = int(port_s)

    host = host.removesuffix(".")

    ip_from_host = _try_ip_network(host)
    if ip_from_host is not None:
        return {"kind": "ip", "raw": raw, "network": ip_from_host}

    if host.startswith("*."):
        base = host[2:]
        if not base or "*" in base:
            raise ScopePatternError(f"invalid wildcard pattern: {raw!r}")
        if not _HOSTNAME_CHARS.match(base) or "" in base.split("."):
            return None
        if "." not in base:
            raise ScopePatternError(
                f"refusing overly broad wildcard {raw!r} -- a single-label base "
                f"would match an entire TLD"
            )
        if _is_public_suffix(base):
            raise ScopePatternError(
                f"refusing wildcard over public suffix {base!r} in {raw!r} -- "
                f"this would put the entire suffix in scope"
            )
    else:
        if "*" in host:
            raise ScopePatternError(f"unsupported wildcard placement in {raw!r}")
        if not host or not _HOSTNAME_CHARS.match(host) or "" in host.split("."):
            return None

    return {"kind": "domain", "raw": raw, "host": host, "port": port, "path": path}


@dataclass
class ScopeDecision:
    """A deterministic scope decision with attribution.

    ``status`` is BLACKHEART's :class:`~blackheart.models.AssetStatus`:
    ``AUTHORIZED`` when an allow rule matched and no exclusion did, else
    ``OUT_OF_SCOPE``. ``matched_rule`` and ``reason`` explain *why* -- so a
    reviewer can see which pattern decided it.
    """

    in_scope: bool
    status: AssetStatus
    host: Optional[str]
    kind: str            # "domain" | "ip" | "invalid"
    matched_rule: Optional[str]
    reason: str

    def to_dict(self) -> dict:
        return {
            "in_scope": self.in_scope, "status": self.status.value,
            "host": self.host, "kind": self.kind,
            "matched_rule": self.matched_rule, "reason": self.reason,
        }


class ScopeMatcher:
    """Deterministic allow/deny matcher for bug-bounty scope patterns."""

    def __init__(
        self,
        allow: Optional[list[str]] = None,
        exclude: Optional[list[str]] = None,
        excluded_classes: Optional[list[str]] = None,
    ) -> None:
        """
        Args:
            allow: allowlist patterns (``["*.target.com", "api.target.com"]``).
            exclude: denylist patterns.
            excluded_classes: vulnerability classes excluded by the program.

        Raises:
            ScopePatternError: if any pattern is dangerous.
        """
        self._allow_domain: list[dict] = []
        self._allow_ip: list[dict] = []
        for raw in allow or []:
            rule = _parse_pattern(raw)
            if rule is None:
                continue
            (self._allow_ip if rule["kind"] == "ip" else self._allow_domain).append(rule)

        self._exclude_domain: list[dict] = []
        self._exclude_ip: list[dict] = []
        for raw in exclude or []:
            rule = _parse_pattern(raw)
            if rule is None:
                continue
            (self._exclude_ip if rule["kind"] == "ip" else self._exclude_domain).append(rule)

        self.allow = [p.lower() for p in (allow or [])]
        self.exclude = [p.lower() for p in (exclude or [])]
        self.excluded_classes = [c.lower() for c in (excluded_classes or [])]

    def explain(self, url: str) -> ScopeDecision:
        """The single source of truth: a deterministic decision with attribution."""
        parsed = _normalize_and_parse(url)
        if parsed is None:
            return ScopeDecision(
                in_scope=False, status=AssetStatus.OUT_OF_SCOPE, host=None,
                kind="invalid", matched_rule=None,
                reason=("URL is empty, malformed, or uses an ambiguous/unsupported "
                        "form (bad scheme, encoding trick, or alternate IP encoding) "
                        "-- failing closed"),
            )

        kind, host, _port, path, scheme = parsed

        if kind == "ip":
            host_str = str(host)
            for rule in self._exclude_ip:
                if host in rule["network"]:
                    return ScopeDecision(False, AssetStatus.OUT_OF_SCOPE, host_str,
                                         "ip", rule["raw"],
                                         f"{host_str} is inside excluded range {rule['raw']}")
            for rule in self._allow_ip:
                if host in rule["network"]:
                    return ScopeDecision(True, AssetStatus.AUTHORIZED, host_str,
                                         "ip", rule["raw"],
                                         f"{host_str} is inside in-scope range {rule['raw']}")
            return ScopeDecision(False, AssetStatus.OUT_OF_SCOPE, host_str, "ip", None,
                                 f"{host_str} matches no in-scope IP/CIDR rule")

        for rule in self._exclude_domain:
            if _exclusion_matches(host, rule["host"]):
                return ScopeDecision(False, AssetStatus.OUT_OF_SCOPE, host, "domain",
                                     rule["raw"],
                                     f"{host} matches exclusion {rule['raw']}")

        eff_port = _port if _port is not None else (443 if scheme == "https" else 80)
        for rule in self._allow_domain:
            if not _domain_matches(host, rule["host"]):
                continue
            if rule["port"] is not None and rule["port"] != eff_port:
                continue
            if not _path_matches(path, rule["path"]):
                continue
            return ScopeDecision(True, AssetStatus.AUTHORIZED, host, "domain",
                                 rule["raw"],
                                 f"{host} matches in-scope rule {rule['raw']}")

        return ScopeDecision(False, AssetStatus.OUT_OF_SCOPE, host, "domain", None,
                             f"{host} matches no in-scope rule")

    def is_in_scope(self, url: str) -> bool:
        """True only if the URL matches an allow rule and no exclusion."""
        return self.explain(url).in_scope

    def is_class_allowed(self, vuln_class: str) -> bool:
        """True unless the program excludes this vulnerability class."""
        return vuln_class.lower() not in self.excluded_classes

    def filter_urls(self, urls: list[str]) -> tuple[list[str], list[str]]:
        """Split a list of URLs into ``(in_scope, out_of_scope)``."""
        in_scope, out = [], []
        for url in urls:
            (in_scope if self.is_in_scope(url) else out).append(url)
        return in_scope, out
