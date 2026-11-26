"""Structured discovery over You.com -- find and *verify* live infrastructure.

A mission needs three things the engine cannot invent: the RPC endpoint of the
chain a target lives on, the on-chain address of the target, and the chain's own
metadata. Today those are looked up by hand or guessed, and a wrong guess wastes a
run. This module turns each into a *structured, verified* lookup:

  * :func:`discover_rpc_endpoints` searches for the chain's RPC URLs -- from the
    keyless authoritative registry (``chainid.network/chains.json``) **and** from
    You.com -- and **probes each candidate with a real ``eth_chainId`` call**,
    keeping only the endpoints that answer with the expected chain id. An
    unverified endpoint is reported as a candidate, never as a fact.
  * :func:`discover_contract` searches You.com for a protocol's on-chain address
    and verifies it holds code on the RPC it was found for.
  * :func:`discover_chain` resolves a chain's id and name.

The point is the discipline the rest of the project already keeps: external text
is a *lead*, and only a call that runs makes it a fact. The You.com key is used
through the existing, key-safe :class:`~blackheart.intelligence.youcom.YouComClient`;
nothing here reads or logs the key.

This is the search the operator asked for: You.com first and structured, not a
generic web scrape. A caller that wants only verified facts uses the ``verified``
list and never the ``candidates``.
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Optional

from .youcom import IntelResult, YouComClient

#: Where chain RPC endpoints and ids are authoritatively listed.
RPC_SOURCE_DOMAINS = [
    "chainlist.org",
    "chainid.network",
    "ethereum.org",
    "docs.chainstack.com",
    "www.alchemy.com",
    "github.com",
]

#: The keyless, authoritative chain registry. Consulted before search: it gives
#: RPC URLs *deterministically*, so a discover run does not depend on a snippet
#: happening to inline an endpoint. Public, no key, no spend.
CHAIN_REGISTRY_URL = "https://chainid.network/chains.json"

#: A conservative URL shape for a JSON-RPC endpoint.
_URL = re.compile(r"https?://[^\s\"'<>)\]}]+", re.IGNORECASE)

#: Suffixes that mark a URL as *probably* an RPC endpoint (not a docs page).
_RPC_HINTS = ("rpc", "json-rpc", "node", "gateway", "archive")

#: In-process cache of the parsed chain registry (one fetch per process).
_REGISTRY_CACHE: Optional[list[dict]] = None


def _registry_entries(*, timeout: int = 15) -> list[dict]:
    """The parsed keyless chain registry, cached per process (``[]`` on failure)."""
    global _REGISTRY_CACHE
    if _REGISTRY_CACHE is None:
        try:
            req = urllib.request.Request(CHAIN_REGISTRY_URL,
                                         headers={"User-Agent": "blackheart/1"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                _REGISTRY_CACHE = json.loads(resp.read().decode("utf-8"))
        except (urllib.error.URLError, OSError, ValueError, TimeoutError):
            _REGISTRY_CACHE = []
    return _REGISTRY_CACHE or []


def _registry_match(chain: str) -> list[dict]:
    """Registry entries whose name, short name, chain alias, or id is ``chain``."""
    key = str(chain).strip().lower()
    out: list[dict] = []
    for entry in _registry_entries():
        names = [str(entry.get("name", "")).lower(),
                 str(entry.get("shortName", "")).lower(),
                 *[str(a).lower() for a in entry.get("chain", [])]]
        ids = {str(entry.get("chainId", "")), str(entry.get("networkId", ""))}
        if key in names or key in ids:
            out.append(entry)
    return out


def _registry_rpc_urls(chain: str, *, timeout: int = 15) -> list[str]:
    """RPC URLs for ``chain`` from the keyless registry, or ``[]``.

    ``chain`` matches a chain's name (case-insensitive) or its numeric id. The
    registry is public and needs no key; a fetch failure is reported as an empty
    list, never as a fabricated endpoint.
    """
    out: list[str] = []
    for entry in _registry_match(chain):
        out.extend(str(u) for u in entry.get("rpc", []) if str(u).startswith("http"))
    return out


def _registry_chain_id(chain: str) -> Optional[int]:
    """The chain's numeric id from the keyless registry, or ``None``.

    ``None`` when the chain is not in the registry *or* the name is ambiguous
    (matches several entries with different ids) -- an ambiguous name is never
    resolved to one id by guessing.
    """
    ids = {int(e["chainId"]) for e in _registry_match(chain)
           if isinstance(e.get("chainId"), int)}
    return next(iter(ids)) if len(ids) == 1 else None


@dataclass
class RpcEndpoint:
    """A candidate RPC endpoint, with the verification that (dis)qualified it."""

    url: str
    source: str = ""                 # where the URL came from (search result URL)
    verified: bool = False
    chain_id: int = 0
    error: str = ""

    def to_dict(self) -> dict:
        return {"url": self.url, "source": self.source, "verified": self.verified,
                "chain_id": self.chain_id, "error": self.error}


@dataclass
class DiscoveryResult:
    """The honest outcome of one discovery lookup."""

    kind: str                        # rpc | contract | chain
    query: str
    ok: bool = False
    verified: list[dict] = field(default_factory=list)
    candidates: list[dict] = field(default_factory=list)
    sources: list[dict] = field(default_factory=list)
    error: str = ""
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"kind": self.kind, "query": self.query, "ok": self.ok,
                "verified": list(self.verified), "candidates": list(self.candidates),
                "sources": list(self.sources), "error": self.error,
                "notes": list(self.notes)}


def _extract_urls(text: str) -> list[str]:
    return [m.group(0).rstrip(".,);") for m in _URL.finditer(text or "")]


def _rpc_like(url: str) -> bool:
    low = url.lower()
    if any(bad in low for bad in (".png", ".jpg", ".svg", ".css", ".js", ".pdf")):
        return False
    return any(h in low for h in _RPC_HINTS) or "rpc" in low


def _candidate_urls(result: IntelResult) -> list[tuple[str, str]]:
    """Pull candidate URLs out of a search result, tagging each with its source.

    URLs are collected from the result's own URLs, its snippets, and its
    descriptions -- an RPC endpoint is often written inline in a snippet rather
    than being the result's own link.
    """
    seen: set[str] = set()
    out: list[tuple[str, str]] = []
    for s in result.sources:
        texts = [s.url, s.description, *s.snippets]
        for t in texts:
            for url in _extract_urls(t):
                if url in seen:
                    continue
                seen.add(url)
                out.append((url, s.url))
    return out


def _probe_chain_id(url: str, *, timeout: int = 15) -> tuple[bool, int, str]:
    """Probe an endpoint with a real ``eth_chainId`` call. Never raises."""
    from ..deployed import ChainClient, RpcUnavailable

    try:
        client = ChainClient(url, timeout=timeout)
        raw = client.call("eth_chainId", [])
    except RpcUnavailable as exc:
        return False, 0, str(exc)
    except Exception as exc:  # noqa: BLE001 -- an unreachable endpoint is a result
        return False, 0, f"{type(exc).__name__}: {exc}"
    try:
        chain_id = int(str(raw), 16) if str(raw).startswith("0x") else int(raw)
    except (TypeError, ValueError):
        return False, 0, f"unparseable chain id: {raw!r}"
    return True, chain_id, ""


def discover_rpc_endpoints(
    chain: str,
    *,
    client: Optional[YouComClient] = None,
    expect_chain_id: Optional[int] = None,
    count: int = 10,
    probe: bool = True,
    timeout: int = 15,
) -> DiscoveryResult:
    """Find live RPC endpoints for ``chain`` and verify them by probing.

    Only endpoints that answer ``eth_chainId`` (and, when given, match
    ``expect_chain_id``) are placed in ``verified``; everything else found is a
    ``candidate``. With ``probe=False`` the search runs but nothing is called --
    every URL is a candidate and ``verified`` is empty, honestly.
    """
    client = client or YouComClient()
    res = DiscoveryResult(kind="rpc", query=chain)

    # 1) The keyless authoritative registry: deterministic RPC URLs, no spend.
    registry_urls = _registry_rpc_urls(chain, timeout=timeout)
    for u in registry_urls:
        res.candidates.append(RpcEndpoint(url=u, source="chainid.network/chains.json").to_dict())
    if registry_urls:
        res.notes.append(f"{len(registry_urls)} endpoint(s) from the keyless chain registry")

    # 2) You.com search: fills gaps the registry does not cover, as a lead.
    query = f"{chain} public RPC endpoint JSON-RPC URL chain id"
    r = client.search(query, count=count, include_domains=RPC_SOURCE_DOMAINS)
    if r.ok:
        res.sources = [s.to_dict() for s in r.sources]
        for u, src in _candidate_urls(r):
            if _rpc_like(u) and not any(c["url"] == u for c in res.candidates):
                res.candidates.append(RpcEndpoint(url=u, source=src).to_dict())
    elif not registry_urls:
        res.error = r.error or "search failed"
        return res
    else:
        res.notes.append(f"You.com search failed ({r.error or 'error'}); "
                         "registry candidates only")

    if not res.candidates:
        res.notes.append("no RPC-shaped URL found; none verified")
        return res

    if not probe:
        res.notes.append("probing disabled; every endpoint is an unverified candidate")
        return res

    # 3) Verify every candidate with a real eth_chainId call. Only the ones that
    #    answer (and match the expected id, when given) are promoted to facts.
    cand_urls = [c["url"] for c in res.candidates]
    res.candidates = []
    for url in cand_urls:
        ok, chain_id, err = _probe_chain_id(url, timeout=timeout)
        ep = RpcEndpoint(url=url, verified=ok, chain_id=chain_id, error=err)
        if ok and expect_chain_id is not None and chain_id != expect_chain_id:
            ep.verified = False
            ep.error = f"chain id {chain_id} != expected {expect_chain_id}"
        (res.verified if ep.verified else res.candidates).append(ep.to_dict())
    res.ok = bool(res.verified)
    if not res.verified:
        res.notes.append("no endpoint answered eth_chainId; nothing verified")
    return res


def discover_contract(
    protocol: str,
    *,
    chain: str = "",
    rpc_url: str = "",
    client: Optional[YouComClient] = None,
    count: int = 10,
) -> DiscoveryResult:
    """Find a protocol's on-chain address and verify it holds code.

    ``rpc_url`` is the endpoint to verify against. Without it the result is
    unverified candidates only -- the address is a lead until a call confirms it.
    """
    client = client or YouComClient()
    res = DiscoveryResult(kind="contract", query=f"{protocol} {chain}".strip())
    query = f"{protocol} {chain} contract address etherscan deployed".strip()
    r = client.search(query, count=count)
    if not r.ok:
        res.error = r.error or "search failed"
        return res
    res.sources = [s.to_dict() for s in r.sources]

    addr_re = re.compile(r"\b0x[a-fA-F0-9]{40}\b")
    seen: set[str] = set()
    for s in r.sources:
        for text in (s.description, *s.snippets, s.title):
            for addr in addr_re.findall(text or ""):
                a = addr.lower()
                if a in seen:
                    continue
                seen.add(a)
                res.candidates.append({"address": addr, "source": s.url})

    if rpc_url:
        from ..deployed import ChainClient, RpcUnavailable

        c = ChainClient(rpc_url)
        for cand in res.candidates:
            try:
                code = c.call("eth_getCode", [cand["address"], "latest"])
            except (RpcUnavailable, Exception) as exc:  # noqa: BLE001
                cand["error"] = str(exc)
                continue
            if isinstance(code, str) and code not in ("0x", "0x0"):
                cand["code_size"] = max(0, (len(code) - 2) // 2)
                res.verified.append(cand)
        res.ok = bool(res.verified)
    else:
        res.notes.append("no rpc_url given; addresses are unverified candidates")
    return res


def discover_chain(
    name: str,
    *,
    client: Optional[YouComClient] = None,
    count: int = 8,
) -> DiscoveryResult:
    """Resolve a chain's numeric id from its name, and report the source.

    The keyless registry is consulted first: it names a chain and its id
    exactly, so a chain in it is resolved without ambiguity. Only when the
    registry does not have the chain is the id taken from search results, and
    then only a *single* id is treated as verified -- several ids (a name shared
    by a testnet) are reported as ambiguous, never guessed.
    """
    client = client or YouComClient()
    res = DiscoveryResult(kind="chain", query=name)

    # 1) The keyless registry: exact and deterministic.
    registry_id = _registry_chain_id(name)
    if registry_id is not None:
        res.verified = [{"chain_id": registry_id, "source": "chainid.network/chains.json"}]
        res.ok = True
        return res

    # 2) You.com search, only if the registry did not have it.
    r = client.search(f"{name} chain id network id", count=count,
                      include_domains=RPC_SOURCE_DOMAINS)
    if not r.ok:
        res.error = r.error or "search failed"
        return res
    res.sources = [s.to_dict() for s in r.sources]

    id_re = re.compile(r"\b(?:chain\s*id|network\s*id|chainId)[^\d]{0,12}(\d{1,9})\b",
                       re.IGNORECASE)
    found: set[int] = set()
    for s in r.sources:
        for text in (s.title, s.description, *s.snippets):
            for m in id_re.finditer(text or ""):
                found.add(int(m.group(1)))
    res.candidates = [{"chain_id": cid} for cid in sorted(found)]
    if len(found) == 1:
        res.verified = [{"chain_id": next(iter(found)), "source": "search"}]
        res.ok = True
    elif not found:
        res.notes.append("no chain id found in the results")
    else:
        res.notes.append(f"{len(found)} distinct chain ids seen; ambiguous, not verified")
    return res
