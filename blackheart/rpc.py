"""Universal RPC resolution: find a *live* endpoint, don't hardcode one.

BLACKHEART had several hardcoded mainnet RPC URLs (``targets``, ``adversarial``,
the ``deployed`` CLI). A hardcoded endpoint is a single point of failure -- when
it dies the fork tests are silently skipped -- and it silently pins every run to
one provider. This module resolves an endpoint honestly and in a fixed order:

  1. an explicit ``--rpc`` / ``BLACKHEART_ETH_RPC`` value (the operator's choice
     always wins, and is used verbatim, never overridden);
  2. the keyless ``chainid.network`` registry (:mod:`blackheart.intelligence.discover`),
     which needs no API key;
  3. **You.com** discovery (:func:`blackheart.intelligence.discover.discover_rpc_endpoints`),
     the enforced search provider, as a lead source;
  4. a last-resort list of well-known public endpoints, so a fresh sandbox still
     works when both the registry and the search are unreachable.

Every candidate is *probed* with a real ``eth_chainId`` call and only a live
endpoint is returned. When none answers, the resolver returns ``None`` and says
so -- it never returns an endpoint it did not see answer.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Optional

#: The operator's explicit override. Always honoured first, never replaced.
ENV_VAR = "BLACKHEART_ETH_RPC"

#: Last-resort public endpoints, tried only when the registry and the search both
#: fail. These are convenience fallbacks, not a guarantee; each is still probed.
FALLBACKS: tuple[str, ...] = (
    "https://eth.drpc.org",
    "https://ethereum-rpc.publicnode.com",
    "https://gateway.tenderly.co/public/mainnet",
)

#: The mainnet chain id, for the default resolution.
MAINNET_CHAIN_ID = 1


@dataclass
class RpcResolution:
    """The resolved endpoint and the honest trail of how it was found."""

    url: str = ""
    ok: bool = False
    chain_id: int = 0
    source: str = ""
    tried: list[dict] = field(default_factory=list)
    error: str = ""

    def to_dict(self) -> dict:
        return {"url": self.url, "ok": self.ok, "chain_id": self.chain_id,
                "source": self.source, "tried": list(self.tried), "error": self.error}


def resolve_rpc(
    chain: str = "mainnet",
    *,
    explicit: Optional[str] = None,
    expect_chain_id: Optional[int] = None,
    use_search: bool = True,
    use_registry: bool = True,
    timeout: int = 15,
) -> RpcResolution:
    """Resolve one live RPC endpoint for ``chain``, or ``None`` with a reason.

    ``chain`` may be a name or a numeric id; a numeric id is also enforced as the
    expected chain id, so a fallback endpoint for another chain is never returned
    as if it were the requested one.

    ``explicit`` (or ``$BLACKHEART_ETH_RPC``) is returned unprobed-by-default only
    when it answers; a caller that must not pay a probe can pass ``probe=False``
    through :func:`probe_rpc`.
    """
    if expect_chain_id is None:
        numeric = str(chain).strip()
        if numeric.isdigit():
            expect_chain_id = int(numeric)
    res = RpcResolution()
    chosen = explicit or os.environ.get(ENV_VAR)

    # 1) The operator's explicit choice wins and is used verbatim.
    if chosen:
        ok, cid, err = probe_rpc(chosen, timeout=timeout)
        res.tried.append({"url": chosen, "source": "explicit", "ok": ok, "error": err})
        if ok:
            res.url, res.ok, res.chain_id, res.source = chosen, True, cid, "explicit"
            return res
        res.error = f"explicit endpoint {chosen} did not answer: {err}"
        return res

    # 2) The keyless registry -- deterministic, no spend.
    if use_registry:
        from .intelligence.discover import _registry_rpc_urls

        for url in _registry_rpc_urls(chain, timeout=timeout):
            ok, cid, err = probe_rpc(url, timeout=timeout)
            res.tried.append({"url": url, "source": "registry", "ok": ok, "error": err})
            if ok and _id_ok(cid, expect_chain_id):
                res.url, res.ok, res.chain_id, res.source = url, True, cid, "registry"
                return res

    # 3) You.com discovery -- the enforced search provider, as a lead source.
    if use_search:
        try:
            from .intelligence.discover import discover_rpc_endpoints

            found = discover_rpc_endpoints(
                chain, expect_chain_id=expect_chain_id, count=10,
                probe=True, timeout=timeout)
            for ep in found.verified:
                res.tried.append({"url": ep["url"], "source": "you.com",
                                  "ok": True, "error": ""})
                res.url, res.ok, res.chain_id, res.source = (
                    ep["url"], True, ep.get("chain_id", 0), "you.com")
                return res
            for cand in found.candidates:
                res.tried.append({"url": cand["url"], "source": "you.com",
                                  "ok": False, "error": cand.get("error", "")})
        except Exception as exc:  # noqa: BLE001 -- a search failure is a recorded miss
            res.tried.append({"url": "", "source": "you.com", "ok": False,
                              "error": f"{type(exc).__name__}: {exc}"})

    # 4) Last-resort well-known endpoints -- still probed, never trusted blindly.
    for url in FALLBACKS:
        ok, cid, err = probe_rpc(url, timeout=timeout)
        res.tried.append({"url": url, "source": "fallback", "ok": ok, "error": err})
        if ok and _id_ok(cid, expect_chain_id):
            res.url, res.ok, res.chain_id, res.source = url, True, cid, "fallback"
            return res

    res.error = res.error or "no endpoint answered eth_chainId"
    return res


def probe_rpc(url: str, *, timeout: int = 15) -> tuple[bool, int, str]:
    """Probe ``url`` with a real ``eth_chainId``. Never raises."""
    from .deployed import ChainClient, RpcUnavailable

    try:
        raw = ChainClient(url, timeout=timeout).call("eth_chainId", [])
    except RpcUnavailable as exc:
        return False, 0, str(exc)
    except Exception as exc:  # noqa: BLE001 -- an unreachable endpoint is a result
        return False, 0, f"{type(exc).__name__}: {exc}"
    try:
        cid = int(str(raw), 16) if str(raw).startswith("0x") else int(raw)
    except (TypeError, ValueError):
        return False, 0, f"unparseable chain id: {raw!r}"
    return True, cid, ""


def _id_ok(chain_id: int, expect: Optional[int]) -> bool:
    return expect is None or chain_id == expect


def resolve_mainnet_rpc(explicit: Optional[str] = None, *, timeout: int = 15) -> str:
    """A live mainnet RPC URL, or ``""`` when none answered.

    Convenience for callers that just want a URL string; the empty string means
    "none resolved" and must be treated as unavailable, never replaced by a guess.
    """
    return resolve_rpc("mainnet", explicit=explicit, expect_chain_id=MAINNET_CHAIN_ID,
                       timeout=timeout).url
