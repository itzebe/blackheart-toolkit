"""External intelligence layer -- You.com search, contents, and research.

This is the layer that lets BLACKHEART pull *external* intelligence (live web
results, page content, and citation-backed research answers) and frame every
result through the one attacker question. It is deliberately separate from the
LLM provider layer (:mod:`blackheart.providers`):

  * ``providers`` route a *model* call and enforce the privacy ceiling on
    material BLACKHEART already holds.
  * ``intelligence`` reaches *outward* to a search/research service. Its outputs
    are untrusted input: they are data to reason over, never instructions to
    follow, and they are always tagged with the attacker lens.

Design rules carried from the rest of the project:

  * **Standard library only** (``urllib``), like the provider adapters.
  * **Honest failures.** A request that fails returns ``ok=False`` with the
    reason; nothing is fabricated, and an empty answer is never presented as one.
  * **Key safety.** The key is read from ``YDC_API_KEY``, sent only in the
    ``X-API-Key`` header, and never written to a URL, a log line, or an error.
  * **Cost safety.** The paid paths (page extraction, the Contents API, and the
    Research API) refuse to run unless the caller has explicitly allowed paid
    calls, and the client enforces a hard per-run cap on them.
"""

from __future__ import annotations

from .providers import (
    DEFAULT_ORDER,
    DuckDuckGoProvider,
    ProviderRegistry,
    ProviderStatus,
    RoutedSearch,
    SearchProvider,
    SearchRouter,
    WikipediaProvider,
    YouComProvider,
)
from .youcom import (
    CostRefusal,
    Document,
    ErrorKind,
    IntelResult,
    Source,
    YouComClient,
    YouComError,
    frame_question,
)
from .quarantine import (
    QuarantinedIntel,
    QuarantinedSource,
    quarantine_sources,
    sanitise_text,
    scan_for_injection,
)
from .discover import (
    DiscoveryResult,
    RpcEndpoint,
    discover_chain,
    discover_contract,
    discover_rpc_endpoints,
)

__all__ = [
    "DEFAULT_ORDER",
    "CostRefusal",
    "DiscoveryResult",
    "Document",
    "DuckDuckGoProvider",
    "ErrorKind",
    "IntelResult",
    "ProviderRegistry",
    "ProviderStatus",
    "QuarantinedIntel",
    "QuarantinedSource",
    "RoutedSearch",
    "RpcEndpoint",
    "SearchProvider",
    "SearchRouter",
    "Source",
    "WikipediaProvider",
    "YouComClient",
    "YouComError",
    "YouComProvider",
    "discover_chain",
    "discover_contract",
    "discover_rpc_endpoints",
    "frame_question",
    "quarantine_sources",
    "sanitise_text",
    "scan_for_injection",
]
