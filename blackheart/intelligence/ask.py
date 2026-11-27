"""Standing external-help policy: BLACKHEART asks You.com first, by default.

The search router already enforces You.com as the sole provider when YDC_API_KEY is
configured (keyless fallbacks answer only when it is not). This module is the thin,
stable entry point: ``ask(question)`` uses the You.com-first default, and
``provider_order()`` honours BLACKHEART_INTEL_ORDER so a deployment can reorder or
extend providers without code changes. Callers never pass "use you.com" -- it is the
default.
"""

from __future__ import annotations

import os
from typing import Optional

from .providers import DEFAULT_ORDER, ProviderRegistry, RoutedSearch, SearchRouter

ORDER_ENV = "BLACKHEART_INTEL_ORDER"


def provider_order() -> tuple[str, ...]:
    """You.com-first by default; BLACKHEART_INTEL_ORDER (comma list) overrides it."""
    raw = os.environ.get(ORDER_ENV, "").strip()
    if raw:
        return tuple(p.strip() for p in raw.split(",") if p.strip())
    return DEFAULT_ORDER


def ask(
    question: str,
    *,
    count: int = 10,
    registry: Optional[ProviderRegistry] = None,
    cross_check: bool = False,
) -> RoutedSearch:
    """Ask the intelligence router -- You.com first when YDC_API_KEY is set."""
    router = SearchRouter(registry)
    return router.search(question, count=count, order=provider_order(),
                         cross_check=cross_check)
