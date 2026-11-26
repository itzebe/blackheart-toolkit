"""External-research integration for the runtime engine.

The runtime engine establishes what a target *does*. This module adds the
external half of a real investigation: given a runtime finding, ask BLACKHEART's
existing external-intelligence layer (You.com first, then the free keyless
providers) whether the same weakness is already known -- a published advisory, a
CVE, prior art, or a documented intended behaviour.

Two hard rules, both inherited from the intelligence layer and re-stated here
because this is a new call site:

  * **External text is data, never instructions.** A result is passed through
    :func:`~blackheart.intelligence.quarantine.quarantine_sources` before it is
    used, so an injected instruction in a fetched page cannot steer the engine.
  * **A missing key is not a failure and not a success.** When no provider is
    configured the result says so plainly (``status="unavailable"``); it never
    fabricates a finding or a negative. This is the mission's "missing API key
    must produce a clear setup instruction, not a fake successful connection".

The integration is *optional*: the runtime engine works without it, and the
research step degrades honestly when the network or a key is absent.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from ...intelligence import ProviderRegistry, SearchRouter
from ...intelligence.quarantine import quarantine_sources
from ...intelligence.youcom import KEY_ENV

#: How a research call ended. Distinct so a caller never confuses them.
RESEARCH_STATUS = ("ok", "no_results", "unavailable", "failed")


@dataclass
class ResearchNote:
    """The external context gathered for one runtime finding (untrusted data)."""

    finding: str
    status: str = "unavailable"
    query: str = ""
    provider: str = ""
    provider_chain: list[str] = field(default_factory=list)
    sources: list[dict] = field(default_factory=list)   # url/title/snippet
    already_known: Optional[bool] = None
    setup_hint: str = ""
    error: str = ""

    def to_dict(self) -> dict:
        return {
            "finding": self.finding,
            "status": self.status,
            "query": self.query,
            "provider": self.provider,
            "provider_chain": list(self.provider_chain),
            "sources": list(self.sources),
            "already_known": self.already_known,
            "setup_hint": self.setup_hint,
            "error": self.error,
        }


#: Phrases that, in a result title/snippet, suggest the weakness is already known.
_KNOWN_MARKERS = (
    "cve-", "advisory", "security bulletin", "patch", "fixed in", "vulnerability",
    "exploit", "disclosed", "ghsa-",
)


def _looks_known(texts: list[str]) -> bool:
    hay = " ".join(texts).lower()
    return any(m in hay for m in _KNOWN_MARKERS)


def research_finding(finding: str, *, target: str = "", invariant: str = "",
                     cross_check: bool = False) -> ResearchNote:
    """Look up whether a runtime finding is already known, using real providers.

    Returns a :class:`ResearchNote` whose ``status`` is one of
    :data:`RESEARCH_STATUS`. Nothing is fabricated: an unavailable provider is
    reported as ``unavailable`` with a setup hint, and a live failure is reported
    as ``failed`` with the reason.
    """
    query = _query_for(finding, target, invariant)
    note = ResearchNote(finding=finding, query=query)
    registry = ProviderRegistry()
    available = [n for n in registry.names() if registry.get(n).available()]
    note.provider_chain = available
    if not available:
        note.status = "unavailable"
        note.setup_hint = (
            f"no intelligence provider is configured; set {KEY_ENV} in the runtime "
            "environment to enable You.com search (free keyless providers "
            "duckduckgo/wikipedia are tried otherwise)"
        )
        return note
    try:
        routed = SearchRouter(registry).search(query, count=5, cross_check=cross_check)
    except Exception as exc:  # noqa: BLE001 -- a research failure must not break the run
        note.status = "failed"
        note.error = f"{type(exc).__name__}: {exc}"
        return note
    if not routed.ok or routed.result is None:
        note.status = "failed" if routed.attempts else "unavailable"
        note.error = "all configured providers failed"
        return note
    note.provider = routed.provider
    result = routed.result
    # treat every source as untrusted: quarantine before use
    quarantined = quarantine_sources(result)
    note.sources = [
        {"url": s.url, "title": s.title, "snippet": (s.snippets[0] if s.snippets else "")[:400],
         "provider": getattr(s, "provider", note.provider)}
        for s in quarantined.sources
    ]
    if not note.sources:
        note.status = "no_results"
        return note
    note.status = "ok"
    note.already_known = _looks_known(
        [f"{s['title']} {s['snippet']}" for s in note.sources])
    return note


def research_findings(report: dict, *, target: str = "", cross_check: bool = False) -> list[dict]:
    """Attach a research note to every violation in a runtime report.

    Returns a list of notes (one per violation); the caller decides whether to
    merge them into the report. Never raises on a research failure.
    """
    notes = []
    for v in report.get("violations", []):
        notes.append(research_finding(
            v["invariant_id"], target=target or report.get("target", ""),
            invariant=v["invariant_id"], cross_check=cross_check).to_dict())
    return notes


def _query_for(finding: str, target: str, invariant: str) -> str:
    parts = []
    if target:
        parts.append(target)
    if invariant:
        parts.append(invariant.replace("-", " "))
    else:
        parts.append(finding.replace("-", " "))
    parts.append("vulnerability")
    return " ".join(parts).strip()
