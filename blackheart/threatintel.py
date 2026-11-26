"""Public threat-intel ingestion: disclosed bugs -> reusable research leads.

The legitimate version of "what the underground knows" is the public record of
disclosed vulnerabilities: Solodit's aggregated audit findings, Immunefi's
disclosed reports, and DeFiLlama's hack database. Mining that record for reusable
*attack patterns* is how a research engine gets sharper without inventing
anything -- every pattern traces to a public source with a URL and a date.

This module turns a feed record into a :class:`ThreatPattern` (a normalized lead)
and from it into a :class:`~blackheart.threatintel.RegressionFixture`-shaped dict
the corpus/regression machinery can load. It introduces no engine and no score.

Honesty rules that shape the API:

* **A pattern is a lead, never a finding.** A disclosed bug in another protocol
  says "this class of thing broke once", not "this target is vulnerable". The
  verdict is always ``LEAD``; nothing here is ever ``CONFIRMED``.
* **No invented severity or payout.** ``severity`` is copied verbatim from the
  source when present and left empty otherwise; ``attack_class`` is the source's
  own wording, or ``"unclassified"`` -- never a guessed class. No numeric score
  is computed, because eligibility and severity belong to the target's own policy
  (see ``blackheart.bounty.gate``).
* **No network by default.** Fetching is an injected callable; the default
  refuses, so the ordinary path is a local file and the suite stays offline. A
  caller that wants the live feed passes ``allow_network=True`` and a fetcher.
* **Dropped records are reported, not hidden.** ``ingest`` returns the accepted
  patterns *and* the rejected records with a reason, so a malformed feed cannot
  masquerade as a clean one.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional

#: The public sources this module understands.
SOURCE_KINDS: tuple[str, ...] = ("solodit", "immunefi", "defillama")

#: A fetcher maps a URL to response text. Injected so tests never touch a network.
Fetcher = Callable[[str], str]


class ThreatIntelError(ValueError):
    """The feed record is malformed or the source is unknown."""


class NetworkDisabled(RuntimeError):
    """A live fetch was requested without an explicit fetcher/allow_network."""


@dataclass
class ThreatPattern:
    """One disclosed vulnerability, normalized into a reusable lead."""

    source: str
    source_id: str
    title: str
    attack_class: str
    invariant: str = ""
    severity: str = ""
    url: str = ""
    reported_at: str = ""
    project: str = ""
    root_cause: str = ""
    minimal_repro: list[str] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)
    #: Always ``LEAD`` -- a disclosed pattern is a lead, never a confirmed finding.
    verdict: str = "LEAD"

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "source_id": self.source_id,
            "title": self.title,
            "attack_class": self.attack_class,
            "invariant": self.invariant,
            "severity": self.severity,
            "url": self.url,
            "reported_at": self.reported_at,
            "project": self.project,
            "root_cause": self.root_cause,
            "minimal_repro": list(self.minimal_repro),
            "verdict": self.verdict,
        }


@dataclass
class IngestResult:
    patterns: list[ThreatPattern] = field(default_factory=list)
    skipped: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "accepted": len(self.patterns),
            "skipped": len(self.skipped),
            "patterns": [p.to_dict() for p in self.patterns],
            "rejected": list(self.skipped),
        }


def _first(record: dict[str, Any], *keys: str) -> str:
    for key in keys:
        value = record.get(key)
        if value not in (None, ""):
            return str(value).strip()
    return ""


def _class_from(record: dict[str, Any]) -> str:
    """Use the source's own classification wording; never guess a class."""
    value = record.get("attack_class") or record.get("category") or record.get("classification")
    if isinstance(value, list):
        value = ", ".join(str(v) for v in value if v)
    return str(value).strip() if value else "unclassified"


def _steps_from(record: dict[str, Any]) -> list[str]:
    for key in ("minimal_repro", "steps", "exploit_steps", "poc_steps"):
        value = record.get(key)
        if isinstance(value, list):
            return [str(v) for v in value]
        if isinstance(value, str) and value.strip():
            return [value.strip()]
    return []


def normalize_record(record: dict[str, Any], source: str) -> ThreatPattern:
    """Normalize one feed record from ``source`` into a :class:`ThreatPattern`."""
    if source not in SOURCE_KINDS:
        raise ThreatIntelError(f"unknown source {source!r}; expected one of {SOURCE_KINDS}")
    if not isinstance(record, dict):
        raise ThreatIntelError("record must be a JSON object")

    title = _first(record, "title", "name", "summary")
    source_id = _first(record, "id", "source_id", "findingId", "slug", "uuid")
    if not title or not source_id:
        raise ThreatIntelError("record has no title/id; cannot normalize")

    return ThreatPattern(
        source=source,
        source_id=source_id,
        title=title,
        attack_class=_class_from(record),
        invariant=_first(record, "invariant", "property"),
        severity=_first(record, "severity", "risk"),
        url=_first(record, "url", "source_url", "link", "report_url"),
        reported_at=_first(record, "reported_at", "date", "published_at", "created_at"),
        project=_first(record, "project", "protocol", "target"),
        root_cause=_first(record, "root_cause", "description", "summary_text"),
        minimal_repro=_steps_from(record),
        raw=dict(record),
    )


def ingest(records: Any, source: str) -> IngestResult:
    """Normalize a list of records, keeping accepted patterns and rejected reasons."""
    if not isinstance(records, list):
        raise ThreatIntelError("feed must be a JSON array of records")
    result = IngestResult()
    for index, record in enumerate(records):
        try:
            result.patterns.append(normalize_record(record, source))
        except ThreatIntelError as exc:
            result.skipped.append({"index": index, "reason": str(exc)})
    return result


def default_fetcher(_url: str) -> str:
    raise NetworkDisabled(
        "live threat-intel fetch is disabled; pass a fetcher or read a local file "
        "(the suite stays offline by design)"
    )


def fetch_text(url: str, *, fetcher: Optional[Fetcher] = None,
               allow_network: bool = False) -> str:
    """Fetch a URL's text, refusing unless a fetcher is supplied (or allowed)."""
    if fetcher is not None:
        return fetcher(url)
    if not allow_network:
        return default_fetcher(url)
    import urllib.request  # local import: the offline path never touches it

    with urllib.request.urlopen(url, timeout=30) as resp:  # noqa: S310 - explicit opt-in
        return resp.read().decode("utf-8", "replace")


def ingest_from_url(url: str, source: str, *, fetcher: Optional[Fetcher] = None,
                    allow_network: bool = False) -> IngestResult:
    """Fetch a JSON feed from ``url`` and ingest it."""
    text = fetch_text(url, fetcher=fetcher, allow_network=allow_network)
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ThreatIntelError(f"feed is not valid JSON: {exc}") from exc
    return ingest(data, source)


def to_regression_fixture(pattern: ThreatPattern) -> dict[str, Any]:
    """Turn a pattern into a corpus-loadable regression fixture (a lead)."""
    return {
        "id": pattern.source_id,
        "source": pattern.source,
        "class": pattern.attack_class,
        "invariant": pattern.invariant,
        "steps": list(pattern.minimal_repro),
        "expected": "violated",
        "provenance": {"url": pattern.url, "reported_at": pattern.reported_at,
                       "project": pattern.project},
        # A disclosed bug elsewhere is a lead for this target, never a finding.
        "verdict": "LEAD",
    }


def write_fixtures(patterns: list[ThreatPattern], out_dir: str | Path) -> list[Path]:
    """Write one ``<source>__<id>.json`` fixture per pattern; return the paths."""
    root = Path(out_dir)
    root.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for pattern in patterns:
        safe = "".join(c if c.isalnum() or c in "-_" else "-" for c in pattern.source_id)
        path = root / f"{pattern.source}__{safe}.json"
        path.write_text(json.dumps(to_regression_fixture(pattern), indent=2), encoding="utf-8")
        written.append(path)
    return written


__all__ = [
    "SOURCE_KINDS",
    "ThreatIntelError",
    "NetworkDisabled",
    "ThreatPattern",
    "IngestResult",
    "normalize_record",
    "ingest",
    "fetch_text",
    "ingest_from_url",
    "to_regression_fixture",
    "write_fixtures",
]
