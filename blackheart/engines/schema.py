"""The unified finding schema every engine's output is normalised into.

An engine's own report shape is preserved under ``raw``; the normalised fields
below are what the orchestrator correlates, deduplicates, verifies, and reports.
Two properties matter more than completeness:

  * **Deterministic identity.** ``fingerprint`` is a content hash over the
    *root-cause-bearing* fields (engine-independent), and ``finding_id`` is
    derived from it, so the same defect from two engines or two runs collapses to
    one id.
  * **Provenance is never lost.** ``source_engine``, ``engine_version``,
    ``raw_artifact`` and ``raw`` keep the original record; normalisation is
    additive, never destructive.

A normalised finding is a *candidate*. Its ``disposition`` starts at
``NEEDS_MORE_EVIDENCE`` and can only be raised by BLACKHEART's own verification
gate -- never by the engine that produced it.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Any, Optional

from ..models import Classification, sha256_of, utcnow

#: The engine-independent severity vocabulary (reuses models.Severity values).
SEVERITIES = ("critical", "high", "medium", "low", "info")

#: Loose normalisation of the many severity spellings engines emit.
_SEVERITY_ALIASES = {
    "critical": "critical", "crit": "critical", "sev0": "critical", "s0": "critical",
    "high": "high", "sev1": "high", "s1": "high", "error": "high",
    "medium": "medium", "med": "medium", "moderate": "medium", "sev2": "medium",
    "s2": "medium", "warning": "medium",
    "low": "low", "sev3": "low", "s3": "low", "note": "low",
    "info": "info", "informational": "info", "none": "info", "sev4": "info",
}

_CWE_RE = re.compile(r"\bCWE[-_: ]?\s*(\d{1,4})\b", re.IGNORECASE)
_BARE_NUM_RE = re.compile(r"^\s*(\d{1,4})\s*$")


def normalize_severity(value: Any) -> str:
    """Map any engine's severity spelling onto the canonical five levels."""
    if value is None:
        return "info"
    text = str(value).strip().lower()
    if text in _SEVERITY_ALIASES:
        return _SEVERITY_ALIASES[text]
    for token in re.split(r"[^a-z0-9]+", text):
        if token in _SEVERITY_ALIASES:
            return _SEVERITY_ALIASES[token]
    return "info"


def normalize_cwe(value: Any) -> str:
    """Extract a canonical ``CWE-NNN`` id from any spelling, or ''."""
    if value is None:
        return ""
    if isinstance(value, int):
        return f"CWE-{value}"
    text = str(value).strip()
    m = _CWE_RE.search(text)
    if m:
        return f"CWE-{int(m.group(1))}"
    bare = _BARE_NUM_RE.match(text)  # a bare "306" is a CWE id
    return f"CWE-{int(bare.group(1))}" if bare else ""


def normalize_cvss(value: Any) -> Optional[float]:
    """Parse a CVSS score to a 0.0-10.0 float, or None when unusable."""
    if value is None:
        return None
    if isinstance(value, (int, float)):
        score = float(value)
    else:
        m = re.search(r"\d+(?:\.\d+)?", str(value))
        if not m:
            return None
        score = float(m.group(0))
    if not 0.0 <= score <= 10.0:
        return None
    return round(score, 1)


#: Severity ranking for sorting (most severe first).
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


@dataclass
class NormalizedFinding:
    """One engine candidate finding in the engine-independent schema.

    ``disposition`` is the BLACKHEART verdict and is *not* set by the engine; the
    default is the honest "not yet proven" value.
    """

    # -- identity + provenance --
    finding_id: str = ""
    fingerprint: str = ""
    source_engine: str = ""
    engine_version: str = ""
    target_id: str = ""
    scope_reference: str = ""
    raw_artifact: str = ""

    # -- classification --
    category: str = ""
    title: str = ""
    description: str = ""
    severity: str = "info"
    cvss: Optional[float] = None
    cwe: str = ""
    owasp: str = ""
    confidence: str = ""

    # -- location / vector --
    component: str = ""
    source_location: str = ""
    attack_vector: str = ""
    preconditions: list[str] = field(default_factory=list)
    attacker_capabilities: list[str] = field(default_factory=list)

    # -- proof --
    exploit_steps: list[str] = field(default_factory=list)
    reproduction: str = ""
    evidence_refs: list[str] = field(default_factory=list)
    request_response: str = ""
    execution_environment: str = ""

    # -- disposition / lifecycle --
    timestamp: str = field(default_factory=utcnow)
    reproduction_status: str = "not_attempted"
    verification_status: str = "unverified"
    novelty_status: str = "unknown"
    duplicate_of: str = ""
    impact: str = ""
    remediation: str = ""
    disposition: str = Classification.NEEDS_MORE_EVIDENCE.value

    # -- preserved original --
    raw: dict = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.severity = normalize_severity(self.severity)
        self.cwe = normalize_cwe(self.cwe) or self.cwe
        if not self.finding_id:
            self.finding_id = self.compute_id()

    # -- identity ---------------------------------------------------------- #
    def root_cause_key(self) -> str:
        """The engine-independent identity of the defect.

        Deliberately *excludes* engine, severity, title wording, and timestamp:
        two engines describing the same defect with different words and different
        severity must still collide here. It *includes* the component and the
        normalised source location/description, which is what makes it the same
        bug rather than a coincidental symptom.
        """
        parts = [
            self.target_id.strip().lower(),
            self.component.strip().lower(),
            _normalize_location(self.source_location),
            _normalize_text(self.description or self.title),
            self.cwe.lower(),
        ]
        return "|".join(parts)

    def compute_fingerprint(self) -> str:
        return hashlib.sha256(self.root_cause_key().encode("utf-8")).hexdigest()

    def compute_id(self) -> str:
        """A deterministic id derived from the fingerprint (stable across runs)."""
        return "ENG-" + self.compute_fingerprint()[:12].upper()

    def finalize(self) -> "NormalizedFinding":
        """Compute the fingerprint/id once the identifying fields are set."""
        self.fingerprint = self.compute_fingerprint()
        self.finding_id = self.compute_id()
        return self

    # -- serialisation ----------------------------------------------------- #
    def to_dict(self) -> dict:
        return {
            "finding_id": self.finding_id,
            "fingerprint": self.fingerprint,
            "source_engine": self.source_engine,
            "engine_version": self.engine_version,
            "target_id": self.target_id,
            "scope_reference": self.scope_reference,
            "raw_artifact": self.raw_artifact,
            "category": self.category,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "cvss": self.cvss,
            "cwe": self.cwe,
            "owasp": self.owasp,
            "confidence": self.confidence,
            "component": self.component,
            "source_location": self.source_location,
            "attack_vector": self.attack_vector,
            "preconditions": list(self.preconditions),
            "attacker_capabilities": list(self.attacker_capabilities),
            "exploit_steps": list(self.exploit_steps),
            "reproduction": self.reproduction,
            "evidence_refs": list(self.evidence_refs),
            "request_response": self.request_response,
            "execution_environment": self.execution_environment,
            "timestamp": self.timestamp,
            "reproduction_status": self.reproduction_status,
            "verification_status": self.verification_status,
            "novelty_status": self.novelty_status,
            "duplicate_of": self.duplicate_of,
            "impact": self.impact,
            "remediation": self.remediation,
            "disposition": self.disposition,
            "raw": self.raw,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "NormalizedFinding":
        known = {f for f in cls.__dataclass_fields__}
        return cls(**{k: v for k, v in d.items() if k in known})

    @property
    def severity_rank(self) -> int:
        return SEVERITY_ORDER.get(self.severity, 5)

    def may_be_read_as_vulnerability(self) -> bool:
        """Only a CONFIRMED disposition may ever be read as a real vulnerability."""
        return self.disposition == Classification.CONFIRMED.value


def _normalize_text(text: str) -> str:
    return re.sub(r"\s+", " ", (text or "").strip().lower())[:512]


def _normalize_location(location: str) -> str:
    """Normalise a source location so ``a/b.sol:10`` and ``a/b.sol:10-12`` collide."""
    if not location:
        return ""
    text = location.strip().lower()
    text = re.sub(r":\d+\s*[-–]\s*\d+", "", text)  # drop line ranges
    text = re.sub(r":\d+", "", text)               # drop single line numbers
    return text.strip()


def content_fingerprint(record: dict) -> str:
    """A stable hash of a normalised record's identifying content."""
    identifying = {
        k: record.get(k)
        for k in ("target_id", "component", "source_location", "description",
                  "title", "cwe", "severity", "category")
    }
    return sha256_of(identifying)
