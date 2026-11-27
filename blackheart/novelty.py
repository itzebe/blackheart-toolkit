"""Pre-submission novelty gate (mission Phase 2 & 3).

OSS-001 was a real, independently reproducible vulnerability that was rejected as
a **duplicate**. The lesson is structural, not incidental:

    A strong PoC does not establish originality.
    A new exploit technique does not establish a new vulnerability.

This module makes a documented novelty review a *hard gate* before any finding is
treated as submission-ready. The gate is deliberately pessimistic:

  * A candidate starts as ``INSUFFICIENT_EVIDENCE`` and is **blocked**.
  * A match against a public disclosure forces ``LIKELY_DUPLICATE`` or
    ``ALREADY_FIXED`` and is **blocked**.
  * Only a documented search with sufficient coverage and no matching disclosure
    can reach ``LIKELY_NEW`` or ``POSSIBLE_VARIANT``.
  * "I searched and found nothing" is recorded as ``INSUFFICIENT_EVIDENCE`` when
    the search coverage is too thin to support a claim of novelty -- never as
    proof of novelty.

The module does not perform the public search itself; it consumes a recorded
``NoveltyReview`` and adjudicates it, and it provides the matching heuristic the
reviewer uses to compare a candidate against each public disclosure.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .models import (
    NoveltyClass,
    NoveltyReview,
    PublicDisclosure,
)

# Minimum number of distinct databases/sources a review must cite before a
# "no matching disclosure" result may be read as novelty rather than as an
# inconclusive search. Raising this raises the bar; it is intentionally > 1.
MIN_SOURCES_FOR_NOVELTY = 4

# Minimum number of distinct queries recorded for the same reason.
MIN_QUERIES_FOR_NOVELTY = 3


def _tokens(text: str) -> set[str]:
    return {t for t in re.split(r"[^a-z0-9]+", text.lower()) if len(t) > 2}


def _jaccard(a: set[str], b: set[str]) -> float:
    if not a and not b:
        return 0.0
    return len(a & b) / len(a | b)


@dataclass
class MatchResult:
    disclosure: PublicDisclosure
    score: float
    shared: list[str]
    field_sims: dict[str, float] = field(default_factory=dict)

    def same_root_cause_and_component(self) -> bool:
        """Two issues with the same root cause in the same component are the same
        underlying bug, even when the exploit technique or wording differs.

        The root-cause threshold is deliberately moderate: the *mechanism* is
        usually described in different words by different reporters, but a shared
        component plus a substantially-shared root cause is the same defect.
        """
        return (
            self.field_sims.get("root_cause", 0.0) >= 0.4
            and self.field_sims.get("affected_component", 0.0) >= 0.5
        )

    def to_dict(self) -> dict:
        return {
            "identifier": self.disclosure.identifier or self.disclosure.source,
            "url": self.disclosure.url,
            "score": round(self.score, 3),
            "shared": self.shared,
            "same_root_cause_and_component": self.same_root_cause_and_component(),
        }


def _candidate_fields(review: NoveltyReview) -> dict[str, str]:
    return {
        "root_cause": review.root_cause,
        "affected_component": review.affected_component,
        "trust_boundary": review.trust_boundary,
        "exploit_path": review.exploit_path,
        "impact": review.impact,
        "vulnerability_class": review.vulnerability_class,
    }


def match_disclosure(review: NoveltyReview, disclosure: PublicDisclosure) -> MatchResult:
    """Compare one candidate against one public disclosure, field by field.

    The comparison uses the same dimensions the mission lists -- root cause,
    affected component, trust boundary, exploit path, impact -- plus the class.
    Weighting favours *root cause* and *component*: two issues with the same root
    cause in the same component are the same underlying bug even if the exploit
    technique differs.
    """
    weights = {
        "root_cause": 0.35,
        "affected_component": 0.25,
        "trust_boundary": 0.12,
        "exploit_path": 0.13,
        "impact": 0.08,
        "vulnerability_class": 0.07,
    }
    cand = _candidate_fields(review)
    disc = {
        "root_cause": disclosure.root_cause,
        "affected_component": disclosure.affected_component,
        "trust_boundary": disclosure.trust_boundary,
        "exploit_path": disclosure.exploit_path,
        "impact": disclosure.impact,
        "vulnerability_class": "",  # disclosures often do not carry a class
    }
    total = 0.0
    shared: list[str] = []
    field_sims: dict[str, float] = {}
    for field, w in weights.items():  # noqa: F402  loop var shadows dataclasses.field
        c, d = _tokens(cand[field]), _tokens(disc[field])
        if not c or not d:
            continue
        sim = _jaccard(c, d)
        field_sims[field] = sim
        total += w * sim
        if sim >= 0.5:
            shared.append(field)
    # Normalise by the weight actually applicable, so a disclosure with few
    # populated fields is not unfairly penalised to zero.
    applicable = sum(
        w for field, w in weights.items()
        if _tokens(cand[field]) and _tokens(disc[field])
    )
    score = total / applicable if applicable else 0.0
    return MatchResult(disclosure, score, shared, field_sims)


def evaluate_novelty(review: NoveltyReview) -> NoveltyReview:
    """Adjudicate a novelty review and set its classification.

    Rules, in order:

    1. A disclosure with a very high match (>= 0.72) is a **duplicate**. A
       disclosure that matches highly *and* records a remediation is
       **already fixed**.
    2. A disclosure with a moderate match (>= 0.45) makes the candidate at most a
       **possible variant**.
    3. No matching disclosure, but an under-powered search (too few sources or
       queries) is **insufficient evidence** -- blocked, not "novel".
    4. No matching disclosure and a documented, adequately powered search is
       **likely new**.
    """
    matches = sorted(
        (match_disclosure(review, d) for d in review.disclosures),
        key=lambda m: -m.score,
    )
    best = matches[0] if matches else None

    if best is not None and best.score >= 0.72:
        if best.disclosure.remediation:
            review.classification = NoveltyClass.ALREADY_FIXED.value
            review.classification_reason = (
                f"matches public disclosure {best.disclosure.identifier or best.disclosure.source} "
                f"(score {best.score:.2f}) which already has a remediation: "
                f"{best.disclosure.remediation}"
            )
        else:
            review.classification = NoveltyClass.LIKELY_DUPLICATE.value
            review.classification_reason = (
                f"matches public disclosure {best.disclosure.identifier or best.disclosure.source} "
                f"(score {best.score:.2f}) on {', '.join(best.shared) or 'the recorded fields'}"
            )
        return review

    # The decisive rule (the OSS-001 lesson): the same root cause in the same
    # component is the same underlying bug, whatever the exploit path is called.
    # A "new technique" for a known bug is a duplicate, not a new vulnerability.
    if best is not None and best.same_root_cause_and_component():
        review.classification = NoveltyClass.LIKELY_DUPLICATE.value
        review.classification_reason = (
            f"the same root cause in the same affected component as public disclosure "
            f"{best.disclosure.identifier or best.disclosure.source} (score {best.score:.2f}); "
            "a different exploit technique does not make this a new vulnerability"
        )
        return review

    if best is not None and best.score >= 0.40:
        review.classification = NoveltyClass.POSSIBLE_VARIANT.value
        review.classification_reason = (
            f"partial match with {best.disclosure.identifier or best.disclosure.source} "
            f"(score {best.score:.2f}) on {', '.join(best.shared) or 'some fields'}; "
            "differs enough to be a possible variant, not a clear duplicate"
        )
        return review

    # No strong match: novelty now depends on the quality of the search itself.
    #
    # Coverage is measured by *independent origins*, not by provider names: four
    # pages from one publisher are one origin, not four. A hand-recorded review
    # that names only providers (no origins) falls back to the provider count so
    # its previous meaning is preserved; a live search always populates origins.
    queries = [q for q in review.queries if q.strip()]
    origins = {s.strip().lower() for s in review.independent_sources if s.strip()}
    if origins:
        coverage = len(origins)
        coverage_basis = f"{coverage} independent source(s)"
    else:
        coverage = len({s.strip().lower() for s in review.databases_searched if s.strip()})
        coverage_basis = f"{coverage} source(s) recorded (no origin detail)"
    if coverage < MIN_SOURCES_FOR_NOVELTY or len(queries) < MIN_QUERIES_FOR_NOVELTY:
        review.classification = NoveltyClass.INSUFFICIENT_EVIDENCE.value
        review.classification_reason = (
            "no matching public disclosure identified, but the search is "
            f"under-powered ({coverage_basis}, {len(queries)} query(ies); "
            f"need >= {MIN_SOURCES_FOR_NOVELTY} independent sources and "
            f">= {MIN_QUERIES_FOR_NOVELTY} queries). "
            "Absence of a public result is not proof of novelty."
        )
        return review

    review.classification = NoveltyClass.LIKELY_NEW.value
    review.classification_reason = (
        "no matching public disclosure identified after a documented search across "
        f"{coverage_basis} with {len(queries)} queries. "
        "This is 'no matching public disclosure identified', not a guarantee of novelty."
    )
    return review


def collect_disclosures(
    review: NoveltyReview,
    search_fn,
    *,
    per_query: int = 5,
    max_disclosures: int = 25,
) -> NoveltyReview:
    """Populate ``review``'s public search from a live search function.

    A novelty review only means something if its search was real. This runs each
    of the review's ``queries`` through ``search_fn`` -- any callable
    ``(query, count=...) -> result`` whose result has ``.ok``, ``.provider`` and
    ``.sources``; BLACKHEART's provider router satisfies this -- and turns the
    returned sources into :class:`~blackheart.models.PublicDisclosure`
    candidates. It records which providers actually answered in
    ``databases_searched``, so the coverage check in :func:`evaluate_novelty`
    rests on providers that responded, not on a hand-written claim.

    Provenance is preserved: each disclosure records the provider that supplied
    it. A failed query is recorded in ``search_limitations``; nothing is
    fabricated, and a provider that returned nothing simply contributes no
    disclosure.
    """
    seen: set[str] = set()
    providers_used: set[str] = set()
    collected: list[PublicDisclosure] = []

    for query in review.queries:
        if not query.strip():
            continue
        try:
            result = search_fn(query, count=per_query)
        except Exception as exc:  # noqa: BLE001 - a search backend must not crash the review
            review.search_limitations.append(
                f"query {query!r} failed: {type(exc).__name__}: {exc}")
            continue
        if not getattr(result, "ok", False):
            review.search_limitations.append(
                f"query {query!r} returned no usable results"
                + (f" ({result.error})" if getattr(result, "error", "") else ""))
            continue
        # A router returns a wrapper (``.ok``/``.provider``/``.result``); a bare
        # provider returns the result itself. Unwrap to the object that actually
        # carries the sources, so provenance and the disclosure set are correct
        # either way.
        payload = getattr(result, "result", None) or result
        provider = getattr(payload, "provider", "") or getattr(result, "provider", "") or "unknown"
        for src in getattr(payload, "sources", []):
            url = getattr(src, "url", "")
            if not url or url in seen:
                continue
            seen.add(url)
            src_provider = getattr(src, "provider", "") or provider
            # Only a provider that actually *contributed* a disclosure counts as
            # coverage. A provider that answered 200 with nothing must not
            # inflate ``databases_searched`` and so the novelty coverage check.
            providers_used.add(src_provider)
            collected.append(PublicDisclosure(
                source=src_provider,
                url=url,
                summary=getattr(src, "title", "") or getattr(src, "description", ""),
            ))
            if len(collected) >= max_disclosures:
                break
        if len(collected) >= max_disclosures:
            break

    review.disclosures = collected
    # Coverage must reflect *independent origins*, not provider names. Two
    # providers that both return pages from one publisher are one origin, and a
    # single provider returning four pages from four publishers is four origins.
    # Record both facts so the novelty gate can rest on genuine independence.
    from .intelligence.sources import analyse as _analyse_sources

    indep = _analyse_sources([d.url for d in collected])
    review.independent_sources = list(indep.origins)
    # ``databases_searched`` stays the provider-level coverage record (a manual
    # CVE/advisory search is legitimate coverage too); the independent-origin
    # count is what the novelty threshold is measured against.
    documented = {s for s in review.databases_searched if s.strip()}
    review.databases_searched = sorted(documented | providers_used)
    if not providers_used:
        review.search_limitations.append(
            "no provider returned results for any query; the search is "
            "under-powered and novelty must not be claimed")
    elif indep.independent_source_count < len(providers_used):
        review.search_limitations.append(
            f"{len(providers_used)} provider(s) answered but only "
            f"{indep.independent_source_count} independent origin(s) were found "
            f"({', '.join(indep.origins) or 'none'}); provider count is not a "
            "substitute for source independence")
    return review


class NoveltyGate:
    """The mandatory pre-submission gate.

    Refuses to let a finding be promoted to submission-ready without a novelty
    review that classifies it as LIKELY_NEW or POSSIBLE_VARIANT. Every refusal
    states why.
    """

    def __init__(self, reviews: dict[str, NoveltyReview] | None = None) -> None:
        self._reviews: dict[str, NoveltyReview] = reviews or {}

    def record(self, review: NoveltyReview) -> NoveltyReview:
        """Evaluate and store a review, returning the adjudicated review."""
        evaluate_novelty(review)
        self._reviews[review.finding_id] = review
        return review

    def review_for(self, finding_id: str) -> NoveltyReview | None:
        return self._reviews.get(finding_id)

    def allows_submission(self, finding_id: str) -> tuple[bool, str]:
        """Return (allowed, reason). Fails closed when no review exists."""
        review = self._reviews.get(finding_id)
        if review is None:
            return False, (
                "no novelty review recorded for this finding; a documented "
                "novelty review is required before submission"
            )
        if review.is_submittable():
            return True, review.classification_reason
        return False, review.blocking_reason()

    def all_reviews(self) -> list[NoveltyReview]:
        return list(self._reviews.values())

    # -- durability (mission Part H: research continuity across sandboxes) -- #
    def save(self, root) -> "Path":  # noqa: F821  string annotation; Path imported lazily
        """Append-only persistence of novelty reviews, keyed by finding id."""
        import json
        from pathlib import Path

        root = Path(root)
        root.mkdir(parents=True, exist_ok=True)
        path = root / "novelty-reviews.jsonl"
        with path.open("a", encoding="utf-8") as fh:
            for review in self._reviews.values():
                fh.write(json.dumps(review.to_dict(), default=str) + "\n")
        return path

    @classmethod
    def load(cls, root) -> "NoveltyGate":
        """Replay the append-only review log; the latest entry per id wins."""
        import json
        from pathlib import Path

        path = Path(root) / "novelty-reviews.jsonl"
        gate = cls()
        if not path.exists():
            return gate
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            gate._reviews[NoveltyReview.from_dict(json.loads(line)).finding_id] = (
                NoveltyReview.from_dict(json.loads(line))
            )
        return gate
