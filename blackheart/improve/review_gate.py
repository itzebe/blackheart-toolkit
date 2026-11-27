"""A fail-closed gate over reviewer provenance.

A configured key is not a reviewer. This gate distinguishes an available,
distinct, verified model from a configured-but-unprobed key and from a same-model
fallback, and it refuses to call the latter independent. It is the policy layer a
caller can apply before recording a review, not a new provider.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..models import ReviewIndependence
from ..providers.router import ReviewerModel


@dataclass
class ReviewGateResult:
    status: str  # PASS | CONFIGURED_UNVERIFIED | SAME_MODEL | UNAVAILABLE
    reason: str
    independence: str
    provider: str = ""
    model: str = ""

    @property
    def independent(self) -> bool:
        return self.status == "PASS"

    def to_dict(self) -> dict:
        return {
            "status": self.status,
            "reason": self.reason,
            "independence": self.independence,
            "provider": self.provider,
            "model": self.model,
            "independent": self.independent,
        }


def gate_review(reviewer: ReviewerModel, *, require_independent: bool = True) -> ReviewGateResult:
    """Return PASS only for a distinct, verified, available reviewer model."""
    independence = reviewer.independence.value
    if (reviewer.available
            and reviewer.independence == ReviewIndependence.INDEPENDENT_MODEL):
        return ReviewGateResult(
            "PASS", "a distinct, verified reviewer model is available",
            independence, reviewer.provider, reviewer.model,
        )
    if reviewer.configured and not reviewer.verified:
        return ReviewGateResult(
            "CONFIGURED_UNVERIFIED",
            "a reviewer key is configured but no liveness probe verified it",
            independence, reviewer.provider, reviewer.model,
        )
    if not require_independent:
        return ReviewGateResult(
            "SAME_MODEL",
            "independent review is not required; a same-model review is a "
            "recorded fallback, never an independent verification",
            independence, reviewer.provider, reviewer.model,
        )
    return ReviewGateResult(
        "SAME_MODEL" if reviewer.configured or reviewer.provider else "UNAVAILABLE",
        reviewer.reason or "no independent reviewer model is available",
        independence, reviewer.provider, reviewer.model,
    )


__all__ = ["ReviewGateResult", "gate_review"]
