"""A verified second model is used directly; an absent one is not faked."""

from __future__ import annotations

from types import SimpleNamespace

from blackheart import reviewer as reviewer_mod
from blackheart.models import ReviewIndependence
from blackheart.providers.router import ReviewerModel
from blackheart.reviewer import independent_review


class FakeRouter:
    def __init__(self):
        self.calls = []

    def complete_with(self, provider, prompt, **kwargs):
        self.calls.append((provider, prompt, kwargs))
        return SimpleNamespace(ok=True, provider=provider, model=kwargs.get("model", ""),
                               text="review text", error="")


def test_a_verified_distinct_model_is_used(monkeypatch):
    monkeypatch.setattr(reviewer_mod, "resolve_reviewer_model", lambda *a, **k: ReviewerModel(
        True, provider="other", model="different-model", reason="verified",
        independence=ReviewIndependence.INDEPENDENT_MODEL, configured=True,
        verified=True))
    router = FakeRouter()
    outcome = independent_review(router, "review this", primary="primary")
    assert outcome.status == "INDEPENDENT"
    assert outcome.independent
    assert outcome.provider == "other"
    assert router.calls[0][0] == "other"
    assert router.calls[0][2]["model"] == "different-model"


def test_default_data_class_is_public_not_a_ceiling_refusal(monkeypatch):
    """Regression: the default must be DataClass.PUBLIC, not lowercase "public".

    A lowercase default made ``may_transmit("public", "PUBLIC")`` false, so every
    default call returned UNAVAILABLE with "data class public is above the
    off-host ceiling PUBLIC". The recording router proves the real class passed.
    """
    from blackheart.providers.registry import DataClass

    seen: dict = {}

    def fake_resolve(router, **kwargs):
        seen["resolve_dc"] = kwargs.get("data_class")
        return ReviewerModel(True, provider="other", model="different-model",
                             reason="verified",
                             independence=ReviewIndependence.INDEPENDENT_MODEL,
                             configured=True, verified=True)

    class Recording(FakeRouter):
        def complete_with(self, provider, prompt, **kwargs):
            seen["complete_dc"] = kwargs.get("data_class")
            return SimpleNamespace(ok=True, provider=provider,
                                   model=kwargs.get("model", ""), text="t", error="")

    monkeypatch.setattr(reviewer_mod, "resolve_reviewer_model", fake_resolve)
    outcome = independent_review(Recording(), "review this")
    assert seen["resolve_dc"] == DataClass.PUBLIC
    assert seen["complete_dc"] == DataClass.PUBLIC
    assert outcome.status == "INDEPENDENT"


def test_an_unavailable_reviewer_is_not_replaced_by_the_primary(monkeypatch):
    monkeypatch.setattr(reviewer_mod, "resolve_reviewer_model", lambda *a, **k: ReviewerModel(
        False, reason="only the primary provider is configured",
        independence=ReviewIndependence.SAME_MODEL))
    router = FakeRouter()
    outcome = independent_review(router, "review this", primary="primary")
    assert outcome.status == "UNAVAILABLE"
    assert not outcome.independent
    assert router.calls == []


def test_a_provider_error_is_reported_not_claimed_independent(monkeypatch):
    monkeypatch.setattr(reviewer_mod, "resolve_reviewer_model", lambda *a, **k: ReviewerModel(
        True, provider="other", model="different-model",
        independence=ReviewIndependence.INDEPENDENT_MODEL, verified=True))

    class Broken(FakeRouter):
        def complete_with(self, provider, prompt, **kwargs):
            return SimpleNamespace(ok=False, provider=provider, model="",
                                   text="", error="timeout")

    outcome = independent_review(Broken(), "review this", primary="primary")
    assert outcome.status == "ERROR"
    assert not outcome.independent
    assert "timeout" in outcome.reason
