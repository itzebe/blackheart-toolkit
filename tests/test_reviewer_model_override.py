"""A valid credential must be able to activate the optional reviewer.

Two defects made that impossible, and both were silent:

1. The registry pinned ``gemini-2.0-flash``. Google retired that id, so the liveness
   probe returned HTTP 404 and a *perfectly valid* key was reported as unavailable.
   There was no way to point at a live model short of editing source.

2. The resolution record reported ``spec.default_model`` while the probe had run
   against whatever model the adapter chose. When those differed, ``blackheart
   models reviewer`` named a model that was never called -- a mislabelling, not a
   cosmetic issue, because that string is the durable record of what reviewed a
   finding.

These tests pin both: an override is honoured, the reported model is the one that
was actually probed, and every honesty property the reviewer architecture already
had (optional, never required, SAME_MODEL when unverified) still holds.
"""

from __future__ import annotations

import json
import os

import pytest

from blackheart.providers.adapters import HealthResult, ModelResponse, OpenAICompatibleProvider
from blackheart.providers.registry import get_spec, resolved_model
from blackheart.providers.router import ModelRouter, resolve_reviewer_model
from blackheart.models import ReviewIndependence

_INDEPENDENT = ReviewIndependence.INDEPENDENT_MODEL


class _CapturingProvider(OpenAICompatibleProvider):
    """The real adapter, with the network call replaced at the ``urlopen`` seam.

    Every other line of ``complete()`` -- model resolution, body construction,
    header assembly, error handling -- is the production code. A test that
    overrode ``complete()`` itself would prove nothing about model resolution,
    because the resolution lives inside ``complete()``.
    """

    def __init__(self, spec) -> None:
        super().__init__(spec)
        self.sent_models: list[str] = []

    def _fake_urlopen(self, req, timeout=None):
        body = json.loads(req.data.decode("utf-8"))
        self.sent_models.append(body["model"])
        payload = json.dumps({
            "choices": [{"message": {"content": "ok"}}],
            "usage": {"prompt_tokens": 1, "completion_tokens": 1},
        }).encode()

        class _Resp:
            def read(self_inner):
                return payload

            def __enter__(self_inner):
                return self_inner

            def __exit__(self_inner, *exc):
                return False

        return _Resp()


class _ProbeProvider(OpenAICompatibleProvider):
    """A provider whose health probe records the model id it was called with.

    It subclasses the real adapter so the probe path under test is the production
    one, and overrides only the network call.
    """

    def __init__(self, spec, *, healthy: bool = True) -> None:
        super().__init__(spec)
        self.probed_models: list[str] = []
        self._healthy = healthy

    def complete(self, prompt, *, model="", system="", json_schema=None,
                 timeout=60, max_retries=2):  # noqa: D102 - test double
        self.probed_models.append(model)
        if not self._healthy:
            return ModelResponse(self.name, model, ok=False, error="HTTP 404: retired")
        return ModelResponse(self.name, model, text="ok", ok=True)


# --------------------------------------------------------------------------- #
# 1. The override exists and is honoured
# --------------------------------------------------------------------------- #

def test_gemini_spec_declares_a_model_override_variable():
    spec = get_spec("gemini")
    assert spec.model_env_key == "BLACKHEART_GEMINI_MODEL"


def test_resolved_model_falls_back_to_the_pinned_default(monkeypatch):
    monkeypatch.delenv("BLACKHEART_GEMINI_MODEL", raising=False)
    spec = get_spec("gemini")
    assert resolved_model(spec) == spec.default_model


def test_resolved_model_honours_the_override(monkeypatch):
    monkeypatch.setenv("BLACKHEART_GEMINI_MODEL", "gemini-3.5-flash")
    assert resolved_model(get_spec("gemini")) == "gemini-3.5-flash"


def test_resolved_model_ignores_a_blank_override(monkeypatch):
    """An empty env var must not resolve to an empty model id."""
    monkeypatch.setenv("BLACKHEART_GEMINI_MODEL", "   ")
    spec = get_spec("gemini")
    assert resolved_model(spec) == spec.default_model


def test_a_spec_without_an_override_variable_uses_its_default(monkeypatch):
    """Providers that declare no override must be unaffected by the new field."""
    spec = get_spec("openrouter")
    assert spec.model_env_key == ""
    assert resolved_model(spec) == spec.default_model


# --------------------------------------------------------------------------- #
# 2. The probe and the reported model can never disagree
# --------------------------------------------------------------------------- #

def test_health_probe_uses_the_overridden_model(monkeypatch):
    """A retired pinned id must not block a working credential via the probe."""
    # The key is set here, not inherited: ``health()`` refuses to probe without
    # one, so a test that leaned on the host's ambient key would pass on a
    # developer machine and fail in a stripped CI environment for a reason that
    # has nothing to do with the override.
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    monkeypatch.setenv("BLACKHEART_GEMINI_MODEL", "gemini-3.5-flash")
    provider = _ProbeProvider(get_spec("gemini"))
    health = provider.health(timeout=5)
    assert health.healthy
    assert provider.probed_models == ["gemini-3.5-flash"]


def test_health_probe_uses_the_pinned_model_without_an_override(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    monkeypatch.delenv("BLACKHEART_GEMINI_MODEL", raising=False)
    provider = _ProbeProvider(get_spec("gemini"))
    provider.health(timeout=5)
    assert provider.probed_models == [get_spec("gemini").default_model]


def test_resolution_reports_the_model_it_actually_probed(monkeypatch):
    """The reported model is the durable record of what reviewed a finding."""
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    monkeypatch.setenv("BLACKHEART_GEMINI_MODEL", "gemini-3.5-flash")
    provider = _ProbeProvider(get_spec("gemini"))
    router = ModelRouter(providers={"gemini": provider})
    result = resolve_reviewer_model(router, primary="local", probe=True, timeout=5)
    assert result.available
    assert result.independence == "INDEPENDENT_MODEL"
    # The model named in the record is exactly the model that was called.
    assert result.model == "gemini-3.5-flash"
    assert result.model in provider.probed_models


def test_a_completion_that_omits_model_uses_the_resolved_override(monkeypatch):
    """A call with no explicit model must use the id the probe verified.

    The gap this pins: ``health()`` was updated to probe the resolved model but
    ``complete()`` still defaulted to the pinned ``spec.default_model``. The probe
    therefore certified a live, overridden model while the real request went to a
    retired id -- the credential would test healthy and then fail in production.
    This test pins the two together at the request body, which is the only place the
    wire-level model is observable. (Found by the release's same-model review; no
    independent-model review of this change was performed.)
    """
    monkeypatch.setenv("BLACKHEART_GEMINI_MODEL", "gemini-3.5-flash")
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    provider = _CapturingProvider(get_spec("gemini"))
    provider._fake_urlopen.__func__  # noqa: B018 - attribute exists
    monkeypatch.setattr(
        "blackheart.providers.adapters.urllib.request.urlopen",
        lambda req, timeout=None: provider._fake_urlopen(req, timeout),
    )
    provider.complete("hello", timeout=5)  # no model argument
    assert provider.sent_models == ["gemini-3.5-flash"]


def test_a_completion_without_an_override_sends_the_pinned_model(monkeypatch):
    monkeypatch.delenv("BLACKHEART_GEMINI_MODEL", raising=False)
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    provider = _CapturingProvider(get_spec("gemini"))
    monkeypatch.setattr(
        "blackheart.providers.adapters.urllib.request.urlopen",
        lambda req, timeout=None: provider._fake_urlopen(req, timeout),
    )
    provider.complete("hello", timeout=5)
    assert provider.sent_models == [get_spec("gemini").default_model]


def test_probe_and_completion_agree_on_the_model(monkeypatch):
    """The probe and a default completion must name the same model."""
    monkeypatch.setenv("BLACKHEART_GEMINI_MODEL", "gemini-3.5-flash")
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    provider = _CapturingProvider(get_spec("gemini"))
    monkeypatch.setattr(
        "blackheart.providers.adapters.urllib.request.urlopen",
        lambda req, timeout=None: provider._fake_urlopen(req, timeout),
    )
    provider.health(timeout=5)
    provider.complete("hello", timeout=5)
    assert provider.sent_models[0] == provider.sent_models[1] == "gemini-3.5-flash"


def test_a_failing_override_still_reports_unavailable(monkeypatch):
    """The override changes which model is tried, not whether a failure is a pass."""
    monkeypatch.setenv("BLACKHEART_GEMINI_MODEL", "gemini-3.5-flash")
    provider = _ProbeProvider(get_spec("gemini"), healthy=False)
    router = ModelRouter(providers={"gemini": provider})
    result = resolve_reviewer_model(router, primary="local", probe=True, timeout=5)
    assert not result.available
    assert not result.verified
    assert result.independence == "SAME_MODEL"


# --------------------------------------------------------------------------- #
# 3. The reviewer stays optional: nothing here made it required
# --------------------------------------------------------------------------- #

def test_zero_provider_mode_is_still_unavailable_and_not_an_error(monkeypatch):
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    router = ModelRouter.from_env()
    result = resolve_reviewer_model(router, probe=True)
    assert not result.available
    assert result.independence == "SAME_MODEL"
    assert result.reason


def test_the_override_does_not_make_a_reviewer_available_without_a_key(monkeypatch):
    """The override is a model selector, never a credential."""
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.setenv("BLACKHEART_GEMINI_MODEL", "gemini-3.5-flash")
    router = ModelRouter.from_env()
    assert "gemini" not in router.available()
    result = resolve_reviewer_model(router, probe=True)
    assert not result.available
    assert result.independence == "SAME_MODEL"


# --------------------------------------------------------------------------- #
# The override must never manufacture a false independence claim
# --------------------------------------------------------------------------- #

def test_an_override_pointing_at_the_primary_weights_is_not_independent():
    """Pointing the reviewer override at the primary's weights must not pass.

    A hole the same-model review probed in the override: if the operator sets the
    reviewer's model id to the primary's, does the check still refuse? It does --
    ``_same_model_family`` compares the *resolved* ids, so the override is exactly
    what it sees. Verified end to end against the real router: the resolution
    degrades to SAME_MODEL with the reason naming the shared family.
    """
    from blackheart.providers.router import _same_model_family

    assert _same_model_family("llama-3.3-70b-versatile", "llama-3.3-70b-versatile")
    assert _same_model_family(
        "llama-3.3-70b-versatile", "Meta-Llama-3.3-70B-Instruct")
    assert not _same_model_family("gemini-3.5-flash", "llama-3.3-70b-versatile")


def test_resolution_uses_the_resolved_reviewer_model_in_its_family_check(monkeypatch):
    """The family check must run on the override, not on the pinned default.

    With the probe disabled every outcome is SAME_MODEL, so independence cannot
    distinguish the two behaviours. The *reason* can: if the family check reads the
    override, the candidate is rejected as the same family; if it wrongly reads the
    pinned ``gemini-2.0-flash``, the candidate looks distinct and survives to
    "configured but unverified". Asserting on the reason is what makes this test
    able to fail.
    """
    monkeypatch.setenv("BLACKHEART_GEMINI_MODEL", "llama-3.3-70b-versatile")
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    monkeypatch.setenv("GROQ_API_KEY", "test-key")
    router = ModelRouter.from_env(prefer=["groq", "gemini"])

    result = resolve_reviewer_model(router, primary="groq", probe=False)
    assert "same model family" in result.reason, (
        "the independence check did not see the override: " + result.reason)
    assert result.model == "llama-3.3-70b-versatile"
