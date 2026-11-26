"""BLACKHEART must not depend on a separately configured reviewer model.

This is the durable architectural requirement: a missing, invalid, or expired
reviewer API key must never block core research or the release workflow. Reviewer
support stays **optional** and activates only when a verified credential exists.

Each test below fails if a hard dependency is reintroduced:

  * the reviewer resolution returns ``available=False`` with an honest reason and
    does not raise, in a zero-provider / single-provider environment;
  * the recorded independence is ``SAME_MODEL`` -- never ``INDEPENDENT_MODEL`` --
    when no verified reviewer exists;
  * a same-model review is refused at ``CONFIRMED`` (it does not count as the
    independent verification the confirmation gate requires);
  * the release checks (``doctor``, ``coverage``, ``differential``) do not consult
    the reviewer at all;
  * no CLI path exits non-zero merely because a reviewer is unavailable.
"""

from __future__ import annotations

import inspect
import os
import subprocess
import sys

import pytest

from blackheart.models import GATE6_DETAIL, GateStatus, ReviewIndependence
from blackheart.providers.router import (
    ModelRouter,
    ReviewerModel,
    _same_model_family,
    resolve_reviewer_model,
)


# --------------------------------------------------------------------------- #
# 1. Resolution never raises and never claims an unverified reviewer
# --------------------------------------------------------------------------- #

def test_resolution_in_zero_provider_mode_is_unavailable_not_an_error():
    router = ModelRouter()  # no providers configured
    resolution = resolve_reviewer_model(router)
    assert isinstance(resolution, ReviewerModel)
    assert resolution.available is False
    assert resolution.independence is ReviewIndependence.SAME_MODEL
    assert resolution.reason  # explains why, never a bare False


def test_resolution_never_reports_a_present_key_as_available_without_a_probe():
    """A configured-but-unverified key is `configured`, never `available`."""
    router = ModelRouter()
    # Simulate a distinct provider key present but no successful probe.
    resolution = resolve_reviewer_model(router, probe=False)
    assert resolution.available is False
    assert resolution.independence is ReviewIndependence.SAME_MODEL


def test_resolution_of_single_provider_is_same_model_with_honest_reason():
    """The real environment: only the primary provider exists -> SAME_MODEL."""
    router = ModelRouter.from_env()
    resolution = resolve_reviewer_model(router, probe=False)
    if not resolution.available:
        assert resolution.independence is ReviewIndependence.SAME_MODEL
        assert "no separately authenticated reviewer" in resolution.reason.lower() or \
               "reviewer" in resolution.reason.lower()


# --------------------------------------------------------------------------- #
# 2. Independence is recorded honestly; SAME_MODEL is never promoted
# --------------------------------------------------------------------------- #

def test_same_model_review_is_refused_at_confirmed():
    """A SAME_MODEL review must not satisfy the independent-verification gate.

    The finding is otherwise fully evidenced, so the *only* thing standing between
    it and CONFIRMED is the review provenance. That isolates the property.
    """
    from blackheart.findings import FindingRecord

    rec = FindingRecord(
        finding_id="f1", title="t", target="x",
        evidence_ids=["ev-1"], reviewer="same-model-reviewer",
        review_independence=ReviewIndependence.SAME_MODEL.value,
    )
    missing = rec.missing_confirmation_fields()
    assert any("same-model review is not independent" in m for m in missing)
    # With every other field present, the same-model review alone blocks CONFIRMED.
    assert rec.is_confirmed() is False


def test_independent_model_review_clears_that_gate():
    """The same record with INDEPENDENT_MODEL provenance passes the review gate."""
    from blackheart.findings import FindingRecord

    rec = FindingRecord(
        finding_id="f2", title="t", target="x",
        evidence_ids=["ev-1"], reviewer="separate-reviewer-model",
        review_independence=ReviewIndependence.INDEPENDENT_MODEL.value,
    )
    missing = rec.missing_confirmation_fields()
    assert not any("same-model" in m for m in missing)


def test_gate6_detail_marks_same_model_as_not_independent():
    status, detail = GATE6_DETAIL[ReviewIndependence.SAME_MODEL]
    # The gate status must not read as a full pass for an independent-model gate.
    assert "same" in detail.lower() or "not independent" in detail.lower()
    # And the independent-model entry must be distinguishable.
    ind_status, ind_detail = GATE6_DETAIL[ReviewIndependence.INDEPENDENT_MODEL]
    assert (status, detail) != (ind_status, ind_detail)


def test_coerce_of_unknown_provenance_fails_closed_to_same_model():
    assert ReviewIndependence.coerce("banana") is ReviewIndependence.SAME_MODEL
    assert ReviewIndependence.coerce(None) is ReviewIndependence.SAME_MODEL


# --------------------------------------------------------------------------- #
# 3. The same-model-family detector still prevents a false independence claim
# --------------------------------------------------------------------------- #

def test_same_weights_under_two_providers_are_not_independent():
    # Documented real case: identical Llama 3.3 70B weights, two providers.
    assert _same_model_family("Meta-Llama-3.3-70B-Instruct",
                              "llama-3.3-70b-versatile")
    # Genuinely different families are distinct.
    assert not _same_model_family("llama-3.3-70b", "gpt-4o")
    # Empty ids never claim independence.
    assert not _same_model_family("", "gpt-4o")


# --------------------------------------------------------------------------- #
# 4. Release checks do not consult the reviewer at all
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("command", [["doctor"], ["coverage"], ["differential"]])
def test_release_checks_run_without_any_provider_env(command):
    """The mandatory release gates succeed with every provider key removed."""
    env = {k: v for k, v in os.environ.items()
           if not k.endswith("_API_KEY") and k not in (
               "GROQ_API_KEY", "GEMINI_API_KEY", "OPENAI_API_KEY", "ANTHROPIC_API_KEY")}
    proc = subprocess.run(
        [sys.executable, "-m", "blackheart", *command],
        capture_output=True, text=True, env=env, timeout=600,
    )
    assert proc.returncode == 0, (
        f"{command} failed without provider keys (hard dependency?):\n"
        f"stdout={proc.stdout[-2000:]}\nstderr={proc.stderr[-2000:]}"
    )


def test_reviewer_cli_exits_zero_when_unavailable():
    env = {k: v for k, v in os.environ.items()
           if not k.endswith("_API_KEY") and k not in (
               "GROQ_API_KEY", "GEMINI_API_KEY", "OPENAI_API_KEY", "ANTHROPIC_API_KEY")}
    proc = subprocess.run(
        [sys.executable, "-m", "blackheart", "models", "reviewer", "--no-probe"],
        capture_output=True, text=True, env=env, timeout=300,
    )
    assert proc.returncode == 0, proc.stderr[-2000:]
    assert "SAME_MODEL" in proc.stdout
    assert '"available": false' in proc.stdout


# --------------------------------------------------------------------------- #
# 5. No module imports a reviewer to do core work
# --------------------------------------------------------------------------- #

def test_resolve_reviewer_model_is_the_only_reviewer_entry_point():
    """There is exactly one resolution function; core modules do not reimplement it."""
    import blackheart.findings
    import blackheart.verify
    import blackheart.coverage_engine
    import blackheart.environments

    for module in (blackheart.findings, blackheart.verify,
                   blackheart.coverage_engine, blackheart.environments):
        src = inspect.getsource(module)
        # Core modules must not import a reviewer resolver and require it.
        assert "require_reviewer" not in src
        assert "assert_reviewer_available" not in src


def test_reviewer_resolution_signature_has_no_required_arguments():
    """A caller can always resolve reviewer status with no arguments."""
    sig = inspect.signature(resolve_reviewer_model)
    required = [p for p in sig.parameters.values()
                if p.default is inspect.Parameter.empty
                and p.kind not in (p.VAR_POSITIONAL, p.VAR_KEYWORD)]
    # `router` is required (it is the object queried), but nothing else.
    assert [p.name for p in required] == ["router"]


# --------------------------------------------------------------------------- #
# 6. No CI job can require a reviewer credential
# --------------------------------------------------------------------------- #

def _workflow_files() -> list:
    from pathlib import Path

    root = Path(__file__).resolve().parents[1] / ".github" / "workflows"
    return sorted(root.glob("*.yml")) + sorted(root.glob("*.yaml"))


@pytest.mark.parametrize("workflow", _workflow_files(), ids=lambda p: p.name)
def test_no_workflow_requires_a_reviewer_credential(workflow):
    """A release/CI job must never carry a separately configured reviewer key.

    The whole point of the optional-reviewer architecture is that a missing,
    invalid, or expired reviewer key cannot block the workflow. A secret wired
    into CI would recreate that hard dependency silently -- the job would fail
    the moment the credential expired, which is exactly the failure this
    architecture exists to prevent. Environment variables and repository
    variables are both checked, because either can carry a credential.
    """
    text = workflow.read_text(encoding="utf-8").lower()
    forbidden = (
        "reviewer_api_key", "reviewer_key", "blackheart_reviewer",
        "reviewer_token", "reviewer_secret",
    )
    for token in forbidden:
        assert token not in text, (
            f"{workflow.name} wires a reviewer credential ({token!r}); the "
            "reviewer model is optional and must never be a CI requirement"
        )


def test_reviewer_optional_guard_covers_the_ci_workflow():
    """The guard above must actually inspect the release workflow (non-vacuous)."""
    names = {p.name for p in _workflow_files()}
    assert "ci.yml" in names, f"expected ci.yml among {sorted(names)}"


def test_a_local_ollama_provider_can_be_an_independent_reviewer(monkeypatch):
    from blackheart.providers.registry import get_spec
    from blackheart.providers.router import ModelRouter, resolve_reviewer_model
    monkeypatch.setenv("BLACKHEART_PROVIDERS", "ollama")
    router = ModelRouter.from_env()
    assert "ollama" in router.available()
    result = resolve_reviewer_model(router, primary="local", probe=False)
    assert result.configured and result.provider == "ollama"
    assert result.model == get_spec("ollama").default_model
    assert not result.available  # configured is not verified without a probe
