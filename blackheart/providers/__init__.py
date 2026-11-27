"""Multi-model research intelligence (mission Part B).

A provider-independent layer that lets several models take *different analytical
roles* -- and disagree -- while keeping private evidence on the host by default.

Public surface:

  * :mod:`blackheart.providers.adapters`  -- OpenAI-compatible, local, and mock providers
  * :mod:`blackheart.providers.registry`  -- provider specs + data classification
  * :mod:`blackheart.providers.roles`     -- the seven analytical roles
  * :mod:`blackheart.providers.router`    -- privacy-gated routing + quotas
  * :func:`benchmark_router`              -- measure a router against known cases

The load-bearing rule, enforced here and in the router: **AI output is advisory**.
Agreement between models is not confirmation of a vulnerability; only
deterministic reproduction, verified impact, and applicable authorization can
confirm a finding. This module never promotes a model claim to CONFIRMED.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .adapters import (
    HealthResult,
    LocalProvider,
    MockProvider,
    ModelResponse,
    OpenAICompatibleProvider,
    Provider,
    ProviderError,
)
from .registry import (
    NEVER_TRANSMIT,
    REMOTE_DEFAULT_CEILING,
    DataClass,
    ProviderSpec,
    all_providers,
    get_spec,
    may_transmit,
)
from .roles import ROLES, Role, RoleResult, summarise
from .router import (
    ModelRouter,
    PrivacyViolation,
    QuotaTracker,
    ReviewerModel,
    RouteDecision,
    build_router,
    resolve_reviewer_model,
)


@dataclass
class BenchmarkCase:
    """One known research scenario for measuring the router's judgement roles.

    ``expect`` is what a correct adversarial/code-analysis judgement should say
    about the material. Cases are drawn from BLACKHEART's own history (mission B4)
    so the benchmark measures real lessons, not invented ones.
    """

    name: str
    prompt: str
    expect_verdict: str          # supports | disputes | inconclusive
    note: str = ""
    provenance: str = ""


# Historical cases from the mission brief. Each is a *judgement* case: the role
# must reach the recorded verdict on real material.
BENCHMARK_CASES: list[BenchmarkCase] = [
    BenchmarkCase(
        name="dvdf-unstoppable",
        prompt=(
            "A vault's totalAssets() reads the live token balance. A user donates "
            "tokens directly to the vault; the balance and accounting diverge and a "
            "liveness monitor pauses the vault permanently. The invariant "
            "'accounting == live balance' is violated by a single external transfer."
        ),
        expect_verdict="supports",
        note="Training fixture: a real, deterministic invariant violation.",
        provenance="harnesses/dvdf (Damn Vulnerable DeFi Unstoppable)",
    ),
    BenchmarkCase(
        name="oss-001-duplicate",
        prompt=(
            "A workflow_run continuation checks out a repository/ref taken from a "
            "downloaded artifact. An independent reproduction works, but a public "
            "disclosure already documents the same root cause in the same component."
        ),
        expect_verdict="disputes",
        note="Real bug, but a duplicate: novelty, not reproduction, decides.",
        provenance="PR #26 novelty gate (OSS-001)",
    ),
    BenchmarkCase(
        name="mpc-001-assert-only",
        prompt=(
            "A peer key length-prefix abort reproduces only when an assert-enabled "
            "co-signer is used; production builds compile asserts out, so the abort "
            "is unreachable. No impact is demonstrated on a release build."
        ),
        expect_verdict="disputes",
        note="NEEDS_MORE_EVIDENCE: mechanism real, impact unreachable in production.",
        provenance="PR #30 (MPC-001)",
    ),
    BenchmarkCase(
        name="frost-self-weakening",
        prompt=(
            "A hypothesis claims a signing participant can weaken its own share to "
            "produce a signature. No other participant loses funds or authority; the "
            "only victim is the attacker's own key."
        ),
        expect_verdict="disputes",
        note="Rejected: self-weakening is not a vulnerability against others.",
        provenance="FROST rejected hypothesis",
    ),
    BenchmarkCase(
        name="gha-script-injection",
        prompt=(
            "A pull_request_target workflow interpolates github.event.pull_request.title "
            "directly into a run: script that also has contents: write. An attacker "
            "controls the PR title, so shell metacharacters reach a privileged shell."
        ),
        expect_verdict="supports",
        note="A reachable untrusted-input-to-privileged-execution flow.",
        provenance="blackheart/gha.py rule GH-UNTRUSTED-SCRIPT-INJECTION",
    ),
]


def _judge_verdict(result: RoleResult) -> str:
    """Extract a verdict from a role result, honestly.

    A local (rule-based) or simulated result cannot judge semantics, so it is
    reported as ``inconclusive`` rather than being counted as a correct guess.
    """
    if not result.ok:
        return "unavailable"
    if result.simulated:
        # The local engine and mocks cannot reason; do not credit them.
        return "inconclusive"
    if isinstance(result.structured, dict):
        return result.structured.get("verdict", "inconclusive")
    return "inconclusive"


@dataclass
class BenchmarkReport:
    cases: int = 0
    correct: int = 0
    unavailable: int = 0
    inconclusive: int = 0
    per_case: list[dict] = field(default_factory=list)

    @property
    def accuracy(self) -> float:
        judged = self.cases - self.unavailable
        return (self.correct / judged) if judged else 0.0

    def to_dict(self) -> dict:
        return {
            "cases": self.cases, "correct": self.correct,
            "unavailable": self.unavailable, "inconclusive": self.inconclusive,
            "accuracy_over_judged": round(self.accuracy, 3),
            "per_case": self.per_case,
            "note": (
                "accuracy is over cases the provider actually judged; a simulated "
                "or local engine is counted inconclusive, never correct"
            ),
        }


def benchmark_router(router: ModelRouter, *,
                     cases: list[BenchmarkCase] | None = None,
                     data_class: str = DataClass.PUBLIC) -> BenchmarkReport:
    """Measure the router's adversarial judgement against the known cases.

    Uses the ``adversarial`` role, because that role's job is exactly to decide
    supports/disputes. A local or mock provider is counted inconclusive.
    """
    cases = cases if cases is not None else BENCHMARK_CASES
    report = BenchmarkReport(cases=len(cases))
    for case in cases:
        result = router.complete(case.prompt, role="adversarial",
                                 data_class=data_class)
        verdict = _judge_verdict(result)
        if verdict == "unavailable":
            report.unavailable += 1
        elif verdict == "inconclusive":
            report.inconclusive += 1
        elif verdict == case.expect_verdict:
            report.correct += 1
        report.per_case.append({
            "case": case.name, "expected": case.expect_verdict,
            "verdict": verdict, "provider": result.provider,
            "simulated": result.simulated, "ok": result.ok,
            "note": case.note, "provenance": case.provenance,
        })
    return report


__all__ = [
    "Provider", "ModelResponse", "HealthResult", "ProviderError",
    "OpenAICompatibleProvider", "LocalProvider", "MockProvider",
    "ProviderSpec", "DataClass", "all_providers", "get_spec", "may_transmit",
    "NEVER_TRANSMIT", "REMOTE_DEFAULT_CEILING",
    "Role", "ROLES", "RoleResult", "summarise",
    "ModelRouter", "build_router", "RouteDecision", "QuotaTracker",
    "PrivacyViolation",
    "BenchmarkCase", "BENCHMARK_CASES", "BenchmarkReport", "benchmark_router",
]
