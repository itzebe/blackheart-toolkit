"""The bounty watchtower: hourly, evidence-driven change intelligence.

It monitors each bounty program independently across three sources:

* the official policy (scope, eligibility, rewards, restrictions),
* the repositories whose code may ship, and
* the deployed contracts' runtime bytecode, proxy implementation, admin and owner.

It classifies every change into one of the mission's seven statuses, scores a
credible lead out of 100 with a per-component rationale, enforces known-issue
exclusions and participation gates, and writes a durable, deduplicated report.

The package never sends a transaction, never tests a live target, and never
treats a commit as a deployment.
"""

from __future__ import annotations

from .classify import (
    Event,
    Kind,
    Lead,
    SCORE_THRESHOLD,
    SCORE_WEIGHTS,
    Status,
    classify_event,
    make_event,
    score_lead,
)
from .cycle import CycleConfig, CycleReport, run_cycle
from .fetch import (
    ContractObservation,
    FetchResult,
    GitHubClient,
    GitHubResult,
    HttpFetcher,
    RpcClient,
)
from .registry import (
    ContractRef,
    Eligibility,
    KnownIssue,
    PolicyRef,
    RepoRef,
    RegistryError,
    Target,
    load_registry,
    validate_targets,
    write_target_records,
)
from .state import WatchState
from .source import SourceBundle, SourceClient, SourceDiff, diff_bundles

__all__ = [
    "Event",
    "Kind",
    "Lead",
    "Status",
    "SCORE_THRESHOLD",
    "SCORE_WEIGHTS",
    "classify_event",
    "make_event",
    "score_lead",
    "CycleConfig",
    "CycleReport",
    "run_cycle",
    "ContractObservation",
    "FetchResult",
    "GitHubClient",
    "GitHubResult",
    "HttpFetcher",
    "RpcClient",
    "ContractRef",
    "Eligibility",
    "KnownIssue",
    "PolicyRef",
    "RepoRef",
    "RegistryError",
    "Target",
    "load_registry",
    "validate_targets",
    "write_target_records",
    "WatchState",
    "SourceBundle",
    "SourceClient",
    "SourceDiff",
    "diff_bundles",
]
