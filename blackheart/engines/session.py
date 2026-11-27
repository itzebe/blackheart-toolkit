"""A single multi-engine session: authorization gate -> orchestration -> persistence.

This is the one place that decides whether an engine run may proceed, so the gate
cannot be bypassed by calling an adapter directly through the CLI. A session:

  1. refuses to run unless the target is authorized -- either by BLACKHEART's
     authorization gate (``authz`` record + asset) or by an explicit
     ``allow_local`` opt-in for a local/disposable target;
  2. builds the requested adapters;
  3. runs the orchestrator under a cancellation token;
  4. persists the orchestration result so ``findings``/``report`` can re-read it.

The persisted state file is what makes ``engines status``/``report``/``cancel``
work across processes without a long-lived daemon.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from ..models import AuthorizationRecord
from . import get_adapter, list_engines
from .contract import EngineState
from .orchestrator import EngineOrchestrator, OrchestrationResult

STATE_FILENAME = "engines-run.json"
CANCEL_FILENAME = "engines-cancel"


class EngineSessionError(RuntimeError):
    """A session-level failure (authorization refused, bad engine name, ...)."""


class FileCancelEvent:
    """A cancellation token backed by a file's existence.

    Lets ``engines cancel --workdir DIR`` stop a run started in another process
    (or the same one) without a socket or signal plumbing.
    """

    def __init__(self, path: Path):
        self.path = Path(path)

    def is_set(self) -> bool:
        return self.path.exists()


@dataclass
class SessionOutcome:
    allowed: bool
    blocked_reason: str = ""
    result: Optional[OrchestrationResult] = None
    state_path: str = ""
    reports: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "allowed": self.allowed,
            "blocked_reason": self.blocked_reason,
            "state_path": self.state_path,
            "reports": dict(self.reports),
            "result": self.result.to_dict() if self.result else None,
        }


def check_authorization(*, authz: Optional[AuthorizationRecord], asset: str,
                        allow_local: bool, target: str) -> tuple[bool, str]:
    """The single authorization decision for an engine run.

    Fails closed: without either an authorized ``authz`` record for ``asset`` or an
    explicit ``allow_local`` opt-in, the run is refused.
    """
    if allow_local:
        return True, "explicit local/disposable-target opt-in"
    if authz is None:
        return False, ("no authorization provided: pass --authz <record> --asset <id> "
                       "for a real target, or --allow-local for a local/disposable target")
    from ..authz import authorize_active_testing

    decision = authorize_active_testing(authz, asset)
    if not decision.allowed:
        return False, "; ".join(decision.blockers) or "authorization refused"
    return True, "authorized via the BLACKHEART gate"


def run_session(
    workspace: str | Path,
    target: str,
    *,
    engines: Optional[list[str]] = None,
    authz: Optional[AuthorizationRecord] = None,
    asset: str = "",
    allow_local: bool = False,
    engine_options: Optional[dict] = None,
    ledger_fingerprints: Optional[set[str]] = None,
    compatibility: object = None,
) -> SessionOutcome:
    ws = Path(workspace)
    ws.mkdir(parents=True, exist_ok=True)

    allowed, reason = check_authorization(authz=authz, asset=asset or target,
                                          allow_local=allow_local, target=target)
    if not allowed:
        return SessionOutcome(allowed=False, blocked_reason=reason)

    names = engines or list_engines()
    unknown = [n for n in names if n not in list_engines()]
    if unknown:
        raise EngineSessionError(f"unknown engine(s): {', '.join(unknown)}")

    adapters = [get_adapter(n, ws, config=(engine_options or {}).get(n, {}).get("config"))
                for n in names]
    cancel = FileCancelEvent(ws / CANCEL_FILENAME)
    for opts in (engine_options or {}).values():
        opts.setdefault("cancel_event", cancel)

    orch = EngineOrchestrator(ws, adapters, ledger_fingerprints=ledger_fingerprints)
    result = orch.run(target, engine_options=engine_options, cancel_event=cancel,
                     compatibility=compatibility)

    state_path = ws / STATE_FILENAME
    state_path.write_text(json.dumps(result.to_dict(), indent=2, default=str), encoding="utf-8")
    # Clear the cancel token so a subsequent run in the same workspace is not
    # immediately cancelled by a stale file.
    try:
        os.unlink(ws / CANCEL_FILENAME)
    except FileNotFoundError:
        pass
    return SessionOutcome(allowed=True, result=result, state_path=str(state_path))


def load_state(workspace: str | Path) -> Optional[OrchestrationResult]:
    """Re-read a persisted orchestration result, or None if there is none."""
    path = Path(workspace) / STATE_FILENAME
    if not path.is_file():
        return None
    data = json.loads(path.read_text(encoding="utf-8"))
    result = OrchestrationResult(target=data.get("target", ""))
    result.started_at = data.get("started_at", "")
    result.finished_at = data.get("finished_at", "")
    result.missing_engines = list(data.get("missing_engines", []))
    result.notes = list(data.get("notes", []))
    # Re-hydrate clusters via the orchestrator so ids/dispositions stay consistent.
    from .orchestrator import EngineOrchestrator as _O

    from .schema import NormalizedFinding

    # Every cluster's representative is re-coordinated, so ids and dispositions
    # stay consistent. Membership is *not* re-derived from the representatives:
    # corroboration is the record that more than one engine saw the same defect,
    # and rebuilding from representatives alone would silently erase it, leaving
    # the CLI denying what the saved run recorded.
    candidates = []
    for cluster in data.get("clusters", []):
        rep = cluster.get("representative") or {}
        candidates.append(rep)
    orch = _O(Path(workspace))
    result.candidates = [NormalizedFinding.from_dict(rep) for rep in candidates]
    orch._coordinate(result)

    saved = {c.get("cluster_id"): c for c in data.get("clusters", [])}
    for cluster in result.clusters:
        record = saved.get(cluster.cluster_id)
        if not record:
            continue
        # Restore the recorded cross-engine agreement rather than recomputing it
        # from a single representative.
        sources = list(record.get("sources") or [])
        if sources:
            cluster.sources = sources
            cluster.corroborated = len(set(sources)) > 1
        member_ids = list(record.get("member_ids") or [])
        if member_ids:
            by_id = {m.finding_id: m for m in cluster.members}
            cluster.members = [by_id[i] for i in member_ids if i in by_id] or cluster.members
    return result


def request_cancel(workspace: str | Path) -> Path:
    """Create the cancel token a running session watches for."""
    ws = Path(workspace)
    ws.mkdir(parents=True, exist_ok=True)
    path = ws / CANCEL_FILENAME
    path.write_text("cancel\n", encoding="utf-8")
    return path


def cluster_to_record(cluster) -> "object":
    """Map an engine cluster onto a ``FindingRecord`` for the findings repository.

    The record is created UNCONFIRMED: an external engine candidate is a lead, not
    a proven vulnerability, and the findings repository's own evidence gate is the
    only route to CONFIRMED.
    """
    from ..findings import FindingRecord, FindingVerdict

    r = cluster.representative
    return FindingRecord(
        finding_id="BH-" + cluster.cluster_id,
        title=r.title or "Engine finding",
        target=r.target_id,
        component=r.component,
        status=FindingVerdict.UNCONFIRMED.value,
        category=r.category,
        cwe=r.cwe,
        cvss_score=str(r.cvss) if r.cvss is not None else "",
        severity=cluster.severity,
        hypothesis=r.description,
        attack_sequence=list(r.exploit_steps),
        consequences=r.impact,
        source_refs=[r.raw_artifact] if r.raw_artifact else [],
        logs=[f"source_engine:{s}" for s in cluster.sources]
             + ([f"corroborated:{','.join(cluster.sources)}"] if cluster.corroborated else [])
             + ([f"contradiction:{cluster.contradiction_detail}"] if cluster.contradiction else []),
    )


def document_run(workspace: str | Path, repo_dir: str | Path, *, name: str = "findings") -> list[str]:
    """Persist the last run's clusters into the findings repository. Returns ids."""
    from ..findings import FindingRepository

    result = load_state(workspace)
    if result is None:
        raise EngineSessionError(f"no engine run in {workspace}")
    repo = FindingRepository(str(repo_dir), name)
    written: list[str] = []
    for cluster in result.clusters:
        record = cluster_to_record(cluster)
        repo.add(record)
        written.append(record.finding_id)
    return written


def engine_status(workspace: str | Path) -> dict:
    """A status snapshot for ``engines status``: run state + per-engine health."""
    ws = Path(workspace)
    state = load_state(ws)
    health = {}
    for name in list_engines():
        try:
            h = get_adapter(name, ws).verify_health()
            health[name] = {"state": h.state.value, "version": h.version, "detail": h.detail}
        except Exception as e:  # noqa: BLE001
            health[name] = {"state": EngineState.FAILED.value, "detail": type(e).__name__}
    return {
        "workspace": str(ws),
        "has_run": state is not None,
        "run_finished_at": state.finished_at if state else "",
        "cancelled_pending": (ws / CANCEL_FILENAME).exists(),
        "engines": health,
    }
