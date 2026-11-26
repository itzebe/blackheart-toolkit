"""Run a real deployed-target investigation and emit auditable evidence.

This is the composition layer: it takes the pieces that already exist --
:mod:`blackheart.deployed_research` for retrieval and hypotheses,
:mod:`blackheart.deployed_multicontract` for the graph and execution, and
:class:`blackheart.coverage_engine.record.CoverageState` for the honest verdict
vocabulary -- and writes one machine-readable record per experiment.

The classification rules are the doctrine's, applied literally:

  * a candidate that was never executed is ``UNRESOLVED``, not ``TESTED``;
  * a target that could not be reached is ``BLOCKED``, and the reason names the
    obstacle;
  * an execution that completed and produced no violation under a discriminating
    control is ``TESTED_NO_ISSUE_FOUND`` -- which the coverage engine already
    documents as *not* proof of absence;
  * only a violation reproduced in a fresh process is ``REPRODUCED``, and even
    that is not a confirmed finding until the finding gates pass.

No state is ever upgraded to make a run look better.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from .coverage_engine.record import CoverageState
from .deployed import ChainClient, RpcUnavailable
from .deployed_multicontract import ContractGraph, SequenceResult, build_graph, run_sequence
from .deployed_research import (
    DeployedTarget,
    propose_hypotheses,
    resolve_target,
)

__all__ = [
    "ExperimentRecord",
    "run_deployed_experiment",
    "write_evidence_package",
]


@dataclass
class ExperimentRecord:
    """One experiment, with everything a reviewer needs to re-run it."""

    experiment_id: str
    #: Coverage vocabulary -- never a bespoke set of states.
    state: str = CoverageState.NOT_ASSESSED.value
    target: Optional[dict] = None
    graph: Optional[dict] = None
    hypotheses: list[dict] = field(default_factory=list)
    execution: Optional[dict] = None
    #: What the run could not establish, in plain words.
    limitations: list[str] = field(default_factory=list)
    blocked_reason: str = ""
    reproduction: str = "NOT_ATTEMPTED"

    def to_dict(self) -> dict:
        body = {
            "experiment_id": self.experiment_id,
            "state": self.state,
            "target": self.target,
            "graph": self.graph,
            "hypotheses": self.hypotheses,
            "execution": self.execution,
            "limitations": self.limitations,
            "blocked_reason": self.blocked_reason,
            "reproduction": self.reproduction,
        }
        # A content hash makes the record tamper-evident: any edit changes it.
        body["integrity_sha256"] = hashlib.sha256(
            json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        return body


def run_deployed_experiment(
    experiment_id: str,
    *,
    address: str,
    block_number: Optional[int] = None,
    rpc_urls: Optional[list[str]] = None,
    graph_roots: Optional[list[tuple[str, str]]] = None,
    execute: bool = False,
    steps: Optional[list] = None,
    observe: Optional[list[tuple[str, str, str]]] = None,
    node_factory: Optional[Any] = None,
    compatibility: object = None,
) -> ExperimentRecord:
    """Retrieve, hypothesise, optionally execute -- and classify honestly.

    ``execute=False`` is the default: retrieval and hypothesis generation are
    read-only, and an experiment that stops there is ``UNRESOLVED`` (candidates
    exist but were not run), never ``TESTED_NO_ISSUE_FOUND``.
    """
    rec = ExperimentRecord(experiment_id=_safe_experiment_id(experiment_id))

    try:
        target: DeployedTarget = resolve_target(
            address, block_number=block_number, rpc_urls=rpc_urls
        )
    except RpcUnavailable as exc:
        rec.state = CoverageState.BLOCKED.value
        rec.blocked_reason = f"RPC unavailable: {exc}"
        rec.limitations.append(
            "no chain data was retrieved, so nothing about this target is known"
        )
        return rec

    rec.target = target.to_dict()

    if target.unavailable_reason:
        rec.state = CoverageState.BLOCKED.value
        rec.blocked_reason = target.unavailable_reason
        rec.limitations.append(
            "the address holds no code at the pinned block; this is not evidence "
            "that the contract is safe, only that there is nothing to analyse"
        )
        return rec

    hypotheses = propose_hypotheses(target)
    rec.hypotheses = [h.to_dict() for h in hypotheses]

    if graph_roots:
        client = ChainClient(target.rpc_url)
        graph: ContractGraph = build_graph(
            graph_roots, client=client, block_number=target.block_number
        )
        rec.graph = graph.to_dict()

    if not execute:
        rec.state = CoverageState.UNRESOLVED.value
        rec.limitations.append(
            f"{len(hypotheses)} candidates were generated but none was executed; "
            "generation is not testing"
        )
        return rec

    if node_factory is None:
        rec.state = CoverageState.BLOCKED.value
        rec.blocked_reason = "no local fork node was supplied"
        rec.limitations.append(
            "execution was requested but no isolated fork was available; the "
            "candidates remain untested"
        )
        return rec

    node = node_factory(target)
    try:
        pin = node.assert_fork_pinned()
        if pin.get("block_number") != target.block_number:
            rec.state = CoverageState.BLOCKED.value
            rec.blocked_reason = (
                f"fork is on block {pin.get('block_number')} but evidence names "
                f"{target.block_number}"
            )
            return rec
        if not steps:
            # An empty sequence executes nothing, so "no issue found" would be a
            # claim about work that never happened. It stays unresolved.
            rec.state = CoverageState.UNRESOLVED.value
            rec.limitations.append(
                "execution was requested but no steps were supplied; nothing ran, "
                "so no test result exists"
            )
            return rec
        result: SequenceResult = run_sequence(node, steps, observe=observe,
                                              compatibility=compatibility)
        rec.execution = result.to_dict()
        rec.execution["fork_pin"] = pin
        if result.reverted_at:
            # A revert is a real observation, but it did not demonstrate a
            # violation: the candidate stays unresolved, not "tested clean".
            rec.state = CoverageState.UNRESOLVED.value
            rec.limitations.append(
                f"the sequence reverted at {result.reverted_at!r}; no violation was "
                "demonstrated and the path is not proven unreachable"
            )
        else:
            rec.state = CoverageState.TESTED_NO_ISSUE_FOUND.value
            rec.limitations.append(
                "the sequence executed without demonstrating a violation; "
                "TESTED_NO_ISSUE_FOUND is not proof of absence"
            )
    finally:
        node.stop()
    return rec


def _safe_experiment_id(experiment_id: str) -> str:
    """Reduce an id to a single safe path component.

    The id is operator-supplied (``--experiment-id``) and becomes a filename, so
    an unchecked value is an arbitrary-write primitive: ``../../x`` would place
    evidence outside the evidence directory. Reject separators outright rather
    than silently rewriting them -- a caller that meant a path should learn it
    was wrong, not get a file somewhere unexpected.
    """
    if not experiment_id or experiment_id in (".", ".."):
        raise ValueError(f"invalid experiment id {experiment_id!r}")
    if "/" in experiment_id or "\\" in experiment_id or "\x00" in experiment_id:
        raise ValueError(
            f"experiment id {experiment_id!r} must be a single path component; "
            "it may not contain a path separator"
        )
    return experiment_id


def write_evidence_package(
    records: list[ExperimentRecord],
    *,
    root: Path,
    source_commit: str,
    category: str,
) -> Path:
    """Write one JSON file per experiment plus a SHA256SUMS manifest."""
    out = Path(root) / category
    out.mkdir(parents=True, exist_ok=True)
    lines: list[str] = []
    for rec in records:
        body = rec.to_dict()
        body["source_commit"] = source_commit
        path = out / f"{_safe_experiment_id(rec.experiment_id)}.json"
        text = json.dumps(body, indent=2, sort_keys=True) + "\n"
        path.write_text(text, encoding="utf-8")
        lines.append(f"{hashlib.sha256(text.encode()).hexdigest()}  {path.name}")
    manifest = out / "SHA256SUMS.txt"
    manifest.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return out
