"""Automatic deployment binding: address -> chain -> source -> component -> record.

An operator should not have to hand-assemble the chain facts, the verified
source, the contract name and the compatibility record. This module performs
the join and fails closed when any link is missing:

* a live RPC that answers ``eth_chainId``;
* a deployment whose verified source is *bound* to the deployed runtime;
* a source tree containing the named component;
* a commit and repository for the identity binding;
* a smoke test that the native compiler can build the source.

A record is emitted only when all of those hold. A source that is verified but
not runtime-bound is ``BLOCKED`` -- a verified source is not a semantic
equivalence proof.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from ..rpc import resolve_rpc
from ..toolchain import CompatibilityRecord, admit
from ..verified_source import attest
from .truth import deployment_truth, validate_deployment_truth
from .solc import compile_sources
from .solidity import scan_source
from .verified import best_contract, source_files


@dataclass
class DeploymentBinding:
    """The result of binding one deployed address to one compatibility record."""

    status: str  # BOUND | BLOCKED
    reason: str = ""
    address: str = ""
    chain_id: Optional[int] = None
    component: str = ""
    commit: str = ""
    repository: str = ""
    truth: dict = field(default_factory=dict)
    record: dict = field(default_factory=dict)
    decision: dict = field(default_factory=dict)
    missing: list[str] = field(default_factory=list)
    source_files: list[str] = field(default_factory=list)
    smoke_test: str = "not-run"

    @property
    def bound(self) -> bool:
        return self.status == "BOUND"

    def to_dict(self) -> dict:
        return {
            "status": self.status,
            "bound": self.bound,
            "reason": self.reason,
            "address": self.address,
            "chain_id": self.chain_id,
            "component": self.component,
            "commit": self.commit,
            "repository": self.repository,
            "truth": dict(self.truth),
            "record": dict(self.record),
            "decision": dict(self.decision),
            "missing": list(self.missing),
            "source_files": list(self.source_files),
            "smoke_test": self.smoke_test,
        }


def _blocked(**kwargs: Any) -> DeploymentBinding:
    return DeploymentBinding(status="BLOCKED", **kwargs)


def bind_deployment(
    address: str,
    chain_id: int,
    *,
    repository: str,
    commit: str,
    rpc_url: str = "",
    component: str = "",
    client: Any = None,
    source_client: Any = None,
    recompile: Any = None,
    smoke_test: str = "auto",
    timeout: int = 300,
) -> DeploymentBinding:
    """Bind a deployment to a component and emit a compatibility record.

    ``client`` and ``source_client`` are injectable for tests and for a caller
    that already fetched the chain/source facts. ``recompile`` is passed to the
    runtime-binding step; the default uses the native Solidity compiler.
    """
    if not repository.strip():
        return _blocked(address=address, chain_id=chain_id,
                        reason="repository is required for an identity binding",
                        missing=["repository"])
    if not commit.strip():
        return _blocked(address=address, chain_id=chain_id,
                        repository=repository,
                        reason="commit is required for an identity binding; a "
                               "deployment record must name the commit it was verified against",
                        missing=["commit"])

    if not rpc_url:
        resolution = resolve_rpc(str(chain_id), expect_chain_id=chain_id)
        if not resolution.ok:
            return _blocked(address=address, chain_id=chain_id,
                            repository=repository, commit=commit,
                            reason="no live RPC answered eth_chainId: "
                                   + (resolution.error or "unresolved"),
                            missing=["rpc"])
        rpc_url = resolution.url

    truth = deployment_truth(address, rpc_url, client=client,
                             source_client=source_client, recompile=recompile)
    truth_dict = truth.to_dict()
    ok, why = validate_deployment_truth(truth_dict)
    if not ok:
        return _blocked(address=address, chain_id=chain_id,
                        repository=repository, commit=commit, truth=truth_dict,
                        reason=f"deployment truth is not bound: {why}",
                        missing=["source_bound"])

    target = address
    if truth.status == "IMPLEMENTATION_VERIFIED":
        target = truth.implementation
    att = attest(chain_id, target, client=source_client)
    files = source_files(att)
    if not files:
        return _blocked(address=address, chain_id=chain_id,
                        repository=repository, commit=commit, truth=truth_dict,
                        reason="the verified bundle has no Solidity source",
                        missing=["source"])

    surfaces = tuple(
        contract for path, text in sorted(files.items())
        for contract in scan_source(text, path)
    )
    chosen = None
    if component:
        chosen = next((c for c in surfaces if c.name == component), None)
        if chosen is None:
            return _blocked(address=address, chain_id=chain_id,
                            repository=repository, commit=commit, truth=truth_dict,
                            reason=f"component {component!r} is not in the verified source",
                            missing=["component"],
                            source_files=sorted(files))
    else:
        chosen = best_contract(surfaces)
        if chosen is None:
            return _blocked(address=address, chain_id=chain_id,
                            repository=repository, commit=commit, truth=truth_dict,
                            reason="no contract surface was recovered from the verified source",
                            missing=["component"],
                            source_files=sorted(files))
    component = chosen.name

    compiler = truth.source_compiler or att.compiler
    smoke = smoke_test
    smoke_detail = ""
    if smoke == "auto":
        compiled = compile_sources(files, compiler=compiler, timeout=timeout)
        smoke = "passed" if compiled.ok else "failed"
        smoke_detail = compiled.reason
    if smoke not in ("passed", "failed", "not-run"):
        return _blocked(address=address, chain_id=chain_id, component=component,
                        repository=repository, commit=commit, truth=truth_dict,
                        reason=f"unknown smoke_test value {smoke!r}",
                        missing=["smoke_test"], source_files=sorted(files))
    if smoke != "passed":
        return _blocked(address=address, chain_id=chain_id, component=component,
                        repository=repository, commit=commit, truth=truth_dict,
                        reason=(f"native compiler smoke test is {smoke}; a record "
                                "cannot be bound without a passing smoke test"),
                        missing=["smoke_test"], source_files=sorted(files),
                        smoke_test=smoke)

    limitations = "; ".join(truth.limitations) or "bounded source model; not a proof of safety"
    record = CompatibilityRecord(
        target_component=component,
        language="Solidity",
        language_version=compiler or "unknown",
        framework="Foundry",
        runtime="EVM (verified deployment; no broadcast)",
        tool="Foundry",
        compatibility_evidence="registry:Solidity/Foundry",
        selection_reason=(
            "the verified source is Solidity and Foundry is the registered native "
            "harness; the source is bound to the deployed runtime"),
        expected_coverage=(
            "source-level access control, accounting, arithmetic and invariant "
            "checks on a local harness"),
        known_limitations=limitations,
        smoke_test=smoke,
        repository=repository,
        commit=commit,
    )
    decision = admit(record)
    result = DeploymentBinding(
        status="BOUND" if decision.admitted else "BLOCKED",
        reason=("verified deployment bound to a complete compatibility record"
                if decision.admitted else
                "compatibility record is incomplete: " + "; ".join(decision.reasons)),
        address=address, chain_id=chain_id, component=component,
        commit=commit, repository=repository, truth=truth_dict,
        record=record.to_dict(), decision=decision.to_dict(),
        missing=list(record.missing_fields()),
        source_files=sorted(files), smoke_test=smoke,
    )
    if smoke_detail:
        result.reason += f"; smoke: {smoke_detail}"
    return result


def write_binding(binding: DeploymentBinding, path: str) -> None:
    """Write the binding and, when bound, the record as a loadable sidecar."""
    payload = binding.to_dict()
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    if binding.bound:
        record_path = target.with_suffix(".record.json")
        record_path.write_text(json.dumps(binding.record, indent=2), encoding="utf-8")
