"""Feed a promoted hypothesis's component into the synthesizer for a Target.

This closes the loop -- scanner lead -> grounded hypothesis -> certifiable Target
-- by reusing the exact path ``ingest --synthesize`` uses:

    ingest(path).contracts -> synthesize(contract, registry) -> certify(target)

Two honesty rules hold:

* **A synthesized target is a model.** It is what the certifier searches; it is
  not the deployed contract.
* **A certification result is model-level.** A model violation is a *witness to
  reproduce*, never a confirmed vulnerability. ``TargetOutcome`` carries no
  finding fields and says so in its ``note``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

#: Statuses that mean "a target now exists and can be searched".
_SEARCHABLE = ("SYNTHESIZED", "CERTIFIED", "NO_VIOLATION", "NO_OPS")


@dataclass
class TargetOutcome:
    """What synthesizing (and optionally certifying) a hypothesis produced."""

    component: str
    status: str            # SYNTHESIZED | NO_OPS | NOT_FOUND | CERTIFIED | NO_VIOLATION | ERROR
    detail: str = ""
    target_name: str = ""
    modelled_ops: int = 0
    unmodelled_ops: int = 0
    invariants: list[str] = field(default_factory=list)
    violations: int = 0
    source_path: str = ""
    #: The raw certificate, kept only so a PoC can be rendered from its witness.
    #: Excluded from ``as_dict`` -- it is not serialisable provenance.
    certificate: Any = field(default=None, repr=False, compare=False)

    @property
    def searchable(self) -> bool:
        return self.status in _SEARCHABLE

    def as_dict(self) -> dict:
        return {
            "component": self.component,
            "status": self.status,
            "detail": self.detail,
            "target_name": self.target_name,
            "modelled_ops": self.modelled_ops,
            "unmodelled_ops": self.unmodelled_ops,
            "invariants": list(self.invariants),
            "violations": self.violations,
            "source_path": self.source_path,
            "searchable": self.searchable,
            "note": "model-level result; a violation is a witness to reproduce, "
                    "never a confirmed finding",
        }


def _find_contract(contracts: list, component: str, source_path: str = "") -> Any:
    low = component.lower()
    for contract in contracts:
        if str(getattr(contract, "name", "")).lower() == low:
            return contract
    if source_path:
        stem = Path(source_path).stem.lower()
        for contract in contracts:
            if str(getattr(contract, "name", "")).lower() == stem:
                return contract
    return None


def target_from_hypothesis(hyp: dict, *, root: str, certify_result: bool = False,
                           max_depth: int = 4) -> TargetOutcome:
    """Synthesize (and optionally certify) the component a hypothesis names."""
    component = str((hyp or {}).get("component", "") or "")
    if not component:
        return TargetOutcome("", "ERROR", "the hypothesis names no component")
    source_path = str(((hyp or {}).get("source") or {}).get("path", "") or "")
    try:
        from ..ingest import ingest
        report = ingest(str(root))
    except Exception as exc:  # noqa: BLE001 -- reported, never hidden
        return TargetOutcome(component, "ERROR", f"ingest failed: {exc}")
    contracts = list(getattr(report, "contracts", []) or [])
    contract = _find_contract(contracts, component, source_path)
    if contract is None:
        found = ", ".join(str(getattr(c, "name", "?")) for c in contracts) or "none"
        return TargetOutcome(
            component, "NOT_FOUND",
            f"no contract {component!r} under {root!r} (found: {found})")
    from ..ingest.synthesize import synthesize

    registry = {str(c.name): c for c in contracts}
    target, srep = synthesize(contract, registry=registry)
    outcome = TargetOutcome(
        component, "SYNTHESIZED",
        target_name=str(getattr(target, "name", "")),
        modelled_ops=len(getattr(srep, "modelled_ops", ()) or ()),
        unmodelled_ops=len(getattr(srep, "unmodelled_ops", ()) or ()),
        invariants=list(getattr(srep, "invariants", ()) or ()),
        source_path=str(getattr(srep, "path", "") or ""),
    )
    if not target.ops():
        outcome.status = "NO_OPS"
        outcome.detail = "no externally callable, modelled operation to certify"
        return outcome
    if not certify_result:
        outcome.detail = "synthesized (not certified); this is a model, not a finding"
        return outcome
    from ..assurance.certify import CertifyConfig, certify

    cert = certify(target, CertifyConfig(max_depth=max_depth, price_findings=False))
    outcome.certificate = cert
    outcome.violations = len(getattr(cert, "violations", []) or [])
    outcome.status = "CERTIFIED" if outcome.violations else "NO_VIOLATION"
    outcome.detail = (
        f"{outcome.violations} model-level witness(es) to reproduce (never a finding)"
        if outcome.violations
        else "no model-level violation within the bound (not a proof of safety)")
    return outcome


def targets_from_hypotheses(hypotheses: list[dict], *, root: str,
                            certify_result: bool = False,
                            max_depth: int = 4) -> list[TargetOutcome]:
    """Synthesize every hypothesis that names a component."""
    return [target_from_hypothesis(hyp, root=root, certify_result=certify_result,
                                   max_depth=max_depth)
            for hyp in (hypotheses or [])]


def poc_for_target(outcome: TargetOutcome, *, root: str, compatibility: Any,
                   repository: str = "", commit: str = "",
                   timeout: int = 600) -> dict:
    """Render and run a Foundry reproduction of the certified witness.

    Fail-closed: ``execute_witness``/``execute_source_poc`` refuse to run without a
    compatibility record bound to the target (and without ``forge``). A ``PASS`` is
    a reproduction, not a priced finding, and it never changes the model verdict.
    """
    cert = getattr(outcome, "certificate", None)
    if cert is None or not getattr(cert, "violations", None):
        return {"status": "SKIPPED", "detail": "no certified witness to reproduce",
                "invariant_id": ""}
    from ..ingest.execute import (
        contract_path_for, execute_witness, read_solidity_sources,
    )

    files = read_solidity_sources(root)
    contract_path = contract_path_for(outcome.source_path or outcome.component, root)
    return execute_witness(
        cert, contract=outcome.component, contract_path=contract_path,
        files=files, compatibility=compatibility, repository=repository,
        commit=commit, timeout=timeout,
    )


__all__ = ["TargetOutcome", "target_from_hypothesis", "targets_from_hypotheses",
           "poc_for_target"]
