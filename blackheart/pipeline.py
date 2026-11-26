"""Close the loop: verified deployment -> model -> price -> verify -> finding.

Every stage of this path already existed. What was missing was one operation that
runs them in order and refuses to upgrade a lead:

1. attest the deployment (read-only, Sourcify);
2. scan the verified source and synthesise an executable model;
3. certify a violating sequence with the bounded-exhaustive certifier;
4. price the sequence with the universal value engine;
5. independently re-run it in a fresh model and, when supplied, against a
   guarded control;
6. write a findings record -- ``CONFIRMED`` only when the independent verifier
   established the disposition *and* the caller established scope/authorization;
   otherwise ``STRONGLY_SUPPORTED``, with the missing control or scope named.

This module introduces no engine. It composes
:mod:`blackheart.ingest.verified`, :mod:`blackheart.value`,
:mod:`blackheart.statespace.verify`, :mod:`blackheart.evidence` and
:mod:`blackheart.findings`, and carries each module's own verdict. A model-level
reproduction is not a Foundry PoC; the result says so, and no finding is written
for a merely certified lead.
"""

from __future__ import annotations

import hashlib
import json
from contextlib import contextmanager
from dataclasses import dataclass, field, replace as _replace
from pathlib import Path
from typing import Any, Callable, Iterator, Optional

from .evidence import EvidenceStore
from .findings import FindingRecord, FindingRepository, FindingVerdict
from .ingest.solidity import scan_source
from .ingest.synthesize import synthesize
from .ingest.verified import (
    VerifiedModel,
    best_contract,
    build_verified_model,
    source_files,
)
from .models import AttackStep, ReviewIndependence
from .pocgen import execute_source_poc, render_source_poc
from .statespace.explore import Violation
from .statespace.verify import IndependentSequenceVerifier, VerifyConfig
from .toolchain.enforce import (
    CompatibilityError,
    ExecutionTarget,
    guarded,
    require_execution_authorized,
)
from .value import analyse
from .verified_source import Attestation, attest

PIPELINE_STAGES: tuple[str, ...] = (
    "attest", "model", "certify", "price", "verify", "evidence", "finding",
)


@dataclass
class PipelineStage:
    """What one stage did, in the stage's own words."""

    stage: str
    status: str = "SKIPPED"
    summary: str = ""
    detail: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {"stage": self.stage, "status": self.status,
                "summary": self.summary, "detail": self.detail}


@dataclass
class PipelineConfig:
    """Inputs and budgets for one close-the-loop run."""

    chain_id: int = 0
    address: str = ""
    #: A local source file or tree. When set, the pipeline runs source-only:
    #: no attestation, no deployment claim, and no human-authored hypothesis.
    source_path: str = ""
    contract_name: str = ""
    #: Compose every recovered contract into one protocol target instead of
    #: modelling a single contract. Inferred links are source-level unless a
    #: compiler call graph is supplied separately.
    protocol: bool = False
    protocol_infer_links: bool = True
    #: Use a solc AST instead of the lexer when a surface is available.
    ast_path: str = ""
    compiler_ast: bool = False
    #: Explicit compiler binary for ``compiler_ast`` (forge, solc or a path).
    compiler: str = ""
    #: Project root used to discover foundry.toml / remappings / libs. Empty
    #: means walk up from the source to the nearest project manifest.
    project_root: str = ""
    include_paths: tuple[str, ...] = ()
    remappings: tuple[str, ...] = ()
    control_address: str = ""
    control_source: str = ""
    control_contract: str = ""
    max_depth: int = 4
    #: Identity the compatibility record is bound to. Empty repository/commit
    #: default to the Sourcify source identity, which the result prints.
    repository: str = ""
    commit: str = ""
    findings_root: str = "research/private/findings"
    evidence_root: str = "research/private/evidence"
    reports_root: str = "research/private/reports"
    write_finding: bool = True
    write_report: bool = False
    reviewer: str = "deterministic-verifier"
    #: Three-valued on purpose. ``None`` is unestablished and can never yield a
    #: CONFIRMED finding; ``True`` must be an explicit operator assertion.
    in_scope: Optional[bool] = None
    authorization_gate_passed: Optional[bool] = None
    scope_reference: str = ""
    #: Optional RPC: when supplied, the deployed runtime is fetched and the
    #: verified source is recompiled and bound to it. Without it, source_bound is
    #: false and the finding says so.
    rpc: str = ""
    block: Optional[int] = None
    #: Test/injection seam: a runtime to bind and the recompiler that should
    #: reproduce it. Production uses ``rpc``; this exists so a caller that
    #: already fetched the runtime does not need a second network read.
    runtime_code: Optional[bytes] = None
    recompile: Optional[Callable[[dict[str, str], str], bytes]] = None
    #: Render and run the certificate as a source-level Foundry test. A PoC that
    #: cannot be rendered is reported, never invented.
    run_poc: bool = False
    poc_timeout: int = 600
    #: Strict verification: INDEPENDENTLY_VERIFIED requires a distinct engine.
    #: A passing Foundry PoC supplies ``foundry``; without one the honest
    #: disposition is REPRODUCED, never a confirmation.
    require_independent_engine: bool = False
    producer_engine: str = "bounded-exhaustive"
    verifier_engine: str = ""
    run_mutation_audit: bool = False
    mutation_classes: tuple[str, ...] = ()
    #: Add SSA-lite whole-program taint flows to the source run. This is a lead
    #: stage, never a finding and never a substitute for the certifier.
    dataflow: bool = False
    #: Constructor arguments and a proxy deployment for the source PoC.
    constructor_args: list = field(default_factory=list)
    proxy: bool = False
    #: Languages the operator explicitly allows to remain unscanned. This is a
    #: recorded partial exception, never a coverage claim.
    allow_unscanned: tuple[str, ...] = ()
    #: Injected for tests and for callers that already hold a record.
    compatibility: Any = None
    client: Any = None
    control_client: Any = None

    def to_dict(self) -> dict:
        return {
            "chain_id": self.chain_id,
            "address": self.address.lower(),
            "source_path": self.source_path,
            "contract": self.contract_name,
            "protocol": self.protocol,
            "protocol_infer_links": self.protocol_infer_links,
            "ast_path": self.ast_path,
            "compiler_ast": self.compiler_ast,
            "compiler": self.compiler,
            "project_root": self.project_root,
            "include_paths": list(self.include_paths),
            "remappings": list(self.remappings),
            "control_source": self.control_source,
            "control_contract": self.control_contract,
            "control_address": self.control_address.lower(),
            "max_depth": self.max_depth,
            "repository": self.repository,
            "commit": self.commit,
            "write_finding": self.write_finding,
            "write_report": self.write_report,
            "reviewer": self.reviewer,
            "in_scope": self.in_scope,
            "authorization_gate_passed": self.authorization_gate_passed,
            "scope_reference": self.scope_reference,
            "rpc": bool(self.rpc),
            "block": self.block,
            "run_poc": self.run_poc,
            "require_independent_engine": self.require_independent_engine,
            "producer_engine": self.producer_engine,
            "verifier_engine": self.verifier_engine,
            "run_mutation_audit": self.run_mutation_audit,
            "mutation_classes": list(self.mutation_classes),
            "dataflow": self.dataflow,
            "constructor_args": list(self.constructor_args),
            "proxy": self.proxy,
            "allow_unscanned": list(self.allow_unscanned),
        }


@dataclass
class PipelineResult:
    """The whole loop, with the one honest status a caller can gate on."""

    address: str
    chain_id: int
    status: str = "ERROR"
    target: str = ""
    invariant_id: str = ""
    model: Optional[dict] = None
    deployment: dict = field(default_factory=dict)
    certificate: dict = field(default_factory=dict)
    source_trace: list[dict] = field(default_factory=list)
    dataflow: dict = field(default_factory=dict)
    poc: dict = field(default_factory=dict)
    mutation: dict = field(default_factory=dict)
    economic: dict = field(default_factory=dict)
    verification: dict = field(default_factory=dict)
    finding_id: str = ""
    finding_status: str = ""
    report_path: str = ""
    stages: list[PipelineStage] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)
    identity: dict = field(default_factory=dict)
    #: Language-level coverage (``ingest.assess_coverage``).
    coverage: dict = field(default_factory=dict)
    #: Statement/model-level coverage for the executable model.
    model_coverage: dict = field(default_factory=dict)

    @property
    def confirmed(self) -> bool:
        return (self.status == "VERIFIED"
                and self.finding_status == FindingVerdict.CONFIRMED.value)

    def verdict_line(self) -> str:
        if self.status == "VERIFIED":
            acct = self.economic
            line = (f"VERIFIED: {self.invariant_id} reproduced independently in a fresh "
                    f"model and controlled at {self.target}")
            if acct.get("financial_impact_established"):
                line += (f"; attacker profit {acct.get('attacker_profit', 0)}, "
                         f"victim loss {acct.get('victim_loss', 0)}, "
                         f"value created {acct.get('value_created', 0)}")
            if self.finding_id:
                line += f". Finding {self.finding_id} ({self.finding_status})."
            return line
        if self.status == "REPRODUCED":
            return (f"REPRODUCED, NOT CONFIRMED: {self.invariant_id} reproduced in a "
                    f"fresh model, but " + "; ".join(self.reasons or
                    ["the discriminating control or scope was not established"]) +
                    ". This is a strong lead, not a confirmed vulnerability.")
        if self.status == "CERTIFIED_LEAD":
            return (f"CERTIFIED LEAD: {self.invariant_id} has a reproducible model "
                    f"witness, but the independent verifier did not establish it "
                    f"({self.verification.get('disposition', 'no disposition')}). "
                    "No finding was written.")
        if self.status == "NO_VIOLATION":
            return ("NO VIOLATION within the model bound. This is a bounded negative, "
                    "not a proof of safety; unmodelled statements and longer "
                    "sequences are outside it.")
        if self.status == "BLOCKED":
            return "BLOCKED: " + "; ".join(self.reasons or ["the compatibility gate refused"])
        if self.status == "NOT_VERIFIED":
            return "NOT VERIFIED: " + "; ".join(self.reasons or ["no verified source"])
        if self.status == "UNMODELLED":
            return "UNMODELLED: " + "; ".join(self.reasons or ["no executable surface"])
        if self.status == "INCOMPLETE":
            return ("INCOMPLETE MODEL COVERAGE: " +
                    "; ".join(self.reasons or ["reachable model gaps remain"]))
        return f"ERROR: {'; '.join(self.reasons) or 'the pipeline did not complete'}"

    def to_dict(self) -> dict:
        return {
            "chain_id": self.chain_id,
            "address": self.address.lower(),
            "status": self.status,
            "confirmed": self.confirmed,
            "target": self.target,
            "invariant_id": self.invariant_id,
            "model": self.model,
            "deployment": self.deployment,
            "certificate": self.certificate,
            "source_trace": list(self.source_trace),
            "dataflow": self.dataflow,
            "poc": self.poc,
            "mutation": self.mutation,
            "economic": self.economic,
            "verification": self.verification,
            "finding_id": self.finding_id,
            "finding_status": self.finding_status,
            "report_path": self.report_path,
            "stages": [s.to_dict() for s in self.stages],
            "reasons": list(self.reasons),
            "identity": dict(self.identity),
            "coverage": dict(self.coverage),
            "model_coverage": dict(self.model_coverage),
            "verdict": self.verdict_line(),
        }


def _stage(result: PipelineResult, stage: str, status: str,
           summary: str, detail: Optional[dict] = None) -> None:
    result.stages.append(PipelineStage(stage, status, summary, detail or {}))


def _verifier_engine(config: PipelineConfig, result: PipelineResult) -> str:
    """The engine that actually re-ran the witness, never an assumed one."""
    if (result.poc or {}).get("status") == "PASS":
        return "foundry"
    return config.verifier_engine


def _contract_for(attestation: Attestation):
    files = source_files(attestation)
    if not files:
        return None
    try:
        contracts = tuple(
            contract for path, source in sorted(files.items())
            for contract in scan_source(source, path)
        )
    except Exception:  # noqa: BLE001 -- the model builder reports the scan failure
        return None
    return best_contract(contracts)


@contextmanager
def _guard(compatibility: Any, identity: ExecutionTarget) -> Iterator[None]:
    """Use the caller's record when given; otherwise inherit the ambient authority.

    With no record this inherits the enclosing authority, and refuses when there
    is none. This context never turns a missing record into permission.
    """
    if compatibility is None:
        # Inherit only. A pipeline with no record and no enclosing authority is
        # blocked here, before the model is built -- never silently ungated.
        require_execution_authorized(identity.name, "pipeline")
        yield
        return
    with guarded(compatibility, identity, "pipeline", grants=(identity.name,)):
        yield


def _build(config: PipelineConfig, att: Attestation, identity: ExecutionTarget,
           *, client: Any = None, runtime_code: Optional[bytes] = None) -> VerifiedModel:
    with _guard(config.compatibility, identity):
        return build_verified_model(
            config.chain_id, att.address, client=client, max_depth=config.max_depth,
            attestation=att, runtime_code=runtime_code,
            recompile=config.recompile,
        )


def _build_control(config: PipelineConfig, att: Attestation,
                   identity: ExecutionTarget,
                   runtime_code: Optional[bytes] = None) -> tuple[Optional[VerifiedModel], str]:
    try:
        model = _build(config, att, identity, client=config.control_client,
                       runtime_code=runtime_code)
    except CompatibilityError as exc:
        return None, f"control not authorized: {exc}"
    except Exception as exc:  # noqa: BLE001 -- a control failure must not sink the primary
        return None, f"control failed: {type(exc).__name__}: {exc}"
    if model.status not in ("CERTIFIED", "NO_VIOLATION") or model.target is None:
        return None, f"control model status {model.status}: {'; '.join(model.reasons)}"
    return model, ""


def _finding_id(chain_id: int, address: str, invariant_id: str, witness: list[dict]) -> str:
    payload = json.dumps({"chain": chain_id, "address": address.lower(),
                          "invariant": invariant_id, "witness": witness},
                         sort_keys=True, default=str)
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:10]
    return f"pipeline-{chain_id}-{address.lower()[:10]}-{digest}"


def _sequence_text(steps: list[AttackStep]) -> list[str]:
    return [
        f"{s.actor}: {s.action}({', '.join(f'{k}={v}' for k, v in sorted(s.params.items()))})"
        for s in steps
    ]


def _deployment_truth_payload(config: PipelineConfig, model: VerifiedModel) -> dict:
    """The runtime-bound truth a deployed-address finding must carry."""
    if not config.address:
        return {}
    binding = model.binding or {}
    runtime = dict(binding.get("runtime") or {})
    attestation = model.attestation or {}
    bound = bool(model.source_bound)
    return {
        "status": "SOURCE_VERIFIED" if bound else "BYTECODE_ONLY",
        "address": config.address.lower(),
        "chain_id": config.chain_id,
        "source_status": attestation.get("status", ""),
        "source_compiler": attestation.get("compiler", ""),
        "source_fingerprint": binding.get("source_fingerprint", ""),
        "source_bound": bound,
        "runtime_binding": runtime,
        "limitations": [] if bound else [
            "verified source was not recompiled and bound to the deployed runtime"
        ],
        "note": "verified source is not a semantic equivalence proof",
    }


def _make_record(config: PipelineConfig, model: VerifiedModel, steps: list[AttackStep],
                 invariant_id: str, certificate: dict, economic: dict,
                 verification: dict, evidence_ids: list[str],
                 identity: ExecutionTarget, poc: Optional[dict] = None) -> FindingRecord:
    contract = model.contract or "contract"
    report = model.report
    path = report.path if report is not None else ""
    trace = certificate.get("trace") or []
    location = ""
    if trace:
        last = trace[-1]
        location = f"{last.get('action', '')} at step {last.get('index', '')}"
    acct = economic
    impact = acct.get("financial_impact_established", False)
    consequences = (
        f"attacker profit {acct.get('attacker_profit', 0)}, "
        f"victim loss {acct.get('victim_loss', 0)}, "
        f"protocol loss {acct.get('protocol_loss', 0)}, "
        f"value created {acct.get('value_created', 0)}, "
        f"repeatable={acct.get('repeatable', False)}"
        if impact else
        "state manipulation was reproduced; no tracked value movement, so financial "
        "impact is not established"
    )
    control_ok = (verification.get("checks", {}).get("control_integrity", {})
                  .get("passed") is True)
    return FindingRecord(
        finding_id=_finding_id(config.chain_id, config.address, invariant_id,
                               certificate.get("witness", [])),
        title=f"{invariant_id} violated in {contract} at {config.address.lower()}",
        target=config.address.lower(),
        component=f"ingest:{contract}",
        affected_version=identity.commit or model.binding.get("source_fingerprint", ""),
        category="value-conservation" if invariant_id.startswith("conservation:") else "invariant-violation",
        severity="unrated",
        security_boundary="unprivileged actor",
        attack_prerequisites=["verified source is available", "the modelled surface is reachable"],
        root_cause_file=path,
        root_cause_location=location,
        vulnerable_implementation=f"{contract} modelled from verified source",
        design_mistake=f"the declared invariant {invariant_id} is violated by an unprivileged sequence",
        why_controls_failed="the model has no guard or accounting step that preserves the invariant",
        hypothesis=f"an unprivileged actor can break {invariant_id} on {contract}",
        attacker_assumptions=["ordinary unprivileged account", "no owner or privileged role"],
        attack_preconditions=["the operation is externally callable"],
        attack_sequence=_sequence_text(steps),
        required_permissions="none beyond an ordinary account",
        exploitability="reproduced in the executable source model",
        consequences=consequences,
        repro_environment=(
            (f"local {'protocol ' if config.protocol else ''}source model at "
             f"{config.source_path}; "
             if config.source_path else
             f"verified source model at chain {config.chain_id}, "
             f"address {config.address.lower()}; ")
            + ("source-level Foundry PoC: " + str(poc.get("status", ""))
               if poc else "Python statement-subset model (no Foundry PoC was run)")
        ),
        repro_steps=_sequence_text(steps),
        repro_commands=[
            (f"blackheart pipeline --source {config.source_path} "
             f"{'--protocol ' if config.protocol else ''}"
             f"--contract {config.contract_name} --max-depth {config.max_depth}"
             if config.source_path else
             f"blackheart pipeline --chain-id {config.chain_id} "
             f"--address {config.address.lower()} --max-depth {config.max_depth}")
        ],
        expected_behavior=f"{invariant_id} holds for every unprivileged sequence",
        observed_behavior=certificate.get("reason", "") or "the certifier found a violating witness",
        execution_result=(
            "PASS (Foundry)" if (poc or {}).get("status") == "PASS"
            else ("PASS (model)" if certificate.get("reproducible") else "INCOMPLETE")
        ),
        repro_success_rate="deterministic model re-run" if certificate.get("reproducible") else "",
        evidence_ids=evidence_ids,
        traces=[json.dumps(t, sort_keys=True, default=str) for t in trace],
        before_after=json.dumps({"economic": acct}, sort_keys=True, default=str),
        verification_methodology="independent re-run in a fresh model; guarded control when supplied",
        reviewer=config.reviewer,
        verification_result=json.dumps(verification, sort_keys=True, default=str),
        alternative_explanations=[
            "the invariant is too weak and does not discriminate intended behaviour"
        ] if not control_ok else [],
        false_positive_analysis=(
            "control integrity established" if control_ok else
            "no guarded control was established; the invariant could be non-discriminating"
        ),
        remaining_uncertainty=(
            "the model covers a fixed statement subset; unmodelled statements and longer "
            "sequences are outside the bound. "
            + (f"Model coverage: {len(model.model_coverage.get('gaps') or [])} reachable "
               f"gap(s), fingerprint {model.model_coverage.get('fingerprint', '')}. "
               if model.model_coverage else "")
            + "A model-level reproduction is not a Foundry PoC. "
            "Severity is unrated: the program's official policy decides it."
        ),
        integrity_impact="value accounting or state invariant violated",
        affected_scope=(f"{contract} in {config.source_path}" if config.source_path
                        else f"{contract} at {config.address.lower()}"),
        exploit_prerequisites=["verified source", "reachable unprivileged operation"],
        severity_justification="not assigned; eligibility and severity come from the program policy",
        recommended_fix=f"restore {invariant_id}; add a regression test for the witness sequence",
        invariants_to_restore=[invariant_id],
        regression_tests=["re-run the witness and assert the invariant holds"],
        retest_result="guarded control clean" if control_ok else "not retested against a control",
        report_status="not-prepared",
        submission_status="not-submitted",
        review_independence=ReviewIndependence.UNRECORDED.value,
        authorizations=[config.scope_reference] if config.scope_reference else [],
        deployment_truth=_deployment_truth_payload(config, model),
    )


def run_pipeline(config: PipelineConfig) -> PipelineResult:
    """Run the loop. Expected gaps are statuses, not exceptions."""
    result = PipelineResult(address=config.address.lower(), chain_id=config.chain_id)

    # 1. Attest ---------------------------------------------------------- #
    att = attest(config.chain_id, config.address, client=config.client)
    _stage(result, "attest", att.status,
           f"Sourcify status {att.status} for {config.address.lower()}",
           att.to_dict())
    if not att.verified:
        result.status = "NOT_VERIFIED"
        result.reasons = [att.reason or att.status]
        return result

    contract = _contract_for(att)
    if contract is None:
        result.status = "UNMODELLED"
        result.reasons = ["the verified bundle has no recoverable contract surface"]
        _stage(result, "model", "UNMODELLED", result.reasons[0])
        return result

    runtime_code: Optional[bytes] = config.runtime_code
    if config.rpc:
        from .deployed import verify_contract
        deployment = verify_contract(config.address, config.rpc, at_block=config.block)
        result.deployment = deployment.to_dict()
        _stage(result, "deploy", "VERIFIED" if deployment.verified else "UNAVAILABLE",
               f"deployed runtime {deployment.code_size} bytes at block "
               f"{deployment.block_number}", deployment.to_dict())
        if deployment.verified and deployment.code:
            runtime_code = bytes.fromhex(deployment.code[2:])
        else:
            result.reasons.append("deployed runtime was not read; source binding is unproven")

    repository = config.repository or f"sourcify:{config.chain_id}:{config.address.lower()}"
    commit = config.commit or (att.bundle.fingerprint() if att.bundle is not None else "")
    identity = ExecutionTarget(name=f"ingest:{contract.name}",
                               repository=repository, commit=commit)
    result.target = identity.name
    result.identity = identity.to_dict()

    # 2. Model and certify ----------------------------------------------- #
    try:
        model = _build(config, att, identity, client=config.client,
                       runtime_code=runtime_code)
    except CompatibilityError as exc:
        result.status = "BLOCKED"
        result.reasons = [str(exc)]
        _stage(result, "model", "BLOCKED", str(exc))
        return result
    except Exception as exc:  # noqa: BLE001 -- report a build failure honestly
        result.status = "ERROR"
        result.reasons = [f"{type(exc).__name__}: {exc}"]
        _stage(result, "model", "ERROR", result.reasons[0])
        return result

    result.model = model.to_dict()
    result.model_coverage = dict(model.model_coverage or {})
    _stage(result, "coverage",
           "COMPLETE" if result.model_coverage.get("complete", True) else "INCOMPLETE",
           (f"{result.model_coverage.get('summary', {}).get('modelled_functions', 0)}/"
            f"{result.model_coverage.get('summary', {}).get('reachable_functions', 0)} "
            f"reachable functions modelled"
            if result.model_coverage else "no model coverage ledger"),
           result.model_coverage)
    _stage(result, "model", model.status,
           f"{model.contract or contract.name}: status {model.status}",
           {"contract": model.contract, "reasons": list(model.reasons),
            "source_bound": model.source_bound})
    if model.status != "CERTIFIED" or model.target is None:
        result.status = model.status
        result.reasons = list(model.reasons)
        if model.status == "NO_VIOLATION":
            result.reasons = list(model.reasons) or [
                f"no violation within depth {config.max_depth}; this is a bound, not safety"]
        return result

    certificate = dict(model.certificate)
    invariant_id = str(certificate.get("invariant_id", ""))
    witness = certificate.get("witness") or []
    steps = [AttackStep(**s) for s in witness]
    if not invariant_id or not steps:
        result.status = "ERROR"
        result.reasons = ["the certifier returned a proof without a witness"]
        _stage(result, "certify", "ERROR", result.reasons[0])
        return result
    result.invariant_id = invariant_id
    result.certificate = certificate
    _stage(result, "certify", "CERTIFIED",
           f"{invariant_id}: {len(steps)} step(s), reproducible={certificate.get('reproducible')}",
           certificate)

    # 3. Price ----------------------------------------------------------- #
    try:
        account = analyse(model.target, steps, invariant_id=invariant_id)
        result.economic = account.to_dict()
        _stage(result, "price", "PRICED" if account.financial_impact_established else "NO_IMPACT",
               (f"attacker profit {account.attacker_profit}, victim loss {account.victim_loss}, "
                f"value created {account.value_created}")
               if account.financial_impact_established else
               "state changed but no tracked value movement",
               account.to_dict())
    except Exception as exc:  # noqa: BLE001 -- a pricing failure is not a finding
        result.economic = {"error": f"{type(exc).__name__}: {exc}"}
        _stage(result, "price", "ERROR", result.economic["error"])

    # 3a. Invariant-strength audit ---------------------------------------- #
    if config.run_mutation_audit and model.target is not None:
        from .assurance.mutation import audit_mutations
        audit = audit_mutations(model.target, classes=config.mutation_classes,
                                max_depth=min(config.max_depth, 3))
        result.mutation = audit.to_dict()
        _stage(result, "mutate",
               "TRUSTWORTHY" if audit.trustworthy else "WEAK",
               ("every mutation was caught" if audit.trustworthy
                else f"{len(audit.weak)} mutation(s) survived; the clean result is weak evidence"),
               audit.to_dict())
    elif config.run_mutation_audit:
        _stage(result, "mutate", "SKIPPED", "no synthesized target to mutate")

    # 3b. Source-level Foundry PoC ---------------------------------------- #
    if config.run_poc:
        report = model.report
        candidate = render_source_poc(
            source_files(att), model.contract or contract.name,
            report.path if report is not None else "", steps, invariant_id,
            constructor_args=config.constructor_args,
            deployed_address=config.address if config.rpc else "",
            proxy=config.proxy,
        )
        if not candidate.rendered:
            result.poc = candidate.to_dict()
            _stage(result, "poc", candidate.status, candidate.reason,
                   candidate.to_dict())
        else:
            outcome = execute_source_poc(
                candidate, compatibility=config.compatibility,
                target_component=identity.name, repository=identity.repository,
                commit=identity.commit, timeout=config.poc_timeout,
                runner=getattr(config, "poc_runner", None),
                fork_url=config.rpc, fork_block=config.block,
            )
            result.poc = outcome.as_dict()
            _stage(result, "poc", outcome.status, outcome.detail,
                   outcome.as_dict())
    else:
        _stage(result, "poc", "SKIPPED", "run_poc is disabled")

    # 4. Independent verification ---------------------------------------- #
    control_model: Optional[VerifiedModel] = None
    control_reason = ""
    if config.control_address:
        control_att = attest(config.chain_id, config.control_address,
                             client=config.control_client or config.client)
        control_contract = _contract_for(control_att) if control_att.verified else None
        if control_contract is None:
            control_reason = (f"control {config.control_address.lower()} is not a verified, "
                              "modelled contract")
        else:
            control_runtime: Optional[bytes] = None
            if config.rpc:
                from .deployed import verify_contract
                control_dep = verify_contract(config.control_address, config.rpc,
                                              at_block=config.block)
                if control_dep.verified and control_dep.code:
                    control_runtime = bytes.fromhex(control_dep.code[2:])
            control_identity = ExecutionTarget(
                name=f"ingest:{control_contract.name}",
                repository=repository, commit=commit)
            control_model, control_reason = _build_control(
                config, control_att, control_identity, runtime_code=control_runtime)

    control_factory = None
    if control_model is not None and control_model.target is not None:
        control_invariants = {i.inv_id for i in control_model.target.invariants()}
        if invariant_id in control_invariants:
            control_factory = control_model.target.fresh_instance
        else:
            control_reason = (f"control model does not declare {invariant_id}; "
                              "it cannot discriminate this violation")
    if control_reason:
        result.reasons.append(control_reason)

    verifier = IndependentSequenceVerifier(
        model.target.fresh_instance,
        VerifyConfig(
            control_factory=control_factory,
            in_scope=config.in_scope,
            scope_reference=config.scope_reference,
            authorization_gate_passed=config.authorization_gate_passed,
            producer_engine=config.producer_engine,
            verifier_engine=_verifier_engine(config, result),
            require_distinct_engine=config.require_independent_engine,
        ),
    )
    violation = Violation(
        invariant_id=invariant_id, sequence=steps, minimal_sequence=steps,
        seed=0, actor_roles=sorted({s.actor for s in steps}),
        observed=(certificate.get("trace") or [{}])[-1].get("state", {}),
        reachable_by_attacker=True,
    )
    try:
        verified = verifier.verify(violation, preconditions_satisfiable=True)
        result.verification = verified.to_dict()
        _stage(result, "verify", verified.disposition,
               "; ".join(verified.reasons) or verified.disposition,
               verified.to_dict())
    except Exception as exc:  # noqa: BLE001 -- a verifier crash is not a pass
        result.verification = {"disposition": "VERIFY_ERROR",
                               "reasons": [f"{type(exc).__name__}: {exc}"]}
        _stage(result, "verify", "ERROR", result.verification["reasons"][0])
        result.status = "CERTIFIED_LEAD"
        return result

    disposition = result.verification.get("disposition", "")
    if disposition == "INDEPENDENTLY_VERIFIED":
        result.status = "VERIFIED"
    elif disposition == "REPRODUCED":
        result.status = "REPRODUCED"
        result.reasons.extend(result.verification.get("reasons", []))
    else:
        result.status = "CERTIFIED_LEAD"
        result.reasons.extend(result.verification.get("reasons", []))
        _stage(result, "finding", "SKIPPED",
               f"verifier disposition {disposition}: no finding written")
        return result

    # 5. Evidence and finding -------------------------------------------- #
    store = EvidenceStore(config.evidence_root)
    evidence = store.put_json(
        {
            "pipeline": result.to_dict(),
            "attestation": att.to_dict(),
            "deployment": result.deployment,
            "binding": model.binding,
            "certificate": certificate,
            "poc": result.poc,
            "mutation": result.mutation,
            "economic": result.economic,
            "verification": result.verification,
            "identity": identity.to_dict(),
        },
        kind="pipeline-reproduction",
        description=f"{invariant_id} at {config.address.lower()} on chain {config.chain_id}",
        command=f"blackheart pipeline --chain-id {config.chain_id} --address {config.address.lower()}",
        metadata={"chain_id": config.chain_id, "address": config.address.lower(),
                  "invariant_id": invariant_id},
    )
    evidence_ids = [evidence.evidence_id]
    _stage(result, "evidence", "STORED", evidence.evidence_id,
           {"evidence_id": evidence.evidence_id, "sha256": evidence.sha256})

    if not config.write_finding:
        _stage(result, "finding", "SKIPPED", "write_finding is disabled")
        return result

    record = _make_record(config, model, steps, invariant_id, certificate,
                          result.economic, result.verification, evidence_ids, identity,
                          poc=result.poc)
    if not (disposition == "INDEPENDENTLY_VERIFIED" and record.confirm()):
        record.status = FindingVerdict.STRONGLY_SUPPORTED.value
    repo = FindingRepository(config.findings_root)
    repo.save(record)
    result.finding_id = record.finding_id
    result.finding_status = record.status
    _stage(result, "finding", record.status,
           f"{record.finding_id} recorded as {record.status}",
           {"finding_id": record.finding_id, "status": record.status,
            "evidence_ids": evidence_ids})

    if config.write_report:
        report_path = (Path(config.reports_root) / f"{record.finding_id}.md").resolve()
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(repo.export_markdown(record), encoding="utf-8")
        result.report_path = str(report_path)
    return result


# --------------------------------------------------------------------------- #
# Source-only pipeline
# --------------------------------------------------------------------------- #

def _project_root(source_path: str, explicit: str = "") -> Path:
    """Find the nearest project manifest, not merely the file's parent.

    A source at ``src/Vault.sol`` must discover ``foundry.toml`` at the project
    root; otherwise its remappings and ``lib/`` dependencies are invisible and a
    compilable project is reported as unresolved.
    """
    if explicit:
        return Path(explicit).expanduser().resolve()
    root = Path(source_path).expanduser().resolve()
    start = root if root.is_dir() else root.parent
    for candidate in (start, *start.parents):
        for manifest in ("foundry.toml", "hardhat.config.js", "hardhat.config.ts"):
            if (candidate / manifest).is_file():
                return candidate
    return start


def _read_source_files(path: str) -> dict[str, str]:
    """Read a local Solidity file or tree, using the same hygiene as ingest.

    A single file is expanded through its relative imports. Without that, a
    contract that imports ``./MockERC20.sol`` compiles alone in a temp tree and
    the compiler path degrades to the lexer for a reason that is not the source's
    fault. Absolute/package imports are left to the compiler's include paths.
    """
    from .control import load_source_tree

    root = Path(path).expanduser()
    if not root.is_file():
        return load_source_tree(root)
    import re

    import_re = re.compile(
        r"""import\s+(?:[^;"']*?\s+from\s+)?["']([^"']+)["']""")
    files: dict[str, str] = {}
    base = root.parent.resolve()
    queue = [root.resolve()]
    while queue:
        current = queue.pop()
        try:
            key = str(current.relative_to(base)).replace("\\", "/")
        except ValueError:
            key = current.name
        if key in files or not current.is_file():
            continue
        text = current.read_text(encoding="utf-8", errors="replace")
        files[key] = text
        for spec in import_re.findall(text):
            if not spec.startswith("."):
                continue
            candidate = (current.parent / spec).resolve()
            if candidate.is_file():
                queue.append(candidate)
    return files


def _source_contracts(files: dict[str, str]):
    return tuple(
        contract for name, text in sorted(files.items())
        for contract in scan_source(text, name)
    )


def _load_ast_units(path: str) -> list[tuple[str, dict]]:
    """Read AST units as ``(source_path, ast)``, preserving source order.

    A solc ``src`` field's third component is an index into the compilation's
    source list. The path must travel with the AST, or a body is sliced from
    whichever file happens to sort first.
    """
    root_path = Path(path).expanduser()
    if root_path.is_dir():
        units: list[tuple[str, dict]] = []
        for candidate in sorted(root_path.glob("*.json")):
            units.extend(_load_ast_units(str(candidate)))
        return units
    payload = json.loads(root_path.read_text(encoding="utf-8"))
    units: list[tuple[str, dict]] = []
    if isinstance(payload, dict) and isinstance(payload.get("nodes"), list):
        units.append(("", payload))
    elif isinstance(payload, dict) and isinstance(payload.get("AST"), dict):
        units.append(("", payload["AST"]))
    sources = payload.get("sources") if isinstance(payload, dict) else None
    if isinstance(sources, dict):
        for source_path, source in sources.items():
            if not isinstance(source, dict):
                continue
            ast = source.get("AST") or source.get("ast")
            if isinstance(ast, dict) and isinstance(ast.get("nodes"), list):
                units.append((str(source_path), ast))
    # Foundry build-info: {"output": {"sources": {path: {"ast": {...}}}}}
    output = payload.get("output") if isinstance(payload, dict) else None
    build_sources = output.get("sources") if isinstance(output, dict) else None
    if isinstance(build_sources, dict):
        for source_path, source in build_sources.items():
            ast = source.get("ast") if isinstance(source, dict) else None
            if isinstance(ast, dict) and isinstance(ast.get("nodes"), list):
                units.append((str(source_path), ast))
    return units


def _load_ast_roots(path: str) -> list[dict]:
    """Backward-compatible AST-only view used by callers that do not need paths."""
    return [ast for _, ast in _load_ast_units(path)]


def _source_text_for(source_path: str, files: dict[str, str]) -> str:
    if source_path in files:
        return files[source_path]
    wanted = Path(source_path).name
    for key, text in files.items():
        if Path(key).name == wanted or key.endswith(source_path) or source_path.endswith(key):
            return text
    return ""


def _ast_contracts_units(units: list[tuple[str, dict]], files: dict[str, str]):
    from .ingest.ast_surface import surfaces_from_ast

    named = [(path, ast) for path, ast in units if path]
    texts = [_source_text_for(path, files) for path, _ in named]
    contracts = []
    for _, ast in units:
        # A named unit belongs to the compilation's ordered source list. An
        # unnamed unit is a single source unit, so the one text is its source.
        contracts.extend(surfaces_from_ast(ast, texts if named else files))
    return tuple(contracts)


def _ast_contracts_from_artifacts(artifacts, files: dict[str, str]):
    """Map each compiled artifact's AST against the compiled source order."""
    from .ingest.ast_surface import surfaces_from_ast

    source_paths = sorted({
        str(a.path).split(":", 1)[0]
        for a in artifacts.values() if getattr(a, "ast", None)
    })
    texts = [_source_text_for(path, files) for path in source_paths]
    contracts = []
    for artifact in artifacts.values():
        ast = getattr(artifact, "ast", None)
        if ast:
            contracts.extend(surfaces_from_ast(ast, texts))
    return tuple(contracts)


def _ast_contracts(roots: list[dict], files: dict[str, str]):
    from .ingest.ast_surface import surfaces_from_ast

    contracts = []
    for root in roots:
        contracts.extend(surfaces_from_ast(root, files))
    return tuple(contracts)


def _pick_contract(contracts, name: str = ""):
    if name:
        return next((c for c in contracts if c.name == name), None)
    return best_contract(contracts)


def _source_identity_component(files: dict[str, str], component: str,
                               path: str) -> ExecutionTarget:
    digest = hashlib.sha256(
        json.dumps(files, sort_keys=True).encode("utf-8")).hexdigest()[:16]
    return ExecutionTarget(
        name=component,
        repository=f"local:{Path(path).expanduser().resolve()}",
        commit=digest,
    )


def _source_identity_name(files: dict[str, str], name: str, path: str) -> ExecutionTarget:
    return _source_identity_component(files, f"ingest:{name}", path)


def _source_identity(files: dict[str, str], contract, path: str) -> ExecutionTarget:
    return _source_identity_name(files, contract.name, path)


def _best_violation(cert, target) -> tuple[dict, list[AttackStep], dict]:
    """Pick the violation with the strongest priced consequence, deterministically."""
    best = None
    for violation in cert.violations:
        steps = [AttackStep(**step) for step in violation.get("minimal_sequence", [])]
        if not steps:
            continue
        try:
            priced = analyse(
                target, steps, invariant_id=violation.get("invariant_id", "")).to_dict()
        except Exception as exc:  # noqa: BLE001 -- pricing is not a gate
            priced = {"error": f"{type(exc).__name__}: {exc}"}
        score = (
            1 if priced.get("financial_impact_established") else 0,
            1 if str(violation.get("invariant_id", "")).startswith("authorization:") else 0,
            int(priced.get("attacker_profit", 0) or 0),
            int(priced.get("victim_loss", 0) or 0),
            int(priced.get("value_created", 0) or 0),
            len(steps),
        )
        candidate = (score, violation, steps, priced)
        if best is None or candidate[0] > best[0]:
            best = candidate
    if best is None:
        return {}, [], {}
    return best[1], best[2], best[3]


def _protocol_steps(steps: list[AttackStep], surfaces: dict[str, Any]) -> list[AttackStep]:
    """Name the owning contract on each step, not the composed target."""
    out: list[AttackStep] = []
    for step in steps:
        owner = step.target_contract
        if "." in step.action:
            prefix = step.action.split(".", 1)[0]
            if prefix in surfaces:
                owner = prefix
        out.append(_replace(step, target_contract=owner))
    return out


def _protocol_source_trace(surfaces: dict[str, Any], steps: list[AttackStep],
                           source_path: str) -> list[dict]:
    """Map protocol steps to the contract that owns each called function."""
    from .witness import source_trace

    frames: list[dict] = []
    for step in steps:
        name = step.target_contract
        action = step.action
        if "." in action:
            prefix = action.split(".", 1)[0]
            if prefix in surfaces:
                # The certifier records the composed target's name in
                # ``target_contract``; the operation prefix is the owning
                # contract and is the stronger fact for a source trace.
                name = prefix
        surface = surfaces.get(name) if name else (
            next(iter(surfaces.values())) if len(surfaces) == 1 else None)
        if surface is None:
            frames.append({
                "index": len(frames), "actor": step.actor, "action": step.action,
                "params": dict(step.params), "contract": name or "",
                "function": "", "file": source_path, "line": 0, "snippet": "",
                "mapped": False, "reason": "no contract named by the protocol step",
            })
            continue
        try:
            mapped = source_trace(surface, [step], source_path=surface.path or source_path)
        except Exception as exc:  # noqa: BLE001 -- a trace failure is not a finding
            frames.append({
                "index": len(frames), "actor": step.actor, "action": step.action,
                "params": dict(step.params), "contract": surface.name,
                "function": "", "file": surface.path or source_path, "line": 0,
                "snippet": "", "mapped": False,
                "reason": f"source trace failed: {type(exc).__name__}: {exc}",
            })
            continue
        for frame in mapped:
            frames.append(_replace(frame, index=len(frames)).to_dict())
    return frames


def _run_protocol_source_pipeline(
    config: PipelineConfig,
    result: PipelineResult,
    files: dict[str, str],
    contracts: tuple[Any, ...],
    surface_source: str,
    ast_reason: str,
) -> PipelineResult:
    """The source loop over a composed protocol, not one contract at a time.

    The composition is explicit: every recovered contract is a sub-state, and a
    call is resolved through a declared or source-inferred link. A call the
    composition cannot resolve is a gap and is never treated as a no-op. The
    result is still a model-level reproduction; a Foundry PoC is rendered from
    the same witness when possible.
    """
    from .assurance.certify import CertifyConfig, certify
    from .ingest.protocol import build_protocol
    from .toolchain.enforce import CompatibilityError, self_test_authority

    surfaces = {c.name: c for c in contracts}
    protocol_name = config.contract_name or "protocol"
    identity = _source_identity_component(
        files, f"ingest:{protocol_name}", config.source_path)
    try:
        if config.compatibility is not None:
            with _guard(config.compatibility, identity):
                target, report = build_protocol(
                    surfaces, infer_links=config.protocol_infer_links,
                    name=protocol_name)
        else:
            with self_test_authority("source-pipeline-protocol"):
                target, report = build_protocol(
                    surfaces, infer_links=config.protocol_infer_links,
                    name=protocol_name)
    except CompatibilityError as exc:
        result.status = "BLOCKED"
        result.reasons = [str(exc)]
        _stage(result, "model", "BLOCKED", str(exc))
        return result
    except Exception as exc:  # noqa: BLE001
        result.status = "ERROR"
        result.reasons = [f"{type(exc).__name__}: {exc}"]
        _stage(result, "model", "ERROR", result.reasons[0])
        return result

    model_coverage = dict(report.model_coverage or {})
    result.model_coverage = model_coverage
    modelled = [f"{name}.{op}"
                for name, sub in report.contracts.items()
                for op in sub.modelled_ops]
    model_status = ("UNMODELLED" if not modelled else
                    "INCOMPLETE" if not model_coverage.get("complete", True) else
                    "CERTIFIED")
    # The verifier drives ``fresh_instance`` through the same compatibility
    # authority as the composer; the composed name must therefore match the
    # identity that authority granted, or a nested run is blocked.
    target.name = identity.name
    result.target = identity.name
    result.identity = identity.to_dict()
    result.model = {
        "status": model_status,
        "contract": target.name,
        "protocol": report.to_dict(),
        "source_bound": False,
        "binding": {"source": "local", "path": config.source_path,
                    "surface_source": surface_source,
                    "repository": identity.repository, "commit": identity.commit},
        "model_coverage": model_coverage,
        "reasons": [ast_reason] if ast_reason else [],
    }
    _stage(result, "coverage",
           "COMPLETE" if model_coverage.get("complete") else "INCOMPLETE",
           (f"{model_coverage.get('summary', {}).get('modelled_functions', 0)}/"
            f"{model_coverage.get('summary', {}).get('reachable_functions', 0)} "
            f"reachable functions modelled across {len(report.contracts)} contract(s); "
            f"{model_coverage.get('summary', {}).get('gaps', 0)} gap(s)"),
           model_coverage)
    _stage(result, "model", model_status,
           f"{target.name}: {len(modelled)} modelled operation(s) across "
           f"{len(report.contracts)} contract(s) via {surface_source}"
           + (f" ({ast_reason})" if ast_reason else ""), result.model)
    if not modelled:
        result.status = "UNMODELLED"
        result.reasons = ["no externally callable operation could be modelled"]
        return result

    try:
        cert = certify(target, CertifyConfig(max_depth=config.max_depth,
                                             price_findings=False))
    except CompatibilityError as exc:
        result.status = "BLOCKED"
        result.reasons = [str(exc)]
        _stage(result, "certify", "BLOCKED", str(exc))
        return result
    except Exception as exc:  # noqa: BLE001
        result.status = "ERROR"
        result.reasons = [f"{type(exc).__name__}: {exc}"]
        _stage(result, "certify", "ERROR", result.reasons[0])
        return result

    if not cert.broke:
        if not model_coverage.get("complete", True):
            gaps = model_coverage.get("gaps") or []
            first = gaps[0] if gaps else {}
            where = f"{first.get('path', '')}:{first.get('line', '')}"
            what = (first.get("statement") or first.get("callee_op")
                    or first.get("name") or "unknown")
            result.status = "INCOMPLETE"
            result.reasons = [f"model coverage incomplete: {len(gaps)} reachable item(s) "
                              f"are outside the model; first at {where} "
                              f"({first.get('kind', 'gap')}: {what}). A clean search "
                              f"is not a clean target"]
            _stage(result, "certify", "INCOMPLETE", result.reasons[0], model_coverage)
            return result
        result.status = "NO_VIOLATION"
        result.reasons = [f"no violation within depth {config.max_depth} over the "
                          "composed protocol model; this is a bound, not proof of safety"]
        _stage(result, "certify", "NO_VIOLATION", result.reasons[0])
        return result

    violation, steps, economic = _best_violation(cert, target)
    steps = _protocol_steps(steps, surfaces)
    invariant_id = str(violation.get("invariant_id", ""))
    if not invariant_id or not steps:
        result.status = "ERROR"
        result.reasons = ["the certifier returned a proof without a usable witness"]
        _stage(result, "certify", "ERROR", result.reasons[0])
        return result
    result.invariant_id = invariant_id
    result.certificate = violation
    result.economic = economic
    result.source_trace = _protocol_source_trace(surfaces, steps, config.source_path)
    _stage(result, "certify", "CERTIFIED",
           f"{invariant_id}: {len(steps)} step(s); selected from "
           f"{len(cert.violations)} violation(s)", violation)
    _stage(result, "price",
           "PRICED" if economic.get("financial_impact_established") else "NO_IMPACT",
           (f"attacker profit {economic.get('attacker_profit', 0)}, "
            f"victim loss {economic.get('victim_loss', 0)}, "
            f"value created {economic.get('value_created', 0)}")
           if economic.get("financial_impact_established") else
           "state changed but no tracked value movement", economic)

    control_factory = None
    control_reason = ""
    if config.control_source:
        control_files = _read_source_files(config.control_source)
        control_surfaces = {c.name: c for c in _source_contracts(control_files)}
        if not control_surfaces:
            control_reason = "the control source has no contract surface"
        else:
            try:
                control_target, _control_report = build_protocol(
                    control_surfaces, infer_links=config.protocol_infer_links,
                    name=config.control_contract or "protocol-control")
                control_target.name = identity.name
            except Exception as exc:  # noqa: BLE001
                control_reason = f"control synthesis failed: {type(exc).__name__}: {exc}"
            else:
                if invariant_id in {i.inv_id for i in control_target.invariants()}:
                    control_factory = control_target.fresh_instance
                else:
                    control_reason = (f"control does not declare {invariant_id}; "
                                      "it cannot discriminate this violation")
    if control_reason:
        result.reasons.append(control_reason)

    if config.run_poc:
        from .pocgen import execute_source_poc, render_protocol_poc

        if config.constructor_args:
            result.poc = {
                "status": "UNSUPPORTED",
                "detail": "protocol PoC requires per-contract constructor arguments; "
                          "supply a single-contract PoC or a deployment plan",
            }
            _stage(result, "poc", "UNSUPPORTED", result.poc["detail"])
        else:
            candidate = render_protocol_poc(files, surfaces, steps, invariant_id)
            if not candidate.rendered:
                result.poc = candidate.to_dict()
                _stage(result, "poc", candidate.status, candidate.reason,
                       candidate.to_dict())
            else:
                try:
                    with self_test_authority("source-pipeline-protocol-poc"):
                        outcome = execute_source_poc(
                            candidate, compatibility=config.compatibility,
                            target_component=identity.name,
                            repository=identity.repository, commit=identity.commit,
                            timeout=config.poc_timeout,
                            runner=getattr(config, "poc_runner", None),
                        )
                    result.poc = outcome.as_dict()
                    _stage(result, "poc", outcome.status, outcome.detail,
                           outcome.as_dict())
                except CompatibilityError as exc:
                    result.poc = {"status": "BLOCKED", "detail": str(exc)}
                    _stage(result, "poc", "BLOCKED", str(exc))
                except Exception as exc:  # noqa: BLE001
                    result.poc = {"status": "ERROR",
                                  "detail": f"{type(exc).__name__}: {exc}"}
                    _stage(result, "poc", "ERROR", result.poc["detail"])
    else:
        _stage(result, "poc", "SKIPPED", "run_poc is disabled")

    verifier = IndependentSequenceVerifier(
        target.fresh_instance,
        VerifyConfig(
            control_factory=control_factory,
            in_scope=config.in_scope,
            scope_reference=config.scope_reference,
            authorization_gate_passed=config.authorization_gate_passed,
            producer_engine=config.producer_engine,
            verifier_engine=_verifier_engine(config, result),
            require_distinct_engine=config.require_independent_engine,
        ),
    )
    violation_obj = Violation(
        invariant_id=invariant_id, sequence=steps, minimal_sequence=steps,
        seed=0, actor_roles=sorted({s.actor for s in steps}),
        observed=(violation.get("trace") or [{}])[-1].get("state", {}),
        reachable_by_attacker=bool(violation.get("reachable_by_attacker", True)),
    )
    try:
        if config.compatibility is not None:
            with _guard(config.compatibility, identity):
                verified = verifier.verify(violation_obj, preconditions_satisfiable=True)
        else:
            with self_test_authority("source-pipeline-protocol-verify"):
                verified = verifier.verify(violation_obj, preconditions_satisfiable=True)
        result.verification = verified.to_dict()
        _stage(result, "verify", verified.disposition,
               "; ".join(verified.reasons) or verified.disposition,
               verified.to_dict())
    except Exception as exc:  # noqa: BLE001
        result.verification = {"disposition": "VERIFY_ERROR",
                               "reasons": [f"{type(exc).__name__}: {exc}"]}
        _stage(result, "verify", "ERROR", result.verification["reasons"][0])
        result.status = "CERTIFIED_LEAD"
        return result

    disposition = result.verification.get("disposition", "")
    if disposition == "INDEPENDENTLY_VERIFIED":
        result.status = "VERIFIED"
    elif disposition == "REPRODUCED":
        result.status = "REPRODUCED"
        result.reasons.extend(result.verification.get("reasons", []))
    else:
        result.status = "CERTIFIED_LEAD"
        result.reasons.extend(result.verification.get("reasons", []))
        _stage(result, "finding", "SKIPPED",
               f"verifier disposition {disposition}: no finding written")
        return result

    store = EvidenceStore(config.evidence_root)
    evidence = store.put_json(
        {
            "pipeline": result.to_dict(),
            "source": {"path": config.source_path, "files": sorted(files),
                       "identity": identity.to_dict()},
            "protocol": report.to_dict(),
            "certificate": violation,
            "poc": result.poc,
            "economic": result.economic,
            "verification": result.verification,
            "model_coverage": model_coverage,
        },
        kind="protocol-source-reproduction",
        description=f"{invariant_id} in {target.name} from {config.source_path}",
        command=(f"blackheart pipeline --source {config.source_path} --protocol "
                 f"--max-depth {config.max_depth}"),
        metadata={"source": config.source_path, "protocol": target.name,
                  "invariant_id": invariant_id},
    )
    evidence_ids = [evidence.evidence_id]
    _stage(result, "evidence", "STORED", evidence.evidence_id,
           {"evidence_id": evidence.evidence_id, "sha256": evidence.sha256})

    if not config.write_finding:
        _stage(result, "finding", "SKIPPED", "write_finding is disabled")
        return result

    model = VerifiedModel(
        status="CERTIFIED", attestation={},
        binding={"source": "local", "path": config.source_path,
                 "repository": identity.repository, "commit": identity.commit},
        contract=target.name, report=None, certificate=violation,
        target=target, source_bound=False, model_coverage=model_coverage,
    )
    record = _make_record(config, model, steps, invariant_id, violation,
                          result.economic, result.verification, evidence_ids, identity,
                          poc=result.poc)
    if not (disposition == "INDEPENDENTLY_VERIFIED" and record.confirm()):
        record.status = FindingVerdict.STRONGLY_SUPPORTED.value
    repo = FindingRepository(config.findings_root)
    repo.save(record)
    result.finding_id = record.finding_id
    result.finding_status = record.status
    _stage(result, "finding", record.status,
           f"{record.finding_id} recorded as {record.status}",
           {"finding_id": record.finding_id, "status": record.status,
            "evidence_ids": evidence_ids})
    if config.write_report:
        report_path = (Path(config.reports_root) / f"{record.finding_id}.md").resolve()
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(repo.export_markdown(record), encoding="utf-8")
        result.report_path = str(report_path)
    return result


def run_source_pipeline(config: PipelineConfig) -> PipelineResult:
    """Run the whole loop on local source, with no human-authored hypothesis.

    This is the source-only counterpart of :func:`run_pipeline`. It scans the
    supplied tree, builds the executable model, lets the bounded-exhaustive
    certifier find every violating invariant, prices each witness, selects the
    strongest one, re-runs it in a fresh model, optionally runs a source-level
    Foundry PoC, and records the result. It never claims a deployment binding:
    ``source_bound`` is false and the finding says the model is local.
    """
    from .assurance.certify import CertifyConfig, certify
    from .toolchain.enforce import CompatibilityError, self_test_authority

    result = PipelineResult(
        address=f"local:{config.contract_name or Path(config.source_path).name}",
        chain_id=0)
    from .ingest import assess_coverage

    coverage = assess_coverage(
        config.source_path, "solidity", allow_unscanned=tuple(config.allow_unscanned)
    )
    result.coverage = coverage.to_dict()
    if coverage.blocked:
        result.status = "BLOCKED"
        result.reasons = [coverage.block_message()]
        _stage(result, "coverage", "BLOCKED", coverage.block_message(), coverage.to_dict())
        return result
    files = _read_source_files(config.source_path)
    if not files:
        result.status = "UNMODELLED"
        result.reasons = [f"no Solidity source found at {config.source_path!r}"]
        _stage(result, "model", "UNMODELLED", result.reasons[0])
        return result

    surface_source = "scanner"
    ast_reason = ""
    contracts = ()
    if config.ast_path:
        try:
            contracts = _ast_contracts_units(_load_ast_units(config.ast_path), files)
        except (OSError, ValueError, TypeError) as exc:
            result.status = "ERROR"
            result.reasons = [f"could not read AST {config.ast_path!r}: {exc}"]
            _stage(result, "model", "ERROR", result.reasons[0])
            return result
        if not contracts:
            result.status = "UNMODELLED"
            result.reasons = [f"AST {config.ast_path!r} has no contract definitions"]
            _stage(result, "model", "UNMODELLED", result.reasons[0])
            return result
        surface_source = "ast"
    elif config.compiler_ast:
        from .ingest.solc import compile_sources

        scanner_contracts = _source_contracts(files)
        target_surface = _pick_contract(scanner_contracts, config.contract_name)
        entry = (target_surface.path,) if target_surface is not None else ()
        project_root = _project_root(config.source_path, config.project_root)
        compiled = compile_sources(
            files, compiler=config.compiler, entry_files=entry,
            include_paths=config.include_paths, remappings=config.remappings,
            project_root=project_root)
        if compiled.ok:
            contracts = _ast_contracts_from_artifacts(compiled.artifacts, files)
            if contracts:
                surface_source = "ast"
            else:
                ast_reason = "the compiler produced no source-unit AST"
        else:
            ast_reason = (f"compiler AST unavailable ({compiled.status}): "
                          f"{compiled.reason}; using the lexer scanner")
    if not contracts:
        contracts = _source_contracts(files)
    if config.protocol:
        return _run_protocol_source_pipeline(
            config, result, files, contracts, surface_source, ast_reason)
    contract = _pick_contract(contracts, config.contract_name)
    if contract is None:
        result.status = "UNMODELLED"
        result.reasons = [
            (f"contract {config.contract_name!r} was not found in the source"
             if config.contract_name else "no contract surface recovered from the source")]
        _stage(result, "model", "UNMODELLED", result.reasons[0])
        return result
    registry = {c.name: c for c in contracts}
    identity = _source_identity(files, contract, config.source_path)
    result.target = identity.name
    result.identity = identity.to_dict()

    try:
        if config.compatibility is not None:
            with _guard(config.compatibility, identity):
                target, report = synthesize(contract, registry=registry)
        else:
            # A local source model is a repository fixture execution. It is
            # gated by the same record as every other fixture, not exempted.
            with self_test_authority("source-pipeline"):
                target, report = synthesize(contract, registry=registry)
    except CompatibilityError as exc:
        result.status = "BLOCKED"
        result.reasons = [str(exc)]
        _stage(result, "model", "BLOCKED", str(exc))
        return result
    except Exception as exc:  # noqa: BLE001
        result.status = "ERROR"
        result.reasons = [f"{type(exc).__name__}: {exc}"]
        _stage(result, "model", "ERROR", result.reasons[0])
        return result

    from .ingest.model_coverage import coverage_for_contract

    model_coverage = coverage_for_contract(contract, report, target).to_dict()
    result.model_coverage = model_coverage
    model_status = ("UNMODELLED" if not report.modelled_ops else
                    "INCOMPLETE" if not model_coverage.get("complete", True) else
                    "CERTIFIED")
    result.model = {
        "status": model_status,
        "contract": contract.name,
        "source_bound": False,
        "binding": {"source": "local", "path": config.source_path,
                    "surface_source": surface_source,
                    "repository": identity.repository, "commit": identity.commit},
        "report": report.__dict__,
        "model_coverage": model_coverage,
        "reasons": [ast_reason] if ast_reason else [],
    }
    _stage(result, "coverage",
           "COMPLETE" if model_coverage.get("complete") else "INCOMPLETE",
           (f"{model_coverage.get('summary', {}).get('modelled_functions', 0)}/"
            f"{model_coverage.get('summary', {}).get('reachable_functions', 0)} "
            f"reachable functions modelled; "
            f"{model_coverage.get('summary', {}).get('gaps', 0)} gap(s)"),
           model_coverage)
    _stage(result, "model", result.model["status"],
           f"{contract.name}: {len(report.modelled_ops)} modelled, "
           f"{len(report.unmodelled_ops)} unmodelled via {surface_source}"
           + (f" ({ast_reason})" if ast_reason else ""), result.model)
    if not report.modelled_ops:
        result.status = "UNMODELLED"
        result.reasons = ["no externally callable function could be modelled"]
        return result

    if config.dataflow:
        try:
            from .dataflow import analyse_source

            flow = analyse_source(files, contract_name=contract.name)
            result.dataflow = flow.to_dict()
            _stage(result, "dataflow", "LEADS",
                   f"{len(flow.unprivileged)} unprivileged taint flow(s) "
                   f"across {flow.functions} function(s)", result.dataflow)
        except Exception as exc:  # noqa: BLE001 -- a lead stage must not sink the run
            result.dataflow = {"status": "ERROR",
                               "detail": f"{type(exc).__name__}: {exc}"}
            _stage(result, "dataflow", "ERROR", result.dataflow["detail"])

    try:
        cert = certify(target, CertifyConfig(max_depth=config.max_depth,
                                             price_findings=False))
    except CompatibilityError as exc:
        result.status = "BLOCKED"
        result.reasons = [str(exc)]
        _stage(result, "certify", "BLOCKED", str(exc))
        return result
    except Exception as exc:  # noqa: BLE001
        result.status = "ERROR"
        result.reasons = [f"{type(exc).__name__}: {exc}"]
        _stage(result, "certify", "ERROR", result.reasons[0])
        return result

    if not cert.broke:
        if not model_coverage.get("complete", True):
            gaps = model_coverage.get("gaps") or []
            first = gaps[0] if gaps else {}
            where = f"{first.get('path', '')}:{first.get('line', '')}"
            what = (first.get("statement") or first.get("callee_op")
                    or first.get("name") or "unknown")
            result.status = "INCOMPLETE"
            result.reasons = [f"model coverage incomplete: {len(gaps)} reachable item(s) "
                              f"are outside the model; first at {where} "
                              f"({first.get('kind', 'gap')}: {what}). A clean search "
                              f"is not a clean target"]
            _stage(result, "certify", "INCOMPLETE", result.reasons[0], model_coverage)
            return result
        result.status = "NO_VIOLATION"
        result.reasons = [f"no violation within depth {config.max_depth} over the "
                          "modelled source surface; this is a bound, not proof of safety"]
        _stage(result, "certify", "NO_VIOLATION", result.reasons[0])
        return result

    violation, steps, economic = _best_violation(cert, target)
    invariant_id = str(violation.get("invariant_id", ""))
    if not invariant_id or not steps:
        result.status = "ERROR"
        result.reasons = ["the certifier returned a proof without a usable witness"]
        _stage(result, "certify", "ERROR", result.reasons[0])
        return result
    result.invariant_id = invariant_id
    result.certificate = violation
    result.economic = economic
    from .witness import source_trace as _source_trace

    result.source_trace = [frame.to_dict() for frame in
                           _source_trace(contract, steps,
                                         source_path=contract.path or config.source_path)]
    _stage(result, "certify", "CERTIFIED",
           f"{invariant_id}: {len(steps)} step(s); selected from "
           f"{len(cert.violations)} violation(s)", violation)
    _stage(result, "price",
           "PRICED" if economic.get("financial_impact_established") else "NO_IMPACT",
           (f"attacker profit {economic.get('attacker_profit', 0)}, "
            f"victim loss {economic.get('victim_loss', 0)}, "
            f"value created {economic.get('value_created', 0)}")
           if economic.get("financial_impact_established") else
           "state changed but no tracked value movement", economic)

    # Optional guarded control from a second source tree/contract.
    control_factory = None
    control_reason = ""
    if config.control_source:
        control_files = _read_source_files(config.control_source)
        control_contracts = _source_contracts(control_files)
        control_contract = _pick_contract(control_contracts, config.control_contract)
        if control_contract is None:
            control_reason = "the control source has no matching contract"
        else:
            try:
                control_target, _ = synthesize(
                    control_contract, registry={c.name: c for c in control_contracts})
            except Exception as exc:  # noqa: BLE001
                control_reason = f"control synthesis failed: {type(exc).__name__}: {exc}"
            else:
                if invariant_id in {i.inv_id for i in control_target.invariants()}:
                    control_factory = control_target.fresh_instance
                else:
                    control_reason = (f"control does not declare {invariant_id}; "
                                      "it cannot discriminate this violation")
    if control_reason:
        result.reasons.append(control_reason)

    # Source-level Foundry PoC.
    if config.run_poc:
        candidate = render_source_poc(
            files, contract.name, report.path, steps, invariant_id,
            constructor_args=config.constructor_args, proxy=config.proxy,
        )
        if not candidate.rendered:
            result.poc = candidate.to_dict()
            _stage(result, "poc", candidate.status, candidate.reason,
                   candidate.to_dict())
        else:
            try:
                with self_test_authority("source-pipeline-poc"):
                    outcome = execute_source_poc(
                        candidate, compatibility=config.compatibility,
                        target_component=identity.name,
                        repository=identity.repository, commit=identity.commit,
                        timeout=config.poc_timeout,
                        runner=getattr(config, "poc_runner", None),
                    )
                result.poc = outcome.as_dict()
                _stage(result, "poc", outcome.status, outcome.detail,
                       outcome.as_dict())
            except CompatibilityError as exc:
                result.poc = {"status": "BLOCKED", "detail": str(exc)}
                _stage(result, "poc", "BLOCKED", str(exc))
            except Exception as exc:  # noqa: BLE001
                result.poc = {"status": "ERROR",
                              "detail": f"{type(exc).__name__}: {exc}"}
                _stage(result, "poc", "ERROR", result.poc["detail"])
    else:
        _stage(result, "poc", "SKIPPED", "run_poc is disabled")

    verifier = IndependentSequenceVerifier(
        target.fresh_instance,
        VerifyConfig(
            control_factory=control_factory,
            in_scope=config.in_scope,
            scope_reference=config.scope_reference,
            authorization_gate_passed=config.authorization_gate_passed,
            producer_engine=config.producer_engine,
            verifier_engine=_verifier_engine(config, result),
            require_distinct_engine=config.require_independent_engine,
        ),
    )
    violation_obj = Violation(
        invariant_id=invariant_id, sequence=steps, minimal_sequence=steps,
        seed=0, actor_roles=sorted({s.actor for s in steps}),
        observed=(violation.get("trace") or [{}])[-1].get("state", {}),
        reachable_by_attacker=bool(violation.get("reachable_by_attacker", True)),
    )
    try:
        if config.compatibility is not None:
            with _guard(config.compatibility, identity):
                verified = verifier.verify(violation_obj, preconditions_satisfiable=True)
        else:
            with self_test_authority("source-pipeline-verify"):
                verified = verifier.verify(violation_obj, preconditions_satisfiable=True)
        result.verification = verified.to_dict()
        _stage(result, "verify", verified.disposition,
               "; ".join(verified.reasons) or verified.disposition,
               verified.to_dict())
    except Exception as exc:  # noqa: BLE001
        result.verification = {"disposition": "VERIFY_ERROR",
                               "reasons": [f"{type(exc).__name__}: {exc}"]}
        _stage(result, "verify", "ERROR", result.verification["reasons"][0])
        result.status = "CERTIFIED_LEAD"
        return result

    disposition = result.verification.get("disposition", "")
    if disposition == "INDEPENDENTLY_VERIFIED":
        result.status = "VERIFIED"
    elif disposition == "REPRODUCED":
        result.status = "REPRODUCED"
        result.reasons.extend(result.verification.get("reasons", []))
    else:
        result.status = "CERTIFIED_LEAD"
        result.reasons.extend(result.verification.get("reasons", []))
        _stage(result, "finding", "SKIPPED",
               f"verifier disposition {disposition}: no finding written")
        return result

    store = EvidenceStore(config.evidence_root)
    evidence = store.put_json(
        {
            "pipeline": result.to_dict(),
            "source": {"path": config.source_path, "files": sorted(files),
                       "identity": identity.to_dict()},
            "certificate": violation,
            "poc": result.poc,
            "economic": result.economic,
            "verification": result.verification,
            "model_coverage": model_coverage,
        },
        kind="source-reproduction",
        description=f"{invariant_id} in {contract.name} from {config.source_path}",
        command=(f"blackheart pipeline --source {config.source_path} "
                 f"--contract {contract.name}"),
        metadata={"source": config.source_path, "contract": contract.name,
                  "invariant_id": invariant_id},
    )
    evidence_ids = [evidence.evidence_id]
    _stage(result, "evidence", "STORED", evidence.evidence_id,
           {"evidence_id": evidence.evidence_id, "sha256": evidence.sha256})

    if not config.write_finding:
        _stage(result, "finding", "SKIPPED", "write_finding is disabled")
        return result

    model = VerifiedModel(
        status="CERTIFIED", attestation={},
        binding={"source": "local", "path": config.source_path,
                 "repository": identity.repository, "commit": identity.commit},
        contract=contract.name, report=report, certificate=violation,
        target=target, source_bound=False, model_coverage=model_coverage,
    )
    record = _make_record(config, model, steps, invariant_id, violation,
                          result.economic, result.verification, evidence_ids, identity,
                          poc=result.poc)
    if not (disposition == "INDEPENDENTLY_VERIFIED" and record.confirm()):
        record.status = FindingVerdict.STRONGLY_SUPPORTED.value
    repo = FindingRepository(config.findings_root)
    repo.save(record)
    result.finding_id = record.finding_id
    result.finding_status = record.status
    _stage(result, "finding", record.status,
           f"{record.finding_id} recorded as {record.status}",
           {"finding_id": record.finding_id, "status": record.status,
            "evidence_ids": evidence_ids})
    if config.write_report:
        report_path = (Path(config.reports_root) / f"{record.finding_id}.md").resolve()
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(repo.export_markdown(record), encoding="utf-8")
        result.report_path = str(report_path)
    return result
