"""From a verified deployment to a certified model, in one honest chain.

The steps are the ones an operator would run by hand:

1. attest the deployed address against Sourcify (read-only);
2. scan the verified Solidity and build an executable model;
3. certify the model with the bounded-exhaustive search.

Nothing is inferred across a gap. An address Sourcify does not have is
``NOT_VERIFIED``; a contract whose functions the interpreter cannot read is
``UNMODELLED``; a blocked execution is ``BLOCKED``; and a negative is
``NO_VIOLATION`` only *within the printed bound*, never "secure".

The attestation is bound to the model by the bundle fingerprint, so a report can
always name the exact source it reasoned about.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from ..verified_source import Attestation, attest
from .solidity import ContractSurface, scan_source
from .synthesize import SynthesisReport, SynthesizedTarget, synthesize

#: EIP-1967 implementation slot.
EIP1967_IMPLEMENTATION = 0x360894A13BA1A3210667C828492DB98DCA3E2076CC3735A920A3CA505D382BBC
_EIP1167_PREFIX = bytes.fromhex("363d3d373d3d3d363d73")
_EIP1167_SUFFIX = bytes.fromhex("5af43d82803e903d91602b57fd5bf3")


@dataclass
class RuntimeBinding:
    """Whether the verified source actually reproduces the deployed runtime."""

    status: str  # EXACT | METADATA_ONLY | MISMATCH | NO_DEPLOYED_CODE | NO_RECOMPILE | RECOMPILE_FAILED
    detail: str = ""
    recompiled_length: int = 0
    deployed_length: int = 0

    @property
    def bound(self) -> bool:
        return self.status in ("EXACT", "METADATA_ONLY")

    def to_dict(self) -> dict:
        return {"status": self.status, "bound": self.bound, "detail": self.detail,
                "recompiled_length": self.recompiled_length,
                "deployed_length": self.deployed_length}


@dataclass
class VerifiedModel:
    status: str  # NOT_VERIFIED | ERROR | UNMODELLED | CERTIFIED | NO_VIOLATION | BLOCKED
    attestation: dict
    binding: dict
    contract: str = ""
    report: Optional[SynthesisReport] = None
    certificate: dict = field(default_factory=dict)
    reasons: tuple[str, ...] = field(default_factory=tuple)
    target: Optional[SynthesizedTarget] = field(default=None, repr=False)
    #: True only when a recompilation reproduced the deployed runtime code.
    source_bound: bool = False
    #: The model-coverage ledger for the synthesized surface.
    model_coverage: dict = field(default_factory=dict)

    @property
    def certified(self) -> bool:
        return self.status == "CERTIFIED"

    def to_dict(self) -> dict:
        return {
            "status": self.status,
            "attestation": dict(self.attestation),
            "binding": dict(self.binding),
            "source_bound": self.source_bound,
            "contract": self.contract,
            "certificate": dict(self.certificate),
            "reasons": list(self.reasons),
            "report": (self.report.__dict__ if self.report is not None else None),
            "model_coverage": dict(self.model_coverage),
        }


def strip_metadata(code: bytes) -> bytes:
    """Drop a Solidity CBOR metadata tail so two builds can be compared.

    The last two bytes are the metadata length; the metadata is a CBOR map that
    starts with a map header (``0xa1``--``0xa4``). A code blob that does not
    match that shape is returned unchanged, so a false strip cannot hide a real
    difference.
    """
    code = bytes(code)
    if len(code) < 4:
        return code
    length = int.from_bytes(code[-2:], "big")
    start = len(code) - 2 - length
    if 0 < start < len(code) - 2 and code[start] in (0xA1, 0xA2, 0xA3, 0xA4):
        return code[:start]
    return code


def bind_runtime(recompiled: bytes, deployed: bytes) -> RuntimeBinding:
    """Compare a local recompilation with the deployed runtime bytecode."""
    recompiled, deployed = bytes(recompiled), bytes(deployed)
    if not deployed:
        return RuntimeBinding("NO_DEPLOYED_CODE", "no runtime code was supplied",
                              len(recompiled), 0)
    if recompiled == deployed:
        return RuntimeBinding("EXACT", "recompilation is byte-identical",
                              len(recompiled), len(deployed))
    left, right = strip_metadata(recompiled), strip_metadata(deployed)
    if left == right:
        return RuntimeBinding("METADATA_ONLY",
                              "code matches; only the metadata tail differs",
                              len(recompiled), len(deployed))
    first = next((i for i, (a, b) in enumerate(zip(left, right)) if a != b), min(len(left), len(right)))
    return RuntimeBinding("MISMATCH",
                          f"runtime differs at byte {first} "
                          f"(recompiled {len(left)} bytes, deployed {len(right)} bytes)",
                          len(recompiled), len(deployed))


def resolve_proxy(code: bytes, storage: dict[int, int]) -> Optional[int]:
    """The implementation address of an EIP-1967 or EIP-1167 proxy, if it is one."""
    slot = storage.get(EIP1967_IMPLEMENTATION, 0)
    if slot:
        return slot & ((1 << 160) - 1)
    code = bytes(code)
    if (len(code) == 45 and code.startswith(_EIP1167_PREFIX)
            and code.endswith(_EIP1167_SUFFIX)):
        return int.from_bytes(code[10:30], "big")
    return None


def _binding(att: Attestation) -> dict:
    bundle = att.bundle
    return {
        "chain_id": att.chain_id,
        "address": att.address,
        "status": att.status,
        "compiler": att.compiler,
        "files": list(att.files),
        "source_fingerprint": bundle.fingerprint() if bundle is not None else "",
    }


def _solidity_files(att: Attestation) -> dict[str, str]:
    bundle = att.bundle
    if bundle is None:
        return {}
    files = getattr(bundle, "files", {}) or {}
    return {path: text for path, text in files.items()
            if path.endswith(".sol") and isinstance(text, str)}


def _best_contract(contracts: tuple[ContractSurface, ...]) -> Optional[ContractSurface]:
    if not contracts:
        return None
    return max(contracts, key=lambda c: (
        sum(1 for f in c.functions if f.externally_callable), len(c.state_vars), c.name))


def source_files(attestation: Attestation) -> dict[str, str]:
    """The Solidity files in an attestation, without re-fetching it."""
    return _solidity_files(attestation)


def best_contract(contracts: tuple[ContractSurface, ...]) -> Optional[ContractSurface]:
    """The contract a model is built from: most external surface, then state, then name."""
    return _best_contract(contracts)


def _bind_source(
    files: dict[str, str],
    compiler: str,
    runtime_code: bytes,
    recompile: Optional[Callable[[dict[str, str], str], bytes]],
) -> RuntimeBinding:
    if recompile is None:
        return RuntimeBinding("NO_RECOMPILE",
                              "a runtime code was supplied but no recompiler")
    try:
        recompiled = recompile(files, compiler or "")
    except Exception as exc:  # noqa: BLE001 -- a failed build is reported, not hidden
        return RuntimeBinding("RECOMPILE_FAILED", str(exc))
    return bind_runtime(bytes(recompiled), bytes(runtime_code))


def bind_verified_source(
    attestation: Attestation,
    runtime_code: bytes,
    *,
    recompile: Optional[Callable[[dict[str, str], str], bytes]] = None,
    auto_recompile: bool = True,
) -> RuntimeBinding:
    """Bind one verified-source attestation to the deployed runtime.

    This is the pure binding step, without scanning or synthesising a model. It
    is used by the deployment-truth gate so a truth record can prove the source
    reproduces the deployment without paying for a model build.
    """
    if not attestation.verified:
        return RuntimeBinding("NOT_VERIFIED",
                              "the source attestation is not verified")
    files = _solidity_files(attestation)
    if not files:
        return RuntimeBinding("NO_SOURCE",
                              "the verified bundle has no Solidity source")
    if not runtime_code:
        return RuntimeBinding("NO_DEPLOYED_CODE", "no runtime code was supplied")
    if recompile is None and auto_recompile:
        from .solc import default_recompiler
        recompile = default_recompiler(bytes(runtime_code))
    return _bind_source(files, attestation.compiler, bytes(runtime_code), recompile)


def build_verified_model(
    chain_id: int,
    address: str,
    *,
    client: Optional[Any] = None,
    max_depth: int = 4,
    runtime_code: Optional[bytes] = None,
    recompile: Optional[Callable[[dict[str, str], str], bytes]] = None,
    storage: Optional[dict[int, int]] = None,
    attestation: Optional[Attestation] = None,
    auto_recompile: bool = True,
) -> VerifiedModel:
    """Attest, model and certify one deployed address. Never raises for a gap.

    When ``runtime_code`` is supplied, the verified source is rebuilt and
    compared with the deployed runtime; only a match sets ``source_bound``. The
    default is a real compiler (``solc``/``forge``); pass ``recompile`` to
    override it or ``auto_recompile=False`` to leave the build to the caller. A
    missing compiler or a failed build is reported, never hidden.

    ``attestation`` lets a caller that already attested the address reuse the
    read-only result, so a gated pipeline does not fetch the same source twice.
    """
    att = attestation or attest(chain_id, address, client=client)
    binding = _binding(att)
    if runtime_code is not None:
        implementation = resolve_proxy(runtime_code, storage or {})
        binding["proxy_implementation"] = (f"0x{implementation:040x}" if implementation else "")
    if not att.verified:
        return VerifiedModel(status="NOT_VERIFIED", attestation=att.to_dict(),
                             binding=binding, reasons=(att.reason or att.status,))

    files = _solidity_files(att)
    if not files:
        if runtime_code is not None:
            binding["runtime"] = RuntimeBinding(
                "NO_SOURCE", "the verified bundle has no Solidity source").to_dict()
        return VerifiedModel(status="UNMODELLED", attestation=att.to_dict(),
                             binding=binding,
                             reasons=("the verified bundle has no Solidity source",))

    try:
        contracts = tuple(
            contract for path, source in sorted(files.items())
            for contract in scan_source(source, path)
        )
    except Exception as exc:  # noqa: BLE001 -- a scanner failure is reported, not hidden
        return VerifiedModel(status="ERROR", attestation=att.to_dict(),
                             binding=binding, reasons=(f"scan failed: {exc}",))

    source_bound = False
    extra_reasons: tuple[str, ...] = ()
    if runtime_code is not None:
        if recompile is None and auto_recompile:
            from .solc import default_recompiler
            recompile = default_recompiler(runtime_code)
        runtime = _bind_source(files, att.compiler, runtime_code, recompile)
        binding["runtime"] = runtime.to_dict()
        source_bound = runtime.bound
        if runtime.status == "MISMATCH":
            extra_reasons = ("verified source does not reproduce the deployed runtime",)
        elif runtime.status == "RECOMPILE_FAILED":
            extra_reasons = (f"recompilation failed: {runtime.detail}",)

    contract = _best_contract(contracts)
    if contract is None:
        return VerifiedModel(status="UNMODELLED", attestation=att.to_dict(),
                             binding=binding, source_bound=source_bound,
                             reasons=("no contract surface recovered from the source",)
                             + extra_reasons)

    try:
        target, report = synthesize(contract)
    except Exception as exc:  # noqa: BLE001
        return VerifiedModel(status="ERROR", attestation=att.to_dict(),
                             binding=binding, contract=contract.name,
                             source_bound=source_bound,
                             reasons=(f"synthesis failed: {exc}",) + extra_reasons)
    coverage = dict(getattr(report, "model_coverage", {}) or {})

    modelled = tuple(m for m in report.modelled_ops)
    if not modelled:
        return VerifiedModel(status="UNMODELLED", attestation=att.to_dict(),
                             binding=binding, contract=contract.name, report=report,
                             source_bound=source_bound, model_coverage=coverage,
                             reasons=("no externally callable function could be modelled",)
                             + extra_reasons)

    from ..discovery.certify import certify_exhaustive
    from ..toolchain.enforce import CompatibilityError

    try:
        certificate = certify_exhaustive(target, max_depth=max_depth)
    except CompatibilityError as exc:
        return VerifiedModel(status="BLOCKED", attestation=att.to_dict(),
                             binding=binding, contract=contract.name, report=report,
                             source_bound=source_bound, model_coverage=coverage,
                             reasons=(str(exc),) + extra_reasons)
    except Exception as exc:  # noqa: BLE001
        return VerifiedModel(status="ERROR", attestation=att.to_dict(),
                             binding=binding, contract=contract.name, report=report,
                             source_bound=source_bound, model_coverage=coverage,
                             reasons=(f"certification failed: {exc}",) + extra_reasons)

    if certificate.proven:
        status = "CERTIFIED"
        reasons = ()
    elif not coverage.get("complete", True):
        status = "INCOMPLETE"
        gaps = coverage.get("gaps") or []
        first = gaps[0] if gaps else {}
        where = f"{first.get('path', '')}:{first.get('line', '')}"
        what = (first.get("statement") or first.get("callee_op")
                or first.get("name") or "unknown")
        reasons = (f"model coverage incomplete: {len(gaps)} reachable item(s) are "
                   f"outside the model; first at {where} "
                   f"({first.get('kind', 'gap')}: {what}). A clean search is not a "
                   f"clean target",)
    else:
        status = "NO_VIOLATION"
        reasons = (f"no violation within depth {max_depth} over the modelled surface; "
                   "this is a bound, not a proof of safety",)
    return VerifiedModel(status=status, attestation=att.to_dict(), binding=binding,
                         contract=contract.name, report=report,
                         certificate=certificate.to_dict(),
                         reasons=reasons + extra_reasons,
                         target=target, source_bound=source_bound,
                         model_coverage=coverage)


def build_decompiled_model(text: str, *, name: str = "Decompiled") -> VerifiedModel:
    """Surface-only model for a closed component. Never claims an effect.

    The decompiler recovers names, selectors and parameters. Every body stays
    unmodelled, so the result is ``UNMODELLED`` with the recovered surface in the
    report -- a reachability lead, not a semantic model.
    """
    from .decompiled import parse_decompiled

    contract = parse_decompiled(text, name=name)
    binding = {"source": "decompiled", "functions": len(contract.functions)}
    if not contract.functions:
        return VerifiedModel(status="UNMODELLED", attestation={}, binding=binding,
                             reasons=("no function surface recovered from the decompiler output",))
    try:
        _target, report = synthesize(contract)
    except Exception as exc:  # noqa: BLE001
        return VerifiedModel(status="ERROR", attestation={}, binding=binding,
                             contract=contract.name,
                             reasons=(f"synthesis failed: {exc}",))
    return VerifiedModel(
        status="UNMODELLED", attestation={}, binding=binding,
        contract=contract.name, report=report,
        model_coverage=dict(getattr(report, "model_coverage", {}) or {}),
        reasons=("the decompiled surface is recovered; its bodies are unmodelled, "
                 "so no effect is simulated",),
    )
