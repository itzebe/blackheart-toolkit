"""One record for deployment truth: chain facts, proxy, and verified source.

``deployed`` answers "is there code at this address"; ``attest`` answers "does a
verified source exist". This module joins them without blurring the difference:

* ``BYTECODE_ONLY`` -- real code, no verified source;
* ``SOURCE_VERIFIED`` -- the proxy/target itself has verified source;
* ``IMPLEMENTATION_VERIFIED`` -- a proxy's implementation has verified source;
* ``UNVERIFIED`` -- no code was read;
* ``UNAVAILABLE`` -- the chain read failed.

A verified source is not a semantic equivalence proof. The record carries the
compiler and the source fingerprint, and says so.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from ..deployed import DeployedContract, verify_contract
from ..verified_source import Attestation, attest
from .verified import bind_verified_source

STATUSES = ("UNAVAILABLE", "UNVERIFIED", "BYTECODE_ONLY", "SOURCE_VERIFIED",
            "IMPLEMENTATION_VERIFIED")

#: Runtime-binding statuses that prove the recompiled source is the deployed code.
BOUND_STATUSES = ("EXACT", "METADATA_ONLY")


def _runtime_bytes(code: str) -> Optional[bytes]:
    text = (code or "").removeprefix("0x")
    if not text:
        return None
    try:
        return bytes.fromhex(text)
    except ValueError:
        return None


@dataclass
class DeploymentTruth:
    status: str
    address: str = ""
    chain_id: Optional[int] = None
    block_number: Optional[int] = None
    code_sha256: str = ""
    code_size: int = 0
    proxy: bool = False
    proxy_kind: str = ""
    implementation: str = ""
    admin: str = ""
    source_status: str = ""
    source_compiler: str = ""
    source_fingerprint: str = ""
    source_files: list[str] = field(default_factory=list)
    implementation_source_status: str = ""
    source_bound: bool = False
    implementation_source_bound: bool = False
    runtime_binding: dict = field(default_factory=dict)
    implementation_runtime_binding: dict = field(default_factory=dict)
    limitations: list[str] = field(default_factory=list)

    @property
    def has_verified_source(self) -> bool:
        return self.status in ("SOURCE_VERIFIED", "IMPLEMENTATION_VERIFIED")

    def to_dict(self) -> dict:
        return {
            "status": self.status, "address": self.address,
            "chain_id": self.chain_id, "block_number": self.block_number,
            "code_sha256": self.code_sha256, "code_size": self.code_size,
            "proxy": self.proxy, "proxy_kind": self.proxy_kind,
            "implementation": self.implementation, "admin": self.admin,
            "source_status": self.source_status,
            "source_compiler": self.source_compiler,
            "source_fingerprint": self.source_fingerprint,
            "source_files": list(self.source_files),
            "implementation_source_status": self.implementation_source_status,
            "source_bound": self.source_bound,
            "implementation_source_bound": self.implementation_source_bound,
            "runtime_binding": dict(self.runtime_binding),
            "implementation_runtime_binding": dict(self.implementation_runtime_binding),
            "has_verified_source": self.has_verified_source,
            "limitations": list(self.limitations),
            "note": "verified source is not a semantic equivalence proof",
        }


def _source_fields(att: Optional[Attestation]) -> tuple[str, str, str, list[str]]:
    if att is None:
        return "", "", "", []
    fingerprint = ""
    if att.bundle is not None and att.verified:
        fingerprint = att.bundle.fingerprint()
    return att.status, att.compiler, fingerprint, list(att.files)


def truth_for_deployment(
    deployed: DeployedContract,
    *,
    attestation: Optional[Attestation] = None,
    implementation_attestation: Optional[Attestation] = None,
    runtime_binding: Any = None,
    implementation_runtime_binding: Any = None,
) -> DeploymentTruth:
    """Join deployment facts with an already-fetched attestation (no network).

    ``runtime_binding`` is the result of recompiling the verified source and
    comparing it with the deployed runtime. Without it the source may be
    ``SOURCE_VERIFIED`` but ``source_bound`` stays false: a truth record is not a
    semantic-equivalence proof until the runtime comparison succeeds.
    """
    if not deployed.verified:
        status = "UNAVAILABLE" if deployed.limitations else "UNVERIFIED"
        return DeploymentTruth(status, deployed.address, deployed.chain_id,
                               deployed.block_number, deployed.code_sha256,
                               deployed.code_size, deployed.proxy,
                               deployed.proxy_kind, deployed.implementation,
                               deployed.admin, limitations=list(deployed.limitations))
    source_status, compiler, fingerprint, files = _source_fields(attestation)
    impl_status, _, _, _ = _source_fields(implementation_attestation)
    binding = runtime_binding.to_dict() if hasattr(runtime_binding, "to_dict") else (
        dict(runtime_binding) if isinstance(runtime_binding, dict) else {})
    impl_binding = (implementation_runtime_binding.to_dict()
                    if hasattr(implementation_runtime_binding, "to_dict")
                    else (dict(implementation_runtime_binding)
                          if isinstance(implementation_runtime_binding, dict) else {}))
    source_bound = bool(binding.get("status") in BOUND_STATUSES)
    impl_source_bound = bool(impl_binding.get("status") in BOUND_STATUSES)
    if source_status == "verified":
        status = "SOURCE_VERIFIED"
    elif deployed.proxy and impl_status == "verified":
        status = "IMPLEMENTATION_VERIFIED"
    else:
        status = "BYTECODE_ONLY"
    limitations = list(deployed.limitations)
    if status == "BYTECODE_ONLY":
        limitations.append("no verified source was found for this deployment")
    if deployed.proxy and impl_status != "verified":
        limitations.append("the proxy implementation has no verified source")
    return DeploymentTruth(
        status, deployed.address, deployed.chain_id, deployed.block_number,
        deployed.code_sha256, deployed.code_size, deployed.proxy,
        deployed.proxy_kind, deployed.implementation, deployed.admin,
        source_status, compiler, fingerprint, files, impl_status, source_bound,
        impl_source_bound, binding, impl_binding, limitations,
    )


def deployment_truth(
    address: str,
    rpc_url: str,
    *,
    at_block: Optional[int] = None,
    client: Any = None,
    source_client: Any = None,
    bind_runtime: bool = True,
    recompile: Any = None,
) -> DeploymentTruth:
    """Read chain facts and verified source, without sending a transaction.

    When ``bind_runtime`` is true (the default) the verified source is
    recompiled and compared with the deployed runtime. A missing compiler or a
    failed build is recorded as a binding status, never hidden; only an
    ``EXACT`` or ``METADATA_ONLY`` match sets ``source_bound``.
    """
    deployed = verify_contract(address, rpc_url, at_block=at_block, client=client)
    if not deployed.verified or deployed.chain_id is None:
        return truth_for_deployment(deployed)
    att = attest(deployed.chain_id, address, client=source_client)
    impl_att = None
    if deployed.proxy and deployed.implementation:
        impl_att = attest(deployed.chain_id, deployed.implementation,
                          client=source_client)
    runtime_binding = None
    runtime = _runtime_bytes(deployed.code)
    if bind_runtime and runtime and att.verified:
        runtime_binding = bind_verified_source(
            att, runtime, recompile=recompile)
    impl_binding = None
    if bind_runtime and deployed.proxy and deployed.implementation and impl_att is not None:
        impl_deployed = verify_contract(deployed.implementation, rpc_url,
                                        at_block=at_block, client=client)
        impl_runtime = _runtime_bytes(impl_deployed.code)
        if impl_deployed.verified and impl_runtime:
            impl_binding = bind_verified_source(
                impl_att, impl_runtime, recompile=recompile)
    return truth_for_deployment(
        deployed, attestation=att, implementation_attestation=impl_att,
        runtime_binding=runtime_binding,
        implementation_runtime_binding=impl_binding,
    )


def validate_deployment_truth(payload: Any) -> tuple[bool, str]:
    """Whether a deployment-truth record proves source-to-runtime identity.

    A record passes only when it names an address and chain, carries verified
    source, and a recompilation reproduced the deployed runtime. A source-only
    attestation, a bytecode-only record, a mismatch and a failed build all fail
    closed. The check is deliberately narrow: it proves the source matches the
    runtime, not that the runtime is safe.
    """
    if not isinstance(payload, dict) or not payload:
        return False, "no deployment truth record"
    status = str(payload.get("status") or "")
    if status not in ("SOURCE_VERIFIED", "IMPLEMENTATION_VERIFIED"):
        return False, f"deployment truth status is {status or 'missing'}"
    if not str(payload.get("address") or "").strip():
        return False, "deployment truth has no address"
    if payload.get("chain_id") is None:
        return False, "deployment truth has no chain id"
    if status == "IMPLEMENTATION_VERIFIED":
        if payload.get("implementation_source_status") != "verified":
            return False, "proxy implementation source is not verified"
        if payload.get("implementation_source_bound") is not True:
            return False, "proxy implementation source is not bound to its runtime"
        binding = payload.get("implementation_runtime_binding") or {}
    else:
        if payload.get("source_bound") is not True:
            return False, "verified source is not bound to the deployed runtime"
        binding = payload.get("runtime_binding") or {}
    if binding.get("status") not in BOUND_STATUSES:
        return False, (
            "runtime binding is "
            f"{binding.get('status') or 'missing'}; expected one of "
            + ", ".join(BOUND_STATUSES))
    return True, "verified source is bound to the deployed runtime"
