"""Plan a local deployment without inventing constructor arguments.

A PoC needs a deployed target: implementation, optional proxy, and helper
contracts such as tokens. This module reads the constructor signatures from the
source and produces an explicit plan. A required argument that was not supplied
is ``BLOCKED`` with the missing names; it is never defaulted to zero.

Proxy facts are read from the standard EIP-1967 slots when a runtime code and
storage snapshot are supplied. The plan models a minimal delegatecall proxy with
no admin or upgrade path, because inventing one would change the target.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Optional

from .solidity import _match_brace, _split_params, scan_source

_CONTRACT_HEAD = re.compile(
    r"\b(?:abstract\s+contract|contract|library|interface)\s+([A-Za-z_]\w*)[^{;]*\{")
_CONSTRUCTOR = re.compile(r"\bconstructor\s*\(([^)]*)\)")
EIP1967_IMPLEMENTATION = 0x360894A13BA1A3210667C828492DB98DCA3E2076CC3735A920A3CA505D382BBC
EIP1967_ADMIN = 0xB53127684A568B3173AE13B9F8A6016E243E63B6E8EE1178D6A717850B5D6103


@dataclass
class DeploymentStep:
    name: str
    kind: str = "contract"
    constructor_params: tuple[str, ...] = ()
    constructor_args: tuple[Any, ...] = ()
    status: str = "READY"
    reason: str = ""

    @property
    def ready(self) -> bool:
        return self.status == "READY"

    def to_dict(self) -> dict:
        return {"name": self.name, "kind": self.kind,
                "constructor_params": list(self.constructor_params),
                "constructor_args": list(self.constructor_args),
                "status": self.status, "reason": self.reason}


@dataclass
class DeploymentPlan:
    contract: str
    status: str = "READY"  # READY | BLOCKED | PARTIAL
    steps: tuple[DeploymentStep, ...] = ()
    proxy: bool = False
    proxy_implementation: str = ""
    proxy_admin: str = ""
    notes: tuple[str, ...] = ()

    @property
    def ready(self) -> bool:
        return self.status == "READY"

    def to_dict(self) -> dict:
        return {"contract": self.contract, "status": self.status,
                "ready": self.ready, "proxy": self.proxy,
                "proxy_implementation": self.proxy_implementation,
                "proxy_admin": self.proxy_admin,
                "steps": [s.to_dict() for s in self.steps],
                "notes": list(self.notes)}


def _contract_block(source: str, name: str) -> str:
    for match in _CONTRACT_HEAD.finditer(source):
        if match.group(1) != name:
            continue
        brace = source.find("{", match.start())
        if brace == -1:
            return ""
        end = _match_brace(source, brace)
        return source[brace + 1:end]
    return ""


def constructor_params(source: str, contract: str) -> tuple[str, ...]:
    """The constructor's parameter declarations, or ``()`` when it has none."""
    block = _contract_block(source, contract)
    match = _CONSTRUCTOR.search(block)
    if not match:
        return ()
    return _split_params(match.group(1))


def _param_names(params: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(p.split()[-1] for p in params if p.split())


def _step(name: str, source: str, args: Optional[list[Any]],
          kind: str = "contract") -> DeploymentStep:
    params = constructor_params(source, name)
    supplied = tuple(args or ())
    if len(supplied) < len(params):
        missing = _param_names(params[len(supplied):])
        return DeploymentStep(name, kind, params, supplied, "BLOCKED",
                              "missing constructor argument(s): " + ", ".join(missing))
    if len(supplied) > len(params):
        return DeploymentStep(name, kind, params, supplied, "BLOCKED",
                              f"{len(supplied)} arguments supplied for {len(params)} parameter(s)")
    return DeploymentStep(name, kind, params, supplied)


def plan_deployment(
    files: dict[str, str],
    contract: str,
    *,
    constructor_args: Optional[list[Any]] = None,
    proxy: bool = False,
    helper_deployments: tuple[tuple[str, list[Any]], ...] = (),
    runtime_code: bytes = b"",
    storage: Optional[dict[int, int]] = None,
) -> DeploymentPlan:
    """Plan a target, helpers and a minimal proxy from the source signatures."""
    source = "\n".join(files.values())
    contracts = {c.name for c in scan_source(source, "source.sol")}
    if contract not in contracts:
        return DeploymentPlan(contract, "BLOCKED",
                              notes=(f"contract {contract!r} was not found in the source",))
    steps: list[DeploymentStep] = []
    target = _step(contract, source, constructor_args)
    steps.append(target)
    for name, args in helper_deployments:
        if name not in contracts:
            steps.append(DeploymentStep(name, "helper", (), tuple(args), "BLOCKED",
                                        "helper contract not found in the source"))
            continue
        steps.append(_step(name, source, args, kind="helper"))
    implementation = ""
    admin = ""
    if runtime_code and storage:
        impl = storage.get(EIP1967_IMPLEMENTATION, 0)
        adm = storage.get(EIP1967_ADMIN, 0)
        implementation = f"0x{impl & ((1 << 160) - 1):040x}" if impl else ""
        admin = f"0x{adm & ((1 << 160) - 1):040x}" if adm else ""
    if proxy:
        steps.append(DeploymentStep("BHProxy", "proxy", ("address",),
                                    (target.name,), "READY" if target.ready else "BLOCKED",
                                    "minimal delegatecall proxy; no admin or upgrade path"))
    status = "READY" if all(step.ready for step in steps) else "BLOCKED"
    notes: list[str] = []
    if proxy and not implementation:
        notes.append("proxy requested; implementation address is the locally deployed target")
    if implementation:
        notes.append("EIP-1967 implementation slot was supplied by the caller")
    if admin:
        notes.append("EIP-1967 admin slot was supplied by the caller")
    return DeploymentPlan(contract, status, tuple(steps), proxy, implementation, admin,
                          tuple(notes))
