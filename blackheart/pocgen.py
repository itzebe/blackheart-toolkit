"""Turn a certified source-model witness into a runnable Foundry test.

The existing PoC path starts from runtime bytecode. This module starts from the
*verified source* and the certifier's witness, so the generated test calls the
real contract through its own ABI. It renders only what it can justify:

* the contract is deployed with no constructor arguments (an unmodelled
  constructor is a compile error, reported as ``INCOMPLETE`` -- never guessed);
* each witness step becomes ``vm.prank(actor); target.fn(args);``;
* the invariant is asserted through public getters named by the invariant id
  (``conservation:balance-totalSupply`` -> ``balance(actor)`` and
  ``totalSupply()``).

A rendered test is not a reproduction until it runs. The runner returns
``PASS`` / ``FAIL`` / ``BLOCKED`` / ``INCOMPLETE`` and the caller must not
upgrade it to a finding.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Optional

from .models import AttackStep
from .symbolic.poc_runner import PocRunOutcome, run_poc_text
from .toolchain.enforce import CompatibilityRecord

STATUSES = ("RENDERED", "UNSUPPORTED", "INCOMPLETE")

_IDENT = re.compile(r"^[A-Za-z_]\w*$")
_CONSERVATION = re.compile(r"^conservation:([A-Za-z_]\w*)-([A-Za-z_]\w*)$")
_AUTHORIZATION = re.compile(r"^authorization:([A-Za-z_]\w*)$")
_SOLVENCY = re.compile(r"^solvency:([A-Za-z_]\w*)-([A-Za-z_]\w*)$")
_BOUNDED = re.compile(r"^bounded:([A-Za-z_]\w*)-(\d+)$")


@dataclass
class PocCandidate:
    status: str
    solidity: str = ""
    test_name: str = "test_certificate_witness"
    reason: str = ""
    invariant_id: str = ""
    constructor_args: tuple = ()
    deployed_address: str = ""
    proxy: bool = False
    helpers: tuple = ()
    sources: dict[str, str] = field(default_factory=dict, repr=False)

    @property
    def rendered(self) -> bool:
        return self.status == "RENDERED" and bool(self.solidity)

    def to_dict(self) -> dict:
        return {
            "status": self.status,
            "test_name": self.test_name,
            "reason": self.reason,
            "invariant_id": self.invariant_id,
            "solidity_len": len(self.solidity),
            "source_files": sorted(self.sources),
            "constructor_args": list(self.constructor_args),
            "deployed_address": self.deployed_address,
            "proxy": self.proxy,
            "helpers": [name for name, _ in self.helpers],
        }


def _literal(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    text = str(value)
    if text in ("attacker", "victim"):
        return text
    if text == "admin":
        return "address(0xAD)"
    if text.startswith("0x") and len(text) == 42:
        return f"address(uint160({int(text, 16)}))"
    if text == "0x":
        return "address(0)"
    return str(int(text)) if text.isdigit() else "0"


def _actor(name: str) -> Optional[str]:
    return name if name in ("attacker", "victim") else None


def render_source_poc(
    files: dict[str, str],
    contract: str,
    contract_path: str,
    steps: list[AttackStep],
    invariant_id: str,
    *,
    constructor_args: Optional[list[Any]] = None,
    deployed_address: str = "",
    proxy: bool = False,
    helper_deployments: tuple[tuple[str, list[Any]], ...] = (),
) -> PocCandidate:
    """Render a Foundry test from the witness, or say why it cannot."""
    conservation = _CONSERVATION.match(invariant_id)
    authorization = _AUTHORIZATION.match(invariant_id)
    solvency = _SOLVENCY.match(invariant_id)
    bounded = _BOUNDED.match(invariant_id)
    if not (conservation or authorization or solvency or bounded):
        return PocCandidate(
            "UNSUPPORTED", invariant_id=invariant_id,
            reason="renderable invariants are conservation:<mapping>-<total>, "
                   "authorization:<field>, solvency:<asset>-<liability> and "
                   "bounded:<field>-<bound>",
        )
    if not _IDENT.match(contract):
        return PocCandidate("UNSUPPORTED", invariant_id=invariant_id,
                            reason=f"contract name {contract!r} is not an identifier")
    if not contract_path:
        return PocCandidate("UNSUPPORTED", invariant_id=invariant_id,
                            reason="the contract path is unknown")
    if conservation:
        mapping, total = conservation.groups()
    if not steps:
        return PocCandidate("UNSUPPORTED", invariant_id=invariant_id,
                            reason="the certificate has no witness steps")
    for helper, _args in helper_deployments:
        if not _IDENT.match(helper):
            return PocCandidate("UNSUPPORTED", invariant_id=invariant_id,
                                reason=f"helper contract {helper!r} is not an identifier")
    if deployed_address and not (deployed_address.startswith("0x") and len(deployed_address) == 42):
        return PocCandidate("UNSUPPORTED", invariant_id=invariant_id,
                            reason="deployed_address must be a 20-byte hex address")

    body: list[str] = []
    for step in steps:
        if not _IDENT.match(step.action):
            return PocCandidate("UNSUPPORTED", invariant_id=invariant_id,
                                reason=f"operation {step.action!r} is not an identifier")
        actor = _actor(step.actor)
        if actor is None:
            return PocCandidate("UNSUPPORTED", invariant_id=invariant_id,
                                reason=f"actor {step.actor!r} has no rendered address")
        args = ", ".join(_literal(v) for v in step.params.values())
        body.append(f"        vm.prank({actor});")
        body.append(f"        target.{step.action}({args});")
    calls = "\n".join(body)
    args = ", ".join(_literal(value) for value in (constructor_args or []))
    helper_lines = "\n".join(
        f"        {name} {name.lower()} = new {name}({', '.join(_literal(v) for v in values)});"
        for name, values in helper_deployments)
    if deployed_address:
        target_line = (f"        {contract} target = "
                       f"{contract}(address(uint160({int(deployed_address, 16)})));")
    elif proxy:
        target_line = (
            f"        {contract} implementation = new {contract}({args});\n"
            f"        BHProxy proxy = new BHProxy(address(implementation));\n"
            f"        {contract} target = {contract}(address(proxy));")
    else:
        target_line = f"        {contract} target = new {contract}({args});"

    clean_path = contract_path.replace("\\", "/").lstrip("/")
    if clean_path.startswith("src/"):
        clean_path = clean_path[4:]
    parts = [part for part in clean_path.split("/") if part not in ("", ".")]
    if ".." in parts:
        parts = [parts[-1]]
    import_path = "../src/" + "/".join(parts)
    helper_names = "".join(f", {name}" for name, _ in helper_deployments)
    proxy_contract = ""
    if proxy:
        proxy_contract = """
contract BHProxy {
    address public implementation;
    constructor(address impl) { implementation = impl; }
    fallback() external payable {
        address impl = implementation;
        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }
}
"""
    if conservation:
        assertion = (
            f"        uint256 observed = target.{mapping}(attacker) + "
            f"target.{mapping}(victim);\n"
            f"        require(observed != target.{total}(), "
            f"\"invariant held: no violation\");")
    elif authorization:
        field = authorization.group(1)
        assertion = (f"        require(target.{field}() != initialOwner, "
                     f"\"authorization held: owner unchanged\");")
    elif solvency:
        asset, liability = solvency.groups()
        assertion = (f"        require(target.{asset}() < target.{liability}(), "
                     f"\"solvency held: assets cover liabilities\");")
    else:
        field, bound = bounded.groups()
        assertion = (f"        require(target.{field}() > {bound}, "
                     f"\"bound held: field within bound\");")

    snapshot = (f"        address initialOwner = target.{authorization.group(1)}();\n"
                if authorization else "")
    solidity = f"""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Generated by BLACKHEART from a certified source-model witness.
// It calls the verified source through its ABI and asserts the invariant.
// Constructor arguments are supplied, never inferred: a compile failure is
// INCOMPLETE, not a reproduction.

import {{{contract}{helper_names}}} from "{import_path}";
{proxy_contract}

interface Vm {{
    function prank(address sender) external;
}}

contract BlackheartCertificateTest {{
    Vm private constant vm =
        Vm(address(bytes20(uint160(uint256(keccak256("hevm cheat code"))))));

    function test_certificate_witness() public {{
        address attacker = address(0xA11CE);
        address victim = address(0xB0B);
{helper_lines}
{target_line}
{snapshot}{calls}
{assertion}
    }}
}}
"""
    return PocCandidate("RENDERED", solidity=solidity, invariant_id=invariant_id,
                        constructor_args=tuple(constructor_args or ()),
                        deployed_address=deployed_address, proxy=proxy,
                        helpers=tuple(helper_deployments),
                        sources=dict(files), reason="rendered from the source model")


def _protocol_var(name: str) -> str:
    """A stable Solidity variable name for a contract in a protocol PoC."""
    clean = re.sub(r"[^A-Za-z0-9_]", "_", name)
    if not clean or clean[0].isdigit():
        clean = "c_" + clean
    return clean[0].lower() + clean[1:]


def _protocol_import_path(contract_path: str) -> str:
    clean_path = contract_path.replace("\\", "/").lstrip("/")
    if clean_path.startswith("src/"):
        clean_path = clean_path[4:]
    parts = [part for part in clean_path.split("/") if part not in ("", ".")]
    if ".." in parts:
        parts = [parts[-1]]
    return "../src/" + "/".join(parts)


def _split_protocol_invariant(invariant_id: str,
                              contracts: dict[str, Any]) -> tuple[str, str]:
    """Split ``Token:conservation:balance-totalSupply`` into its contract.

    A single-contract invariant has no contract prefix; a composed protocol
    prefixes it so two contracts can declare the same property.
    """
    prefix, sep, rest = invariant_id.partition(":")
    if sep and prefix in contracts and rest:
        return prefix, rest
    return "", invariant_id


def render_protocol_poc(
    files: dict[str, str],
    contracts: dict[str, Any],
    steps: list[AttackStep],
    invariant_id: str,
    *,
    constructor_args: Optional[dict[str, list[Any]]] = None,
) -> PocCandidate:
    """Render a multi-contract witness as one Foundry test.

    Each concrete contract is deployed once, then every step calls the contract
    named by ``target_contract`` or the ``Contract.function`` prefix. A witness
    that names an interface, an unknown contract, or an unrenderable invariant
    is ``UNSUPPORTED`` -- never silently reduced to a single-contract test.
    """
    if not contracts:
        return PocCandidate("UNSUPPORTED", invariant_id=invariant_id,
                            reason="the protocol has no contracts to deploy")
    if not steps:
        return PocCandidate("UNSUPPORTED", invariant_id=invariant_id,
                            reason="the certificate has no witness steps")
    target_name, assertion_id = _split_protocol_invariant(invariant_id, contracts)
    conservation = _CONSERVATION.match(assertion_id)
    authorization = _AUTHORIZATION.match(assertion_id)
    solvency = _SOLVENCY.match(assertion_id)
    bounded = _BOUNDED.match(assertion_id)
    if not (conservation or authorization or solvency or bounded):
        return PocCandidate(
            "UNSUPPORTED", invariant_id=invariant_id,
            reason="renderable protocol invariants are conservation:<mapping>-<total>, "
                   "authorization:<field>, solvency:<asset>-<liability> and "
                   "bounded:<field>-<bound>",
        )

    needed: set[str] = {target_name} if target_name else set()
    for step in steps:
        if step.target_contract:
            needed.add(step.target_contract)
        if "." in step.action:
            prefix = step.action.split(".", 1)[0]
            if prefix in contracts:
                needed.add(prefix)
    needed.discard("")

    concrete: dict[str, Any] = {}
    for name, surface in contracts.items():
        if needed and name not in needed:
            continue
        if not _IDENT.match(name):
            return PocCandidate("UNSUPPORTED", invariant_id=invariant_id,
                                reason=f"contract name {name!r} is not an identifier")
        if str(getattr(surface, "kind", "contract")) == "interface":
            continue
        if not getattr(surface, "path", ""):
            return PocCandidate("UNSUPPORTED", invariant_id=invariant_id,
                                reason=f"contract {name!r} has no source path")
        concrete[name] = surface
    if not concrete:
        return PocCandidate("UNSUPPORTED", invariant_id=invariant_id,
                            reason="the protocol has no concrete contract to deploy")
    if target_name and target_name not in concrete:
        return PocCandidate("UNSUPPORTED", invariant_id=invariant_id,
                            reason=f"invariant names non-concrete contract {target_name!r}")
    if not target_name:
        target_name = next(iter(concrete))

    args_by_contract = constructor_args or {}
    imports: dict[str, list[str]] = {}
    deploy_lines: list[str] = []
    for name, surface in concrete.items():
        imports.setdefault(_protocol_import_path(surface.path), []).append(name)
        args = args_by_contract.get(name, [])
        deploy_lines.append(
            f"        {name} {_protocol_var(name)} = new {name}"
            f"({', '.join(_literal(value) for value in args)});"
        )

    body: list[str] = []
    for step in steps:
        action = step.action
        contract = step.target_contract
        if "." in action:
            prefix, suffix = action.split(".", 1)
            if prefix in contracts:
                contract = contract or prefix
                action = suffix
        if not contract:
            contract = target_name if len(concrete) == 1 else ""
        if contract not in concrete:
            return PocCandidate(
                "UNSUPPORTED", invariant_id=invariant_id,
                reason=f"step {step.index} names contract {contract!r}, which is not "
                       "a deployed concrete contract",
            )
        if not _IDENT.match(action):
            return PocCandidate("UNSUPPORTED", invariant_id=invariant_id,
                                reason=f"operation {action!r} is not an identifier")
        actor = _actor(step.actor)
        if actor is None:
            return PocCandidate("UNSUPPORTED", invariant_id=invariant_id,
                                reason=f"actor {step.actor!r} has no rendered address")
        args = ", ".join(_literal(value) for value in step.params.values())
        body.append(f"        vm.prank({actor});")
        body.append(f"        {_protocol_var(contract)}.{action}({args});")

    var = _protocol_var(target_name)
    if conservation:
        mapping, total = conservation.groups()
        assertion = (
            f"        uint256 observed = {var}.{mapping}(attacker) + "
            f"{var}.{mapping}(victim);\n"
            f"        require(observed != {var}.{total}(), "
            f"\"invariant held: no violation\");")
        snapshot = ""
    elif authorization:
        field = authorization.group(1)
        snapshot = f"        address initialOwner = {var}.{field}();\n"
        assertion = (f"        require({var}.{field}() != initialOwner, "
                     f"\"authorization held: owner unchanged\");")
    elif solvency:
        asset, liability = solvency.groups()
        snapshot = ""
        assertion = (f"        require({var}.{asset}() < {var}.{liability}(), "
                     f"\"solvency held: assets cover liabilities\");")
    else:
        field, bound = bounded.groups()
        snapshot = ""
        assertion = (f"        require({var}.{field}() > {bound}, "
                     f"\"bound held: field within bound\");")

    import_lines = "\n".join(
        f"import {{{', '.join(sorted(names))}}} from \"{path}\";"
        for path, names in sorted(imports.items())
    )
    solidity = f"""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Generated by BLACKHEART from a certified multi-contract witness.
// Each contract is deployed once; calls are routed by the witness's contract.

{import_lines}

interface Vm {{
    function prank(address sender) external;
}}

contract BlackheartProtocolTest {{
    Vm private constant vm =
        Vm(address(bytes20(uint160(uint256(keccak256("hevm cheat code"))))));

    function test_protocol_witness() public {{
        address attacker = address(0xA11CE);
        address victim = address(0xB0B);
{chr(10).join(deploy_lines)}
{snapshot}{chr(10).join(body)}
{assertion}
    }}
}}
"""
    return PocCandidate("RENDERED", solidity=solidity,
                        test_name="test_protocol_witness",
                        invariant_id=invariant_id, sources=dict(files),
                        reason="rendered from the multi-contract source model")


def execute_source_poc(
    candidate: PocCandidate,
    *,
    compatibility: Optional[CompatibilityRecord],
    target_component: str,
    repository: str,
    commit: str = "",
    timeout: int = 600,
    runner: Any = None,
    fork_url: str = "",
    fork_block: Optional[int] = None,
) -> PocRunOutcome:
    """Run a rendered candidate under the gate; unsupported candidates do not run."""
    if not candidate.rendered:
        return PocRunOutcome("INCOMPLETE", candidate.reason or candidate.status,
                             candidate.test_name)
    return run_poc_text(
        candidate.solidity, test_name=candidate.test_name,
        compatibility=compatibility, target_component=target_component,
        repository=repository, commit=commit, timeout=timeout, runner=runner,
        sources=candidate.sources, fork_url=fork_url, fork_block=fork_block,
    )
