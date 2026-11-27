"""Generate a Foundry invariant test from a verified contract surface.

The hand-written harnesses under ``harnesses/`` prove that an invariant test can
discriminate a vulnerable contract from its guarded twin. This module removes
the hand-transcription step: it reads the recovered surface, deploys the
contract and its asset, and emits a real Foundry ``invariant_`` test with a
handler that fuzzes the public operations.

It has three shapes: the ERC4626 share-dilution invariant
(``convertToShares(1) > 0`` while supply is non-zero), an owner-unchanged
invariant when the surface exposes an explicit owner getter, and a
caller-supplied Solidity property. A surface that supports none of them is
refused, never guessed.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from ..symbolic.poc_runner import PocRunOutcome, run_poc_text
from ..toolchain.enforce import CompatibilityRecord
from .solidity import ContractSurface, scan_source


@dataclass(frozen=True)
class GeneratedInvariant:
    solidity: str
    contract: str
    asset: str
    test_name: str
    invariant_name: str
    sources: dict[str, str]
    template: str = ""
    skipped: tuple[str, ...] = ()

    def to_dict(self) -> dict:
        return {
            "contract": self.contract,
            "asset": self.asset,
            "test_name": self.test_name,
            "invariant_name": self.invariant_name,
            "template": self.template,
            "skipped": list(self.skipped),
            "solidity_len": len(self.solidity),
        }


def _surface(files: dict[str, str], name: str) -> ContractSurface:
    for path, text in files.items():
        for contract in scan_source(text, path):
            if contract.name == name:
                return contract
    raise ValueError(f"contract {name!r} not found in the source tree")


def _function(contract: ContractSurface, name: str):
    return next((fn for fn in contract.functions if fn.name == name), None)


def _import_path(files: dict[str, str], name: str) -> str:
    for path, text in files.items():
        for contract in scan_source(text, path):
            if contract.name == name:
                clean = str(path).replace("\\", "/").lstrip("/")
                if clean.startswith("src/"):
                    clean = clean[4:]
                parts = [part for part in clean.split("/") if part not in ("", ".")]
                if ".." in parts:
                    parts = [parts[-1]]
                return "../src/" + "/".join(parts)
    raise ValueError(f"contract {name!r} has no source path")


def infer_asset(files: dict[str, str], contract: str) -> str:
    """Infer the constructor's asset contract, or refuse to guess."""
    vault = _surface(files, contract)
    constructor = _function(vault, "constructor")
    if constructor is not None:
        for param in constructor.params:
            words = param.replace("memory", " ").split()
            for word in words:
                if word in files or any(c.name == word for _p, text in files.items()
                                        for c in scan_source(text, _p)):
                    return word
    for path, text in files.items():
        for candidate in scan_source(text, path):
            if _function(candidate, "mint") is not None and candidate.name != contract:
                return candidate.name
    raise ValueError(f"cannot infer {contract}'s asset; pass --asset")


# --------------------------------------------------------------------------- #
# General surface synthesis
# --------------------------------------------------------------------------- #

_OWNER_NAMES = ("owner", "admin", "governance", "authority")


def applicable_invariants(files: dict[str, str], contract: str) -> tuple[str, ...]:
    """The invariant templates the recovered surface can actually support.

    This is a *surface* judgement, not a vulnerability claim: an ERC4626 shape
    supports the share-dilution invariant, and an explicit owner getter supports
    the owner-unchanged invariant. A surface that supports neither is refused.
    """
    surface = _surface(files, contract)
    out: list[str] = []
    if _function(surface, "convertToShares") is not None and _function(surface, "deposit") is not None:
        out.append("erc4626:nonzero-shares")
    if any(_function(surface, name) is not None for name in _OWNER_NAMES):
        out.append("authorization:owner-unchanged")
    return tuple(out)


def _param_parts(param: str) -> tuple[str, str]:
    """Return ``(solidity_type, name)`` from a scanned parameter declaration."""
    words = [word for word in param.replace("memory", " ").replace("calldata", " ")
             .replace("storage", " ").split() if word]
    if not words:
        return "uint256", "p"
    base = words[0].split("[")[0]
    name = words[-1] if len(words) > 1 else "p"
    return base, name


def _fuzz_argument(param: str, index: int) -> Optional[tuple[str, str]]:
    """A fuzz parameter and the argument expression for one Solidity type.

    Unsupported types (arrays, structs, strings, bytes) are skipped rather than
    guessed. A skipped function is reported in ``GeneratedInvariant.skipped``.
    """
    base, _name = _param_parts(param)
    name = f"p{index}"
    if base.startswith("uint") or base.startswith("int"):
        return f"uint256 {name}", f"{name} % 1e24"
    if base == "address":
        return f"address {name}", f"address(uint160({name}))"
    if base == "bool":
        return f"bool {name}", name
    if base == "bytes32":
        return f"bytes32 {name}", f"bytes32({name})"
    return None


def _handler_functions(surface: ContractSurface) -> tuple[str, tuple[str, ...]]:
    """Render one fuzz function per externally callable state-changing function."""
    chunks: list[str] = []
    skipped: list[str] = []
    for index, fn in enumerate(surface.functions):
        if not fn.externally_callable or not fn.state_changing:
            continue
        if fn.name in ("constructor", "receive", "fallback"):
            continue
        if fn.mutability == "payable":
            skipped.append(f"{fn.name}: payable value transfer is not modelled")
            continue
        params: list[str] = []
        args: list[str] = []
        supported = True
        for i, param in enumerate(fn.params):
            rendered = _fuzz_argument(param, i)
            if rendered is None:
                skipped.append(f"{fn.name}: unsupported parameter {param!r}")
                supported = False
                break
            params.append(rendered[0])
            args.append(rendered[1])
        if not supported:
            continue
        call = f"vault.{fn.name}({', '.join(args)})"
        chunks.append(
            f"    function call_{fn.name}_{index}({', '.join(params)}) public {{\n"
            f"        vm.prank(ATTACKER);\n"
            f"        try {call} {{}} catch {{}}\n"
            f"    }}"
        )
    return "\n\n".join(chunks), tuple(skipped)


def _constructor_expression(files: dict[str, str], contract: str,
                            asset: str) -> tuple[str, bool]:
    """The deployment expression and whether the asset variable is required."""
    surface = _surface(files, contract)
    constructor = _function(surface, "constructor")
    if constructor is None or not constructor.params:
        return f"new {contract}()", False
    if len(constructor.params) == 1 and asset:
        base, _ = _param_parts(constructor.params[0])
        if base == "address" or base.startswith("contract"):
            return f"new {contract}(asset)", True
    raise ValueError(
        f"{contract}'s constructor parameters cannot be inferred from the surface; "
        "supply a constructor with no arguments or a single asset argument")


def _render_handler_test(files: dict[str, str], contract: str, asset: str,
                         invariant_body: str, *, test_name: str,
                         invariant_name: str, template: str) -> GeneratedInvariant:
    surface = _surface(files, contract)
    handler, skipped = _handler_functions(surface)
    if not handler:
        raise ValueError(f"{contract} has no externally callable state-changing function")
    deployment, needs_asset = _constructor_expression(files, contract, asset)
    contract_import = _import_path(files, contract)
    token_import = _import_path(files, asset) if needs_asset else ""
    token_decl = f"    {asset} private asset;\n" if needs_asset else ""
    token_setup = f"        asset = new {asset}();\n" if needs_asset else ""
    token_import_line = f'import {{{asset}}} from "{token_import}";\n' if needs_asset else ""
    solidity = f"""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Generated by BLACKHEART from the recovered source surface. The handler fuzzes
// every externally callable state-changing function it can model; a failing
// invariant is a reproduced model, never a priced finding.

import {{{contract}}} from "{contract_import}";
{token_import_line}
interface Vm {{
    function prank(address sender) external;
}}

contract {contract}Handler {{
    Vm private constant vm =
        Vm(address(bytes20(uint160(uint256(keccak256("hevm cheat code"))))));
    address public constant ATTACKER = address(0xA11CE);
    {contract} public vault;

    constructor({contract} _vault) {{
        vault = _vault;
    }}

{handler}
}}

contract {contract}GeneratedInvariant {{
    Vm private constant vm =
        Vm(address(bytes20(uint160(uint256(keccak256("hevm cheat code"))))));
    {contract} private vault;
{token_decl}    {contract}Handler private handler;

    function setUp() public {{
{token_setup}        vault = {deployment};
        handler = new {contract}Handler(vault);
    }}

    function targetContracts() public view returns (address[] memory contracts) {{
        contracts = new address[](1);
        contracts[0] = address(handler);
    }}

    function {invariant_name}() public view {{
        {invariant_body}
    }}
}}
"""
    return GeneratedInvariant(
        solidity=solidity, contract=contract, asset=asset if needs_asset else "",
        test_name=test_name, invariant_name=invariant_name, sources=dict(files),
        template=template, skipped=skipped)


def render_owner_invariant(files: dict[str, str], contract: str, *,
                           test_name: str = "invariant_owner_unchanged",
                           invariant_name: str = "invariant_owner_unchanged") -> GeneratedInvariant:
    """Generate an owner-unchanged invariant from an explicit owner getter.

    The handler calls every external state-changing function as the attacker.
    The invariant fails when an unprivileged call changes the owner, which is a
    real authorization regression rather than a name-based guess. A contract
    without an explicit ``owner()``/``admin()`` getter is refused.
    """
    surface = _surface(files, contract)
    owner_fn = next((name for name in _OWNER_NAMES if _function(surface, name) is not None), "")
    if not owner_fn:
        raise ValueError(
            f"{contract} has no explicit owner/admin getter; the owner invariant "
            "cannot be generated without one")
    body = (f'if (vault.{owner_fn}() != originalOwner) {{\n'
            f'            revert("owner changed by an unprivileged call");\n'
            f'        }}')
    # The generated test needs the original owner, so render it with a small
    # wrapper rather than mutating the generic template.
    generated = _render_handler_test(
        files, contract, "", body, test_name=test_name,
        invariant_name=invariant_name, template="authorization:owner-unchanged")
    generated = GeneratedInvariant(
        solidity=generated.solidity.replace(
            f"    {contract}Handler private handler;",
            f"    address private originalOwner;\n    {contract}Handler private handler;",
        ).replace(
            "        handler = new "
            f"{contract}Handler(vault);",
            f"        originalOwner = vault.{owner_fn}();\n"
            f"        handler = new {contract}Handler(vault);",
        ),
        contract=contract, asset="", test_name=test_name,
        invariant_name=invariant_name, sources=dict(files),
        template="authorization:owner-unchanged", skipped=generated.skipped)
    return generated


def render_generic_invariant(files: dict[str, str], contract: str,
                             invariant_body: str, *, asset: str = "",
                             test_name: str = "invariant_generated",
                             invariant_name: str = "invariant_generated") -> GeneratedInvariant:
    """Generate a handler for every modelled function plus a caller-supplied body.

    The body is Solidity statements (not an expression): the caller states the
    property, and the generator supplies the fuzzed calls. An expression without
    a semicolon is wrapped in ``require`` so a simple condition is usable.
    """
    body = invariant_body.strip()
    if not body:
        raise ValueError("an invariant body is required")
    if not body.endswith(";") and not body.endswith("}"):
        body = f'require({body}, "generated invariant failed");'
    return _render_handler_test(files, contract, asset, body,
                                test_name=test_name, invariant_name=invariant_name,
                                template="generic")


def render_surface_invariant(files: dict[str, str], contract: str, *,
                             asset: str = "", template: str = "",
                             invariant_body: str = "",
                             test_name: str = "invariant_generated",
                             invariant_name: str = "invariant_generated") -> GeneratedInvariant:
    """Choose the strongest invariant the surface supports, or refuse.

    ``template`` is one of the names returned by :func:`applicable_invariants`.
    An empty template is accepted only when exactly one template applies; an
    ambiguous surface must be disambiguated by the operator, never guessed.
    """
    if invariant_body:
        return render_generic_invariant(
            files, contract, invariant_body, asset=asset, test_name=test_name,
            invariant_name=invariant_name)
    selected = template.strip()
    if selected in ("", "auto"):
        choices = applicable_invariants(files, contract)
        if len(choices) == 1:
            selected = choices[0]
        elif not choices:
            raise ValueError(
                f"no built-in invariant applies to {contract}; pass "
                "--invariant-body with a Solidity property")
        else:
            raise ValueError(
                f"{contract} supports several invariants ({', '.join(choices)}); "
                "choose one with --invariant-template")
    if selected == "erc4626:nonzero-shares":
        asset = asset or infer_asset(files, contract)
        return render_erc4626_invariant(
            files, contract, asset, test_name=test_name,
            invariant_name=invariant_name)
    if selected == "authorization:owner-unchanged":
        return render_owner_invariant(
            files, contract, test_name=test_name, invariant_name=invariant_name)
    raise ValueError(f"unknown invariant template {selected!r}")


def render_erc4626_invariant(files: dict[str, str], contract: str,
                             asset: str, *,
                             test_name: str = "invariant_nonzero_shares",
                             invariant_name: str = "invariant_nonzero_shares") -> GeneratedInvariant:
    """Render a complete Foundry invariant test for an ERC4626-like pair."""
    vault = _surface(files, contract)
    token = _surface(files, asset)
    if _function(vault, "convertToShares") is None:
        raise ValueError(f"{contract} has no convertToShares function")
    if _function(token, "balanceOf") is None:
        # balanceOf is a public mapping getter, not always a function; accept a
        # state variable of that name instead.
        if not any(name == "balanceOf" for name, _typ in token.state_types):
            raise ValueError(f"{asset} is not an ERC20-like token surface")
    constructor = _function(vault, "constructor")
    if constructor is not None:
        if not any(asset in param for param in constructor.params):
            raise ValueError(
                f"{contract}'s constructor does not take {asset}; deployment is not inferred")
    if _function(token, "mint") is None:
        raise ValueError(f"{asset} has no mint function; the handler cannot fund the attacker")

    vault_import = _import_path(files, contract)
    token_import = _import_path(files, asset)
    solidity = f"""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Generated by BLACKHEART from the recovered source surface.
// It is a real Foundry invariant test: the handler fuzzes mint/approve/deposit/
// donate/withdraw, and the invariant asserts that a positive deposit cannot
// mint zero shares. A failing invariant is a reproduced model, not a priced
// finding.

import {{{contract}}} from "{vault_import}";
import {{{asset}}} from "{token_import}";

interface Vm {{
    function prank(address sender) external;
}}

contract {contract}Handler {{
    Vm private constant vm =
        Vm(address(bytes20(uint160(uint256(keccak256("hevm cheat code"))))));
    address public constant ATTACKER = address(0xA11CE);
    {contract} public vault;
    {asset} public asset;
    uint256 public lastDepositAssets;
    uint256 public lastDepositShares;

    constructor({contract} _vault, {asset} _asset) {{
        vault = _vault;
        asset = _asset;
    }}

    function _bound(uint256 value) internal pure returns (uint256) {{
        return value % 1e24;
    }}

    function mintAsset(uint256 amount) public {{
        vm.prank(ATTACKER);
        asset.mint(ATTACKER, _bound(amount));
    }}

    function approveAsset(uint256 amount) public {{
        vm.prank(ATTACKER);
        asset.approve(address(vault), _bound(amount));
    }}

    function deposit(uint256 amount) public {{
        amount = _bound(amount);
        vm.prank(ATTACKER);
        try vault.deposit(amount) returns (uint256 shares) {{
            lastDepositAssets = amount;
            lastDepositShares = shares;
        }} catch {{}}
    }}

    function donate(uint256 amount) public {{
        vm.prank(ATTACKER);
        asset.transfer(address(vault), _bound(amount));
    }}

    function withdraw(uint256 shares) public {{
        vm.prank(ATTACKER);
        vault.withdraw(_bound(shares));
    }}
}}

contract {contract}GeneratedInvariant {{
    Vm private constant vm =
        Vm(address(bytes20(uint160(uint256(keccak256("hevm cheat code"))))));
    {contract} private vault;
    {asset} private asset;
    {contract}Handler private handler;

    function setUp() public {{
        asset = new {asset}();
        vault = new {contract}(asset);
        handler = new {contract}Handler(vault, asset);
    }}

    function targetContracts() public view returns (address[] memory contracts) {{
        contracts = new address[](1);
        contracts[0] = address(handler);
    }}

    function {invariant_name}() public view {{
        if (handler.lastDepositAssets() == 0) return;
        require(handler.lastDepositShares() > 0,
                "a successful positive deposit minted zero shares");
    }}
}}
"""
    return GeneratedInvariant(solidity=solidity, contract=contract, asset=asset,
                              test_name=test_name, invariant_name=invariant_name,
                              sources=dict(files))


def run_generated_invariant(
    generated: GeneratedInvariant,
    *,
    compatibility: Optional[CompatibilityRecord],
    target_component: str,
    repository: str,
    commit: str = "",
    timeout: int = 600,
    runner=None,
) -> PocRunOutcome:
    """Run the generated invariant test and map a failing invariant to PASS.

    ``run_poc_text`` says PASS when an assertion holds. For an invariant test the
    useful result is the opposite: a *failing* invariant is the reproduced bug.
    The mapping is explicit and never upgrades an unrun or unparsed result.
    """
    outcome = run_poc_text(
        generated.solidity, test_name=generated.test_name,
        compatibility=compatibility, target_component=target_component,
        repository=repository, commit=commit, timeout=timeout, runner=runner,
        sources=generated.sources,
    )
    if outcome.status == "FAIL":
        return PocRunOutcome(
            "PASS", "the invariant failed: the generated test reproduced the bug",
            generated.test_name, outcome.output, outcome.project_dir)
    if outcome.status == "PASS":
        return PocRunOutcome(
            "NO_FINDINGS", "the invariant held; a clean fuzz run is not a proof",
            generated.test_name, outcome.output, outcome.project_dir)
    return outcome
