// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {Test} from "forge-std/Test.sol";
import {DamnValuableToken} from "../src/DamnValuableToken.sol";
import {UnstoppableVault} from "../src/UnstoppableVault.sol";

/// @title UnstoppableHandler — a stateful fuzzing handler.
/// @notice Foundry's invariant fuzzer drives this handler. The handler exposes the
///         vault's real operations plus a `donate` action, and maintains a ghost
///         variable of the tokens it has moved in. Crucially it does NOT touch
///         state the invariant checks; that is what lets the fuzzer discover the
///         donation-induced inconsistency on its own.
///
///         Deterministic: the harness foundry.toml pins the fuzz/invariant seed.
contract UnstoppableHandler is Test {
    DamnValuableToken public token;
    UnstoppableVault public vault;

    address internal immutable actor;

    constructor(DamnValuableToken _token, UnstoppableVault _vault, address _actor) {
        token = _token;
        vault = _vault;
        actor = _actor;
    }

    function deposit(uint256 amount) external {
        amount = bound(amount, 1, 1_000e18);
        vm.startPrank(actor);
        token.approve(address(vault), amount);
        try vault.deposit(amount, actor) {} catch {}
        vm.stopPrank();
    }

    /// @notice The hostile action: donate tokens without minting shares.
    function donate(uint256 amount) external {
        amount = bound(amount, 1, 1_000e18);
        vm.prank(actor);
        token.transfer(address(vault), amount);
    }
}

/// @title UnstoppableInvariants — the security property as an executable invariant.
/// @notice The property: the vault's share accounting and its asset accounting must
///         stay consistent, i.e. `convertToShares(totalSupply) == totalAssets()`.
///         The fuzzer must be able to *break* it, which is exactly the finding.
contract UnstoppableInvariants is Test {
    DamnValuableToken internal token;
    UnstoppableVault internal vault;
    UnstoppableHandler internal handler;

    address internal constant DEPLOYER = address(0xD0);
    address internal constant FUZZ_ACTOR = address(0xF0F0);

    function setUp() public {
        vm.startPrank(DEPLOYER);
        token = new DamnValuableToken();
        vault = new UnstoppableVault(token, DEPLOYER, DEPLOYER);
        token.mint(DEPLOYER, 1_000_000e18);
        token.approve(address(vault), 1_000_000e18);
        vault.deposit(1_000_000e18, DEPLOYER);
        token.mint(FUZZ_ACTOR, 1_000_000e18);
        vm.stopPrank();

        handler = new UnstoppableHandler(token, vault, FUZZ_ACTOR);
        targetContract(address(handler));
    }

    /// @notice Invariant: internal accounting must equal live assets.
    /// @dev This is expected to FAIL on the vulnerable vault (the fuzzer finds the
    ///      donation). It is the machine-checkable form of the finding.
    function invariant_accounting_consistent() public view {
        assertEq(
            vault.convertToShares(vault.totalSupply()),
            vault.totalAssets(),
            "INVARIANT VIOLATED: accounting != assets"
        );
    }
}
