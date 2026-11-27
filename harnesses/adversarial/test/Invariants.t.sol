// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {Test} from "forge-std/Test.sol";
import {AdversarialERC20} from "../src/token/AdversarialERC20.sol";
import {VulnerableVault} from "../src/vault/VulnerableVault.sol";
import {SafeVault} from "../src/vault/SafeVault.sol";
import {VaultHandler} from "./VaultHandler.sol";

/// @title VulnerableVaultInvariants
/// @notice Stateful invariant search against the vulnerable vault. The invariant
///         below MUST break; the counterexample is the finding, and Foundry
///         minimises it automatically. Deterministic reproduction comes from the
///         seed the runner passes with `--fuzz-seed`.
contract VulnerableVaultInvariants is Test {
    AdversarialERC20 token;
    VulnerableVault vault;
    VaultHandler handler;

    function setUp() public {
        token = new AdversarialERC20(0);
        vault = new VulnerableVault(token);
        handler = new VaultHandler(token, vault);
        targetContract(address(handler));
    }

    /// @notice Security property: no sequence of actions may let any actor extract
    ///         value from the vault beyond what it deposited. A reentrant
    ///         withdrawal breaks this.
    function invariant_no_profit_from_reentrancy() public view {
        assertEq(handler.ghostProfit(), 0, "attacker extracted value beyond its deposit");
    }
}

/// @title SafeVaultInvariants
/// @notice The identical actor model, invariant, and fuzz budget against the
///         defended vault. The invariant must HOLD here. That is the non-vacuity
///         proof: the vulnerable break is caused by the missing reentrancy
///         defence, not by the harness itself.
contract SafeVaultInvariants is Test {
    AdversarialERC20 token;
    SafeVault vault;
    VaultHandler handler;

    function setUp() public {
        token = new AdversarialERC20(0);
        vault = new SafeVault(token);
        // VaultHandler is typed against the shared vault surface; SafeVault
        // exposes the same deposit/withdraw/balanceOf functions.
        handler = new VaultHandler(token, VulnerableVault(address(vault)));
        targetContract(address(handler));
    }

    function invariant_no_profit_from_reentrancy() public view {
        assertEq(handler.ghostProfit(), 0, "attacker extracted value beyond its deposit");
    }
}
