// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {AdversarialERC20} from "../src/token/AdversarialERC20.sol";
import {VulnerableVault} from "../src/vault/VulnerableVault.sol";
import {ReentrancyAttacker} from "../src/attack/ReentrancyAttacker.sol";

/// @title MedusaVulnerableVault
/// @notice Medusa property harness for the vulnerable vault. Medusa treats any
///         `property_*` function that returns false as a violation; it must find
///         a counterexample for `property_noValueExtraction` on the vulnerable
///         vault. Deliberately vulnerable.
contract MedusaVulnerableVault {
    AdversarialERC20 public token;
    VulnerableVault public vault;
    uint256 public ghostProfit;

    constructor() {
        token = new AdversarialERC20(0);
        vault = new VulnerableVault(token);
    }

    function deposit(uint256 amount) public {
        amount = (amount % 1_000e18) + 1e6;
        token.mint(address(this), amount);
        token.approve(address(vault), amount);
        vault.deposit(amount);
    }

    function reentrancyAttack(uint256 amount) public {
        amount = (amount % 100e18) + 1e6;
        ReentrancyAttacker atk = new ReentrancyAttacker();
        token.mint(address(atk), amount);
        atk.attack(address(vault), token, amount);
        uint256 held = token.balanceOf(address(atk));
        if (held > amount) ghostProfit += held - amount;
    }

    /// @notice Must always hold. Medusa falsifies it on the vulnerable vault.
    function property_noValueExtraction() public view returns (bool) {
        return ghostProfit == 0;
    }
}
