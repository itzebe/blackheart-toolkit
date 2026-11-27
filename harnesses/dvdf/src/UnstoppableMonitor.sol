// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {UnstoppableVault} from "./UnstoppableVault.sol";
import {DamnValuableToken} from "./DamnValuableToken.sol";

/// @title UnstoppableMonitor — an on-chain liveness monitor for the vault's
///        flash-loan feature, modelled on Damn Vulnerable DeFi's "Unstoppable".
/// @notice It takes a flash loan; if the loan *reverts*, it treats that as a
///         liveness fault, pauses the vault, and hands ownership back to a human.
///         This is the second half of the vulnerability: it turns a temporary
///         accounting inconsistency into a permanent shutdown.
///         Local training fixture only.
contract UnstoppableMonitor {
    UnstoppableVault public immutable vault;
    address public immutable owner;

    error UnexpectedFlashLoan();
    event FlashLoanStatus(bool success);

    modifier onlyOwner() {
        if (msg.sender != owner) revert UnexpectedFlashLoan();
        _;
    }

    constructor(address _vault) {
        vault = UnstoppableVault(_vault);
        owner = msg.sender;
    }

    function onFlashLoan(address initiator, address token, uint256 amount, uint256 fee, bytes calldata)
        external
        returns (bytes32)
    {
        if (
            initiator != address(this) || msg.sender != address(vault)
                || token != address(vault.asset()) || fee != 0
        ) {
            revert UnexpectedFlashLoan();
        }
        DamnValuableToken(token).approve(address(vault), amount);
        return keccak256("IERC3156FlashBorrower.onFlashLoan");
    }

    function checkFlashLoan(uint256 amount) external onlyOwner {
        require(amount > 0, "zero");
        address asset = address(vault.asset());
        try vault.flashLoan(address(this), asset, amount, bytes("")) {
            emit FlashLoanStatus(true);
        } catch {
            emit FlashLoanStatus(false);
            // Treat a failed flash loan as a fault: shut the vault down.
            vault.setPause(true);
            vault.transferOwnership(owner);
        }
    }
}
