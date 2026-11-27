// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {AdversarialERC20} from "../token/AdversarialERC20.sol";

/// @title IVault
/// @notice Minimal deposit/withdraw surface used by the adversarial harnesses.
interface IVault {
    function deposit(uint256 amount) external;
    function withdraw(uint256 amount) external;
    function balanceOf(address who) external view returns (uint256);
    function totalAssets() external view returns (uint256);
}

/// @title VulnerableVault
/// @notice Classic reentrancy: state is written *after* the external transfer,
///         and the balance check precedes it. A malicious token (or a callback
///         target) can re-enter `withdraw` before the balance is decremented.
/// @dev Deliberately vulnerable. Used to prove the reentrancy invariant breaks.
contract VulnerableVault is IVault {
    AdversarialERC20 public immutable asset;
    mapping(address => uint256) public balanceOf;
    uint256 public totalAssets;

    constructor(AdversarialERC20 asset_) {
        asset = asset_;
    }

    function deposit(uint256 amount) external {
        asset.transferFrom(msg.sender, address(this), amount);
        balanceOf[msg.sender] += amount;
        totalAssets += amount;
    }

    function withdraw(uint256 amount) external {
        require(balanceOf[msg.sender] >= amount, "insufficient");
        // BUG: external call before the state update, and the balance is read
        // again on re-entry while it is still inflated.
        asset.transfer(msg.sender, amount);
        // The unchecked block mirrors the gas-optimisation many real vaults use;
        // without it Solidity 0.8 would revert on the second decrement, which is
        // what hides the underlying CEI violation in review.
        unchecked {
            balanceOf[msg.sender] -= amount;
        }
        totalAssets -= amount;
    }
}
