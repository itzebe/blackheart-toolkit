// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {AdversarialERC20} from "../token/AdversarialERC20.sol";
import {IVault} from "./VulnerableVault.sol";

/// @title SafeVault
/// @notice The same vault with the checks-effects-interactions order enforced and
///         a reentrancy guard. Identical surface; the only change is the defence.
/// @dev The negative control: the exact attack that drains VulnerableVault must
///      fail here, otherwise the PoC is not specific to the vulnerability.
contract SafeVault is IVault {
    AdversarialERC20 public immutable asset;
    mapping(address => uint256) public balanceOf;
    uint256 public totalAssets;
    uint256 private _locked = 1;

    modifier nonReentrant() {
        require(_locked == 1, "reentrant");
        _locked = 2;
        _;
        _locked = 1;
    }

    constructor(AdversarialERC20 asset_) {
        asset = asset_;
    }

    function deposit(uint256 amount) external {
        asset.transferFrom(msg.sender, address(this), amount);
        balanceOf[msg.sender] += amount;
        totalAssets += amount;
    }

    function withdraw(uint256 amount) external nonReentrant {
        require(balanceOf[msg.sender] >= amount, "insufficient");
        // EFFECTS first, then the external interaction.
        balanceOf[msg.sender] -= amount;
        totalAssets -= amount;
        asset.transfer(msg.sender, amount);
    }
}
