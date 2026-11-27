// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {MockERC20} from "./MockERC20.sol";

/// @title VulnerableVault — ERC4626-style share accounting with no virtual-share defence.
/// @notice Local reference target for BLACKHEART's adversarial harnesses. It
///         deliberately reproduces the share-inflation / first-depositor flaw so
///         the invariant engine has a genuine violation to find. It is NOT a
///         bounty target and holds no real funds.
contract VulnerableVault {
    MockERC20 public immutable asset;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;

    constructor(MockERC20 _asset) {
        asset = _asset;
    }

    /// @dev Trusts the live token balance, so a direct transfer inflates it.
    function totalAssets() public view returns (uint256) {
        return asset.balanceOf(address(this));
    }

    function convertToShares(uint256 assets) public view returns (uint256) {
        uint256 supply = totalSupply;
        if (supply == 0) return assets;
        return (assets * supply) / totalAssets();
    }

    function convertToAssets(uint256 shares) public view returns (uint256) {
        uint256 supply = totalSupply;
        if (supply == 0) return shares;
        return (shares * totalAssets()) / supply;
    }

    function deposit(uint256 assets) external returns (uint256 shares) {
        require(assets > 0, "zero");
        shares = convertToShares(assets);
        // No minimum-shares guard: a tiny deposit against a huge asset base mints 0 shares.
        asset.transferFrom(msg.sender, address(this), assets);
        totalSupply += shares;
        balanceOf[msg.sender] += shares;
    }

    function withdraw(uint256 shares) external returns (uint256 assets) {
        require(shares > 0, "zero");
        assets = convertToAssets(shares);
        balanceOf[msg.sender] -= shares;
        totalSupply -= shares;
        asset.transfer(msg.sender, assets);
    }

    function previewRedeem(address who) external view returns (uint256) {
        return convertToAssets(balanceOf[who]);
    }
}
