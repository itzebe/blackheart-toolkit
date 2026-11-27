// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {MockERC20} from "./MockERC20.sol";

/// @title SafeVault — same accounting with a virtual-shares/offset defence.
/// @notice Reference target that must NOT be breakable by the same harness. Used
///         to prove the invariants are meaningful (they fail on VulnerableVault
///         and hold on SafeVault).
contract SafeVault {
    MockERC20 public immutable asset;
    uint256 internal constant VIRTUAL_SHARES = 1e18;
    uint256 internal constant VIRTUAL_ASSETS = 1;

    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;

    constructor(MockERC20 _asset) {
        asset = _asset;
    }

    function totalAssets() public view returns (uint256) {
        return asset.balanceOf(address(this));
    }

    function convertToShares(uint256 assets) public view returns (uint256) {
        return (assets * (totalSupply + VIRTUAL_SHARES)) / (totalAssets() + VIRTUAL_ASSETS);
    }

    function convertToAssets(uint256 shares) public view returns (uint256) {
        return (shares * (totalAssets() + VIRTUAL_ASSETS)) / (totalSupply + VIRTUAL_SHARES);
    }

    function deposit(uint256 assets) external returns (uint256 shares) {
        require(assets > 0, "zero");
        shares = convertToShares(assets);
        require(shares > 0, "no shares");
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
