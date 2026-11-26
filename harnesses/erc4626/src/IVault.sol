// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

/// @notice Minimal shared interface for the reference vaults.
interface IVault {
    function deposit(uint256 assets) external returns (uint256 shares);
    function withdraw(uint256 shares) external returns (uint256 assets);
    function donate(uint256 assets) external;
    function balanceOf(address who) external view returns (uint256);
    function totalSupply() external view returns (uint256);
    function totalAssets() external view returns (uint256);
    function previewRedeem(address who) external view returns (uint256);
}
