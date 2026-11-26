// SPDX-License-Identifier: MIT
pragma solidity =0.8.25;

import {SafeTransferLib, ERC4626, ERC20} from "solmate/tokens/ERC4626.sol";
import {Owned} from "solmate/auth/Owned.sol";

/// @title StoredAssetsVault -- differential control for DVDF "Unstoppable"
/// @notice The minimal fix for the Unstoppable flaw: track assets in storage
///         instead of trusting the live token balance. A donation therefore
///         cannot desynchronise `totalAssets()` from `convertToShares(totalSupply)`.
///         Interface-compatible with the challenge (deposit, totalAssets, totalSupply).
contract StoredAssetsVault is Owned, ERC4626 {
    uint256 private _storedAssets;

    constructor(ERC20 _token, address _owner, address _feeRecipient)
        ERC4626(_token, "Too Damn Valuable Token", "tDVT")
        Owned(_owner)
    {
        _feeRecipient; // fee recipient is irrelevant to the invariant under test
    }

    function totalAssets() public view override returns (uint256) {
        return _storedAssets;
    }

    function afterDeposit(uint256 assets, uint256) internal override {
        _storedAssets += assets;
    }

    function beforeWithdraw(uint256 assets, uint256) internal override {
        _storedAssets -= assets;
    }
}
