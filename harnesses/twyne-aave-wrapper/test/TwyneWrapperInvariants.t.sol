// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {TwyneWrapperForkBase} from "./TwyneWrapperForkBase.sol";
import {WrapperHandler} from "./WrapperHandler.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IAToken} from "aave-v3/interfaces/IAToken.sol";
import {console2} from "forge-std/console2.sol";

/// @notice Stateful invariant search over the *real* Twyne AaveV3 aToken wrapper
/// on a local mainnet fork. The fuzzer drives arbitrary sequences of
/// deposit / withdraw / donate / cvRebalance and checks properties that must hold
/// for every sequence. Any counterexample Foundry shrinks is a candidate; the
/// independent verifier decides whether it is a vulnerability.
contract TwyneWrapperInvariantsTest is TwyneWrapperForkBase {
    WrapperHandler internal handler;

    function setUp() public override {
        super.setUp();
        handler = new WrapperHandler(wrapper, weth, IERC20(aWETH), AAVE_V3_POOL);
        factory.setIsCollateralVault(address(handler), false);
        // Register the handler's CV so its rebalance path is exercised.
        factory.setIsCollateralVault(handler.cv(), true);
        targetContract(address(handler));
    }

    /// @notice The wrapper must hold enough backed aTokens (scaled) to redeem
    /// every share that is NOT held by a collateral vault. A CV may pull the
    /// aTokens matching its own shares, but nothing beyond that.
    function invariant_remaining_holders_are_backed() public view {
        uint256 supply = wrapper.totalSupply();
        uint256 cvShares = wrapper.balanceOf(handler.cv());
        uint256 required = supply >= cvShares ? supply - cvShares : 0;
        uint256 held = IAToken(aWETH).scaledBalanceOf(address(wrapper));
        assertGe(held, required, "wrapper aTokens do not cover non-CV shares");
    }

    /// @notice The victim's realised value (assets withdrawn + still-redeemable
    /// shares) must never exceed what the victim deposited. No sequence of
    /// other-actor operations may create value for the victim out of nothing.
    function invariant_victim_never_profits() public view {
        uint256 redeemable = wrapper.previewRedeem(wrapper.balanceOf(handler.victim()));
        uint256 realised = handler.victimWithdrawn() + redeemable;
        assertLe(realised, handler.victimDeposited() + 1, "victim realised more than deposited");
    }

    /// @notice totalAssets() is derived from the supply index, so it must stay
    /// consistent with a fresh conversion of the whole supply.
    function invariant_total_assets_consistent() public view {
        uint256 supply = wrapper.totalSupply();
        uint256 derived = supply == 0 ? 0 : wrapper.convertToAssets(supply);
        // totalAssets() == floor(supply * rate / RAY); allow 1 wei of floor drift.
        assertApproxEqAbs(wrapper.totalAssets(), derived, 1, "totalAssets inconsistent with supply");
    }

    /// @notice Every share must be backed in *scaled* aToken terms: the shares
    /// outstanding cannot exceed the scaled aTokens held by the wrapper plus
    /// those held by its registered CV (which the wrapper can re-pull).
    function invariant_shares_fully_backed() public view {
        uint256 supply = wrapper.totalSupply();
        if (supply == 0) return;
        uint256 scaledHeld =
            IAToken(aWETH).scaledBalanceOf(address(wrapper)) + IAToken(aWETH).scaledBalanceOf(handler.cv());
        // +1 wei tolerates per-op floor rounding of the scaled balance.
        assertLe(supply, scaledHeld + 1, "supply exceeds scaled aTokens held by wrapper+CV");
    }

    /// @notice In *asset* terms, the assets the whole supply claims must be
    /// covered by the real aToken balances held by the wrapper and its CV.
    function invariant_reported_within_holdings() public view {
        uint256 reported = wrapper.totalAssets();
        uint256 heldAssets =
            IAToken(aWETH).balanceOf(address(wrapper)) + IAToken(aWETH).balanceOf(handler.cv());
        assertLe(reported, heldAssets + 2, "reported assets exceed aToken balances held");
    }
}
