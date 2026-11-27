// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {AdversarialERC20} from "../token/AdversarialERC20.sol";
import {IPriceOracle} from "../oracle/Oracles.sol";

/// @title VulnerableLendingMarket
/// @notice A collateralised-debt market that values collateral at a *spot* oracle
///         price. The manipulation primitive (moving the pool the oracle reads)
///         lets an attacker inflate collateral value inside one transaction and
///         borrow against it, leaving bad debt.
/// @dev Deliberately vulnerable. Invariant that must hold:
///      "no account's debt ever exceeds its collateral valued at a
///       manipulation-resistant price times the LTV".
contract VulnerableLendingMarket {
    AdversarialERC20 public immutable collateral;
    AdversarialERC20 public immutable debt;
    IPriceOracle public immutable oracle;
    uint256 public constant LTV_BPS = 5_000; // 50%

    mapping(address => uint256) public collateralOf;
    mapping(address => uint256) public debtOf;

    constructor(AdversarialERC20 collateral_, AdversarialERC20 debt_, IPriceOracle oracle_) {
        collateral = collateral_;
        debt = debt_;
        oracle = oracle_;
    }

    function depositCollateral(uint256 amount) external {
        collateral.transferFrom(msg.sender, address(this), amount);
        collateralOf[msg.sender] += amount;
    }

    function borrow(uint256 amount) external {
        uint256 value = (collateralOf[msg.sender] * oracle.price(address(collateral))) / 1e18;
        uint256 maxDebt = (value * LTV_BPS) / 10_000;
        require(debtOf[msg.sender] + amount <= maxDebt, "undercollateralised");
        debtOf[msg.sender] += amount;
        debt.transfer(msg.sender, amount);
    }
}

/// @title SafeLendingMarket
/// @notice The same market valued at a manipulation-resistant TWAP. The attack
///         that inflates the spot market cannot move a TWAP, so the borrow is
///         rejected. Negative control for the oracle-manipulation PoC.
contract SafeLendingMarket {
    AdversarialERC20 public immutable collateral;
    AdversarialERC20 public immutable debt;
    IPriceOracle public immutable oracle;
    uint256 public constant LTV_BPS = 5_000;

    mapping(address => uint256) public collateralOf;
    mapping(address => uint256) public debtOf;

    constructor(AdversarialERC20 collateral_, AdversarialERC20 debt_, IPriceOracle oracle_) {
        collateral = collateral_;
        debt = debt_;
        oracle = oracle_;
    }

    function depositCollateral(uint256 amount) external {
        collateral.transferFrom(msg.sender, address(this), amount);
        collateralOf[msg.sender] += amount;
    }

    function borrow(uint256 amount) external {
        uint256 value = (collateralOf[msg.sender] * oracle.price(address(collateral))) / 1e18;
        uint256 maxDebt = (value * LTV_BPS) / 10_000;
        require(debtOf[msg.sender] + amount <= maxDebt, "undercollateralised");
        debtOf[msg.sender] += amount;
        debt.transfer(msg.sender, amount);
    }
}
