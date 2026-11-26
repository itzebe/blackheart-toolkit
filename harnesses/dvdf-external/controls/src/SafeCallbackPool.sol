// SPDX-License-Identifier: MIT
pragma solidity =0.8.25;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

interface IFlashLoanReceiver {
    function onFlashLoan(uint256 amount) external;
}

/// @title SafeCallbackPool -- differential control for DVDF "Truster"
/// @notice The minimal fix for the Truster flaw: never make a caller-chosen call.
///         The borrower must be a typed receiver that returns funds itself; there
///         is no arbitrary `target.functionCall(data)`.
contract SafeCallbackPool is ReentrancyGuard {
    IERC20 public immutable token;

    error RepayFailed();
    error CallbackFailed();

    constructor(IERC20 _token) {
        token = _token;
    }

    function flashLoan(uint256 amount, IFlashLoanReceiver borrower) external nonReentrant {
        uint256 balanceBefore = token.balanceOf(address(this));

        token.transfer(address(borrower), amount);
        borrower.onFlashLoan(amount);

        if (token.balanceOf(address(this)) < balanceBefore) {
            revert RepayFailed();
        }
    }
}
