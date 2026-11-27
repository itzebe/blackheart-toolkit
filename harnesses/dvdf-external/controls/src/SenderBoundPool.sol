// SPDX-License-Identifier: MIT
pragma solidity =0.8.25;

import {IERC3156FlashBorrower} from "@openzeppelin/contracts/interfaces/IERC3156FlashBorrower.sol";
import {IERC3156FlashLender} from "@openzeppelin/contracts/interfaces/IERC3156FlashLender.sol";
import {WETH} from "solmate/tokens/WETH.sol";

/// @title SenderBoundPool -- differential control for DVDF "Naive Receiver"
/// @notice The minimal fix for the Naive Receiver flaw: a flash loan may only be
///         initiated by the borrower itself, so an attacker cannot force a victim
///         receiver to take a loan (and pay its fee). Interface-compatible with
///         the challenge's `NaiveReceiverPool.flashLoan`.
contract SenderBoundPool is IERC3156FlashLender {
    uint256 private constant FIXED_FEE = 1e18;
    bytes32 private constant CALLBACK_SUCCESS = keccak256("ERC3156FlashBorrower.onFlashLoan");

    WETH public immutable weth;
    address public immutable feeReceiver;

    error CallbackFailed();
    error UnsupportedCurrency();
    error NotBorrower();

    constructor(address payable _weth, address _feeReceiver) payable {
        weth = WETH(_weth);
        feeReceiver = _feeReceiver;
    }

    function maxFlashLoan(address token) external view returns (uint256) {
        if (token == address(weth)) return weth.balanceOf(address(this));
        return 0;
    }

    function flashFee(address token, uint256) external view returns (uint256) {
        if (token != address(weth)) revert UnsupportedCurrency();
        return FIXED_FEE;
    }

    function flashLoan(IERC3156FlashBorrower receiver, address token, uint256 amount, bytes calldata data)
        external
        returns (bool)
    {
        if (token != address(weth)) revert UnsupportedCurrency();
        if (msg.sender != address(receiver)) revert NotBorrower();

        weth.transfer(address(receiver), amount);
        if (receiver.onFlashLoan(msg.sender, address(weth), amount, FIXED_FEE, data) != CALLBACK_SUCCESS) {
            revert CallbackFailed();
        }
        weth.transferFrom(address(receiver), address(this), amount + FIXED_FEE);
        return true;
    }

    receive() external payable {}
}
