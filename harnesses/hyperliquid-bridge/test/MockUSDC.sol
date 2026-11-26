// SPDX-License-Identifier: MIT
pragma solidity ^0.8.9;

import {ERC20Permit} from "@openzeppelin/contracts/token/ERC20/extensions/draft-ERC20Permit.sol";
import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

// Minimal stand-in for Arbitrum native USDC (which supports EIP-2612 permit).
// Only used to exercise the real Bridge2 deposit/withdraw paths locally.
contract MockUSDC is ERC20Permit {
  constructor() ERC20Permit("USD Coin") ERC20("USD Coin", "USDC") {}

  function mint(address to, uint256 amount) external {
    _mint(to, amount);
  }
}
