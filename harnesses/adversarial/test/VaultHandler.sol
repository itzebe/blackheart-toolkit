// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {Test} from "forge-std/Test.sol";
import {AdversarialERC20} from "../src/token/AdversarialERC20.sol";
import {VulnerableVault} from "../src/vault/VulnerableVault.sol";
import {ReentrancyAttacker} from "../src/attack/ReentrancyAttacker.sol";

/// @title VaultHandler
/// @notice Actor model for the stateful invariant fuzzer. It drives the *same*
///         actions against whichever vault it is wired to, so a vulnerable vault
///         and a defended vault are compared under an identical search space.
///         The only variable is the vault implementation.
/// @dev Deterministic given a seed. No I/O, no time dependence.
contract VaultHandler is Test {
    AdversarialERC20 public token;
    VulnerableVault public vault;
    address[] public actors;

    /// @notice Total profit extracted by reentrancy attempts across the run.
    ///         The security invariant is that this stays zero.
    uint256 public ghostProfit;

    constructor(AdversarialERC20 token_, VulnerableVault vault_) {
        token = token_;
        vault = vault_;
        actors.push(makeAddr("actor0"));
        actors.push(makeAddr("actor1"));
        actors.push(makeAddr("actor2"));
    }

    function _actor(uint256 seed) internal view returns (address) {
        return actors[seed % actors.length];
    }

    function deposit(uint256 actorSeed, uint256 amount) external {
        address actor = _actor(actorSeed);
        amount = bound(amount, 1e6, 1_000e18);
        token.mint(actor, amount);
        vm.startPrank(actor);
        token.approve(address(vault), amount);
        vault.deposit(amount);
        vm.stopPrank();
    }

    function withdraw(uint256 actorSeed, uint256 amount) external {
        address actor = _actor(actorSeed);
        uint256 bal = vault.balanceOf(actor);
        if (bal == 0) return;
        amount = bound(amount, 1, bal);
        vm.prank(actor);
        vault.withdraw(amount);
    }

    /// @notice The attacker primitive: run a reentrant drain through a hostile
    ///         token callback. On the vulnerable vault the attacker leaves with
    ///         more tokens than it put in; on the defended vault the nested
    ///         withdrawal reverts and is swallowed, so there is no profit.
    function reentrancyAttack(uint256 amount) external {
        amount = bound(amount, 1e6, 100e18);
        ReentrancyAttacker atk = new ReentrancyAttacker();
        token.mint(address(atk), amount);
        atk.attack(address(vault), token, amount);
        atk.drain(address(atk));

        uint256 held = token.balanceOf(address(atk));
        if (held > amount) ghostProfit += held - amount;
    }
}
