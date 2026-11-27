// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {Test} from "forge-std/Test.sol";
import {MockERC20} from "../src/MockERC20.sol";
import {VulnerableVault} from "../src/VulnerableVault.sol";

/// @title VaultHandler — the stateful fuzzer's adversarial actor.
/// @notice Exposes bounded, actor-scoped operations so Foundry's invariant fuzzer
///         explores arbitrary sequences. It records two security-relevant facts:
///         whether any actor ever received zero shares for a positive deposit, and
///         whether the attacker ever redeemed more underlying than they put in.
contract VaultHandler is Test {
    MockERC20 token;
    VulnerableVault vault;

    address attacker = address(0xA11CE);
    address victim = address(0x71C71);

    uint256 public attackerIn;    // underlying the attacker put into the vault
    uint256 public attackerOut;   // underlying the attacker took out
    bool public zeroShareDeposit;

    constructor(MockERC20 _token, VulnerableVault _vault) {
        token = _token;
        vault = _vault;
        token.mint(attacker, 1_000_000e18);
        token.mint(victim, 1_000_000e18);
        vm.prank(attacker);
        token.approve(address(vault), type(uint256).max);
        vm.prank(victim);
        token.approve(address(vault), type(uint256).max);
    }

    function deposit(uint256 assets, bool asAttacker) external {
        assets = bound(assets, 1, 1000e18);
        address actor = asAttacker ? attacker : victim;
        vm.prank(actor);
        uint256 shares = vault.deposit(assets);
        if (shares == 0) {
            zeroShareDeposit = true;
        }
        if (asAttacker) attackerIn += assets;
    }

    /// @notice Direct transfer of underlying to the vault (no shares minted).
    function donate(uint256 assets) external {
        assets = bound(assets, 1, 1000e18);
        vm.prank(attacker);
        token.transfer(address(vault), assets);
        attackerIn += assets;
    }

    function withdraw(uint256 shares, bool asAttacker) external {
        address actor = asAttacker ? attacker : victim;
        uint256 bal = vault.balanceOf(actor);
        if (bal == 0) return;
        shares = bound(shares, 1, bal);
        vm.prank(actor);
        uint256 out = vault.withdraw(shares);
        if (asAttacker) attackerOut += out;
    }
}
