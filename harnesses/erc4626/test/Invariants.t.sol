// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {Test} from "forge-std/Test.sol";
import {MockERC20} from "../src/MockERC20.sol";
import {VulnerableVault} from "../src/VulnerableVault.sol";
import {SafeVault} from "../src/SafeVault.sol";
import {VaultHandler} from "./VaultHandler.sol";

/// @title InvariantsTest — stateful invariant search over arbitrary sequences.
/// @notice `test_invariant_vulnerable_vault_breaks` MUST fail on the vulnerable
///         vault (that failure IS the finding); `test_invariant_safe_vault_holds`
///         MUST pass, proving the invariant is meaningful rather than vacuous.
contract InvariantsTest is Test {
    MockERC20 token;
    VulnerableVault vuln;
    VaultHandler handler;

    function setUp() public {
        token = new MockERC20();
        vuln = new VulnerableVault(token);
        handler = new VaultHandler(token, vuln);
        targetContract(address(handler));
    }

    /// @notice An attacker must never end with more underlying than they supplied.
    function invariant_no_material_attacker_profit() public view {
        uint256 out = handler.attackerOut();
        uint256 inAmount = handler.attackerIn();
        // Allow dust (1e-4 of input) for rounding; anything above is real profit.
        uint256 dust = inAmount / 10_000;
        assertLe(out, inAmount + dust, "attacker extracted material profit");
    }

    /// @notice No positive deposit may mint zero shares.
    function invariant_no_zero_share_deposit() public view {
        assertFalse(handler.zeroShareDeposit(), "a positive deposit minted zero shares");
    }
}

/// @notice Same invariants against the defended vault; these must hold.
contract SafeInvariantsTest is Test {
    MockERC20 token;
    SafeVault safe;
    SafeVaultHandler handler;

    function setUp() public {
        token = new MockERC20();
        safe = new SafeVault(token);
        handler = new SafeVaultHandler(token, safe);
        targetContract(address(handler));
    }

    function invariant_safe_no_zero_share_deposit() public view {
        assertFalse(handler.zeroShareDeposit(), "safe vault minted zero shares");
    }

    function invariant_safe_no_attacker_profit() public view {
        uint256 out = handler.attackerOut();
        uint256 inAmount = handler.attackerIn();
        uint256 dust = inAmount / 10_000;
        assertLe(out, inAmount + dust, "safe vault leaked attacker profit");
    }
}

/// @dev Handler bound to SafeVault (identical actor model).
contract SafeVaultHandler is Test {
    MockERC20 token;
    SafeVault vault;

    address attacker = address(0xA11CE);
    address victim = address(0x71C71);

    uint256 public attackerIn;
    uint256 public attackerOut;
    bool public zeroShareDeposit;

    constructor(MockERC20 _token, SafeVault _vault) {
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
        if (shares == 0) zeroShareDeposit = true;
        if (asAttacker) attackerIn += assets;
    }

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
