// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../src/Bootstrap.sol";
import "../src/MockERC20.sol";
import "euler/modules/EToken.sol";
import "euler/modules/DToken.sol";
import "euler/modules/Markets.sol";
import "euler/modules/Installer.sol";
import "euler/modules/Liquidation.sol";
import "euler/modules/Governance.sol";
import "euler/modules/Exec.sol";
import "euler/modules/RiskManager.sol";
import "euler/modules/interest-rate-models/IRMDefault.sol";

// Empirical validation of the harness bootstrap and the donateToReserves
// solvency-bypass mechanics, against the *unmodified* vendored Euler V1.
// This is a local, self-contained test; it is not a production interaction.
contract BootstrapTest is Test {
    Bootstrap boot;
    MockERC20 token;

    address eTok;
    address dTok;
    address euler;
    address mkt;

    address victim;

    function setUp() public {
        bytes32 commit = bytes32(0);

        address installerImpl = address(new Installer(commit));
        address marketsImpl = address(new Markets(commit));
        address liquidationImpl = address(new Liquidation(commit));
        address governanceImpl = address(new Governance(commit));
        address execImpl = address(new Exec(commit));
        address eTokenImpl = address(new EToken(commit));
        address dTokenImpl = address(new DToken(commit));
        address irmDefaultImpl = address(new IRMDefault(commit));

        token = new MockERC20("Test Token", "TST", 18);

        boot = new Bootstrap(
            commit, address(token), installerImpl, marketsImpl, liquidationImpl,
            governanceImpl, execImpl, eTokenImpl, dTokenImpl, irmDefaultImpl
        );

        // Cache the proxy addresses: each boot.*() is an external call and would
        // otherwise consume a single-use vm.prank.
        eTok = boot.eTokenAddr();
        dTok = boot.dTokenAddr();
        euler = address(boot.euler());
        mkt = address(boot.markets());

        victim = makeAddr("victim");
    }

    function _openPosition(address who, uint depositAmount, uint borrowAmount) internal {
        token.mint(who, depositAmount);
        vm.startPrank(who);
        token.approve(euler, type(uint).max);
        EToken(eTok).deposit(0, depositAmount);
        Markets(mkt).enterMarket(0, address(token));
        DToken(dTok).borrow(0, borrowAmount);
        vm.stopPrank();
    }

    function testBootstrapActivatesMarket() public {
        assertTrue(eTok != address(0), "eToken");
        assertTrue(dTok != address(0), "dToken");
        assertEq(Markets(mkt).underlyingToEToken(address(token)), eTok);
    }

    function testDonateToReservesHasNoSolvencyCheck() public {
        _openPosition(victim, 100e18, 1e18);

        uint coll = boot.collateralValue(victim);
        uint liab = boot.liabilityValue(victim);
        assertGe(coll, liab, "victim should be solvent after borrow");

        // Donate the whole eToken balance to reserves. This reduces the user's
        // balance (and thus their collateral value) and does NOT call
        // checkLiquidity, unlike every other balance-reducing path.
        uint bal = EToken(eTok).balanceOf(victim);
        vm.prank(victim);
        EToken(eTok).donateToReserves(0, bal);

        uint coll2 = boot.collateralValue(victim);
        uint liab2 = boot.liabilityValue(victim);
        assertLt(coll2, liab2, "victim should be underwater after the donation");
    }

    function testWithdrawHasSolvencyCheck() public {
        // Control: the same economic move via `withdraw` (which DOES check
        // liquidity) is reverted, proving the invariant is enforced on the other
        // paths and that donateToReserves is the exception.
        _openPosition(victim, 100e18, 1e18);

        uint bal = EToken(eTok).balanceOf(victim);
        vm.prank(victim);
        vm.expectRevert(); // e/collateral-violation
        EToken(eTok).withdraw(0, bal);
    }
}
