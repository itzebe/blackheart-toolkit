// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity 0.8.16;

import "forge-std/Test.sol";
import "../../src/optimistic-oracle-v3/implementation/OptimisticOracleV3.sol";
import "../../src/optimistic-oracle-v3/interfaces/OptimisticOracleV3Interface.sol";
import "../../src/data-verification-mechanism/implementation/Constants.sol";
import "./Mocks.sol";

// Baseline lifecycle + accounting-solvency invariants for OOv3.
// Uses a real OOv3 instance against minimal DVM-compatible mocks.
contract OOv3LifecycleTest is Test {
    OptimisticOracleV3 oo;
    MockFinder finder;
    MockStore store;
    MockIdentifierWhitelist idWhitelist;
    AddressWhitelist collateralWhitelist;
    MockOracle oracle;
    TestERC20 currency;

    address asserter = address(0xA11CE);
    address disputer = address(0xB0B);
    address stranger = address(0xC0FFEE);

    bytes32 constant IDENT = "ASSERT_TRUTH";
    uint64 constant LIVENESS = 7200;
    uint256 constant FINAL_FEE = 1000e6; // e.g. 1000 USDC

    function setUp() public {
        vm.warp(1_700_000_000);
        currency = new TestERC20("Test USD", "TUSD");
        finder = new MockFinder();
        store = new MockStore();
        idWhitelist = new MockIdentifierWhitelist();
        collateralWhitelist = new AddressWhitelist();
        oracle = new MockOracle();

        collateralWhitelist.addToWhitelist(address(currency));
        idWhitelist.setSupported(IDENT, true);
        store.setFinalFee(address(currency), FINAL_FEE);

        finder.changeImplementationAddress(OracleInterfaces.Oracle, address(oracle));
        finder.changeImplementationAddress(OracleInterfaces.Store, address(store));
        finder.changeImplementationAddress(OracleInterfaces.IdentifierWhitelist, address(idWhitelist));
        finder.changeImplementationAddress(OracleInterfaces.CollateralWhitelist, address(collateralWhitelist));

        oo = new OptimisticOracleV3(finder, IERC20(address(currency)), LIVENESS);

        currency.mint(asserter, 1_000_000e6);
        currency.mint(disputer, 1_000_000e6);
        currency.mint(stranger, 1_000_000e6);
        vm.prank(asserter);
        currency.approve(address(oo), type(uint256).max);
        vm.prank(disputer);
        currency.approve(address(oo), type(uint256).max);
        vm.prank(stranger);
        currency.approve(address(oo), type(uint256).max);
    }

    function _assert(bytes memory claim) internal returns (bytes32) {
        uint256 bond = oo.getMinimumBond(address(currency)); // compute before prank: external call would consume it
        vm.prank(asserter);
        return oo.assertTruth(claim, asserter, address(0), address(0), LIVENESS, IERC20(address(currency)), bond, IDENT, bytes32(0));
    }

    // INVARIANT: total currency held by OOv3 == sum of live bonds (one bond if asserted, two if disputed).
    function _oooBalance() internal view returns (uint256) {
        return currency.balanceOf(address(oo));
    }

    function test_minimumBondIsTwiceFinalFee() public {
        // burnedBondPercentage defaults to 0.5e18 -> min bond = finalFee / 0.5 = 2x finalFee
        assertEq(oo.burnedBondPercentage(), 0.5e18);
        assertEq(oo.getMinimumBond(address(currency)), 2 * FINAL_FEE);
    }

    function test_undisputedResolveReturnsBondToAsserter() public {
        uint256 bond = oo.getMinimumBond(address(currency));
        bytes32 id = _assert("undisputed claim");
        assertEq(_oooBalance(), bond, "ooo holds one bond");

        vm.warp(block.timestamp + LIVENESS);
        oo.settleAssertion(id);

        assertEq(currency.balanceOf(asserter), 1_000_000e6, "asserter whole after refund");
        assertEq(_oooBalance(), 0, "ooo drained");
        assertTrue(oo.getAssertionResult(id));
    }

    function test_disputeEscrowsTwoBonds() public {
        uint256 bond = oo.getMinimumBond(address(currency));
        bytes32 id = _assert("disputed claim");
        vm.prank(disputer);
        oo.disputeAssertion(id, disputer);
        assertEq(_oooBalance(), 2 * bond, "two bonds escrowed");
        assertEq(oracle.requestCount(), 1, "one DVM request made");
    }

    // The DVM price must be pushed before settling a disputed assertion; helper.
    function _pushTrue(bytes32 id) internal {
        OptimisticOracleV3Interface.Assertion memory a = oo.getAssertion(id);
        oracle.pushPrice(a.identifier, a.assertionTime, oo.stampAssertion(id), 1e18);
    }

    function test_disputedResolvedTruePaysAsserter() public {
        uint256 bond = oo.getMinimumBond(address(currency));
        bytes32 id = _assert("claim A");
        vm.prank(disputer);
        oo.disputeAssertion(id, disputer);
        _pushTrue(id);

        oo.settleAssertion(id);

        uint256 fee = (oo.burnedBondPercentage() * bond) / 1e18;
        assertEq(currency.balanceOf(asserter), 1_000_000e6 - bond + (2 * bond - fee), "asserter wins both bonds minus fee");
        assertEq(currency.balanceOf(disputer), 1_000_000e6 - bond, "disputer loses bond");
        assertEq(currency.balanceOf(address(store)), fee, "store gets fee");
        assertEq(_oooBalance(), 0, "ooo drained");
        assertTrue(oo.getAssertionResult(id));
    }

    function test_disputedResolvedFalsePaysDisputer() public {
        uint256 bond = oo.getMinimumBond(address(currency));
        bytes32 id = _assert("claim B");
        vm.prank(disputer);
        oo.disputeAssertion(id, disputer);
        OptimisticOracleV3Interface.Assertion memory a = oo.getAssertion(id);
        oracle.pushPrice(a.identifier, a.assertionTime, oo.stampAssertion(id), 0); // false

        oo.settleAssertion(id);

        uint256 fee = (oo.burnedBondPercentage() * bond) / 1e18;
        assertEq(currency.balanceOf(disputer), 1_000_000e6 - bond + (2 * bond - fee), "disputer wins");
        assertEq(currency.balanceOf(address(store)), fee);
        assertEq(_oooBalance(), 0);
        assertFalse(oo.getAssertionResult(id));
    }

    // A stranger (not asserter/disputer) cannot settle early or steal.
    function test_cannotSettleBeforeExpiryUndisputed() public {
        bytes32 id = _assert("claim C");
        vm.expectRevert(bytes("Assertion not expired"));
        oo.settleAssertion(id);
    }

    function test_cannotDisputeAfterExpiry() public {
        bytes32 id = _assert("claim D");
        vm.warp(block.timestamp + LIVENESS + 1);
        vm.prank(disputer);
        vm.expectRevert(bytes("Assertion is expired"));
        oo.disputeAssertion(id, disputer);
    }

    function test_cannotDoubleSettle() public {
        bytes32 id = _assert("claim E");
        vm.warp(block.timestamp + LIVENESS);
        oo.settleAssertion(id);
        vm.expectRevert(bytes("Assertion already settled"));
        oo.settleAssertion(id);
    }

    function test_assertionIdIsUniqueAcrossRepeatSameClaim() public {
        bytes32 id1 = _assert("same claim");
        vm.warp(block.timestamp + 1);
        bytes32 id2 = _assert("same claim");
        assertTrue(id1 != id2, "id includes timestamp");
    }
}
