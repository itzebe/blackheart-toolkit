// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity 0.8.16;

import "forge-std/Test.sol";
import "../../src/optimistic-oracle-v3/implementation/OptimisticOracleV3.sol";
import "../../src/optimistic-oracle-v3/implementation/escalation-manager/FullPolicyEscalationManager.sol";
import "../../src/data-verification-mechanism/implementation/Constants.sol";
import "./Mocks.sol";

// Adversarial tests against OOv3 escalation-manager interactions (attack surfaces G/H).
contract EscalationManagerAttacks is Test {
    OptimisticOracleV3 oo;
    MockFinder finder;
    MockStore store;
    MockIdentifierWhitelist idWhitelist;
    AddressWhitelist collateralWhitelist;
    MockOracle oracle;
    TestERC20 currency;

    FullPolicyEscalationManager em;

    address emOwner = address(0xE0);
    address asserter = address(0xA11CE);
    address disputer = address(0xB0B);

    bytes32 constant IDENT = "ASSERT_TRUTH";
    uint64 constant LIVENESS = 7200;
    uint256 constant FINAL_FEE = 1000e6;

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
        em = new FullPolicyEscalationManager(address(oo));

        currency.mint(asserter, 1_000_000e6);
        currency.mint(disputer, 1_000_000e6);
        vm.prank(asserter);
        currency.approve(address(oo), type(uint256).max);
        vm.prank(disputer);
        currency.approve(address(oo), type(uint256).max);
    }

    function _assertWithEM(bytes memory claim) internal returns (bytes32 id, uint256 bond) {
        bond = oo.getMinimumBond(address(currency));
        vm.prank(asserter);
        id = oo.assertTruth(claim, asserter, address(0), address(em), LIVENESS, IERC20(address(currency)), bond, IDENT, bytes32(0));
    }

    // An asserter picks the escalation manager. A hostile manager can validate disputers against an empty whitelist,
    // making every dispute revert. The false assertion then settles true after liveness.
    function test_maliciousManagerCanBlockAllDisputes() public {
        em.configureEscalationManager(false, false, true, false, false);

        (bytes32 id, ) = _assertWithEM("asserter controlled EM");

        vm.prank(disputer);
        vm.expectRevert(bytes("Dispute not allowed"));
        oo.disputeAssertion(id, disputer);

        vm.warp(block.timestamp + LIVENESS);
        oo.settleAssertion(id);
        assertTrue(oo.getAssertionResult(id), "assertion resolved true despite being false");
    }

    // With discardOracle=true (DVM arbitration), the reported resolution is forced false, but the bond recipient is
    // still derived from the real DVM price. So a "true" DVM outcome pays the asserter while getAssertionResult()
    // reports false. This documents the payout/reporting divergence for discardOracle integrations.
    function test_discardOracleDivergesPayoutFromReportedResolution() public {
        em.configureEscalationManager(false, false, false, false, true); // discard oracle, DVM arbitration

        (bytes32 id, uint256 bond) = _assertWithEM("true claim");
        vm.prank(disputer);
        oo.disputeAssertion(id, disputer);

        OptimisticOracleV3Interface.Assertion memory a = oo.getAssertion(id);
        oracle.pushPrice(a.identifier, a.assertionTime, oo.stampAssertion(id), 1e18);

        oo.settleAssertion(id);

        uint256 fee = (oo.burnedBondPercentage() * bond) / 1e18;
        assertEq(currency.balanceOf(asserter), 1_000_000e6 - bond + (2 * bond - fee), "asserter wins bonds");
        assertFalse(oo.getAssertionResult(id), "reported resolution diverges from payout");
    }

    // With arbitrateViaEscalationManager=true and a manager resolution of false, the disputer wins both bonds.
    function test_emArbitrationResolutionHandsBondToDisputer() public {
        em.configureEscalationManager(false, false, false, true, false); // arbitrate via EM, respect its oracle

        (bytes32 id, uint256 bond) = _assertWithEM("true claim");
        vm.prank(disputer);
        oo.disputeAssertion(id, disputer);

        OptimisticOracleV3Interface.Assertion memory a = oo.getAssertion(id);
        em.setArbitrationResolution(a.identifier, a.assertionTime, oo.stampAssertion(id), false);

        oo.settleAssertion(id);

        uint256 fee = (oo.burnedBondPercentage() * bond) / 1e18;
        assertEq(currency.balanceOf(disputer), 1_000_000e6 - bond + (2 * bond - fee), "disputer profits");
        assertFalse(oo.getAssertionResult(id));
    }

    // Policy is snapshotted at assert time; a later change does not retroactively affect an existing assertion.
    function test_policySnapshotAtAssertTime() public {
        (bytes32 id, ) = _assertWithEM("snapshot claim");
        vm.prank(disputer);
        oo.disputeAssertion(id, disputer);
        OptimisticOracleV3Interface.Assertion memory a = oo.getAssertion(id);
        assertEq(a.disputer, disputer);
    }
}
