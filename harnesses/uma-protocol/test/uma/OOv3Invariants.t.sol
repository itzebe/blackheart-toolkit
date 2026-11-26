// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity 0.8.16;

import "forge-std/Test.sol";
import "../../src/optimistic-oracle-v3/implementation/OptimisticOracleV3.sol";
import "../../src/optimistic-oracle-v3/interfaces/OptimisticOracleV3Interface.sol";
import "../../src/data-verification-mechanism/implementation/Constants.sol";
import "./Mocks.sol";

// Stateful invariant search over the OOv3 lifecycle.
// INVARIANT: at all times the OOv3's currency balance equals the sum of the live escrows
// (bond for an undisputed assertion, 2*bond for a disputed one). Any sequence that breaks this
// is a real accounting/solvency defect: funds created, lost, or paid to the wrong party.
contract OOv3Handler is Test {
    OptimisticOracleV3 public oo;
    MockOracle public oracle;
    TestERC20 public currency;
    MockStore public store;

    bytes32 constant IDENT = "ASSERT_TRUTH";
    uint64 constant LIVENESS = 7200;

    address[3] public actors;
    bytes32[] public ids;
    uint256 public expectedBalance; // sum of live escrows the contract must be holding

    constructor(
        OptimisticOracleV3 _oo,
        MockOracle _oracle,
        TestERC20 _currency,
        MockStore _store,
        address[3] memory _actors
    ) {
        oo = _oo;
        oracle = _oracle;
        currency = _currency;
        store = _store;
        actors = _actors;
        for (uint256 i = 0; i < 3; i++) {
            vm.prank(actors[i]);
            currency.approve(address(oo), type(uint256).max);
        }
    }

    function _actor(uint256 seed) internal view returns (address) {
        return actors[seed % 3];
    }

    function assertTruth(uint256 actorSeed, uint256 claimSeed) public {
        address a = _actor(actorSeed);
        uint256 bond = oo.getMinimumBond(address(currency));
        bytes memory claim = abi.encodePacked("claim-", claimSeed);
        vm.prank(a);
        bytes32 id = oo.assertTruth(claim, a, address(0), address(0), LIVENESS, IERC20(address(currency)), bond, IDENT, bytes32(0));
        ids.push(id);
        expectedBalance += bond;
    }

    function dispute(uint256 actorSeed, uint256 idSeed) public {
        if (ids.length == 0) return;
        bytes32 id = ids[idSeed % ids.length];
        OptimisticOracleV3Interface.Assertion memory asrt = oo.getAssertion(id);
        if (asrt.disputer != address(0) || asrt.settled) return;
        if (asrt.expirationTime <= oo.getCurrentTime()) return;
        address d = _actor(actorSeed);
        vm.prank(d);
        oo.disputeAssertion(id, d);
        expectedBalance += asrt.bond;
    }

    function settle(uint256 idSeed) public {
        if (ids.length == 0) return;
        bytes32 id = ids[idSeed % ids.length];
        OptimisticOracleV3Interface.Assertion memory asrt = oo.getAssertion(id);
        if (asrt.settled) return;
        if (asrt.disputer == address(0) && asrt.expirationTime > oo.getCurrentTime()) return;
        if (asrt.disputer != address(0)) {
            // Dispute path needs a resolved DVM price.
            vm.prank(address(this));
            try oracle.pushPrice(IDENT, asrt.assertionTime, oo.stampAssertion(id), 1e18) {} catch {}
            if (!oracle.hasPrice(IDENT, asrt.assertionTime, oo.stampAssertion(id))) return;
        }
        oo.settleAssertion(id);
        expectedBalance -= (asrt.disputer == address(0) ? asrt.bond : asrt.bond * 2);
    }

    function warp(uint256 dt) public {
        vm.warp(oo.getCurrentTime() + (dt % 100000));
    }

    function liveIdCount() external view returns (uint256) {
        return ids.length;
    }
}

contract OOv3InvariantsTest is Test {
    OptimisticOracleV3 oo;
    MockFinder finder;
    MockStore store;
    MockIdentifierWhitelist idWhitelist;
    AddressWhitelist collateralWhitelist;
    MockOracle oracle;
    TestERC20 currency;
    OOv3Handler handler;

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
        idWhitelist.setSupported("ASSERT_TRUTH", true);
        store.setFinalFee(address(currency), FINAL_FEE);

        finder.changeImplementationAddress(OracleInterfaces.Oracle, address(oracle));
        finder.changeImplementationAddress(OracleInterfaces.Store, address(store));
        finder.changeImplementationAddress(OracleInterfaces.IdentifierWhitelist, address(idWhitelist));
        finder.changeImplementationAddress(OracleInterfaces.CollateralWhitelist, address(collateralWhitelist));

        oo = new OptimisticOracleV3(finder, IERC20(address(currency)), 7200);

        address[3] memory actors = [address(0xA11CE), address(0xB0B), address(0xC0FFEE)];
        for (uint256 i = 0; i < 3; i++) currency.mint(actors[i], 1_000_000e6);

        handler = new OOv3Handler(oo, oracle, currency, store, actors);
        targetContract(address(handler));
    }

    function invariant_bondSolvency() public {
        assertEq(
            currency.balanceOf(address(oo)),
            handler.expectedBalance(),
            "OOv3 balance != sum of live escrows"
        );
    }
}
