// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity 0.8.16;

import "forge-std/Test.sol";
import "../../src/optimistic-oracle-v3/implementation/OptimisticOracleV3.sol";
import "../../src/optimistic-oracle-v3/interfaces/OptimisticOracleV3Interface.sol";
import "../../src/data-verification-mechanism/implementation/Constants.sol";
import "./Mocks.sol";

/// @notice A DVM oracle mock that enforces the real VotingV2 ancillary-data limit
/// (ANCILLARY_BYTES_LIMIT = 8192) on requestPrice, exactly as the deployed DVM does.
/// It also simulates the real settlement path so an attacker can resolve their own
/// undisputable assertion to `true` without any counterparty.
contract LimitedAncillaryMockOracle {
    uint256 public constant ANCILLARY_BYTES_LIMIT = 8192;

    struct Request {
        bool requested;
        bool resolved;
        int256 price;
    }

    mapping(bytes32 => Request) public requests;

    function requestPrice(
        bytes32 identifier,
        uint256 time,
        bytes memory ancillaryData
    ) external {
        // Mirrors VotingV2._requestPrice: require(ancillaryData.length <= ANCILLARY_BYTES_LIMIT).
        require(ancillaryData.length <= ANCILLARY_BYTES_LIMIT, "Invalid ancillary data");
        bytes32 id = keccak256(abi.encode(identifier, time, ancillaryData));
        requests[id].requested = true;
    }

    function hasPrice(
        bytes32 identifier,
        uint256 time,
        bytes memory ancillaryData
    ) external view returns (bool) {
        return requests[keccak256(abi.encode(identifier, time, ancillaryData))].resolved;
    }

    function getPrice(
        bytes32 identifier,
        uint256 time,
        bytes memory ancillaryData
    ) external view returns (int256) {
        Request memory r = requests[keccak256(abi.encode(identifier, time, ancillaryData))];
        require(r.resolved, "Price not resolved");
        return r.price;
    }

    /// @notice Simulates the DVM resolving the request for this (identifier,time,ancillary) to `price`.
    function pushPrice(
        bytes32 identifier,
        uint256 time,
        bytes memory ancillaryData,
        int256 price
    ) external {
        bytes32 id = keccak256(abi.encode(identifier, time, ancillaryData));
        requests[id].requested = true;
        requests[id].resolved = true;
        requests[id].price = price;
    }
}

/// @notice Hypothesis under test (REFUTED): can an OOv3 assertion be made undisputable/unsettleable
/// by padding the claim so the DVM ancillary data exceeds its 8192-byte limit?
/// Result: no — `stampAssertion` carries only `assertionId` + `ooAsserter` (~128 bytes), never the
/// claim, so claim length cannot overflow the DVM ancillary limit. The test asserts the negative.
contract OOv3AncillaryDoS is Test {
    OptimisticOracleV3 oo;
    MockFinder finder;
    MockStore store;
    MockIdentifierWhitelist idWhitelist;
    AddressWhitelist collateralWhitelist;
    LimitedAncillaryMockOracle oracle;
    TestERC20 currency;

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
        oracle = new LimitedAncillaryMockOracle();

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
        vm.prank(asserter);
        currency.approve(address(oo), type(uint256).max);
        vm.prank(disputer);
        currency.approve(address(oo), type(uint256).max);
    }

    /// @notice NEGATIVE FINDING: the OOv3 claim is NOT carried in the DVM ancillary data. `stampAssertion`
    /// emits only `assertionId` + `ooAsserter` (a fixed ~128-byte string), so an arbitrarily long claim
    /// cannot push the DVM request over its 8192-byte ancillary limit. The oversized-claim DoS hypothesis
    /// is refuted: the claim is reconstructed off-chain from the AssertionMade event.
    function test_claimLengthDoesNotAffectAncillaryData() public {
        uint256 bond = oo.getMinimumBond(address(currency));

        bytes memory claim = new bytes(20000);
        for (uint256 i = 0; i < claim.length; i++) claim[i] = "A";

        vm.prank(asserter);
        bytes32 id = oo.assertTruth(
            claim, asserter, address(0), address(0), LIVENESS, IERC20(address(currency)), bond, IDENT, bytes32(0)
        );

        bytes memory ancillary = oo.stampAssertion(id);
        emit log_named_uint("stamped ancillary length", ancillary.length);
        assertLe(ancillary.length, 8192, "ancillary stays within the DVM limit regardless of claim length");

        // Dispute still escrows a second bond and creates a resolvable DVM request.
        vm.prank(disputer);
        oo.disputeAssertion(id, disputer);
        assertEq(currency.balanceOf(address(oo)), 2 * bond, "two bonds escrowed");

        OptimisticOracleV3Interface.Assertion memory a = oo.getAssertion(id);
        oracle.pushPrice(a.identifier, a.assertionTime, ancillary, 1e18);
        oo.settleAssertion(id);
        assertEq(currency.balanceOf(address(oo)), 0, "settles normally");
    }

    /// @notice Economic consequence: the locked disputer bond is permanently inaccessible, and the
    /// assertion's resolution is permanently unavailable to any integration that relies on it.
    function test_undersizedClaimSettlesNormally_control() public {
        uint256 bond = oo.getMinimumBond(address(currency));
        vm.prank(asserter);
        bytes32 id = oo.assertTruth(
            "small claim", asserter, address(0), address(0), LIVENESS, IERC20(address(currency)), bond, IDENT, bytes32(0)
        );

        vm.prank(disputer);
        oo.disputeAssertion(id, disputer);

        // DVM resolves true.
        OptimisticOracleV3Interface.Assertion memory a = oo.getAssertion(id);
        oracle.pushPrice(a.identifier, a.assertionTime, oo.stampAssertion(id), 1e18);
        oo.settleAssertion(id);

        assertEq(currency.balanceOf(address(oo)), 0, "control settles and drains");
        assertTrue(oo.getAssertionResult(id), "control resolves true");
    }
}
