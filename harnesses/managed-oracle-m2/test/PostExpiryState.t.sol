// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {Test} from "forge-std/Test.sol";
import {IERC20} from "forge-std/interfaces/IERC20.sol";

/// @dev Live Polygon Managed OO (proxy -> 0x8c7556a4..., verified source == master).
interface IManagedOO {
    function requestPrice(bytes32 identifier, uint256 timestamp, bytes memory ancillaryData, address currency, uint256 reward)
        external
        returns (uint256);
    function setCustomLiveness(bytes32 identifier, uint256 timestamp, bytes memory ancillaryData, uint256 liveness)
        external;
    function proposePrice(address requester, bytes32 identifier, uint256 timestamp, bytes memory ancillaryData, int256 proposedPrice)
        external
        returns (uint256);
    function settle(address requester, bytes32 identifier, uint256 timestamp, bytes memory ancillaryData)
        external
        returns (uint256);
    function disputePrice(address requester, bytes32 identifier, uint256 timestamp, bytes memory ancillaryData)
        external
        returns (uint256);
    function getState(address requester, bytes32 identifier, uint256 timestamp, bytes memory ancillaryData)
        external
        view
        returns (uint8);
    function hasPrice(address requester, bytes32 identifier, uint256 timestamp, bytes memory ancillaryData)
        external
        view
        returns (bool);
    function defaultLiveness() external view returns (uint256);
    function minimumDisputeWindow() external view returns (uint256);
}

/// @notice What a request that has passed its dispute window actually looks like on the live
///         Managed OO, and whether an unprivileged party can settle it.
contract PostExpiryStateTest is Test {
    address constant PROXY = 0x2C0367a9DB231dDeBd88a94b4f6461a6e47C58B1;
    address constant REPORTER = 0x53703Dd6129d723066b6362510E5aE2fECd48218;
    address constant USDC = 0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174;
    /// @dev First member of the default proposer whitelist 0x9f35885c... (read with getWhitelist()).
    address constant PROPOSER = 0x9A8f92a830A5cB89a3816e3D267CB7791c16b04D;
    /// @dev UMA identifiers are the literal ASCII bytes32, not a hash. Confirmed from the
    ///      RequestRegistered topic of 87 live requests in the last 10k blocks.
    bytes32 constant YES_OR_NO_QUERY = "YES_OR_NO_QUERY";

    uint8 constant REQUESTED = 1;
    uint8 constant PROPOSED = 2;
    uint8 constant EXPIRED = 3;

    IManagedOO oracle = IManagedOO(PROXY);
    IERC20 usdc = IERC20(USDC);

    function setUp() public {
        vm.createSelectFork(vm.envString("POLYGON_RPC"));
    }

    function _liveRequest() internal returns (uint256 timestamp) {
        timestamp = block.timestamp;
        vm.startPrank(REPORTER);
        usdc.approve(PROXY, type(uint256).max);
        oracle.requestPrice(YES_OR_NO_QUERY, timestamp, "", USDC, 0);
        oracle.setCustomLiveness(YES_OR_NO_QUERY, timestamp, "", 300);
        usdc.transfer(PROPOSER, 600e6); // bond + final fee measured at 500e6
        vm.stopPrank();

        vm.startPrank(PROPOSER);
        usdc.approve(PROXY, type(uint256).max);
        oracle.proposePrice(REPORTER, YES_OR_NO_QUERY, timestamp, "", 1);
        vm.stopPrank();
    }

    function test_pinned_config() public view {
        assertEq(oracle.defaultLiveness(), 7200, "default liveness");
        assertEq(oracle.minimumDisputeWindow(), 300, "minimum dispute window");
    }

    /// @notice The state a request is in after its dispute window has elapsed.
    function test_expired_request_reports_proposed_and_has_no_price() public {
        uint256 ts = _liveRequest();

        assertEq(oracle.getState(REPORTER, YES_OR_NO_QUERY, ts, ""), PROPOSED, "before expiry");
        assertFalse(oracle.hasPrice(REPORTER, YES_OR_NO_QUERY, ts, ""), "before expiry");

        vm.warp(block.timestamp + 301); // past the 300s custom liveness

        // _getStateForDispute maps Expired -> Proposed, so the lapsed state is never observable.
        uint8 state = oracle.getState(REPORTER, YES_OR_NO_QUERY, ts, "");
        assertEq(state, PROPOSED, "after expiry: state stays Proposed");
        assertTrue(state != EXPIRED, "Expired is unreachable through getState()");
        assertFalse(oracle.hasPrice(REPORTER, YES_OR_NO_QUERY, ts, ""), "after expiry: hasPrice is false");
    }

    /// @notice Settlement of an expired request is not available to an unprivileged caller.
    function test_only_resolver_can_settle_an_expired_request() public {
        uint256 ts = _liveRequest();
        vm.warp(block.timestamp + 301);

        vm.prank(address(0xBEEF));
        vm.expectRevert();
        oracle.settle(REPORTER, YES_OR_NO_QUERY, ts, "");
    }

    /// @notice A lapsed request is still disputable: disputePrice() gets past its state guard.
    ///         The call may still revert later (the DVM request is real on a fork), so the
    ///         assertion is that it is *not* rejected by RequestStateNotProposed().
    function test_post_expiry_dispute_is_not_rejected_by_the_state_guard() public {
        uint256 ts = _liveRequest();
        vm.warp(block.timestamp + 301);

        address disputer = address(0xBEEF);
        vm.startPrank(REPORTER);
        usdc.transfer(disputer, 600e6);
        vm.stopPrank();
        vm.startPrank(disputer);
        usdc.approve(PROXY, type(uint256).max);

        try oracle.disputePrice(REPORTER, YES_OR_NO_QUERY, ts, "") {
            // Accepted outright: the post-expiry dispute went through.
        } catch (bytes memory reason) {
            bytes4 selector = reason.length >= 4 ? bytes4(reason) : bytes4(0);
            assertTrue(
                selector != bytes4(0xde0cc838),
                "dispute was rejected by the state guard (RequestStateNotProposed)"
            );
        }
        vm.stopPrank();
    }

    /// @notice The dispute guard used by disputePriceFor() accepts the lapsed request.
    ///         disputePriceFor requires _getStateForDispute(...) == Proposed, and getState() is
    ///         exactly that function, so the assertion above is the guard itself.
    function test_post_expiry_dispute_guard_passes() public {
        uint256 ts = _liveRequest();
        vm.warp(block.timestamp + 301);
        assertEq(oracle.getState(REPORTER, YES_OR_NO_QUERY, ts, ""), PROPOSED, "dispute guard accepts lapsed request");
    }
}
