// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {Test} from "forge-std/Test.sol";
import {IERC20} from "forge-std/interfaces/IERC20.sol";

/// @dev Minimal views of the deployed contracts, transcribed from the verified sources
///      (Sourcify full match) so the assertions below bind to production signatures.
interface IOOReporterLike {
    function owner() external view returns (address);
    function optimisticOracle() external view returns (address);
    function rewardCurrency() external view returns (address);
    function defaultRerequestBudget() external view returns (uint256);
    function isRequester(address) external view returns (bool);
    function isOracleInitializer(address) external view returns (bool);
    function registerRequest(bytes32, bytes32, bytes calldata, uint64, uint64) external;
    function initializeRequest(bytes32, uint256, uint256, uint64) external;
    function priceSettled(bytes32, uint256, bytes calldata, int256) external;
    function claimDeferredPayout(address) external;
    function sweep(address, address, uint256) external;
}

interface IManagedOOv2Like {
    function defaultLiveness() external view returns (uint256);
    function minimumDisputeWindow() external view returns (uint256);
    function minimumLiveness() external view returns (uint256);
    function requesterWhitelist() external view returns (address);
    function defaultProposerWhitelist() external view returns (address);
    function proposePriceFor(address, address, bytes32, uint256, bytes calldata, int256)
        external
        returns (uint256);
    function settle(address, bytes32, uint256, bytes calldata) external returns (uint256);
    function updateRequestRules(bytes32, bytes calldata, bytes calldata) external;
    function hasRole(bytes32, address) external view returns (bool);
}

/// @title Mission 02 gate verification
/// @notice Runs against live Polygon state. Every test asserts a *production* fact: either that
///         an unprivileged caller is refused by a specific error, or that the deployed
///         implementation is the one the sources claim. No state is written (fork only).
contract GateVerification is Test {
    // Polygon mainnet, verified 2026-11-21.
    address constant REPORTER = 0x53703Dd6129d723066b6362510E5aE2fECd48218; // PolymarketOOReporter proxy
    address constant OO = 0x2C0367a9DB231dDeBd88a94b4f6461a6e47C58B1; // ManagedOptimisticOracleV2 proxy
    IERC20 constant USDC_E = IERC20(0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174);

    address constant ATTACKER = address(0xA77ACC);
    bytes32 constant IDENT = "ASSERT_TRUTH";
    bytes32 constant REQUEST_ID = keccak256("m2.probe");

    function setUp() public {
        string memory rpc = vm.envOr("POLYGON_RPC", string("https://polygon-bor-rpc.publicnode.com"));
        vm.createSelectFork(rpc, vm.envOr("FORK_BLOCK", uint256(97702628)));
    }

    /*──────────────────────── deployment identity (positive control) ────────────────────────*/

    /// The reporter is initialized and owned by a non-zero admin.
    function test_reporterIsInitializedAndOwned() public view {
        address owner = IOOReporterLike(REPORTER).owner();
        assertTrue(owner != address(0), "reporter uninitialized: owner is zero");
        assertGt(owner.code.length, 0, "owner is an EOA");
        assertEq(IOOReporterLike(REPORTER).optimisticOracle(), OO, "reporter points elsewhere");
        assertEq(IOOReporterLike(REPORTER).rewardCurrency(), address(USDC_E), "unexpected reward currency");
    }

    /// The live OO implementation is the V2 code: `minimumDisputeWindow` answers, the pre-V2
    /// `minimumLiveness` getter is gone. A stale published address would fail this.
    function test_liveOracleIsTheV2Implementation() public {
        assertEq(IManagedOOv2Like(OO).defaultLiveness(), 7200, "default liveness changed");
        assertGt(IManagedOOv2Like(OO).minimumDisputeWindow(), 0, "minimumDisputeWindow unset");
        vm.expectRevert();
        IManagedOOv2Like(OO).minimumLiveness();
    }

    /// Requests are gated at both ends: only whitelisted requesters may create, only
    /// whitelisted proposers may propose.
    function test_bothWhitelistsAreConfigured() public view {
        assertTrue(IManagedOOv2Like(OO).requesterWhitelist() != address(0), "no requester whitelist");
        assertTrue(IManagedOOv2Like(OO).defaultProposerWhitelist() != address(0), "no proposer whitelist");
    }

    /*──────────────────────── unauthorized caller tests (the gate itself) ──────────────────*/

    function test_attackerCannotRegisterRequest() public {
        vm.prank(ATTACKER);
        vm.expectRevert(bytes4(keccak256("CallerNotRequester()")));
        IOOReporterLike(REPORTER).registerRequest(REQUEST_ID, IDENT, "rules", 3600, 7200);
    }

    function test_attackerCannotInitializeRequest() public {
        vm.prank(ATTACKER);
        vm.expectRevert(bytes4(keccak256("CallerNotOracleInitializer()")));
        IOOReporterLike(REPORTER).initializeRequest(REQUEST_ID, 1e6, 100e6, 3600);
    }

    function test_attackerCannotForgeOracleCallback() public {
        vm.prank(ATTACKER);
        vm.expectRevert(bytes4(keccak256("CallerNotOptimisticOracle()")));
        IOOReporterLike(REPORTER).priceSettled(IDENT, block.timestamp, "rules", 1e18);
    }

    function test_attackerCannotWithdrawOrSweep() public {
        vm.startPrank(ATTACKER);
        vm.expectRevert(abi.encodeWithSelector(bytes4(keccak256("OwnableUnauthorizedAccount(address)")), ATTACKER));
        IOOReporterLike(REPORTER).claimDeferredPayout(ATTACKER);
        vm.expectRevert(abi.encodeWithSelector(bytes4(keccak256("OwnableUnauthorizedAccount(address)")), ATTACKER));
        IOOReporterLike(REPORTER).sweep(address(USDC_E), ATTACKER, 1);
        vm.stopPrank();
    }

    /// The money path is resolver-gated in the live implementation. A pre-V2 deployment would
    /// let this call through to `RequestNotSettleable` instead of an access-control error.
    function test_attackerCannotSettle() public {
        vm.prank(ATTACKER);
        vm.expectRevert(
            abi.encodeWithSelector(
                bytes4(keccak256("AccessControlUnauthorizedAccount(address,bytes32)")),
                ATTACKER,
                keccak256("RESOLVER_ROLE")
            )
        );
        IManagedOOv2Like(OO).settle(REPORTER, IDENT, block.timestamp, "rules");
    }

    /// A non-whitelisted proposer is refused before any request state is read.
    function test_attackerCannotPropose() public {
        vm.prank(ATTACKER);
        vm.expectRevert(bytes4(keccak256("ProposerNotWhitelisted()")));
        IManagedOOv2Like(OO).proposePriceFor(ATTACKER, REPORTER, IDENT, block.timestamp, "rules", 1e18);
    }

    /// `updateRequestRules` answers with its own error, which proves the live implementation
    /// carries the V2 API the deployed reporter calls. A missing function would revert empty.
    function test_liveOracleExposesV2RequestRulesApi() public {
        vm.prank(ATTACKER);
        vm.expectRevert(bytes4(keccak256("RequesterNotWhitelisted()")));
        IManagedOOv2Like(OO).updateRequestRules(IDENT, "rules", "updated");
    }

    /*──────────────────────── attacker profitability (the honest part) ─────────────────────*/

    /// The reporter and the oracle both hold real value, so "no impact" is a claim about
    /// reachability, not about an empty target. Balances are read from live state.
    function test_valueAtStakeIsReal() public view {
        assertGt(USDC_E.balanceOf(OO), 0, "oracle holds no collateral");
        assertGt(USDC_E.balanceOf(REPORTER), 0, "reporter holds no reward float");
    }
}
