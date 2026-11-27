// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity 0.8.16;

import {Test} from "forge-std/Test.sol";
import {VotingV2} from "uma/data-verification-mechanism/implementation/VotingV2.sol";
import {VotingToken} from "uma/data-verification-mechanism/implementation/VotingToken.sol";
import {Finder} from "uma/data-verification-mechanism/implementation/Finder.sol";
import {Registry} from "uma/data-verification-mechanism/implementation/Registry.sol";
import {IdentifierWhitelist} from "uma/data-verification-mechanism/implementation/IdentifierWhitelist.sol";
import {FixedSlashSlashingLibrary} from "uma/data-verification-mechanism/implementation/FixedSlashSlashingLibrary.sol";

/// @notice Tests the suspected stale `pendingStakes` underflow against the unmodified VotingV2.
///         No storage is forced and no production contract is modified: every state transition is
///         reached through the protocol's own functions.
contract PendingStakesTest is Test {
    uint64 constant PHASE = 1000;
    uint256 constant ROUND = uint256(PHASE) * 2;
    uint256 constant S = 100e18;
    uint128 constant GAT = 1e18;
    uint64 constant SPAT = 5e17; // 50%

    VotingToken token;
    Finder finder;
    Registry registry;
    IdentifierWhitelist ids;
    VotingV2 voting;

    address victim = address(0xB0B);
    address attacker = address(0xBAD);
    bytes32 constant ID = "TEST_IDENTIFIER";

    function setUp() public {
        vm.warp(10 * ROUND);

        token = new VotingToken();
        finder = new Finder();
        registry = new Registry();
        ids = new IdentifierWhitelist();
        FixedSlashSlashingLibrary slash = new FixedSlashSlashingLibrary(1e16, 1e16);

        token.addMember(1, address(this)); // Minter
        token.mint(address(this), 10_000_000e18);
        token.mint(victim, S * 4);
        token.mint(attacker, S);

        registry.addMember(1, address(this)); // ContractCreator
        registry.registerContract(new address[](0), address(this));

        finder.changeImplementationAddress(bytes32("Registry"), address(registry));
        finder.changeImplementationAddress(bytes32("IdentifierWhitelist"), address(ids));
        ids.addSupportedIdentifier(ID);

        voting = new VotingV2(
            0,
            0,
            PHASE,
            5,
            100,
            GAT,
            SPAT,
            address(token),
            address(finder),
            address(slash),
            address(0)
        );

        vm.prank(victim);
        token.approve(address(voting), type(uint256).max);
        vm.prank(attacker);
        token.approve(address(voting), type(uint256).max);
    }

    /* ----------------------------- helpers ----------------------------- */

    function _commitStart(uint256 r) internal pure returns (uint256) {
        return r * ROUND;
    }

    function _revealStart(uint256 r) internal pure returns (uint256) {
        return r * ROUND + PHASE;
    }

    function _createRequest(uint256 voteRound, uint256 time) internal {
        vm.warp(_commitStart(voteRound - 1) + 1);
        voting.requestPrice(ID, time, "");
    }

    function _commit(address voter, uint32 roundId, uint256 time, int256 price, int256 salt) internal {
        bytes32 hash = keccak256(abi.encodePacked(price, salt, voter, time, bytes(""), uint256(roundId), ID));
        vm.prank(voter);
        voting.commitVote(ID, time, "", hash);
    }

    function _reveal(address voter, uint256 time, int256 price, int256 salt) internal {
        vm.prank(voter);
        voting.revealVote(ID, time, price, "", salt);
    }

    function _stakeOf(address who) internal view returns (uint128) {
        (uint128 stake,,,,,,,) = voting.voterStakes(who);
        return stake;
    }

    function _pendingUnstakeOf(address who) internal view returns (uint128) {
        (, uint128 pending,,,,,,) = voting.voterStakes(who);
        return pending;
    }

    function _cumulativeStakeAtRound(uint256 r) internal view returns (uint128) {
        (,,, uint128 cum,) = voting.rounds(r);
        return cum;
    }

    /* -------------------- Test 1: normal lifecycle --------------------- */

    function test_1_normal_lifecycle_has_no_stale_pending_stake() public {
        vm.prank(victim);
        voting.stake(uint128(S));

        uint256 time = 1000;
        _createRequest(12, time);

        vm.warp(_commitStart(12) + 1);
        _commit(victim, 12, time, 1e18, 42);
        vm.warp(_revealStart(12) + 1);
        _reveal(victim, time, 1e18, 42);

        vm.warp(_commitStart(13) + 1);
        voting.processResolvablePriceRequests();
        assertTrue(voting.resolvedPriceRequestIds(0) != bytes32(0), "request resolved");

        vm.prank(victim);
        voting.requestUnstake(uint128(S));
        assertEq(uint256(_stakeOf(victim)), 0, "stake moved out");
        assertEq(uint256(_pendingUnstakeOf(victim)), S, "pending unstake recorded");

        voting.updateTrackers(victim);
        vm.prank(victim);
        voting.executeUnstake();
        assertEq(token.balanceOf(victim), S * 4, "principal returned");
        assertEq(voting.getVoterPendingStake(victim, 12), 0, "no stale pending stake");
    }

    /* ----------------- Test 2: third-party stakeTo --------------------- */

    function test_2_third_party_stakeTo_during_reveal() public {
        vm.prank(victim);
        voting.stake(uint128(S));

        uint256 time = 1000;
        _createRequest(12, time);

        vm.warp(_commitStart(12) + 1);
        _commit(victim, 12, time, 1e18, 42);

        vm.warp(_revealStart(12) + 1);
        vm.prank(attacker);
        voting.stakeTo(victim, 1);

        assertEq(voting.getVoterPendingStake(victim, 12), 1, "pendingStakes[R] incremented");
        assertEq(uint256(_stakeOf(victim)), S + 1, "stake incremented");
        assertEq(uint256(_cumulativeStakeAtRound(12)), S, "round aggregate excludes the reveal stake");
    }

    /* ----------------- Test 3: rolled request ordering ----------------- */

    function test_3_active_request_does_not_block_later_resolution() public {
        vm.prank(victim);
        voting.stake(uint128(S));

        _createRequest(12, 1000);
        _createRequest(12, 2000);

        vm.warp(_commitStart(12) + 1);
        _commit(victim, 12, 2000, 1e18, 42);
        vm.warp(_revealStart(12) + 1);
        _reveal(victim, 2000, 1e18, 42);

        vm.warp(_commitStart(13) + 1);
        voting.processResolvablePriceRequests();

        (uint256 pending, uint256 resolved) = voting.getNumberOfPriceRequests();
        assertEq(resolved, 1, "later request resolved despite the earlier Active one");
        assertEq(pending, 1, "the unvoted request stays pending");
    }

    /* --------------- Test 4: underflow attempt, resolvable ------------- */

    function test_4_underflow_attempt_resolvable_round_does_not_revert() public {
        vm.prank(victim);
        voting.stake(uint128(S));

        uint256 time = 1000;
        _createRequest(12, time);

        vm.warp(_commitStart(12) + 1);
        _commit(victim, 12, time, 1e18, 42);

        vm.warp(_revealStart(12) + 1);
        vm.prank(attacker);
        voting.stakeTo(victim, 1);
        _reveal(victim, time, 1e18, 42);

        // Victim holds stake S+1 with pendingStakes[12] == 1 and unstakes everything.
        vm.warp(_commitStart(13) + 1);

        // Round 12 has not been processed yet when the unstake begins.
        (, uint256 resolvedBefore) = voting.getNumberOfPriceRequests();
        assertEq(resolvedBefore, 0, "round 12 not yet in resolvedPriceRequestIds");

        vm.prank(victim);
        voting.requestUnstake(uint128(S + 1));

        // requestUnstake's _updateTrackers resolved round 12 and applied the slash before the
        // stake could move. This is the exact ordering that prevents the underflow.
        (, uint256 resolvedAfter) = voting.getNumberOfPriceRequests();
        assertEq(resolvedAfter, 1, "round 12 processed inside requestUnstake");

        assertEq(uint256(_stakeOf(victim)), 0, "stake reduced to zero");
        assertEq(uint256(_pendingUnstakeOf(victim)), S + 1, "full amount pending");

        // The tracker must not underflow: round 12 was resolved and processed first.
        voting.updateTrackers(victim);
        vm.prank(victim);
        voting.executeUnstake();
        assertEq(token.balanceOf(victim), S * 4 + 1, "principal plus the attacker gift returned");
    }

    /* ----------------- Test 4b: underflow attempt, rolled -------------- */

    function test_4b_underflow_attempt_rolled_round_does_not_revert() public {
        vm.prank(victim);
        voting.stake(uint128(S));

        uint256 time = 1000;
        _createRequest(12, time);

        // Nobody votes: the request cannot resolve and must roll.
        vm.warp(_revealStart(12) + 1);
        vm.prank(attacker);
        voting.stakeTo(victim, 1);

        vm.warp(_commitStart(13) + 1);
        vm.prank(victim);
        voting.requestUnstake(uint128(S + 1));

        assertEq(uint256(_stakeOf(victim)), 0, "stake reduced to zero");
        voting.updateTrackers(victim); // must not revert
        voting.processResolvablePriceRequests();
        voting.updateTrackers(victim);
        (, uint256 resolved) = voting.getNumberOfPriceRequests();
        assertEq(resolved, 0, "unvoted request never resolved");
    }

    /* -------------------- Test 5: no permanent lock -------------------- */

    function test_5_no_permanent_lock_after_attempt() public {
        vm.prank(victim);
        voting.stake(uint128(S));

        uint256 time = 1000;
        _createRequest(12, time);
        vm.warp(_commitStart(12) + 1);
        _commit(victim, 12, time, 1e18, 42);
        vm.warp(_revealStart(12) + 1);
        vm.prank(attacker);
        voting.stakeTo(victim, 1);
        _reveal(victim, time, 1e18, 42);

        vm.warp(_commitStart(13) + 1);
        vm.prank(victim);
        voting.requestUnstake(uint128(S + 1));

        // Every operation named in the hypothesis must still work.
        voting.updateTrackers(victim);
        voting.updateTrackersRange(victim, 10);
        vm.prank(victim);
        voting.withdrawRewards();
        vm.prank(victim);
        voting.executeUnstake();
        vm.prank(victim);
        voting.stake(uint128(S));
        assertEq(uint256(_stakeOf(victim)), S, "can stake again");
    }

    /* ---------------------- Test 6: control case ----------------------- */

    function test_6_control_without_third_party_stake() public {
        vm.prank(victim);
        voting.stake(uint128(S));
        uint256 time = 1000;
        _createRequest(12, time);
        vm.warp(_commitStart(12) + 1);
        _commit(victim, 12, time, 1e18, 42);
        vm.warp(_revealStart(12) + 1);
        _reveal(victim, time, 1e18, 42);

        vm.warp(_commitStart(13) + 1);
        voting.processResolvablePriceRequests();
        vm.prank(victim);
        voting.requestUnstake(uint128(S));
        voting.updateTrackers(victim);
        assertEq(uint256(_stakeOf(victim)), 0);
    }

    /* ------------------- Test 7: boundary conditions ------------------- */

    function test_7a_exact_equality_stake_equals_pending() public {
        vm.prank(victim);
        voting.stake(uint128(S));
        uint256 time = 1000;
        _createRequest(12, time);
        vm.warp(_commitStart(12) + 1);
        _commit(victim, 12, time, 1e18, 42);
        vm.warp(_revealStart(12) + 1);
        vm.prank(attacker);
        voting.stakeTo(victim, uint128(S)); // pendingStakes[12] == S == original stake
        _reveal(victim, time, 1e18, 42);

        assertEq(voting.getVoterPendingStake(victim, 12), S, "pending equals original stake");

        vm.warp(_commitStart(13) + 1);
        vm.prank(victim);
        voting.requestUnstake(uint128(2 * S));
        voting.updateTrackers(victim);
        assertEq(uint256(_stakeOf(victim)), 0);
    }

    function test_7b_sufficient_remaining_stake() public {
        vm.prank(victim);
        voting.stake(uint128(S));
        uint256 time = 1000;
        _createRequest(12, time);
        vm.warp(_commitStart(12) + 1);
        _commit(victim, 12, time, 1e18, 42);
        vm.warp(_revealStart(12) + 1);
        vm.prank(attacker);
        voting.stakeTo(victim, 1);
        _reveal(victim, time, 1e18, 42);

        vm.warp(_commitStart(13) + 1);
        vm.prank(victim);
        voting.requestUnstake(uint128(S - 1)); // leaves 2 > pendingStakes[12] == 1
        voting.updateTrackers(victim);
        assertEq(uint256(_stakeOf(victim)), 2);
    }
}
