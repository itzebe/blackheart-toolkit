// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity 0.8.16;

import "./VotingV2Fixture.sol";

/// @notice Targeted probes for the `pendingStakes` slashing-avoidance hypothesis: a voter that staked
/// during an active reveal records a pending stake for that round; if the record survives a later
/// unstake/restake, a subsequent traversal of the same round's request would under-count the
/// effective stake and reduce the voter's slash.
contract VotingV2PendingStakesTest is VotingV2Fixture {
    address internal constant A = address(0xAAA1);
    address internal constant B = address(0xAAA2);
    address internal constant E = address(0xEEE1);

    uint256 internal t0;

    function setUp() public {
        t0 = 200 * uint256(PHASE_LENGTH) * 2;
        vm.warp(t0);
        _deployDvm();
        _registerRequester(address(this));
        // Lower the unstake cooldown so we can cycle stake quickly.
        vm.prank(OWNER);
        votingV2.setUnstakeCoolDown(0);
        _mintAndStake(A, 10_000_000e18);
        _mintAndStake(B, 10_000_000e18);
    }

    function _roundEnd(uint32 roundId) internal pure returns (uint256) {
        return (uint256(roundId) + 1) * uint256(PHASE_LENGTH) * 2;
    }

    function _revealPhaseStart(uint32 roundId) internal pure returns (uint256) {
        return (uint256(roundId) * 2 + 1) * uint256(PHASE_LENGTH);
    }

    /// @notice E stakes during the active reveal of round R (pending recorded). E then tries to cycle
    /// its stake so that a later traversal of round R's request under-counts E's effective stake.
    /// Expectation: the ordering of `_getStartingIndexForStaker` (which processes resolvable requests
    /// before the cursor is set) prevents the under-count; E is slashed on its full effective stake.
    function test_stalePendingStakeCannotReduceSlash() public {
        // Request voted on in round R.
        votingV2.requestPrice(IDENTIFIER, t0, bytes(""));
        uint32 roundR = votingV2.getCurrentRoundId() + 1;
        vm.warp(_roundEnd(roundR - 1)); // commit phase of round R

        // E is present with a base stake of 1_000_000.
        _mintAndStake(E, 1_000_000e18);

        // A and B vote correctly in round R (they dominate the mode).
        _commit(A, t0, 42, 1, roundR);
        _commit(B, t0, 42, 2, roundR);

        // Reveal phase of round R: E stakes a large pending amount and does NOT vote (no commit).
        vm.warp(_revealPhaseStart(roundR));
        _mintAndStake(E, 5_000_000e18); // pendingStakes[roundR] = 5_000_000e18
        assertEq(votingV2.getVoterPendingStake(E, roundR), 5_000_000e18, "pending recorded");

        _reveal(A, t0, 42, 1);
        _reveal(B, t0, 42, 2);

        // Round R ends. E now cycles its stake: unstake everything, then restake a smaller amount.
        // requestUnstake internally processes resolvable requests, which resolves round R's request
        // BEFORE E's cursor is reset, so E is slashed on the full effective stake.
        vm.warp(_roundEnd(roundR));
        votingV2.processResolvablePriceRequests();
        (, uint256 resolvedAfterR) = votingV2.getNumberOfPriceRequests();

        (uint128 stakeE, , , , , , , ) = votingV2.voterStakes(E);
        vm.prank(E);
        votingV2.updateTrackers(E); // apply the round-R no-vote slash first
        (stakeE, , , , , , , ) = votingV2.voterStakes(E);
        vm.prank(E);
        votingV2.requestUnstake(stakeE);
        vm.prank(E);
        votingV2.executeUnstake();

        // E restakes a small amount. The cursor resets to the current resolved length, past round R's request.
        _mintAndStake(E, 100_000e18);
        (, uint64 cursor, , ) = _voterCursor(E);
        emit log_named_uint("resolved length after round R", resolvedAfterR);
        emit log_named_uint("E cursor after restake", uint256(cursor));
        assertEq(uint256(cursor), resolvedAfterR, "cursor reset past the resolved round-R request");

        // E is not slashed for round R (its cursor skipped it), which is the intended behaviour for a
        // full exit; crucially no stale pending stake is ever subtracted from the new stake.
        votingV2.updateTrackers(E);
        (uint128 stakeE2, , , , , , , ) = votingV2.voterStakes(E);
        assertEq(stakeE2, 100_000e18, "no stale-pending under-count on the new epoch");
    }

    /// @notice Direct probe: a voter with a pending stake for round R and a *smaller* current stake
    /// must not have its effective stake silently floored by subtraction (would be an under-slash).
    /// We verify the slashing math against the effective stake for a plain no-vote with no pending.
    function test_noVoteSlashUsesFullStakeWithoutPending() public {
        votingV2.requestPrice(IDENTIFIER, t0, bytes(""));
        uint32 roundR = votingV2.getCurrentRoundId() + 1;
        vm.warp(_roundEnd(roundR - 1));

        _mintAndStake(E, 1_000_000e18);
        _commit(A, t0, 42, 1, roundR);
        _commit(B, t0, 42, 2, roundR);

        vm.warp(_revealPhaseStart(roundR));
        _reveal(A, t0, 42, 1);
        _reveal(B, t0, 42, 2);

        vm.warp(_roundEnd(roundR));
        votingV2.processResolvablePriceRequests();
        votingV2.updateTrackers(E);

        (uint128 stakeE, , , , , , , ) = votingV2.voterStakes(E);
        // E did not vote: slashed at BASE_SLASH (16%) on its full 1_000_000 stake.
        assertEq(stakeE, 1_000_000e18 - (1_000_000e18 * BASE_SLASH) / 1e18, "full-stake no-vote slash");
    }

    function _voterCursor(address voter)
        internal
        view
        returns (uint128 stake, uint64 cursor, uint64 unstakeTime, address delegate)
    {
        (stake, , , , , cursor, unstakeTime, delegate) = votingV2.voterStakes(voter);
    }
}
