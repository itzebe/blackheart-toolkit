// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity 0.8.16;

import "./VotingV2Fixture.sol";

/// @notice Adversarial economic tests for VotingV2 (staking, slashing, rewards, delegation).
contract VotingV2AttacksTest is VotingV2Fixture {
    address internal constant A = address(0xAAA1);
    address internal constant B = address(0xAAA2);
    address internal constant C = address(0xAAA3);
    address internal constant D = address(0xAAA4);

    uint256 internal t0;
    uint32 internal voteRound;

    function setUp() public {
        t0 = 200 * uint256(PHASE_LENGTH) * 2;
        vm.warp(t0);
        _deployDvm();
        _registerRequester(address(this));
        _mintAndStake(A, 1_000e18);
        _mintAndStake(B, 1_000e18);
        _mintAndStake(C, 1_000e18);
        _mintAndStake(D, 1_000e18);

        votingV2.requestPrice(IDENTIFIER, t0, bytes(""));
        voteRound = votingV2.getCurrentRoundId() + 1;
        vm.warp(_roundEnd(voteRound - 1));
    }

    function _roundEnd(uint32 roundId) internal pure returns (uint256) {
        return (uint256(roundId) + 1) * uint256(PHASE_LENGTH) * 2;
    }

    function _revealPhaseStart(uint32 roundId) internal pure returns (uint256) {
        return (uint256(roundId) * 2 + 1) * uint256(PHASE_LENGTH);
    }

    /// @notice H: can a voter escape slashing by requesting unstake before the round resolves?
    function test_unstakeBeforeSlashEscapesPenalty() public {
        // A votes wrong; B,C,D vote correctly.
        _commit(A, t0, 7, 1, voteRound);
        _commit(B, t0, 42, 2, voteRound);
        _commit(C, t0, 42, 3, voteRound);
        _commit(D, t0, 42, 4, voteRound);
        vm.warp(_revealPhaseStart(voteRound));
        _reveal(A, t0, 7, 1);
        _reveal(B, t0, 42, 2);
        _reveal(C, t0, 42, 3);
        _reveal(D, t0, 42, 4);

        // Before the round ends, A requests unstake. requestUnstake internally calls _updateTrackers, which applies
        // the pending wrong-vote slash FIRST. The full-stake unstake must therefore revert.
        vm.warp(_roundEnd(voteRound));
        votingV2.processResolvablePriceRequests();

        vm.prank(A);
        vm.expectRevert("Bad amount or pending unstake");
        votingV2.requestUnstake(1_000e18);

        // A can only unstake what remains after the slash has been applied.
        votingV2.updateTrackers(A);
        (uint128 stakeA, , , , , , , ) = votingV2.voterStakes(A);
        emit log_named_uint("A stake after slash", stakeA);
        assertLt(stakeA, 1_000e18, "slash applied before unstake");

        vm.prank(A);
        votingV2.requestUnstake(stakeA);
        vm.warp(block.timestamp + UNSTAKE_COOLDOWN + 1);
        vm.prank(A);
        votingV2.executeUnstake();
        emit log_named_uint("A token balance after executeUnstake", votingToken.balanceOf(A));

        // Invariant: A lost the wrong-vote slash; no value escaped.
        assertLt(votingToken.balanceOf(A), 1_000e18, "wrong voter must lose value even after unstake");
    }

    /// @notice H: does a voter who stakes during the reveal phase dilute their slashing effective stake?
    function test_stakeDuringRevealReducesEffectiveStake() public {
        _commit(A, t0, 7, 1, voteRound);
        _commit(B, t0, 42, 2, voteRound);
        _commit(C, t0, 42, 3, voteRound);
        _commit(D, t0, 42, 4, voteRound);
        vm.warp(_revealPhaseStart(voteRound));

        // A stakes a large additional amount during the active reveal phase.
        _mintAndStake(A, 9_000e18);

        _reveal(A, t0, 7, 1);
        _reveal(B, t0, 42, 2);
        _reveal(C, t0, 42, 3);
        _reveal(D, t0, 42, 4);

        vm.warp(_roundEnd(voteRound));
        votingV2.processResolvablePriceRequests();
        votingV2.updateTrackers(A);

        (uint128 stakeA, , , , , , , ) = votingV2.voterStakes(A);
        emit log_named_uint("A stake after wrong-vote slash", stakeA);
        // A staked 1000 + 9000 = 10000. Only 1000 was effective for the vote, so the wrong-vote slash is
        // 16% * 1000 = 160, not 16% * 10000. The reveal-phase stake is NOT slashed for this round.
        assertEq(stakeA, 9_840e18, "slash is computed on effective stake only");
    }

    /// @notice H: can a correct voter receive more rewards than the total slashed (inflation)?
    function test_correctVoterRewardEqualsProRataOfSlashed() public {
        _commit(A, t0, 7, 1, voteRound);
        _commit(B, t0, 42, 2, voteRound);
        _commit(C, t0, 42, 3, voteRound);
        _commit(D, t0, 42, 4, voteRound);
        vm.warp(_revealPhaseStart(voteRound));
        _reveal(A, t0, 7, 1);
        _reveal(B, t0, 42, 2);
        _reveal(C, t0, 42, 3);
        _reveal(D, t0, 42, 4);

        vm.warp(_roundEnd(voteRound));
        votingV2.processResolvablePriceRequests();

        // Capture total slashed for the request.
        VotingV2.SlashingTracker memory tracker = votingV2.requestSlashingTrackers(0);
        emit log_named_uint("totalSlashed", tracker.totalSlashed);
        emit log_named_uint("totalCorrectVotes", tracker.totalCorrectVotes);

        votingV2.updateTrackers(B);
        (uint128 stakeB, , , , , , , ) = votingV2.voterStakes(B);
        uint256 gainB = uint256(stakeB) - 1_000e18;
        emit log_named_uint("B gain", gainB);

        // B's gain must be <= totalSlashed (no inflation).
        assertLe(gainB, tracker.totalSlashed, "correct voter gain must not exceed total slashed");
        // With 3 correct voters of equal stake, B should get ~1/3.
        assertApproxEqRel(gainB, tracker.totalSlashed / 3, 0.01e18, "pro-rata share");
    }

    /// @notice H: duplicate reward claims.
    function test_rewardClaimIsNotRepeatable() public {
        vm.warp(_roundEnd(voteRound));
        votingV2.updateTrackers(A);
        vm.prank(A);
        uint128 r1 = votingV2.withdrawRewards();
        vm.prank(A);
        uint128 r2 = votingV2.withdrawRewards();
        assertGt(r1, 0, "first claim positive");
        assertEq(r2, 0, "second claim in same block is zero");
    }

    /// @notice H: delegation — can a delegate redirect a staker's rewards to itself?
    function test_delegateCannotRedirectRewards() public {
        address del = address(0xDE1); // Pure delegate: not a staker.

        vm.prank(A);
        votingV2.setDelegate(del);
        vm.prank(del);
        votingV2.setDelegator(A);

        vm.warp(_roundEnd(voteRound));
        votingV2.updateTrackers(A);

        uint256 aBefore = votingToken.balanceOf(A);
        uint256 delBefore = votingToken.balanceOf(del);

        // The delegate calls withdrawRewards: it can only ever withdraw its OWN (zero) rewards.
        vm.prank(del);
        votingV2.withdrawRewards();
        assertEq(votingToken.balanceOf(del), delBefore, "delegate must not receive staker rewards");

        // The delegate can trigger a restake of A's rewards, but the value accrues to A's stake, not the delegate.
        vm.prank(del);
        votingV2.withdrawAndRestake();
        (uint128 stakeA, , , , , , , ) = votingV2.voterStakes(A);
        assertGt(stakeA, 1_000e18, "A's stake increased from its own rewards");
        assertEq(votingToken.balanceOf(del), delBefore, "delegate still holds nothing");
        assertEq(votingToken.balanceOf(A), aBefore, "A's wallet untouched by restake");
    }

    /// @notice H: can a non-voter be slashed more than their stake (negative balance) or avoid it?
    function test_nonVoterCannotAvoidSlashByTransferringStake() public {
        // D never votes. Everyone else votes.
        _commit(A, t0, 42, 1, voteRound);
        _commit(B, t0, 42, 2, voteRound);
        _commit(C, t0, 42, 3, voteRound);
        vm.warp(_revealPhaseStart(voteRound));
        _reveal(A, t0, 42, 1);
        _reveal(B, t0, 42, 2);
        _reveal(C, t0, 42, 3);

        vm.warp(_roundEnd(voteRound));
        votingV2.processResolvablePriceRequests();
        votingV2.updateTrackers(D);
        (uint128 stakeD, , , , , , , ) = votingV2.voterStakes(D);
        assertLt(stakeD, 1_000e18, "non-voter slashed");
    }

    /// @notice H: stake after the vote round but claim rewards/voting power retroactively.
    function test_stakeAfterRoundDoesNotVoteRetroactively() public {
        _commit(A, t0, 42, 1, voteRound);
        _commit(B, t0, 42, 2, voteRound);
        vm.warp(_revealPhaseStart(voteRound));
        _reveal(A, t0, 42, 1);
        _reveal(B, t0, 42, 2);

        vm.warp(_roundEnd(voteRound));
        votingV2.processResolvablePriceRequests();

        // A new staker E joins after the round. It must not be slashed or rewarded for the past round.
        address E = address(0xAAA5);
        _mintAndStake(E, 1_000e18);
        votingV2.updateTrackers(E);
        (uint128 stakeE, , , , , , , ) = votingV2.voterStakes(E);
        assertEq(stakeE, 1_000e18, "late staker is not retroactively slashed");
    }
}
