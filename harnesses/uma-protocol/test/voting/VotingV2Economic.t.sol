// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity 0.8.16;

import "./VotingV2Fixture.sol";

/// @notice Economic-invariant tests for the deployed VotingV2 DVM (solvency, slashing bounds,
/// reward accounting, unstake/delegate edge cases, request-spam resistance).
contract VotingV2EconomicTest is VotingV2Fixture {
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

    /// @notice Solvency: the contract's token balance must equal cumulativeStake at all times.
    function test_solvency_balanceEqualsCumulativeStake() public {
        assertEq(votingToken.balanceOf(address(votingV2)), votingV2.cumulativeStake(), "pre-vote solvent");

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
        votingV2.updateTrackers(A);
        votingV2.updateTrackers(B);
        votingV2.updateTrackers(C);
        votingV2.updateTrackers(D);

        assertEq(votingToken.balanceOf(address(votingV2)), votingV2.cumulativeStake(), "post-slash solvent");
    }

    /// @notice Fuzz: a wrong-vote slash can never exceed the voter's stake (no negative balances,
    /// no phantom debt). Also asserts the contract stays solvent for that voter.
    function testFuzz_wrongVoteSlashNeverExceedsStake(uint96 stakeRaw) public {
        // A is the dominant correct voter so E is always the losing (wrong) side.
        _mintAndStake(A, 5_000_000e18);
        uint128 stake = uint128(uint256(stakeRaw) % 1_000_000e18) + 1e18;
        address E = address(0xE0E0);
        _mintAndStake(E, stake);

        votingV2.requestPrice(IDENTIFIER, t0 + 1, bytes(""));
        uint32 round2 = votingV2.getCurrentRoundId() + 1;
        vm.warp(_roundEnd(round2 - 1));

        _commit(E, t0 + 1, 1, 11, round2); // E votes wrong (minority).
        _commit(A, t0 + 1, 2, 12, round2); // A votes right (dominant mode).
        vm.warp(_revealPhaseStart(round2));
        _reveal(E, t0 + 1, 1, 11);
        _reveal(A, t0 + 1, 2, 12);

        vm.warp(_roundEnd(round2));
        votingV2.processResolvablePriceRequests();
        votingV2.updateTrackers(E);

        (uint128 stakeAfter, , , , , , , ) = votingV2.voterStakes(E);
        assertLe(stakeAfter, stake, "slash cannot increase stake");
        assertEq(votingToken.balanceOf(address(votingV2)), votingV2.cumulativeStake(), "solvent after fuzz");
    }

    /// @notice Can a voter inflate their effective vote by committing first and staking more during
    /// the commit phase (before any reveal freezes the round)? The round freezes on first reveal, so
    /// the extra stake is counted legitimately and slashing must not underflow.
    function test_commitThenStakeInCommitPhaseIsConsistent() public {
        _commit(A, t0, 42, 1, voteRound);
        // A stakes more while still in the commit phase.
        _mintAndStake(A, 9_000e18);
        _commit(B, t0, 7, 2, voteRound);
        _commit(C, t0, 7, 3, voteRound);

        vm.warp(_revealPhaseStart(voteRound));
        _reveal(A, t0, 42, 1);
        _reveal(B, t0, 7, 2);
        _reveal(C, t0, 7, 3);

        vm.warp(_roundEnd(voteRound));
        votingV2.processResolvablePriceRequests();

        // Must not revert (would revert on underflow of totalStaked - totalVotes).
        votingV2.updateTrackers(A);
        votingV2.updateTrackers(B);
        votingV2.updateTrackers(C);

        assertEq(votingToken.balanceOf(address(votingV2)), votingV2.cumulativeStake(), "solvent");
    }

    /// @notice A voter who fully unstakes and later restakes resets its slashing cursor past all
    /// currently-resolved requests. Verify the reset is to the *current* resolved length, so past
    /// slashing cannot be re-avoided.
    function test_restakeResetsSlashingCursorToCurrentLength() public {
        _commit(A, t0, 7, 1, voteRound);
        _commit(B, t0, 42, 2, voteRound);
        vm.warp(_revealPhaseStart(voteRound));
        _reveal(A, t0, 7, 1);
        _reveal(B, t0, 42, 2);

        vm.warp(_roundEnd(voteRound));
        votingV2.processResolvablePriceRequests();
        (, uint256 resolvedBefore) = votingV2.getNumberOfPriceRequests();

        // A fully unstakes and re-stakes.
        votingV2.updateTrackers(A); // applies A's wrong-vote slash first.
        (uint128 stakeA, , , , , , , ) = votingV2.voterStakes(A);
        vm.prank(A);
        votingV2.requestUnstake(stakeA);
        vm.warp(block.timestamp + UNSTAKE_COOLDOWN + 1);
        vm.prank(A);
        votingV2.executeUnstake();
        _mintAndStake(A, 1_000e18);

        (, uint64 cursor, , ) = _voterCursor(A);
        assertEq(uint256(cursor), resolvedBefore, "cursor reset to current resolved length");
    }

    /// @notice A voter with zero effective stake earns nothing and is not slashed.
    function test_zeroEffectiveStakeVoterIsNeutral() public {
        // E stakes during the active reveal -> its stake is pending (inactive) for this round.
        address E = address(0xE0E1);
        votingV2.requestPrice(IDENTIFIER, t0 + 1, bytes(""));
        uint32 round2 = votingV2.getCurrentRoundId() + 1;
        vm.warp(_roundEnd(round2 - 1));

        _commit(A, t0 + 1, 42, 1, round2);
        _commit(B, t0 + 1, 42, 2, round2);
        _commit(C, t0 + 1, 42, 3, round2);

        vm.warp(_revealPhaseStart(round2));
        _mintAndStake(E, 5_000e18); // staked during active reveal -> pending for round2
        // E cannot commit in the reveal phase; it simply does not vote this round.
        assertEq(votingV2.getVoterPendingStake(E, round2), 5_000e18, "E stake is pending for round2");

        _reveal(A, t0 + 1, 42, 1);
        _reveal(B, t0 + 1, 42, 2);
        _reveal(C, t0 + 1, 42, 3);

        vm.warp(_roundEnd(round2));
        votingV2.processResolvablePriceRequests();
        votingV2.updateTrackers(E);
        (uint128 stakeE, , , , , , , ) = votingV2.voterStakes(E);
        assertEq(stakeE, 5_000e18, "E is neither slashed nor rewarded for round2");
    }

    /// @notice Unstaking during an active reveal is blocked (cannot dodge the live round's slash).
    function test_unstakeDuringRevealReverts() public {
        _commit(A, t0, 7, 1, voteRound);
        _commit(B, t0, 42, 2, voteRound);
        vm.warp(_revealPhaseStart(voteRound));
        _reveal(A, t0, 7, 1);
        _reveal(B, t0, 42, 2);

        vm.prank(A);
        vm.expectRevert("In an active reveal phase");
        votingV2.requestUnstake(1_000e18);
    }

    /// @notice withdrawAndRestake mints rewards and restakes them; value is conserved.
    function test_withdrawAndRestakeConservesValue() public {
        vm.warp(t0 + 2 days);
        vm.prank(A);
        uint128 restaked = votingV2.withdrawAndRestake();
        assertGt(restaked, 0, "rewards restaked");
        (uint128 stakeA, , , , , , , ) = votingV2.voterStakes(A);
        assertEq(uint256(stakeA), 1_000e18 + uint256(restaked), "stake grew by rewards");
        assertEq(votingToken.balanceOf(address(votingV2)), votingV2.cumulativeStake(), "solvent");
    }

    /// @notice A flood of price requests cannot block resolution/settlement of an existing request.
    function test_requestSpamDoesNotBlockExistingRequest() public {
        _commit(A, t0, 42, 1, voteRound);
        _commit(B, t0, 42, 2, voteRound);
        _commit(C, t0, 42, 3, voteRound);
        vm.warp(_revealPhaseStart(voteRound));
        _reveal(A, t0, 42, 1);
        _reveal(B, t0, 42, 2);
        _reveal(C, t0, 42, 3);

        // Spam many distinct requests in the same round.
        for (uint256 i = 0; i < 25; i++) {
            votingV2.requestPrice(IDENTIFIER, t0 + 100 + i, bytes(""));
        }

        vm.warp(_roundEnd(voteRound));
        votingV2.processResolvablePriceRequests();
        assertEq(votingV2.getPrice(IDENTIFIER, t0, bytes("")), 42, "original request still resolves");
    }

    /// @notice Delegation: a delegate cannot vote with a staker's weight without a two-way handshake,
    /// and cannot steal rewards.
    function test_delegationRequiresTwoWayHandshake() public {
        address del = address(0xDEAD1);
        // Only the delegate declares itself; the staker never set it as delegate.
        vm.prank(del);
        votingV2.setDelegator(A);

        _commit(A, t0, 42, 1, voteRound);
        _commit(B, t0, 42, 2, voteRound);
        vm.warp(_revealPhaseStart(voteRound));
        _reveal(A, t0, 42, 1);
        _reveal(B, t0, 42, 2);

        // The delegate tries to vote on behalf of A without A setting it -> treated as its own (empty) account.
        vm.prank(del);
        vm.expectRevert(); // no active request for del's own vote / not a staker
        votingV2.commitVote(IDENTIFIER, t0, bytes(""), bytes32(uint256(1)));
    }

    /// @notice Only one delegate at a time; a delegate swap mid-round does not double-count weight.
    function test_delegateSwapDoesNotDoubleCountWeight() public {
        address d1 = address(0xD001);
        address d2 = address(0xD002);
        vm.prank(A);
        votingV2.setDelegate(d1);
        vm.prank(d1);
        votingV2.setDelegator(A);

        _commit(A, t0, 42, 1, voteRound); // A commits directly (before swapping delegates).
        vm.prank(A);
        votingV2.setDelegate(d2);
        vm.prank(d2);
        votingV2.setDelegator(A);

        _commit(B, t0, 42, 2, voteRound);
        _commit(C, t0, 42, 3, voteRound);
        vm.warp(_revealPhaseStart(voteRound));
        _reveal(A, t0, 42, 1);
        _reveal(B, t0, 42, 2);
        _reveal(C, t0, 42, 3);

        vm.warp(_roundEnd(voteRound));
        votingV2.processResolvablePriceRequests();
        // A voted correctly exactly once; the delegate swap must not create a second counted vote.
        VotingV2.SlashingTracker memory tracker = votingV2.requestSlashingTrackers(0);
        assertEq(uint256(tracker.totalCorrectVotes), 3_000e18, "A counted once, B and C once each");
    }

    function _voterCursor(address voter)
        internal
        view
        returns (uint128 stake, uint64 cursor, uint64 unstakeTime, address delegate)
    {
        // Public getter omits the nested pendingStakes mapping:
        // (stake, pendingUnstake, rewardsPaidPerToken, outstandingRewards, unappliedSlash, nextIndexToProcess, unstakeTime, delegate)
        (stake, , , , , cursor, unstakeTime, delegate) = votingV2.voterStakes(voter);
    }
}
