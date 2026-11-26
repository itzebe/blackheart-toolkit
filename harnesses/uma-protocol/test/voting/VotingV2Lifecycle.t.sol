// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity 0.8.16;

import "./VotingV2Fixture.sol";

/// @notice Basic lifecycle + economic-invariant tests for the deployed VotingV2 (Staker + DVM).
contract VotingV2LifecycleTest is VotingV2Fixture {
    address internal constant V1 = address(0xB0B1);
    address internal constant V2 = address(0xB0B2);
    address internal constant V3 = address(0xB0B3);

    uint256 internal t0;

    function setUp() public {
        t0 = 200 * uint256(PHASE_LENGTH) * 2; // round 200, phase 0 (commit).
        vm.warp(t0);
        _deployDvm();
        _registerRequester(address(this));
    }

    function _roundEnd(uint32 roundId) internal pure returns (uint256) {
        return (uint256(roundId) + 1) * uint256(PHASE_LENGTH) * 2;
    }

    function test_stakeAndWithdrawRewards() public {
        _mintAndStake(V1, 1_000e18);

        // Accrue some rewards over a day, then withdraw.
        vm.warp(t0 + 1 days);
        vm.prank(V1);
        uint128 rewards = votingV2.withdrawRewards();

        assertGt(rewards, 0, "rewards should accrue");
        assertEq(votingToken.balanceOf(V1), rewards, "voter receives minted rewards");
        assertEq(votingV2.cumulativeStake(), 1_000e18, "stake unchanged");
    }

    function test_requestResolveAndSlashing() public {
        _mintAndStake(V1, 1_000e18);
        _mintAndStake(V2, 1_000e18);
        _mintAndStake(V3, 1_000e18);

        // Request a price. It will be voted on in the next round (currentRound + 1).
        votingV2.requestPrice(IDENTIFIER, t0, bytes(""));
        uint32 voteRound = votingV2.getCurrentRoundId() + 1;

        // Move to the commit phase of the voting round.
        vm.warp(_roundEnd(voteRound - 1)); // start of voteRound (phase 0, commit).
        assertEq(votingV2.getCurrentRoundId(), voteRound, "round check");
        assertEq(uint256(votingV2.getVotePhase()), 0, "commit phase");

        _commit(V1, t0, 42, 1, voteRound);
        _commit(V2, t0, 42, 2, voteRound);
        _commit(V3, t0, 7, 3, voteRound);

        // Move to reveal phase.
        vm.warp(t0 + uint256(PHASE_LENGTH) * (2 * (voteRound - 200) + 1));
        assertEq(uint256(votingV2.getVotePhase()), 1, "reveal phase");

        _reveal(V1, t0, 42, 1);
        _reveal(V2, t0, 42, 2);
        _reveal(V3, t0, 7, 3);

        // Move past the round and process.
        vm.warp(_roundEnd(voteRound));
        votingV2.processResolvablePriceRequests();

        (uint256 pending, uint256 resolved) = votingV2.getNumberOfPriceRequests();
        assertEq(resolved, 1, "request resolved");
        assertEq(pending, 0, "no pending");

        assertEq(votingV2.getPrice(IDENTIFIER, t0, bytes("")), 42, "modal price");

        // V3 voted wrong -> should be slashable; V1/V2 correct -> rewarded with the slash.
        votingV2.updateTrackers(V3);
        (uint128 stakeV3, , , , , , , ) = votingV2.voterStakes(V3);
        assertLt(stakeV3, 1_000e18, "wrong voter slashed");
        votingV2.updateTrackers(V1);
        (uint128 stakeV1, , , , , , , ) = votingV2.voterStakes(V1);
        assertGt(stakeV1, 1_000e18, "correct voter rewarded");
    }
}
