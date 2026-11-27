// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {TwyneWrapperForkBase} from "./TwyneWrapperForkBase.sol";
import {console2} from "forge-std/console2.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IAToken} from "aave-v3/interfaces/IAToken.sol";
import {AaveV3ATokenWrapper} from "src/AaveV3ATokenWrapper.sol";

/// @notice Adversarial, evidence-producing tests against the *real, in-scope*
/// Twyne AaveV3 aToken wrapper, on a local mainnet fork against real Aave V3.
///
/// Each test states the hypothesis it attacks and prints the numbers it
/// measured. A test that asserts a property HOLDS is a negative result (the
/// hypothesis was disproved); a test that demonstrates a break is a candidate
/// finding to be handed to the independent verifier.
contract TwyneWrapperAdversarialTest is TwyneWrapperForkBase {
    // ------------------------------------------------------------------ //
    // H1: donation / share-inflation
    //
    // Hypothesis: an attacker can inflate the share price by donating aTokens
    // to the wrapper (or the underlying via skim) so a later depositor receives
    // fewer shares and the attacker extracts value.
    //
    // The wrapper prices shares off Aave's `getReserveNormalizedIncome` (the
    // supply index), NOT off its own aToken balance, and rejects zero-share
    // deposits. So a donation should not move the price. Disprove or confirm.
    // ------------------------------------------------------------------ //
    function test_H1_donation_does_not_move_share_price() public {
        _fund(victim, 10 ether);
        vm.prank(victim);
        wrapper.deposit(10 ether, victim);

        uint256 priceBefore = wrapper.convertToAssets(1e18);

        // Attacker donates aTokens directly to the wrapper (no shares minted).
        _supplyToAave(attacker, 50 ether);
        uint256 donated = IERC20(aWETH).balanceOf(attacker);
        vm.prank(attacker);
        IERC20(aWETH).transfer(address(wrapper), donated);

        uint256 priceAfter = wrapper.convertToAssets(1e18);
        console2.log("share price before", priceBefore);
        console2.log("share price after donation", priceAfter);
        assertEq(priceBefore, priceAfter, "donation moved the share price (should not)");

        // The donated aTokens are not reflected in totalAssets (supply-based).
        assertApproxEqRel(wrapper.totalAssets(), 10 ether, 1e15);
    }

    // ------------------------------------------------------------------ //
    // H2: share-backing solvency under many small deposits
    //
    // Hypothesis: rounding drift between the wrapper's share minting
    // (floor(assets * RAY / rate)) and Aave's aToken scaled-balance minting
    // makes totalSupply() exceed the wrapper's backed aToken scaled balance
    // after many small deposits, so the last redeemer cannot be paid.
    // ------------------------------------------------------------------ //
    function test_H2_share_backing_holds_under_many_small_deposits() public {
        uint256 n = 200;
        uint256 each = 0.01 ether;
        _fund(victim, n * each + 1 ether);

        for (uint256 i = 0; i < n; i++) {
            vm.prank(victim);
            wrapper.deposit(each, victim);
        }

        uint256 supply = wrapper.totalSupply();
        uint256 scaledHeld = IAToken(aWETH).scaledBalanceOf(address(wrapper));
        console2.log("totalSupply", supply);
        console2.log("aToken scaled held", scaledHeld);
        assertGe(scaledHeld, supply, "wrapper shares exceed backed aToken scaled balance");

        // The victim must be able to redeem every share it holds.
        vm.prank(victim);
        uint256 out = wrapper.redeem(supply, victim, victim);
        assertGt(out, 0);
    }

    // ------------------------------------------------------------------ //
    // H3: collateral-vault rebalance rounding
    //
    // Hypothesis: a registered collateral vault can repeatedly call
    // rebalanceATokens_CV() to accumulate aToken scaled balance beyond its
    // wrapper shares, i.e. leak value out of the wrapper through rounding.
    // ------------------------------------------------------------------ //
    function test_H3_rebalance_rounding_does_not_leak_value() public {
        _fund(victim, 100 ether);
        vm.prank(victim);
        wrapper.deposit(100 ether, victim);

        // Register an attacker-controlled collateral vault and give it shares.
        factory.setIsCollateralVault(attacker, true);
        _fund(attacker, 10 ether);
        vm.prank(attacker);
        uint256 shares = wrapper.deposit(10 ether, attacker);

        uint256 wrapperScaledBefore = IAToken(aWETH).scaledBalanceOf(address(wrapper));
        uint256 attackerScaledBefore = IAToken(aWETH).scaledBalanceOf(attacker);

        // Repeatedly rebalance to the attacker's share count. Each call should be
        // value-neutral for the wrapper (rounding must not favour the CV).
        for (uint256 i = 0; i < 50; i++) {
            vm.prank(attacker);
            wrapper.rebalanceATokens_CV(shares);
        }

        uint256 attackerScaledAfter = IAToken(aWETH).scaledBalanceOf(attacker);
        uint256 wrapperScaledAfter = IAToken(aWETH).scaledBalanceOf(address(wrapper));
        console2.log("attacker shares", shares);
        console2.log("attacker scaled before", attackerScaledBefore);
        console2.log("attacker scaled after", attackerScaledAfter);
        console2.log("wrapper scaled before", wrapperScaledBefore);
        console2.log("wrapper scaled after", wrapperScaledAfter);

        // The attacker must not end with more scaled aTokens than it has shares.
        assertLe(attackerScaledAfter, shares, "CV accrued aTokens beyond its shares");
    }

    // ------------------------------------------------------------------ //
    // H4: collateral-vault trust boundary
    //
    // The wrapper grants any address registered as a collateral vault the power
    // to pull aTokens out of the wrapper with no cap beyond the wrapper's
    // balance. This test documents that boundary: a registered CV that has NO
    // wrapper shares can still move the wrapper's aTokens to itself.
    //
    // Whether this is exploitable depends entirely on who can become a CV; the
    // factory registers a CV for any borrower of an allowed (intermediate
    // vault, target vault, target asset) combination. Recorded as evidence, not
    // asserted as a finding.
    // ------------------------------------------------------------------ //
    function test_H4_registered_cv_can_pull_atokens_without_shares() public {
        _fund(victim, 100 ether);
        vm.prank(victim);
        wrapper.deposit(100 ether, victim);

        factory.setIsCollateralVault(attacker, true);
        uint256 wrapperScaledBefore = IAToken(aWETH).scaledBalanceOf(address(wrapper));

        // Attacker holds ZERO wrapper shares but is a registered CV.
        assertEq(wrapper.balanceOf(attacker), 0);
        vm.prank(attacker);
        wrapper.rebalanceATokens_CV(1 ether); // request 1e18 scaled aTokens

        uint256 attackerScaledAfter = IAToken(aWETH).scaledBalanceOf(attacker);
        uint256 wrapperScaledAfter = IAToken(aWETH).scaledBalanceOf(address(wrapper));
        console2.log("attacker scaled gained", attackerScaledAfter);
        console2.log("wrapper scaled before", wrapperScaledBefore);
        console2.log("wrapper scaled after", wrapperScaledAfter);

        // Wrapper totalAssets is unchanged while its real backing dropped.
        console2.log("wrapper totalAssets", wrapper.totalAssets());
    }

    // ------------------------------------------------------------------ //
    // H5: deterministic demonstration of the CV trust boundary.
    //
    // rebalanceATokens_CV() enforces NO cap of its own: it moves exactly
    // convertToAssets(|shares - scaledBalanceOf(caller)|) between the caller and
    // the wrapper. The bound that keeps this safe is enforced by the CALLER (the
    // Twyne collateral vault, which passes its own tracked collateral). This
    // test records that the wrapper itself does not bound the call, so the
    // safety of the shared aToken pool depends entirely on every registered CV
    // passing a correct value.
    //
    // This is a trust-boundary observation, NOT a demonstrated vulnerability:
    // reaching it requires a registered CV to misbehave, and the CV is Twyne's
    // own implementation. Classified NEEDS_MORE_EVIDENCE (see the engagement
    // ledger) until a CV-side path that over-states collateral is shown.
    // ------------------------------------------------------------------ //
    function test_H5_cv_rebalance_is_unbounded_by_the_wrapper() public {
        _fund(victim, 100 ether);
        vm.prank(victim);
        wrapper.deposit(100 ether, victim);
        uint256 victimShares = wrapper.balanceOf(victim);

        factory.setIsCollateralVault(attacker, true);
        // Attacker holds zero shares but is registered as a CV.
        assertEq(wrapper.balanceOf(attacker), 0);

        // Pull almost the entire wrapper aToken balance. (Leave a sliver so the
        // aToken's own balance/rate rounding cannot make the transfer revert.)
        uint256 pull = (IAToken(aWETH).scaledBalanceOf(address(wrapper)) * 999) / 1000;
        vm.prank(attacker);
        wrapper.rebalanceATokens_CV(pull);

        uint256 attackerScaled = IAToken(aWETH).scaledBalanceOf(attacker);
        uint256 wrapperScaled = IAToken(aWETH).scaledBalanceOf(address(wrapper));
        console2.log("attacker pulled (scaled aTokens)", attackerScaled);
        console2.log("wrapper remaining (scaled aTokens)", wrapperScaled);
        console2.log("victim still holds shares", victimShares);

        assertGt(attackerScaled, 0, "registered CV pulled nothing");
        // The victim's shares now exceed the wrapper's real backing: the wrapper
        // would be unable to redeem them if the CV does not return the aTokens.
        assertLt(wrapperScaled, victimShares, "wrapper still fully backed (unexpected)");
    }

    // ------------------------------------------------------------------ //
    // H6: multi-decimal configurations (mission section 6).
    //
    // USDC (6dp) and USDT (6dp) exercise a different underlying decimals path
    // than WETH (18dp). Round-trips must stay value-preserving.
    // ------------------------------------------------------------------ //
    address internal constant USDC = 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48;

    function test_H6_six_decimal_asset_round_trips() public {
        address aUSDC = pool.getReserveData(USDC).aTokenAddress;
        require(aUSDC != address(0), "aUSDC not found");
        AaveV3ATokenWrapper w6 = _deployWrapper(aUSDC);

        uint256 amount = 1_000_000e6; // 1m USDC
        deal(USDC, victim, amount);
        vm.startPrank(victim);
        IERC20(USDC).approve(address(w6), amount);
        uint256 shares = w6.deposit(amount, victim);
        vm.stopPrank();
        assertGt(shares, 0);

        uint256 price = w6.convertToAssets(1e18);
        vm.startPrank(victim);
        uint256 out = w6.redeem(shares, victim, victim);
        vm.stopPrank();
        console2.log("USDC in", amount);
        console2.log("USDC out", out);
        console2.log("share price (1e18)", price);
        // Redeem must return the same order of magnitude; allow index drift.
        assertApproxEqRel(out, amount, 1e15, "6-decimal round trip lost more than 0.1%");
    }

    // ------------------------------------------------------------------ //
    // H7: yield accrual / rebasing (mission section 6).
    //
    // The wrapper's shares must NOT rebase: after interest accrues in Aave the
    // same share count must redeem MORE underlying, and the share count itself
    // must be unchanged.
    // ------------------------------------------------------------------ //
    function test_H7_shares_do_not_rebase_but_gain_value() public {
        _fund(victim, 100 ether);
        vm.startPrank(victim);
        uint256 shares = wrapper.deposit(100 ether, victim);
        vm.stopPrank();

        uint256 assetsBefore = wrapper.previewRedeem(shares);

        // Accrue real interest on Aave by warping far forward and poking the pool.
        vm.warp(block.timestamp + 365 days);
        vm.roll(block.number + 2_200_000);
        pool.getReserveNormalizedIncome(WETH); // refresh the index

        uint256 assetsAfter = wrapper.previewRedeem(shares);
        assertEq(wrapper.balanceOf(victim), shares, "share count must not rebase");
        assertGt(assetsAfter, assetsBefore, "shares should redeem more after yield accrues");
        console2.log("assets before yield", assetsBefore);
        console2.log("assets after yield", assetsAfter);
    }

    // ------------------------------------------------------------------ //
    // H8: skim is not an attacker profit vector (PR #7 coverage).
    //
    // Hypothesis: skim() is permissionless; an attacker could push stray
    // underlying into the wrapper, skim shares to themselves, and extract more
    // than they put in. Test that the receiver gets shares worth at most the
    // value they supplied (rounding cannot create value).
    // ------------------------------------------------------------------ //
    function test_H8_skim_cannot_create_value() public {
        uint256 inAmount = 5 ether;
        deal(WETH, attacker, inAmount);

        // The only way to get underlying "stranded" in the wrapper is to send it
        // there; the attacker is the one paying, so they cannot gain.
        vm.prank(attacker);
        weth.transfer(address(wrapper), inAmount);

        uint256 before = wrapper.balanceOf(attacker);
        vm.prank(attacker);
        wrapper.skim(attacker);
        uint256 shares = wrapper.balanceOf(attacker) - before;

        uint256 valueOut = wrapper.previewRedeem(shares);
        console2.log("skimmed in (underlying)", inAmount);
        console2.log("shares minted", shares);
        console2.log("value of shares (assets)", valueOut);
        assertGt(shares, 0, "skim minted no shares");
        // Shares are minted at floor(assets/rate) <= assets, so value cannot exceed input.
        assertLe(valueOut, inAmount + 1, "skim created value out of nothing");
    }

    // ------------------------------------------------------------------ //
    // H9: a CV's external-liquidation share burn keeps the vault solvent
    // (PR #7 coverage of burnShares_CV).
    //
    // Hypothesis: when Aave seizes a CV's aTokens, the matching share burn
    // could leave remaining holders under-backed (or the burn could be abused
    // to burn more than the seized collateral). Test that a victim's shares
    // remain fully redeemable afterwards.
    // ------------------------------------------------------------------ //
    function test_H9_cv_share_burn_keeps_victim_solvent() public {
        // A victim deposits and a CV deposits then pulls its own aTokens out.
        _fund(victim, 100 ether);
        vm.startPrank(victim);
        uint256 victimShares = wrapper.deposit(100 ether, victim);
        vm.stopPrank();

        factory.setIsCollateralVault(attacker, true);
        _fund(attacker, 50 ether);
        vm.startPrank(attacker);
        uint256 cvShares = wrapper.deposit(50 ether, attacker);
        wrapper.rebalanceATokens_CV(cvShares); // CV now holds its aTokens
        vm.stopPrank();

        // Simulate Aave seizing the CV's aTokens during an external liquidation:
        // seize them, then the CV burns exactly the matching shares.
        uint256 seized = wrapper.previewRedeem(cvShares);
        vm.prank(attacker);
        IERC20(aWETH).transfer(address(0xdead), seized);
        vm.prank(attacker);
        wrapper.burnShares_CV(cvShares);

        // The victim's shares must still be fully backed by the wrapper's aTokens.
        uint256 victimValue = wrapper.previewRedeem(victimShares);
        uint256 wrapperHeld = IAToken(aWETH).balanceOf(address(wrapper));
        console2.log("victim shares", victimShares);
        console2.log("victim redeemable (assets)", victimValue);
        console2.log("wrapper aToken balance (assets)", wrapperHeld);
        assertGe(wrapperHeld + 2, victimValue, "victim left under-backed after CV burn");
    }

    // ------------------------------------------------------------------ //
    // H10: an Aave index change between operations cannot be arbitraged.
    //
    // Hypothesis (next-priority #2): if the wrapper computed a share/asset
    // conversion using a stale index and settled with a fresh one, a depositor
    // who entered before a yield jump could be diluted, or could extract more
    // than they deposited. Two users deposit around a real yield accrual, then
    // redeem; each must get its fair proportional claim and nobody may profit
    // beyond what they put in.
    // ------------------------------------------------------------------ //
    function test_H10_index_change_between_operations_cannot_be_arbitraged() public {
        _fund(victim, 100 ether);
        vm.startPrank(victim);
        uint256 victimShares = wrapper.deposit(100 ether, victim);
        vm.stopPrank();

        // Real Aave yield accrues between the two deposits.
        vm.warp(block.timestamp + 365 days);
        vm.roll(block.number + 2_200_000);
        pool.getReserveNormalizedIncome(WETH);

        _fund(attacker, 100 ether);
        vm.startPrank(attacker);
        uint256 attackerShares = wrapper.deposit(100 ether, attacker);
        vm.stopPrank();

        // Both redeem everything. The wrapper's own aToken balance is the real
        // backing (it includes the year of yield), so total paid out can never
        // exceed it; the pre-yield depositor keeps its principal; and the
        // post-yield depositor cannot extract more than it deposited (no
        // arbitrage from the index change).
        uint256 backing = IAToken(aWETH).balanceOf(address(wrapper));
        vm.prank(victim);
        uint256 victimOut = wrapper.redeem(victimShares, victim, victim);
        vm.prank(attacker);
        uint256 attackerOut = wrapper.redeem(attackerShares, attacker, attacker);

        console2.log("wrapper backing (assets)", backing);
        console2.log("victim out", victimOut);
        console2.log("attacker out", attackerOut);

        assertGe(victimOut, 100 ether, "pre-yield depositor was diluted by the index change");
        assertLe(attackerOut, 100 ether + 1, "post-yield depositor extracted more than deposited");
        assertLe(victimOut + attackerOut, backing + 2, "redemption created value out of nothing");
    }
}
