// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {TwyneWrapperForkBase} from "./TwyneWrapperForkBase.sol";
import {console2} from "forge-std/console2.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IAToken} from "aave-v3/interfaces/IAToken.sol";

/// @notice Smoke tests: prove the harness is wired to real Aave V3 and the real
/// wrapper source, and that the documented behaviours actually hold on a fork.
/// These are not findings; they establish non-vacuity for the adversarial tests.
contract TwyneWrapperSmokeTest is TwyneWrapperForkBase {
    function test_smoke_wrapper_round_trip() public {
        _fund(victim, 10 ether);
        vm.startPrank(victim);
        uint256 shares = wrapper.deposit(10 ether, victim);
        vm.stopPrank();

        assertGt(shares, 0, "deposit minted zero shares");
        assertEq(wrapper.balanceOf(victim), shares, "share balance mismatch");
        assertApproxEqRel(wrapper.totalAssets(), 10 ether, 1e15, "totalAssets not ~10 ether");

        vm.startPrank(victim);
        uint256 assets = wrapper.redeem(shares, victim, victim);
        vm.stopPrank();
        assertApproxEqRel(assets, 10 ether, 1e15, "redeem did not return ~10 ether");
        console2.log("round-trip shares", shares);
    }

    function test_smoke_zero_share_deposit_reverts() public {
        // The wrapper rejects a deposit that would mint zero shares
        // (StaticATokenInvalidZeroShares). A 1-wei deposit into an empty wrapper
        // rounds to zero shares, so the guard fires -- this is the anti-inflation
        // protection the guarded model relies on.
        _fund(victim, 10 ether);
        vm.prank(victim);
        vm.expectRevert(); // zero-share deposit is rejected
        wrapper.deposit(1, victim);

        // A deposit large enough to mint at least one share succeeds.
        vm.prank(victim);
        uint256 shares = wrapper.deposit(1 ether, victim);
        assertGt(shares, 0);
    }
}
