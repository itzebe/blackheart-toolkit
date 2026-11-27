// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IAToken} from "aave-v3/interfaces/IAToken.sol";
import {AaveV3ATokenWrapper} from "src/AaveV3ATokenWrapper.sol";

/// @notice Stateful handler for the real Twyne AaveV3 aToken wrapper. The
/// invariant fuzzer calls these actions in arbitrary order; the invariants in
/// `TwyneWrapperInvariants.t.sol` must hold for every sequence.
///
/// Actors: one victim (honest holder), one donor (gifts aTokens), one
/// collateral vault (registered, may rebalance/burn its own shares).
contract WrapperHandler is Test {
    AaveV3ATokenWrapper public wrapper;
    IERC20 public weth;
    IERC20 public aToken;
    address public pool;

    address public victim;
    address public donor;
    address public cv;

    uint256 public victimDeposited;   // assets the victim put in
    uint256 public victimWithdrawn;   // assets the victim took out
    uint256 public donorDonated;      // aTokens gifted to the wrapper
    uint256 public cvShares;          // shares the CV legitimately holds
    address[] public actors;

    constructor(AaveV3ATokenWrapper _wrapper, IERC20 _weth, IERC20 _aToken, address _pool) {
        wrapper = _wrapper;
        weth = _weth;
        aToken = _aToken;
        pool = _pool;
        victim = makeAddr("h.victim");
        donor = makeAddr("h.donor");
        cv = makeAddr("h.cv");
        actors.push(victim);
        actors.push(donor);
        vm.prank(victim);
        weth.approve(address(wrapper), type(uint256).max);
        vm.prank(cv);
        weth.approve(address(wrapper), type(uint256).max);
    }

    function _actorAt(uint256 seed) internal view returns (address) {
        return actors[seed % actors.length];
    }

    function _fundWeth(address who, uint256 amount) internal {
        deal(address(weth), who, amount);
        vm.prank(who);
        weth.approve(address(wrapper), type(uint256).max);
    }

    function deposit(uint256 amount) public {
        amount = bound(amount, 1e12, 100 ether);
        _fundWeth(victim, amount);
        vm.prank(victim);
        try wrapper.deposit(amount, victim) returns (uint256 shares) {
            victimDeposited += amount;
            shares; // shares recorded via balanceOf
        } catch {}
    }

    function withdraw(uint256 shares) public {
        uint256 bal = wrapper.balanceOf(victim);
        if (bal == 0) return;
        shares = bound(shares, 1, bal);
        uint256 before = weth.balanceOf(victim);
        vm.prank(victim);
        try wrapper.redeem(shares, victim, victim) returns (uint256 assets) {
            victimWithdrawn += (weth.balanceOf(victim) - before);
            assets;
        } catch {}
    }

    /// @dev Gift real aTokens straight to the wrapper (no shares minted).
    function donate(uint256 amount) public {
        amount = bound(amount, 1e12, 10 ether);
        _fundWeth(donor, amount);
        vm.startPrank(donor);
        weth.approve(pool, amount);
        try IPoolMin(pool).supply(address(weth), amount, donor, 0) {} catch { vm.stopPrank(); return; }
        vm.stopPrank();
        uint256 bal = aToken.balanceOf(donor);
        if (bal == 0) return;
        vm.prank(donor);
        try IERC20(address(aToken)).transfer(address(wrapper), bal) {
            donorDonated += bal;
        } catch {}
    }

    /// @dev The CV deposits then rebalances its aTokens to match its shares.
    function cvRebalance(uint256 amount) public {
        amount = bound(amount, 1e12, 20 ether);
        _fundWeth(cv, amount);
        vm.prank(cv);
        try wrapper.deposit(amount, cv) returns (uint256 shares) {
            cvShares = wrapper.balanceOf(cv);
            vm.prank(cv);
            try wrapper.rebalanceATokens_CV(shares) {} catch {}
        } catch {}
    }

    /// @dev Permissionless skim: stray underlying pushed into the wrapper is
    /// supplied to Aave and shares minted to an arbitrary receiver. The receiver
    /// is the donor (not the victim), so the value that enters is an external
    /// gift and must not be mistaken for victim profit.
    function skim(uint256 receiverSeed, uint256 amount) public {
        receiverSeed; // kept for interface symmetry with other ops
        amount = bound(amount, 1e12, 10 ether);
        deal(address(weth), address(wrapper), amount);
        try wrapper.skim(donor) {} catch {}
    }

    /// @dev Model an external Aave liquidation of the CV: the protocol seizes
    /// some of the CV's aTokens, then the CV burns the matching shares so its
    /// share count tracks the collateral it actually still holds.
    function externalLiquidationBurn(uint256 seizeSeed, uint256 shares) public {
        uint256 bal = wrapper.balanceOf(cv);
        if (bal == 0) return;
        uint256 aBal = aToken.balanceOf(cv);
        if (aBal == 0) return;
        shares = bound(shares, 1, bal);
        uint256 seize = wrapper.previewRedeem(shares);
        if (seize > aBal) seize = aBal;
        address sink = _actorAt(seizeSeed);
        vm.prank(cv);
        try IERC20(address(aToken)).transfer(sink, seize) {
            vm.prank(cv);
            try wrapper.burnShares_CV(shares) {} catch {}
        } catch {}
    }

    /// @dev Redeem as much as possible, to probe the last-redeemer case.
    function withdrawAll() public {
        uint256 bal = wrapper.balanceOf(victim);
        if (bal == 0) return;
        uint256 before = weth.balanceOf(victim);
        vm.prank(victim);
        try wrapper.redeem(bal, victim, victim) returns (uint256 assets) {
            victimWithdrawn += (weth.balanceOf(victim) - before);
            assets;
        } catch {}
    }
}

interface IPoolMin {
    function supply(address asset, uint256 amount, address onBehalfOf, uint16 referralCode) external;
}
