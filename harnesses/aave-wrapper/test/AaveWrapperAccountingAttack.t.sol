// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {AaveV3ATokenWrapper, IRewardsController} from "src/AaveV3ATokenWrapper.sol";
import {IPool} from "aave-v3/interfaces/IPool.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

/// Focused adversarial harness for the priority hypothesis:
/// "Aave aToken / wrapper-share accounting can be converted into unauthorized
///  value extraction (first-depositor inflation / donation dilution)."

contract MU is ERC20 {
    constructor() ERC20("U", "U") {}
    function mint(address to, uint256 a) external { _mint(to, a); }
}

contract MAT {
    address public immutable POOL;
    address public immutable UNDERLYING_ASSET_ADDRESS;
    uint256 public constant RAY = 1e27;
    uint256 public rate;
    mapping(address => uint256) public scaledBalanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    event Transfer(address indexed from, address indexed to, uint256 value);

    constructor(address p, address u, uint256 r) { POOL = p; UNDERLYING_ASSET_ADDRESS = u; rate = r; }
    function setRate(uint256 r) external { rate = r; }
    function balanceOf(address u) public view returns (uint256) { return scaledBalanceOf[u] * rate / RAY; }
    function _s(uint256 a) internal view returns (uint256) { return a * RAY / rate; }
    function mint(address to, uint256 a) external { scaledBalanceOf[to] += _s(a); emit Transfer(address(0), to, a); }
    function approve(address s, uint256 a) external returns (bool) { allowance[msg.sender][s] = a; return true; }
    function transfer(address to, uint256 a) external returns (bool) {
        scaledBalanceOf[msg.sender] -= _s(a); scaledBalanceOf[to] += _s(a);
        emit Transfer(msg.sender, to, a); return true;
    }
    function transferFrom(address f, address to, uint256 a) external returns (bool) {
        if (allowance[f][msg.sender] != type(uint256).max) allowance[f][msg.sender] -= a;
        scaledBalanceOf[f] -= _s(a); scaledBalanceOf[to] += _s(a);
        emit Transfer(f, to, a); return true;
    }
    /// Real Aave pools burn aTokens on withdraw; they do not need an allowance.
    function burn(address from, uint256 a) external {
        scaledBalanceOf[from] -= _s(a);
        emit Transfer(from, address(0), a);
    }
}

contract MP {
    address public immutable ADDRESSES_PROVIDER;
    MU public immutable underlying;
    MAT public at;
    uint256 public immutable rate;
    constructor(address u, uint256 r) { ADDRESSES_PROVIDER = address(1); underlying = MU(u); rate = r; }
    function setAToken(address a) external { at = MAT(a); }
    function supply(address a, uint256 amt, address on, uint16) public {
        require(a == address(underlying), "bad"); underlying.transferFrom(msg.sender, address(this), amt); at.mint(on, amt);
    }
    function deposit(address a, uint256 amt, address on, uint16 r) external { supply(a, amt, on, r); }
    function withdraw(address a, uint256 amt, address to) external returns (uint256) {
        require(a == address(underlying), "bad"); at.burn(msg.sender, amt); underlying.transfer(to, amt); return amt;
    }
    function getReserveNormalizedIncome(address a) external view returns (uint256) {
        require(a == address(underlying), "bad");
        // Must return the SAME rate the aToken uses, as real Aave does.
        return at.rate();
    }
}

contract MCF { address public immutable EVC; constructor(address e) { EVC = e; } function isCollateralVault(address) external pure returns (bool) { return false; } }
contract MR { function claimRewards(address[] calldata, uint256, address, address) external pure returns (uint256) { return 0; } }

contract AaveWrapperAccountingAttack is Test {
    AaveV3ATokenWrapper wrapper;
    MAT at;
    MU underlying;
    MP pool;

    address attacker = address(0xA11CE);
    address victim = address(0xB0B);

    uint256 constant RATE = 1e27;
    uint256 constant DUST = 1e6;

    function setUp() public {
        underlying = new MU();
        pool = new MP(address(underlying), RATE);
        at = new MAT(address(pool), address(underlying), RATE);
        pool.setAToken(address(at));

        address evc = address(0xE7C);
        MCF f = new MCF(evc);
        address impl = address(new AaveV3ATokenWrapper(evc, address(f), IPool(address(pool)), IRewardsController(address(new MR()))));
        bytes memory init = abi.encodeCall(AaveV3ATokenWrapper.initialize, (address(at), address(this), "S", "S"));
        wrapper = AaveV3ATokenWrapper(address(new ERC1967Proxy(impl, init)));
    }

    /// Classic first-depositor inflation: attacker seeds 1 wei, donates a large
    /// aToken amount directly to the wrapper, then a victim deposits. If the
    /// victim's deposit is accepted for (near-)zero shares, the attacker can
    /// redeem the victim's funds. Returns the attacker's net underlying gain.
    function _runInflation(uint256 seedDeposit, uint256 donation, uint256 victimDeposit)
        internal
        returns (int256 attackerNet, bool victimDepositSucceeded, uint256 victimShares)
    {
        underlying.mint(attacker, seedDeposit + donation + victimDeposit + 10e18);
        underlying.mint(victim, victimDeposit);

        vm.prank(attacker);
        underlying.approve(address(wrapper), type(uint256).max);
        vm.prank(victim);
        underlying.approve(address(wrapper), type(uint256).max);

        // 1) attacker seeds a tiny first deposit
        vm.prank(attacker);
        wrapper.deposit(seedDeposit, attacker);

        // 2) attacker donates aTokens directly to the wrapper (raises share price)
        vm.prank(attacker);
        at.mint(attacker, donation); // acquire aTokens
        vm.prank(attacker);
        at.transfer(address(wrapper), donation);

        // 3) victim deposits at the inflated price
        vm.prank(victim);
        try wrapper.deposit(victimDeposit, victim) returns (uint256 s) {
            victimDepositSucceeded = true;
            victimShares = s;
        } catch {
            victimDepositSucceeded = false;
        }

        // 4) attacker redeems all shares
        uint256 aShares = wrapper.balanceOf(attacker);
        uint256 before = underlying.balanceOf(attacker);
        vm.prank(attacker);
        try wrapper.redeem(aShares, attacker, attacker) returns (uint256 out) {
            attackerNet = int256(underlying.balanceOf(attacker) - before) - int256(seedDeposit + donation);
        } catch {
            attackerNet = -int256(seedDeposit + donation);
        }
    }

    /// The headline hypothesis, at the documented attack ratio.
    function test_inflationAttack_is_blocked_by_zero_share_revert() public {
        (int256 net, bool victimOk, uint256 victimShares) = _runInflation(2, 10e18, 1e18);
        // If the wrapper let the victim deposit for zero/near-zero shares, the
        // attacker would profit at the victim's expense.
        if (victimOk) {
            // victim must receive shares worth approximately what they deposited
            uint256 victimValue = wrapper.convertToAssets(victimShares);
            assertGe(victimValue + DUST, 1e18, "victim diluted: deposit not honored");
            assertLe(net, int256(DUST), "attacker extracted value from the victim");
        } else {
            // Blocked: the victim's deposit reverts (zero shares) — no theft.
            assertLt(net, 0, "attacker should not profit when the deposit is blocked");
        }
    }

    /// Fuzz the inflation parameters: find ANY combination where the attacker
    /// ends with a material net gain funded by the victim.
    function testFuzz_inflationAttack_no_profitable_path(uint256 seedDeposit, uint256 donation, uint256 victimDeposit) public {
        seedDeposit = bound(seedDeposit, 1, 1e6);
        donation = bound(donation, 1, 1e24);
        victimDeposit = bound(victimDeposit, 1, 1e24);

        (int256 net, bool victimOk, uint256 victimShares) = _runInflation(seedDeposit, donation, victimDeposit);
        if (victimOk) {
            uint256 victimValue = wrapper.convertToAssets(victimShares);
            assertGe(victimValue + DUST, victimDeposit, "victim deposit diluted");
        }
        assertLe(net, int256(DUST), "attacker profitable via inflation");
    }

    /// Repeated deposit/redeem across a rate change must never create value.
    /// NOTE: the mock pool must be funded for the accrued yield, exactly as real
    /// Aave liquidity would be; otherwise the mock underflows and produces a
    /// false positive that is NOT a wrapper vulnerability.
    function testFuzz_repeatedConversions_never_create_value(uint256 amount, uint256 newRate) public {
        amount = bound(amount, 1e6, 1e24);
        newRate = bound(newRate, RATE, RATE * 2);

        underlying.mint(attacker, amount);
        vm.prank(attacker);
        underlying.approve(address(wrapper), type(uint256).max);

        vm.prank(attacker);
        uint256 shares = wrapper.deposit(amount, attacker);

        // rate changes (yield accrues); fund the pool for the new yield so it can
        // honour the withdrawal, as real Aave liquidity would.
        uint256 yield = (amount * (newRate - RATE)) / RATE;
        underlying.mint(address(pool), yield);
        at.setRate(newRate);

        vm.prank(attacker);
        uint256 out = wrapper.redeem(shares, attacker, attacker);

        assertLe(out, amount + yield + DUST, "impossible yield");
        assertLe(wrapper.totalAssets(), at.balanceOf(address(wrapper)) + 1, "wrapper over-reports assets");
    }
}
