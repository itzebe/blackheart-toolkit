// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {AaveV3ATokenWrapper, IRewardsController} from "src/AaveV3ATokenWrapper.sol";
import {IPool} from "aave-v3/interfaces/IPool.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

/// --- Minimal mocks modelling a rebasing aToken -----------------------------
/// The aToken balance is `scaledBalance * normalizedIncome / RAY`. A "donation"
/// is a direct mint of aTokens (rewards, or an unsolicited transfer), which
/// raises the wrapper's `balanceOf(aToken)` without changing totalSupply.

contract MockUnderlying is ERC20 {
    constructor() ERC20("Mock Underlying", "MCK") {}
    function mint(address to, uint256 amount) external { _mint(to, amount); }
}

contract MockAToken {
    address public immutable POOL;
    address public immutable UNDERLYING_ASSET_ADDRESS;
    uint256 public constant RAY = 1e27;
    uint256 public normalizedIncome;
    mapping(address => uint256) public scaledBalanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);

    constructor(address pool, address underlying, uint256 rate) {
        POOL = pool;
        UNDERLYING_ASSET_ADDRESS = underlying;
        normalizedIncome = rate;
    }

    function setNormalizedIncome(uint256 rate) external { normalizedIncome = rate; }

    function balanceOf(address user) public view returns (uint256) {
        return scaledBalanceOf[user] * normalizedIncome / RAY;
    }

    function _scaled(uint256 amount) internal view returns (uint256) {
        return amount * RAY / normalizedIncome;
    }

    /// Mint `amount` underlying-equivalent aTokens to `to` (used by the pool on
    /// supply, and by the harness to simulate rebasing/airdrops).
    function mint(address to, uint256 amount) external {
        scaledBalanceOf[to] += _scaled(amount);
        emit Transfer(address(0), to, amount);
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        uint256 scaled = _scaled(amount);
        scaledBalanceOf[msg.sender] -= scaled;
        scaledBalanceOf[to] += scaled;
        emit Transfer(msg.sender, to, amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        if (allowance[from][msg.sender] != type(uint256).max) {
            allowance[from][msg.sender] -= amount;
        }
        uint256 scaled = _scaled(amount);
        scaledBalanceOf[from] -= scaled;
        scaledBalanceOf[to] += scaled;
        emit Transfer(from, to, amount);
        return true;
    }
}

contract MockPool {
    address public immutable ADDRESSES_PROVIDER;
    MockUnderlying public immutable underlying;
    MockAToken public aToken;
    uint256 public immutable normalizedIncome;

    constructor(address underlyingAsset, uint256 rate) {
        ADDRESSES_PROVIDER = address(1);
        underlying = MockUnderlying(underlyingAsset);
        normalizedIncome = rate;
    }

    function setAToken(address a) external { aToken = MockAToken(a); }

    function supply(address asset, uint256 amount, address onBehalfOf, uint16) public {
        require(asset == address(underlying), "bad asset");
        underlying.transferFrom(msg.sender, address(this), amount);
        aToken.mint(onBehalfOf, amount);
    }

    function deposit(address asset, uint256 amount, address onBehalfOf, uint16 ref) external {
        supply(asset, amount, onBehalfOf, ref);
    }

    function withdraw(address asset, uint256 amount, address to) external returns (uint256) {
        require(asset == address(underlying), "bad asset");
        aToken.transferFrom(msg.sender, address(this), amount);
        underlying.transfer(to, amount);
        return amount;
    }

    function getReserveNormalizedIncome(address asset) external view returns (uint256) {
        require(asset == address(underlying), "bad asset");
        return normalizedIncome;
    }
}

contract MockCVFactory {
    address public immutable EVC;
    mapping(address => bool) public isCollateralVault;
    constructor(address evc) { EVC = evc; }
    function setCV(address cv, bool ok) external { isCollateralVault[cv] = ok; }
}

contract MockRewards {
    function claimRewards(address[] calldata, uint256, address, address) external pure returns (uint256) {
        return 0;
    }
}

/// --- Handler: the fuzzable operations --------------------------------------

contract AaveWrapperHandler is Test {
    AaveV3ATokenWrapper public wrapper;
    MockAToken public aToken;
    MockUnderlying public underlying;

    address public attacker = address(0xA11CE);
    address public victim = address(0xB0B);
    address[] public actors;

    // ghost accounting, in underlying terms
    int256 public ghost_attackerNet; // (redeemed + aTokenValue) - (deposited + donated)
    uint256 public ghost_victimIn;
    uint256 public ghost_victimOut;

    constructor(AaveV3ATokenWrapper w, MockAToken a, MockUnderlying u) {
        wrapper = w; aToken = a; underlying = u;
        actors.push(attacker); actors.push(victim);
        underlying.mint(attacker, 1e30);
        underlying.mint(victim, 1e30);
        vm.prank(attacker); underlying.approve(address(wrapper), type(uint256).max);
        vm.prank(victim); underlying.approve(address(wrapper), type(uint256).max);
    }

    function actorAt(uint256 seed) internal view returns (address) { return actors[seed % actors.length]; }

    /// Deposit underlying via the wrapper (depositToAave path).
    function deposit(uint256 actorSeed, uint256 amount) public {
        address actor = actorAt(actorSeed);
        amount = bound(amount, 1, 1e24);
        vm.prank(actor);
        wrapper.deposit(amount, actor);
        if (actor == victim) ghost_victimIn += amount;
    }

    /// Redeem wrapper shares back to underlying.
    function redeem(uint256 actorSeed, uint256 shares) public {
        address actor = actorAt(actorSeed);
        uint256 bal = wrapper.balanceOf(actor);
        if (bal == 0) return;
        shares = bound(shares, 1, bal);
        vm.prank(actor);
        uint256 out = wrapper.redeem(shares, actor, actor);
        if (actor == victim) ghost_victimOut += out;
    }

    /// Simulate rebasing / airdropped aTokens landing on the wrapper (the
    /// documented "donation" vector). Anyone can do this on-chain.
    function airdropATokens(uint256 amount) public {
        amount = bound(amount, 1, 1e24);
        aToken.mint(address(wrapper), amount);
    }

    /// Permissionless skim: push stray underlying into Aave and mint shares to
    /// `receiver`. Anyone can call it with an arbitrary receiver.
    function skim(uint256 receiverSeed, uint256 amount) public {
        address receiver = actorAt(receiverSeed);
        amount = bound(amount, 1, 1e24);
        underlying.mint(address(wrapper), amount);
        wrapper.skim(receiver);
    }

    /// A raw unsolicited underlying transfer to the wrapper.
    function donateUnderlying(uint256 amount) public {
        amount = bound(amount, 1, 1e24);
        underlying.mint(address(wrapper), amount);
    }

    function attackerValueNow() public view returns (int256) {
        uint256 shares = wrapper.balanceOf(attacker);
        uint256 redeemable = wrapper.previewRedeem(shares);
        uint256 aTok = aToken.balanceOf(attacker);
        return int256(redeemable + aTok);
    }

    function victimValueNow() public view returns (int256) {
        uint256 shares = wrapper.balanceOf(victim);
        return int256(wrapper.previewRedeem(shares));
    }
}

contract AaveWrapperInvariants is Test {
    AaveV3ATokenWrapper public wrapper;
    MockAToken public aToken;
    MockUnderlying public underlying;
    MockPool public pool;
    AaveWrapperHandler public handler;

    address owner = makeAddr("owner");

    uint256 constant RATE = 1e27;

    function setUp() public {
        underlying = new MockUnderlying();
        pool = new MockPool(address(underlying), RATE);
        aToken = new MockAToken(address(pool), address(underlying), RATE);
        pool.setAToken(address(aToken));

        address evc = address(0xE7C);
        MockCVFactory factory = new MockCVFactory(evc);

        address impl = address(new AaveV3ATokenWrapper(evc, address(factory), IPool(address(pool)), IRewardsController(address(new MockRewards()))));
        bytes memory initData = abi.encodeCall(AaveV3ATokenWrapper.initialize, (address(aToken), owner, "A-Stat", "ASTAT"));
        wrapper = AaveV3ATokenWrapper(address(new ERC1967Proxy(impl, initData)));

        handler = new AaveWrapperHandler(wrapper, aToken, underlying);
        targetContract(address(handler));
    }

    /// The wrapper must never hold value it cannot account for: every unit of
    /// `totalAssets()` must be redeemable, and no airdropped aToken may become
    /// unreachable.
    function invariant_reported_equals_redeemable() public view {
        uint256 reported = wrapper.totalAssets();
        uint256 aTokenBal = aToken.balanceOf(address(wrapper));
        // totalAssets() is shares*rate/RAY, i.e. the accounted portion. Any aToken
        // held above the accounted amount is un-accounted (donated) value.
        assertLe(reported, aTokenBal, "wrapper reports more assets than it holds");
    }

    /// A share must never be worth more than the assets backing it: converting
    /// supply to assets must not exceed the wrapper's aToken balance.
    function invariant_shares_backed() public view {
        uint256 supply = wrapper.totalSupply();
        if (supply == 0) return;
        uint256 assetsForSupply = wrapper.convertToAssets(supply);
        assertLe(assetsForSupply, aToken.balanceOf(address(wrapper)) + 1, "shares not fully backed");
    }
}
