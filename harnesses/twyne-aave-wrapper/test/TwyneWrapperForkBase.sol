// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {console2} from "forge-std/console2.sol";

import {AaveV3ATokenWrapper} from "src/AaveV3ATokenWrapper.sol";
import {CustomERC4626StataTokenUpgradeable} from "src/CustomERC4626StataTokenUpgradeable.sol";

import {IPool} from "aave-v3/interfaces/IPool.sol";
import {IAToken} from "aave-v3/interfaces/IAToken.sol";
import {IRewardsController} from "aave-v3/rewards/interfaces/IRewardsController.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

/// @dev Minimal stand-in for Twyne's CollateralVaultFactory. The real factory is
/// permissionlessly reachable by any borrower (given an allowed intermediate
/// vault + target vault), so a registered collateral vault is an attacker-
/// reachable role. Here we just let the test toggle that role.
contract MockCollateralVaultFactory {
    address public immutable EVC;
    mapping(address => bool) public isCollateralVault;

    constructor(address _evc) {
        EVC = _evc;
    }

    function setIsCollateralVault(address who, bool status) external {
        isCollateralVault[who] = status;
    }
}

/// @notice Base for adversarial tests against the *real, in-scope* Twyne AaveV3
/// aToken wrapper. Deploys the actual upstream implementation behind a UUPS
/// proxy on a local mainnet fork, wired to the real Aave V3 Pool and a real
/// aToken, then funds actors with the real underlying token.
///
/// Nothing here broadcasts: `forge test` runs entirely in-process against a
/// fork. No paid RPC key is required (see foundry.toml `[profile.fork]`).
abstract contract TwyneWrapperForkBase is Test {
    // Ethereum mainnet addresses (pinned; real Aave V3 deployment).
    address internal constant WETH = 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2;
    address internal constant AAVE_V3_POOL = 0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2;
    address internal constant AAVE_ORACLE = 0x54586bE62E3c3580375aE3723C145253060Ca0C2;

    // Real Twyne EVC (in scope). The wrapper only stores it; these tests call the
    // wrapper directly, so no EVC routing is exercised.
    address internal constant TWYNE_EVC = 0x79CF33e623555E899d4EE122b9BfA0214fa5A4A1;

    IPool internal pool;
    IERC20 internal weth;
    address internal aWETH;
    AaveV3ATokenWrapper internal wrapper;
    MockCollateralVaultFactory internal factory;

    address internal owner;
    address internal attacker;
    address internal victim;
    address internal donor;

    function setUp() public virtual {
        _fork();
        pool = IPool(AAVE_V3_POOL);
        weth = IERC20(WETH);
        aWETH = pool.getReserveData(WETH).aTokenAddress;
        require(aWETH != address(0), "aWETH not found on fork");

        owner = makeAddr("owner");
        attacker = makeAddr("attacker");
        victim = makeAddr("victim");
        donor = makeAddr("donor");

        factory = new MockCollateralVaultFactory(TWYNE_EVC);
        wrapper = _deployWrapper(aWETH);
    }

    /// @dev Deploy the real wrapper implementation behind a UUPS proxy for the
    /// given aToken. Reused to exercise different decimal configurations.
    function _deployWrapper(address aToken) internal returns (AaveV3ATokenWrapper w) {
        // claimReward() is out of scope for these hypotheses; a non-zero dummy
        // satisfies the constructor's only requirement on the controller.
        address rewards = address(0xBEEF);
        address impl = address(
            new AaveV3ATokenWrapper(TWYNE_EVC, address(factory), pool, IRewardsController(rewards))
        );
        bytes memory initData =
            abi.encodeCall(AaveV3ATokenWrapper.initialize, (aToken, owner, "Twyne-Wrapped", "tw-W"));
        w = AaveV3ATokenWrapper(address(new ERC1967Proxy(impl, initData)));
    }

    function _fork() internal virtual {
        // Prefer an explicit RPC (BLACKHEART_ETH_RPC) then fall back to the
        // keyless public endpoint configured in foundry.toml [profile.fork].
        string memory rpc = vm.envOr("BLACKHEART_ETH_RPC", string("https://gateway.tenderly.co/public/mainnet"));
        vm.createSelectFork(rpc);
    }

    /// @dev Give an actor real WETH and have them approve the wrapper.
    function _fund(address who, uint256 amount) internal {
        deal(WETH, who, amount);
        vm.prank(who);
        weth.approve(address(wrapper), type(uint256).max);
    }

    /// @dev Turn real WETH into real aWETH by supplying it to Aave directly.
    function _supplyToAave(address who, uint256 amount) internal returns (uint256 aTokenAmount) {
        deal(WETH, who, amount);
        vm.startPrank(who);
        weth.approve(AAVE_V3_POOL, amount);
        pool.supply(WETH, amount, who, 0);
        vm.stopPrank();
        aTokenAmount = IERC20(aWETH).balanceOf(who);
    }
}
