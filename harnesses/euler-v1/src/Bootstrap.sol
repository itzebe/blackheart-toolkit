// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8.0;

// Integration glue for the Mission 08 external-source EVM harness.
//
// This contract contains NO protocol logic. It deploys and configures the *real,
// unmodified* Euler V1 protocol exactly as the upstream Hardhat test harness does
// (see test/lib/eTestLib.js): it constructs the RiskManager, the Euler core, the
// module implementations (deployed separately by the harness and passed in), the
// single-proxy modules and the market, then exposes the resulting proxy addresses
// and a solvency read-back so the discovery engine can drive the protocol through
// its real proxies.
//
// The reference asset is priced PEGGED (1:1) by construction, so a single market
// needs no Uniswap pool. Nothing here is specific to any vulnerability.

import "euler/Euler.sol";
import "euler/Storage.sol";
import "euler/Constants.sol";
import "euler/IRiskManager.sol";
import "euler/modules/Installer.sol";
import "euler/modules/Markets.sol";
import "euler/modules/Governance.sol";
import "euler/modules/Exec.sol";
import "euler/modules/RiskManager.sol";

contract Bootstrap is Constants {
    Euler public immutable euler;
    Markets public immutable markets;
    Exec public immutable exec;
    address public immutable underlying;
    address public eTokenAddr;
    address public dTokenAddr;

    constructor(
        bytes32 gitCommit,
        address token,
        address installerImpl,
        address marketsImpl,
        address liquidationImpl,
        address governanceImpl,
        address execImpl,
        address eTokenImpl,
        address dTokenImpl,
        address irmDefaultImpl
    ) {
        underlying = token;

        // RiskManager is an internal module whose constructor takes a settings
        // struct, so it is deployed here (the module implementations are deployed
        // by the harness and passed in). The reference asset is the market token;
        // the Uniswap factory is unused because the only market is PEGGED-priced.
        RiskManager riskManager = new RiskManager(
            gitCommit,
            RiskManager.RiskManagerSettings({
                referenceAsset: token,
                uniswapFactory: address(0),
                uniswapPoolInitCodeHash: bytes32(0)
            })
        );

        // The Euler core installs the installer module and creates its proxy.
        euler = new Euler(address(this), installerImpl);

        // Install the remaining modules (mirrors eTestLib's install list).
        address[] memory modules = new address[](8);
        modules[0] = marketsImpl;
        modules[1] = liquidationImpl;
        modules[2] = governanceImpl;
        modules[3] = execImpl;
        modules[4] = eTokenImpl;
        modules[5] = dTokenImpl;
        modules[6] = address(riskManager);
        modules[7] = irmDefaultImpl;
        Installer(euler.moduleIdToProxy(MODULEID__INSTALLER)).installModules(modules);

        markets = Markets(euler.moduleIdToProxy(MODULEID__MARKETS));
        exec = Exec(euler.moduleIdToProxy(MODULEID__EXEC));

        // Activate the single (pegged) market.
        eTokenAddr = markets.activateMarket(token);
        dTokenAddr = markets.underlyingToDToken(token);

        // Give the market a real collateral factor (activation defaults it to 0
        // for a pegged reference asset). Collateral 75%, default borrow factor.
        Governance(euler.moduleIdToProxy(MODULEID__GOVERNANCE)).setAssetConfig(
            token,
            Storage.AssetConfig({
                eTokenAddress: eTokenAddr,
                borrowIsolated: false,
                collateralFactor: 3_000_000_000, // 0.75 * CONFIG_FACTOR_SCALE
                borrowFactor: type(uint32).max,  // -> DEFAULT_BORROW_FACTOR
                twapWindow: type(uint24).max     // -> DEFAULT_TWAP_WINDOW_SECONDS
            })
        );
    }

    // -- solvency read-back (the protocol's own liquidity computation) -------- //
    //
    // These are declared non-view because Exec.liquidity performs a delegatecall,
    // but it does not modify state; eth_call evaluates them without persisting.

    function collateralValue(address account) external returns (uint) {
        IRiskManager.LiquidityStatus memory s = exec.liquidity(account);
        return s.collateralValue;
    }

    function liabilityValue(address account) external returns (uint) {
        IRiskManager.LiquidityStatus memory s = exec.liquidity(account);
        return s.liabilityValue;
    }
}
