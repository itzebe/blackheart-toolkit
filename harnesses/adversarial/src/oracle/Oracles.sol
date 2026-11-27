// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title IPriceOracle
interface IPriceOracle {
    function price(address asset) external view returns (uint256);
}

/// @title SpotOracle
/// @notice A naive oracle that reads a *spot* price straight from a pool reserve
///         with no manipulation resistance. This is the classic TWAP-vs-spot
///         divergence target.
contract SpotOracle is IPriceOracle {
    /// @notice reserve0 / reserve1 of the reference pool, settable by anyone who
    ///         can move the pool (i.e. the manipulation primitive).
    uint256 public reserve0;
    uint256 public reserve1;

    constructor(uint256 r0, uint256 r1) {
        reserve0 = r0;
        reserve1 = r1;
    }

    /// @notice The manipulation primitive: an attacker (or a flash loan) moves
    ///         the pool, and the spot price moves with it in the same block.
    function setReserves(uint256 r0, uint256 r1) external {
        reserve0 = r0;
        reserve1 = r1;
    }

    function price(address) external view returns (uint256) {
        return (reserve1 * 1e18) / reserve0;
    }
}

/// @title TwapOracle
/// @notice A manipulation-resistant control: the price is a *time-weighted*
///         average that an attacker cannot move within a single transaction.
///         `observe` returns the last committed average, and committing requires
///         the reserves to have been stable across a window.
contract TwapOracle is IPriceOracle {
    uint256 public immutable twap;

    constructor(uint256 twap_) {
        twap = twap_;
    }

    /// @notice Attempts to manipulate the average. A single-block move cannot
    ///         change a TWAP, so this is a no-op by construction.
    function setReserves(uint256, uint256) external {
        // no effect: the average is committed out-of-band over a window
    }

    function price(address) external view returns (uint256) {
        return twap;
    }
}
