// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {VulnerableAccess} from "../access/Access.sol";

/// @title PhishingProxy
/// @notice A malicious callee. When the real owner interacts with it (thinking it
///         is a benign contract), it replays a privileged call to a target that
///         authorises on `tx.origin`. The owner's transaction becomes the
///         attacker's transaction.
contract PhishingProxy {
    /// @notice Called by the victim owner. Performs the privileged action on the
    ///         victim's behalf because the target checks `tx.origin`.
    function lure(address vulnerable, uint256 value) external {
        VulnerableAccess(vulnerable).setProtected(value);
    }

    /// @notice The same lure against a `msg.sender`-authorised target: the call
    ///         originates from this contract, not the owner, so it reverts.
    function lureSafe(address safeTarget, uint256 value) external {
        (bool ok,) = safeTarget.call(abi.encodeWithSignature("setProtected(uint256)", value));
        require(ok, "safe target rejected (expected)");
    }
}
