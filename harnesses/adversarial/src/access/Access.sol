// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title VulnerableAccess
/// @notice Authorises a privileged action with `tx.origin`, not `msg.sender`.
///         Any contract the owner interacts with can therefore replay the call
///         and perform the privileged action on the owner's behalf (a phishing /
///         malicious-callee access-control bypass).
/// @dev Deliberately vulnerable. The control is the authorisation predicate only.
contract VulnerableAccess {
    address public owner;
    bool public initialized;
    uint256 public protectedValue;

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwnerOrigin() {
        require(tx.origin == owner, "not owner (origin)");
        _;
    }

    function setProtected(uint256 v) external onlyOwnerOrigin {
        protectedValue = v;
    }

    /// @notice Unsafe initializer: callable by anyone while `initialized` is false.
    ///         Models the "unprotected initializer" class.
    function initialize(address newOwner) external {
        require(!initialized, "already initialised");
        initialized = true;
        owner = newOwner;
    }
}

/// @title SafeAccess
/// @notice The same surface with `msg.sender` authorisation and a guarded
///         initializer. Negative control.
contract SafeAccess {
    address public owner;
    bool public initialized;
    uint256 public protectedValue;

    constructor() {
        owner = msg.sender;
        initialized = true;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function setProtected(uint256 v) external onlyOwner {
        protectedValue = v;
    }

    function initialize(address newOwner) external {
        require(!initialized, "already initialised");
        initialized = true;
        owner = newOwner;
    }
}
