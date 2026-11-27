// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {Test} from "forge-std/Test.sol";

// ---------------------------------------------------------------------------
// Self-contained mocks. Halmos 0.3.3 cannot symbolically deploy a contract
// defined in a *different* source file (it emits an unsupported
// `deployCode(string)` cheatcode). Every contract a `check_*` function deploys
// must therefore live in this file. This is a real tool constraint, recorded
// here so it is not re-discovered.
// ---------------------------------------------------------------------------

contract SymToken {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    uint256 public totalSupply;

    function mint(address to, uint256 amount) external {
        totalSupply += amount;
        balanceOf[to] += amount;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        require(balanceOf[msg.sender] >= amount);
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        uint256 a = allowance[from][msg.sender];
        require(a >= amount);
        allowance[from][msg.sender] = a - amount;
        require(balanceOf[from] >= amount);
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}

contract SymSafeVault {
    SymToken public token;
    mapping(address => uint256) public balanceOf;
    uint256 public totalAssets;
    uint256 private _locked = 1;

    constructor(SymToken t) { token = t; }

    function deposit(uint256 amount) external {
        token.transferFrom(msg.sender, address(this), amount);
        balanceOf[msg.sender] += amount;
        totalAssets += amount;
    }

    function withdraw(uint256 amount) external {
        require(_locked == 1, "reentrant");
        _locked = 2;
        require(balanceOf[msg.sender] >= amount);
        balanceOf[msg.sender] -= amount;
        totalAssets -= amount;
        token.transfer(msg.sender, amount);
        _locked = 1;
    }
}

/// @dev Unprotected initializer: anyone can seize ownership before it is locked.
contract SymVulnerableInit {
    address public owner;
    bool public initialized;
    constructor() { owner = msg.sender; }
    function initialize(address newOwner) external {
        require(!initialized);
        initialized = true;
        owner = newOwner;
    }
}

/// @dev The same surface with the initializer locked at construction.
contract SymSafeInit {
    address public owner;
    bool public initialized = true;
    constructor() { owner = msg.sender; }
    function initialize(address newOwner) external {
        require(!initialized);
        initialized = true;
        owner = newOwner;
    }
}

/// @title Symbolic
/// @notice Halmos symbolic-execution suite. `check_*` functions are proven for
///         ALL inputs (within the bounded model). Two kinds of result appear:
///           * a PASS proves the security property holds;
///           * a counterexample (FAIL) is a symbolic proof that the property can
///             be violated, and Halmos prints the concrete witness.
///         Together these are a machine-checked differential, not a heuristic.
contract Symbolic is Test {
    /// @notice PROOF: on the defended vault, the accounting identity
    ///         `totalAssets == token balance` holds for every deposit/withdraw
    ///         pair, so no value is ever created or destroyed.
    function check_safe_vault_accounting_is_exact(uint256 depositAmount, uint256 withdrawAmount) public {
        SymToken token = new SymToken();
        SymSafeVault vault = new SymSafeVault(token);

        depositAmount = 1 + (depositAmount % 1e24);
        withdrawAmount = withdrawAmount % (depositAmount + 1);

        token.mint(address(this), depositAmount);
        token.approve(address(vault), depositAmount);
        vault.deposit(depositAmount);
        if (withdrawAmount > 0) vault.withdraw(withdrawAmount);

        assertEq(vault.totalAssets(), token.balanceOf(address(vault)));
    }

    /// @notice COUNTEREXAMPLE: the unprotected initializer lets an arbitrary
    ///         caller become owner. Halmos returns the witness address.
    function check_unprotected_initializer_cannot_be_taken_over(address attacker) public {
        vm.assume(attacker != address(0) && attacker != address(this));
        SymVulnerableInit v = new SymVulnerableInit();
        v.initialize(attacker);
        // This assertion is false for any attacker != deployer; Halmos falsifies it.
        assert(v.owner() != attacker);
    }

    /// @notice PROOF: the guarded initializer rejects every takeover attempt, so
    ///         ownership can never change.
    function check_guarded_initializer_rejects_takeover(address attacker) public {
        SymSafeInit s = new SymSafeInit();
        (bool ok,) = address(s).call(abi.encodeCall(SymSafeInit.initialize, (attacker)));
        assert(!ok); // the takeover always reverts
        assert(s.owner() == address(this));
    }
}
