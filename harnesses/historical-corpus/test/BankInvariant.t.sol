// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {VulnerableBank, SafeBank} from "../src/Historical.sol";

/// @notice Stateful invariant fuzz over the bank contracts (mission 3.D, Foundry
///         integration). The handler drives deposit/withdraw in random order; the
///         invariant is "the bank always covers its recorded deposits". It FAILS
///         on the vulnerable bank (the reentrancy path can break solvency) and
///         HOLDS on the patched one -- the differential is the evidence.
contract BankHandler is Test {
    VulnerableBank public bank;
    uint256 public owed;          // ghost: what the bank must be able to pay this handler

    constructor(VulnerableBank _bank) {
        bank = _bank;
    }

    function deposit(uint256 amount) external {
        amount = bound(amount, 1, 1 ether);
        vm.deal(address(this), amount);
        bank.deposit{value: amount}();
        owed += amount;
    }

    function withdraw(uint256 amount) external {
        amount = bound(amount, 1, 1 ether);
        uint256 bal = bank.balanceOf(address(this));
        if (bal >= amount) {
            owed -= bal;          // the handler is taking back its whole claim
            bank.withdraw();
        }
    }

    receive() external payable {}
}

/// @dev A target the fuzzer may call; its receive() re-enters withdraw(), which
///      is exactly the operation a random fuzzer over a *plain* handler never
///      performs. Including it lets the stateful fuzzer reach the reentrancy
///      state -- demonstrating that coverage of attacker *callbacks* matters.
contract AttackerTarget is Test {
    VulnerableBank public bank;

    constructor(VulnerableBank _bank) {
        bank = _bank;
    }

    function fundAndAttack(uint256 amount) external {
        amount = bound(amount, 1, 1 ether);
        vm.deal(address(this), amount);
        bank.deposit{value: amount}();
        bank.withdraw();
    }

    receive() external payable {
        if (address(bank).balance >= 1) {
            bank.withdraw();
        }
    }
}

contract BankInvariantTest is Test {
    VulnerableBank bank;
    BankHandler handler;
    AttackerTarget attacker;

    function setUp() public {
        bank = new VulnerableBank();
        handler = new BankHandler(bank);
        attacker = new AttackerTarget(bank);
        targetContract(address(handler));
        targetContract(address(attacker));
    }

    /// @dev The bank must always be able to honour every recorded balance. The
    ///      ghost ``owed`` is the handler's real claim; if the bank's ether drops
    ///      below it, a depositor can no longer withdraw -- insolvency. This
    ///      FAILS on the vulnerable bank: the reentrancy path drains it.
    function invariant_vulnerable_solvent() public view {
        assertGe(address(bank).balance, handler.owed(), "bank cannot honour its deposits");
    }
}

// --------------------------------------------------------------------------- //
// Patched control: the same invariant must HOLD on the guarded bank.
// --------------------------------------------------------------------------- //

contract SafeBankHandler is Test {
    SafeBank public bank;
    uint256 public owed;

    constructor(SafeBank _bank) {
        bank = _bank;
    }

    function deposit(uint256 amount) external {
        amount = bound(amount, 1, 1 ether);
        vm.deal(address(this), amount);
        bank.deposit{value: amount}();
        owed += amount;
    }

    function withdraw(uint256 amount) external {
        amount = bound(amount, 1, 1 ether);
        uint256 bal = bank.balanceOf(address(this));
        if (bal >= amount) {
            owed -= bal;
            bank.withdraw();
        }
    }

    receive() external payable {}
}

contract SafeAttackerTarget is Test {
    SafeBank public bank;

    constructor(SafeBank _bank) {
        bank = _bank;
    }

    function fundAndAttack(uint256 amount) external {
        amount = bound(amount, 1, 1 ether);
        vm.deal(address(this), amount);
        bank.deposit{value: amount}();
        bank.withdraw();
    }

    receive() external payable {
        if (address(bank).balance >= 1) {
            bank.withdraw();       // reverts (zero balance) -> whole tx rolls back
        }
    }
}

contract SafeBankInvariantTest is Test {
    SafeBank bank;
    SafeBankHandler handler;
    SafeAttackerTarget attacker;

    function setUp() public {
        bank = new SafeBank();
        handler = new SafeBankHandler(bank);
        attacker = new SafeAttackerTarget(bank);
        targetContract(address(handler));
        targetContract(address(attacker));
    }

    /// @dev Holds on the patched bank -- the differential that proves the fix.
    function invariant_patched_solvent() public view {
        assertGe(address(bank).balance, handler.owed(), "patched bank cannot honour its deposits");
    }
}
