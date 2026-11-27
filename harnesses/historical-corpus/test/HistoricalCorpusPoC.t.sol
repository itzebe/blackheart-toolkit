// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {
    VulnerableBank,
    SafeBank,
    SafeBankAttacker,
    ReentrancyAttacker,
    VulnerableRegistry,
    SafeRegistry,
    VulnerablePermit,
    SafePermit
} from "../src/Historical.sol";

/// @notice Executable PoCs for the historical corpus (mission 3.G).
///         Each test proves: the exploit runs on the vulnerable contract, and the
///         patched control rejects the same sequence. A passing suite is the
///         "exploit reproduced + patched-version rejection" evidence.
contract HistoricalCorpusPoC is Test {
    receive() external payable {}

    // ------------------------------------------------------------------ //
    // 1. Reentrancy
    // ------------------------------------------------------------------ //

    function test_reentrancy_drains_vulnerable() public {
        VulnerableBank bank = new VulnerableBank();
        ReentrancyAttacker attacker = new ReentrancyAttacker(bank);

        // A victim funds the bank with 5 ether.
        address victim = address(0xBEEF);
        vm.deal(victim, 5 ether);
        vm.prank(victim);
        bank.deposit{value: 5 ether}();

        // The attacker deposits 1 ether and re-enters withdraw().
        vm.deal(address(this), 1 ether);
        attacker.attack{value: 1 ether}();

        // The attacker ends with more than the 1 ether it put in.
        assertGt(address(attacker).balance, 1 ether, "reentrancy did not profit");
        assertLt(address(bank).balance, 5 ether, "bank was not drained");
    }

    function test_reentrancy_patched_control_holds() public {
        SafeBank bank = new SafeBank();
        SafeBankAttacker attacker = new SafeBankAttacker(bank);

        address victim = address(0xBEEF);
        vm.deal(victim, 5 ether);
        vm.prank(victim);
        bank.deposit{value: 5 ether}();

        // The identical attack reverts against the patched bank: the re-entrant
        // withdraw hits a zero balance and the whole transaction is rolled back.
        vm.deal(address(this), 1 ether);
        vm.expectRevert();
        attacker.attack{value: 1 ether}();

        assertEq(address(bank).balance, 5 ether, "patched bank must stay solvent");
    }

    // ------------------------------------------------------------------ //
    // 2. Access control
    // ------------------------------------------------------------------ //

    function test_access_control_vulnerable() public {
        VulnerableRegistry reg = new VulnerableRegistry();
        address attacker = address(0xBAD);
        vm.prank(attacker);
        reg.setProtectedValue(0);
        assertEq(reg.protectedValue(), 0, "attacker changed protected state");
    }

    function test_access_control_patched_control_reverts() public {
        SafeRegistry reg = new SafeRegistry();
        address attacker = address(0xBAD);
        vm.prank(attacker);
        vm.expectRevert("not owner");
        reg.setProtectedValue(0);
        assertEq(reg.protectedValue(), 1000, "protected state unchanged");
    }

    // ------------------------------------------------------------------ //
    // 3. Signature replay
    // ------------------------------------------------------------------ //

    function test_permit_replay_vulnerable() public {
        VulnerablePermit permit = new VulnerablePermit();
        address owner_ = address(0xA11CE);
        address spender = address(0x5EED);
        permit.permit(owner_, spender, 100);
        permit.permit(owner_, spender, 100);
        assertEq(permit.allowance(spender), 200, "permit replayed to double allowance");
    }

    function test_permit_replay_patched_control_reverts() public {
        SafePermit permit = new SafePermit();
        address owner_ = address(0xA11CE);
        address spender = address(0x5EED);
        bytes32 sigHash = keccak256("sig-1");
        permit.permit(owner_, spender, 100, sigHash);
        vm.expectRevert("signature already used");
        permit.permit(owner_, spender, 100, sigHash);
        assertEq(permit.allowance(spender), 100, "allowance honoured exactly once");
    }
}
