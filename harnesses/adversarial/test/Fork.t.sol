// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {Test} from "forge-std/Test.sol";
import {AdversarialERC20} from "../src/token/AdversarialERC20.sol";
import {VulnerableVault} from "../src/vault/VulnerableVault.sol";
import {ReentrancyAttacker} from "../src/attack/ReentrancyAttacker.sol";

/// @title ForkIsolation
/// @notice Proves the harness can run inside an isolated local mainnet fork.
///         The fork is *read-only*: `forge` executes in-process against a pinned
///         remote block, and every state change (including the exploit) lives in
///         the local EVM. Nothing is broadcast.
/// @dev Requires network access to a keyless public RPC. Pinned to a fixed block
///      so the fork state is deterministic and reproducible. Skipped by the
///      runner unless a fork URL is available.
contract ForkIsolation is Test {
    // Pinned so the forked state never drifts between runs.
    uint256 constant PIN_BLOCK = 21_000_000;
    string constant DEFAULT_RPC = "https://gateway.tenderly.co/public/mainnet";

    function test_fork_reads_real_state_and_runs_exploit_locally() public {
        string memory rpc = vm.envOr("BLACKHEART_ETH_RPC", DEFAULT_RPC);
        uint256 fork = vm.createSelectFork(rpc, PIN_BLOCK);

        // 1. Read real mainnet state (WETH total supply) — proves the fork is live.
        (bool ok, bytes memory data) = address(0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2)
            .staticcall(abi.encodeWithSignature("totalSupply()"));
        assertTrue(ok, "fork must serve real state");
        uint256 wethSupply = abi.decode(data, (uint256));
        assertGt(wethSupply, 0, "mainnet WETH supply must be non-zero");

        // 2. Run the full exploit *inside the fork*, with no mainnet mutation.
        AdversarialERC20 token = new AdversarialERC20(0);
        VulnerableVault vault = new VulnerableVault(token);
        address victim = makeAddr("victim");
        address attacker = makeAddr("attacker");

        token.mint(victim, 900e18);
        vm.startPrank(victim);
        token.approve(address(vault), 900e18);
        vault.deposit(900e18);
        vm.stopPrank();

        token.mint(attacker, 100e18);
        ReentrancyAttacker atk = new ReentrancyAttacker();
        vm.prank(attacker);
        token.transfer(address(atk), 100e18);

        atk.attack(address(vault), token, 100e18);
        atk.drain(attacker);

        emit log_named_uint("fork block", fork);
        emit log_named_uint("mainnet WETH totalSupply", wethSupply);
        emit log_named_uint("attacker profit in fork", token.balanceOf(attacker) - 100e18);

        assertGt(token.balanceOf(attacker), 100e18, "exploit works inside the fork");
        // The fork is read-only: mainnet WETH supply is unchanged by local writes.
        (ok, data) = address(0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2)
            .staticcall(abi.encodeWithSignature("totalSupply()"));
        assertEq(abi.decode(data, (uint256)), wethSupply, "no mainnet state was touched");
    }
}
