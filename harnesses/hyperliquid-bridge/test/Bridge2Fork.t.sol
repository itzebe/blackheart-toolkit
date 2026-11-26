// SPDX-License-Identifier: MIT
pragma solidity ^0.8.9;

import {Test} from "forge-std/Test.sol";
import {Bridge2} from "../vendor/src/Bridge2.sol";

// Deployment mapping check. Builds a LOCAL read-only Arbitrum fork (never broadcasts)
// and asserts that the deployed legacy bridge exposes the same interface and a
// self-consistent configuration as the audited source revision.
//
//   forge test --match-contract Bridge2Fork --fork-url https://arb1.arbitrum.io/rpc
contract Bridge2ForkTest is Test {
  address constant DEPLOYED_BRIDGE = 0x2Df1c51E09aECF9cacB7bc98cB1742757f163dF7;
  address constant ARB_USDC = 0xaf88d065e77c8cC2239327C5EDb3A432268e5831;

  function setUp() public {
    // Skip cleanly when no fork RPC is provided so the default `forge test` stays offline.
    // A local EVM starts near block 1; any real Arbitrum fork is far above this.
    if (block.number < 1_000_000) {
      vm.skip(true);
    }
  }

  function test_deployed_bridge_matches_audited_interface() public view {
    Bridge2 b = Bridge2(DEPLOYED_BRIDGE);
    assertEq(address(b.usdcToken()), ARB_USDC, "USDC token mismatch");
    assertEq(b.lockerThreshold(), 2, "unexpected locker threshold");
    assertGt(b.nValidators(), 0, "no validators");
    assertGt(b.totalValidatorPower(), 0, "no validator power");
    assertTrue(b.hotValidatorSetHash() != bytes32(0), "empty hot set hash");
    assertTrue(b.coldValidatorSetHash() != bytes32(0), "empty cold set hash");
    assertFalse(b.paused(), "bridge unexpectedly paused");
    assertEq(b.disputePeriodSeconds(), 200, "unexpected dispute period");
  }
}
