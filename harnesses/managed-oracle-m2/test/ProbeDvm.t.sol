// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {Test} from "forge-std/Test.sol";

/// @notice The DVM leg behind the Managed OO on Polygon is an OracleSpoke, not VotingV2.
///         It gates requestPrice on the Finder's ContractRegistry, so an EOA cannot occupy a
///         price tuple to make a later dispute revert.
contract DvmRegistrationProbeTest is Test {
    address constant SPOKE = 0xac60353a54873c446101216829a6A98cDbbC3f3D;
    bytes32 constant ID = "YES_OR_NO_QUERY";

    function setUp() public {
        vm.createSelectFork(vm.envString("POLYGON_RPC"));
    }

    function test_spoke_is_not_votingv2() public view {
        assertEq(SPOKE.code.length, 7600, "runtime size differs from VotingV2");
        // VotingV2 exposes these; the spoke does not.
        (bool ok,) = SPOKE.staticcall(abi.encodeWithSignature("getCurrentRoundId()"));
        assertFalse(ok, "spoke unexpectedly implements VotingV2 getters");
    }

    function test_eoa_cannot_request_a_dvm_price() public {
        address attacker = address(0xA11CE);
        vm.deal(attacker, 100 ether);

        vm.prank(attacker);
        (bool ok, bytes memory ret) = SPOKE.call(
            abi.encodeWithSignature(
                "requestPrice(bytes32,uint256,bytes)", ID, block.timestamp - 1, "probe-ancillary"
            )
        );

        assertFalse(ok, "an EOA must not be able to request a DVM price");
        assertEq(_revertString(ret), "Caller must be registered");
    }

    function _revertString(bytes memory ret) private pure returns (string memory) {
        if (ret.length < 68) return "";
        bytes memory body = new bytes(ret.length - 4);
        for (uint256 i = 4; i < ret.length; i++) body[i - 4] = ret[i];
        return abi.decode(body, (string));
    }
}
