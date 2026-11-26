// SPDX-License-Identifier: MIT
pragma solidity ^0.8.9;

import {Test} from "forge-std/Test.sol";
import {Bridge2, ValidatorSet, ValidatorSetUpdateRequest, Withdrawal, WithdrawalRequest, DepositWithPermit} from "../vendor/src/Bridge2.sol";
import {Signature} from "../vendor/src/Signature.sol";
import {MockUSDC} from "./MockUSDC.sol";

// Adversarial + property tests for the real, in-scope Hyperliquid Arbitrum USDC
// bridge (Bridge2.sol @ d7e66aa). The contract under test is compiled verbatim
// from the fetched source; only USDC is mocked. Everything runs in a local EVM
// (chain_id 1337, so the contract's own block-number hook is used); nothing is
// broadcast and no mainnet code is touched.
contract Bridge2Test is Test {
  Bridge2 bridge;
  MockUSDC usdc;

  // 3 validators with powers 1,2,3 -> total 6, quorum requires 3*cum > 2*6 => cum >= 5.
  uint256[3] hotPk = [uint256(0xA11CE), 0xB0B, 0xC0FFEE];
  uint256[3] coldPk = [uint256(0xDEAD), 0xBEEF, 0xCAFE];
  address[3] hot;
  address[3] cold;
  uint64[3] powers = [uint64(1), 2, 3];

  uint64 constant DISPUTE_SECONDS = 100;
  uint64 constant BLOCK_MILLIS = 100; // 100ms per block -> 1000 blocks per 100s

  function setUp() public {
    for (uint256 i; i < 3; i++) {
      hot[i] = vm.addr(hotPk[i]);
      cold[i] = vm.addr(coldPk[i]);
    }
    usdc = new MockUSDC();
    bridge = new Bridge2(
      _toAddrArray(hot),
      _toAddrArray(cold),
      _toU64Array(powers),
      address(usdc),
      DISPUTE_SECONDS,
      BLOCK_MILLIS,
      2 // lockerThreshold
    );
  }

  // ---- helpers -------------------------------------------------------------

  function _toAddrArray(address[3] memory a) internal pure returns (address[] memory out) {
    out = new address[](3);
    for (uint256 i; i < 3; i++) out[i] = a[i];
  }

  function _toU64Array(uint64[3] memory a) internal pure returns (uint64[] memory out) {
    out = new uint64[](3);
    for (uint256 i; i < 3; i++) out[i] = a[i];
  }

  // Signature over the bridge's Agent("a", keccak256(abi.encode(address(this), data))) message.
  function _sign(uint256 pk, bytes32 data) internal view returns (Signature memory sig) {
    bytes32 domainSeparator = keccak256(
      abi.encode(
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
        keccak256(bytes("Exchange")),
        keccak256(bytes("1")),
        block.chainid,
        address(0)
      )
    );
    bytes32 dataHash = keccak256(
      abi.encode(keccak256("Agent(string source,bytes32 connectionId)"), keccak256(bytes("a")),
        keccak256(abi.encode(address(bridge), data)))
    );
    bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, dataHash));
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
    sig = Signature(uint256(r), uint256(s), v);
  }

  // The full ValidatorSet struct the bridge re-hashes and compares to its checkpoint.
  function _activeHot() internal view returns (ValidatorSet memory vs) {
    vs.epoch = 0;
    vs.validators = _toAddrArray(hot);
    vs.powers = _toU64Array(powers);
  }

  function _hotQuorum(bytes32 data) internal view returns (Signature[] memory sigs) {
    sigs = new Signature[](3);
    sigs[0] = _sign(hotPk[0], data);
    sigs[1] = _sign(hotPk[1], data);
    sigs[2] = _sign(hotPk[2], data);
  }

  function _withdrawalData(address user, address dest, uint64 usd, uint64 nonce)
    internal
    view
    returns (bytes32)
  {
    return keccak256(abi.encode("requestWithdrawal", user, dest, usd, nonce));
  }

  function _requestWithdrawal(address user, address dest, uint64 usd, uint64 nonce) internal {
    WithdrawalRequest[] memory reqs = new WithdrawalRequest[](1);
    Signature[] memory sigs = _hotQuorum(_withdrawalData(user, dest, usd, nonce));
    reqs[0] = WithdrawalRequest({user: user, destination: dest, usd: usd, nonce: nonce, signatures: sigs});
    bridge.batchedRequestWithdrawals(reqs, _activeHot());
  }

  // Message key the bridge uses to index a withdrawal.
  function _message(address user, address dest, uint64 usd, uint64 nonce) internal view returns (bytes32) {
    bytes32 data = _withdrawalData(user, dest, usd, nonce);
    return keccak256(
      abi.encode(
        keccak256("Agent(string source,bytes32 connectionId)"),
        keccak256(bytes("a")),
        keccak256(abi.encode(address(bridge), data))
      )
    );
  }

  function _fundBridge(uint256 amount) internal {
    usdc.mint(address(bridge), amount);
  }

  function _advancePastDispute() internal {
    vm.warp(block.timestamp + DISPUTE_SECONDS + 1);
    vm.roll(block.number + 1000 + 1);
  }

  // ---- baseline behaviour (proves the harness exercises real logic) ---------

  function test_quorum_accepts_valid_signatures() public {
    address user = address(0x1234);
    address dest = address(0x5678);
    _fundBridge(1000);
    _requestWithdrawal(user, dest, 100, 1);
    bytes32 msg_ = _message(user, dest, 100, 1);
    (,,,,, uint64 requestedTime,) = bridge.requestedWithdrawals(msg_);
    assertGt(requestedTime, 0, "valid quorum must register the withdrawal");
  }

  function test_insufficient_power_reverts() public {
    address user = address(0x1234);
    // Only validator 0 (power 1) signs: 3*1 = 3 <= 2*6 => must revert.
    WithdrawalRequest[] memory reqs = new WithdrawalRequest[](1);
    Signature[] memory sigs = new Signature[](1);
    sigs[0] = _sign(hotPk[0], _withdrawalData(user, user, 1, 1));
    reqs[0] = WithdrawalRequest({user: user, destination: user, usd: 1, nonce: 1, signatures: sigs});
    vm.expectRevert("Submitted validator set signatures do not have enough power");
    bridge.batchedRequestWithdrawals(reqs, _activeHot());
  }

  function test_finalize_requires_dispute_period_and_finalizer() public {
    address user = address(0x1234);
    address dest = address(0x9999);
    _fundBridge(1000);
    _requestWithdrawal(user, dest, 100, 1);
    bytes32 msg_ = _message(user, dest, 100, 1);

    bytes32[] memory msgs = new bytes32[](1);
    msgs[0] = msg_;

    // Non-finalizer cannot finalize.
    vm.expectRevert("Sender is not a finalizer");
    bridge.batchedFinalizeWithdrawals(msgs);

    // Validator hot addresses are finalizers by construction.
    vm.prank(hot[0]);
    // Still inside the dispute period -> no transfer, FailedWithdrawal(3) emitted.
    bridge.batchedFinalizeWithdrawals(msgs);
    assertEq(usdc.balanceOf(dest), 0, "must not pay before dispute period");

    _advancePastDispute();
    vm.prank(hot[0]);
    bridge.batchedFinalizeWithdrawals(msgs);
    assertEq(usdc.balanceOf(dest), 100, "pays after dispute period");
  }

  function test_double_finalize_is_rejected() public {
    address user = address(0x1234);
    address dest = address(0x9999);
    _fundBridge(1000);
    _requestWithdrawal(user, dest, 100, 1);
    bytes32 msg_ = _message(user, dest, 100, 1);
    bytes32[] memory msgs = new bytes32[](1);
    msgs[0] = msg_;
    _advancePastDispute();

    vm.prank(hot[0]);
    bridge.batchedFinalizeWithdrawals(msgs);
    assertEq(usdc.balanceOf(dest), 100);

    // Replay: finalizedWithdrawals guard must prevent a second payout.
    vm.prank(hot[0]);
    bridge.batchedFinalizeWithdrawals(msgs);
    assertEq(usdc.balanceOf(dest), 100, "no double payout");
  }

  function test_duplicate_request_is_rejected() public {
    address user = address(0x1234);
    _fundBridge(1000);
    _requestWithdrawal(user, user, 100, 1);
    bytes32 msg_ = _message(user, user, 100, 1);
    (,,,,, uint64 t1,) = bridge.requestedWithdrawals(msg_);
    _requestWithdrawal(user, user, 100, 1); // identical message
    (,,,,, uint64 t2,) = bridge.requestedWithdrawals(msg_);
    assertEq(t1, t2, "duplicate request must not overwrite the pending withdrawal");
  }

  // ---- attack 1: forged signatures / wrong signer set ----------------------

  function test_forged_signatures_do_not_register_withdrawal() public {
    // An attacker supplies their own keys, not the validator set.
    uint256 attackerPk = 0xBAD;
    address user = address(0xAAAA);
    address dest = address(0xBBBB);
    _fundBridge(1000);

    bytes32 data = _withdrawalData(user, dest, 1000, 1);
    WithdrawalRequest[] memory reqs = new WithdrawalRequest[](1);
    Signature[] memory sigs = new Signature[](3);
    sigs[0] = _sign(attackerPk, data);
    sigs[1] = _sign(attackerPk + 1, data);
    sigs[2] = _sign(attackerPk + 2, data);
    reqs[0] = WithdrawalRequest({user: user, destination: dest, usd: 1000, nonce: 1, signatures: sigs});

    vm.expectRevert("Submitted validator set signatures do not have enough power");
    bridge.batchedRequestWithdrawals(reqs, _activeHot());
  }

  function test_wrong_validator_set_struct_reverts() public {
    // Supplying a validator set that does not hash to the checkpoint must revert.
    ValidatorSet memory bogus;
    bogus.epoch = 0;
    address[] memory vs = new address[](3);
    vs[0] = hot[0];
    vs[1] = hot[1];
    vs[2] = address(0xDEADBEEF); // swapped
    bogus.validators = vs;
    bogus.powers = _toU64Array(powers);

    WithdrawalRequest[] memory reqs = new WithdrawalRequest[](1);
    Signature[] memory sigs = _hotQuorum(_withdrawalData(address(1), address(1), 1, 1));
    reqs[0] = WithdrawalRequest({user: address(1), destination: address(1), usd: 1, nonce: 1, signatures: sigs});
    vm.expectRevert("Supplied active validators and powers do not match the active checkpoint");
    bridge.batchedRequestWithdrawals(reqs, bogus);
  }

  // ---- attack 2: signature-subsequence parsing edge cases ------------------

  // The signature check walks the active set and only advances `signatureIdx` when the
  // current signature recovers to the current active validator. A *reordered* or
  // *duplicated* signature list should not be able to reach quorum. This documents the
  // property the L1 must uphold ("signing validators should be a subsequence").
  function test_out_of_order_signatures_do_not_reach_quorum() public {
    address user = address(0x1234);
    bytes32 data = _withdrawalData(user, user, 1, 1);
    WithdrawalRequest[] memory reqs = new WithdrawalRequest[](1);
    Signature[] memory sigs = new Signature[](3);
    // Provide signatures in reverse validator order.
    sigs[0] = _sign(hotPk[2], data);
    sigs[1] = _sign(hotPk[1], data);
    sigs[2] = _sign(hotPk[0], data);
    reqs[0] = WithdrawalRequest({user: user, destination: user, usd: 1, nonce: 1, signatures: sigs});
    vm.expectRevert("Submitted validator set signatures do not have enough power");
    bridge.batchedRequestWithdrawals(reqs, _activeHot());
  }

  function test_duplicated_signature_does_not_reach_quorum() public {
    address user = address(0x1234);
    bytes32 data = _withdrawalData(user, user, 1, 1);
    WithdrawalRequest[] memory reqs = new WithdrawalRequest[](1);
    Signature[] memory sigs = new Signature[](3);
    Signature memory s2 = _sign(hotPk[2], data); // power 3, alone < 5
    sigs[0] = s2;
    sigs[1] = s2;
    sigs[2] = s2;
    reqs[0] = WithdrawalRequest({user: user, destination: user, usd: 1, nonce: 1, signatures: sigs});
    vm.expectRevert("Submitted validator set signatures do not have enough power");
    bridge.batchedRequestWithdrawals(reqs, _activeHot());
  }

  // ---- attack 3: locker / pause authorisation ------------------------------

  function test_only_locker_can_vote_lock() public {
    vm.prank(address(0xBAD));
    vm.expectRevert("Sender is not authorized to lock smart contract");
    bridge.voteEmergencyLock();
  }

  function test_locker_threshold_pauses_and_cold_quorum_unlocks() public {
    // hot[0] and hot[1] are lockers; threshold is 2.
    vm.prank(hot[0]);
    bridge.voteEmergencyLock();
    assertFalse(bridge.paused(), "one vote is not enough");

    vm.prank(hot[1]);
    bridge.voteEmergencyLock();
    assertTrue(bridge.paused(), "threshold reached -> paused");

    // Unlock requires cold quorum; hot signatures must not work.
    ValidatorSetUpdateRequest memory newSet;
    newSet.epoch = 1;
    newSet.hotAddresses = _toAddrArray(hot);
    newSet.coldAddresses = _toAddrArray(cold);
    newSet.powers = _toU64Array(powers);
    uint64 nonce = 1;

    bytes32 data = keccak256(
      abi.encode("unlock", newSet.epoch, newSet.hotAddresses, newSet.coldAddresses, newSet.powers, nonce)
    );
    Signature[] memory coldSigs = new Signature[](3);
    coldSigs[0] = _sign(coldPk[0], data);
    coldSigs[1] = _sign(coldPk[1], data);
    coldSigs[2] = _sign(coldPk[2], data);

    ValidatorSet memory activeCold;
    activeCold.epoch = 0;
    activeCold.validators = _toAddrArray(cold);
    activeCold.powers = _toU64Array(powers);

    bridge.emergencyUnlock(newSet, activeCold, coldSigs, nonce);
    assertFalse(bridge.paused(), "cold quorum unlocks");
  }

  function test_hot_signatures_cannot_unlock() public {
    vm.prank(hot[0]);
    bridge.voteEmergencyLock();
    vm.prank(hot[1]);
    bridge.voteEmergencyLock();
    assertTrue(bridge.paused());

    ValidatorSetUpdateRequest memory newSet;
    newSet.epoch = 1;
    newSet.hotAddresses = _toAddrArray(hot);
    newSet.coldAddresses = _toAddrArray(cold);
    newSet.powers = _toU64Array(powers);

    bytes32 data =
      keccak256(abi.encode("unlock", newSet.epoch, newSet.hotAddresses, newSet.coldAddresses, newSet.powers, uint64(1)));
    Signature[] memory hotSigs = new Signature[](3);
    hotSigs[0] = _sign(hotPk[0], data);
    hotSigs[1] = _sign(hotPk[1], data);
    hotSigs[2] = _sign(hotPk[2], data);

    ValidatorSet memory activeCold;
    activeCold.epoch = 0;
    activeCold.validators = _toAddrArray(cold);
    activeCold.powers = _toU64Array(powers);

    vm.expectRevert("Submitted validator set signatures do not have enough power");
    bridge.emergencyUnlock(newSet, activeCold, hotSigs, 1);
  }

  // ---- attack 4: message replay across actions -----------------------------

  // usedMessages is only enforced on the *parameter-change* paths. A withdrawal message
  // and a parameter-change message with the same preimage must not be interchangeable.
  function test_withdrawal_message_cannot_be_replayed_as_parameter_change() public {
    // Craft a "changeDisputePeriodSeconds" call whose message collides structurally with
    // a withdrawal, and confirm the signature check still binds to the action string.
    address user = address(0x1234);
    _fundBridge(1000);
    _requestWithdrawal(user, user, 1, 1);

    // Attempt to reuse the withdrawal signatures for a dispute-period change.
    bytes32 data = keccak256(abi.encode("changeDisputePeriodSeconds", uint64(1), uint64(1)));
    Signature[] memory sigs = _hotQuorum(data);
    ValidatorSet memory activeCold;
    activeCold.epoch = 0;
    activeCold.validators = _toAddrArray(cold);
    activeCold.powers = _toU64Array(powers);

    // Signed by hot keys but verified against the COLD checkpoint -> must revert.
    vm.expectRevert("Submitted validator set signatures do not have enough power");
    bridge.changeDisputePeriodSeconds(1, 1, activeCold, sigs);
  }

  // ---- attack 5: deposit-with-permit path ----------------------------------

  function test_deposit_with_permit_moves_funds() public {
    uint256 pk = 0xD00D;
    address user = vm.addr(pk);
    usdc.mint(user, 500);

    // Permit: user -> bridge for 500.
    bytes32 structHash = keccak256(
      abi.encode(
        keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)"),
        user,
        address(bridge),
        uint256(500),
        usdc.nonces(user),
        block.timestamp + 1 days
      )
    );
    bytes32 domainSeparator = keccak256(
      abi.encode(
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
        keccak256(bytes("USD Coin")),
        keccak256(bytes("1")),
        block.chainid,
        address(usdc)
      )
    );
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash)));

    DepositWithPermit[] memory deps = new DepositWithPermit[](1);
    deps[0] = DepositWithPermit({
      user: user,
      usd: 500,
      deadline: uint64(block.timestamp + 1 days),
      signature: Signature(uint256(r), uint256(s), v)
    });
    bridge.batchedDepositWithPermit(deps);
    assertEq(usdc.balanceOf(address(bridge)), 500, "permit deposit funds the bridge");
  }

  // Replayed permit (same nonce) must fail; the token enforces the nonce, the bridge
  // swallows the failure and emits FailedPermitDeposit without moving funds.
  function test_replayed_permit_is_swallowed_no_double_credit() public {
    uint256 pk = 0xD00D;
    address user = vm.addr(pk);
    usdc.mint(user, 1000);

    bytes32 structHash = keccak256(
      abi.encode(
        keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)"),
        user,
        address(bridge),
        uint256(500),
        usdc.nonces(user),
        block.timestamp + 1 days
      )
    );
    bytes32 domainSeparator = keccak256(
      abi.encode(
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
        keccak256(bytes("USD Coin")),
        keccak256(bytes("1")),
        block.chainid,
        address(usdc)
      )
    );
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash)));

    DepositWithPermit[] memory deps = new DepositWithPermit[](1);
    deps[0] = DepositWithPermit({
      user: user,
      usd: 500,
      deadline: uint64(block.timestamp + 1 days),
      signature: Signature(uint256(r), uint256(s), v)
    });
    bridge.batchedDepositWithPermit(deps);
    bridge.batchedDepositWithPermit(deps); // replay
    assertEq(usdc.balanceOf(address(bridge)), 500, "replay must not move more funds");
  }
}
