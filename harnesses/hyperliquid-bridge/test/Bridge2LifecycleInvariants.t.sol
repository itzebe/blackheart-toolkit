// SPDX-License-Identifier: MIT
pragma solidity ^0.8.9;

import {Test} from "forge-std/Test.sol";
import {Bridge2, ValidatorSet, ValidatorSetUpdateRequest, Withdrawal, WithdrawalRequest, DepositWithPermit} from "../vendor/src/Bridge2.sol";
import {Signature} from "../vendor/src/Signature.sol";
import {MockUSDC} from "./MockUSDC.sol";

// ---------------------------------------------------------------------------
// Validator-set lifecycle harness for the real Hyperliquid bridge (Bridge2.sol).
//
// The withdrawal harness (Bridge2Invariants.t.sol) never exercises the privileged
// validator-set machinery. This harness drives it statefully and checks that the
// active validator set / epoch can only advance through genuinely authorized
// paths (hot quorum to request, dispute period + finalizer to finalize, cold
// quorum to emergency-unlock). It also carries the withdrawal invariants so a
// lifecycle bug that corrupts accounting is still caught.
//
// All tests run on the real, unmodified source. Nothing is broadcast.
// ---------------------------------------------------------------------------

contract Bridge2LifecycleHandler is Test {
  Bridge2 public bridge;
  MockUSDC public usdc;

  uint256[3] hotPk = [uint256(0xA11CE), 0xB0B, 0xC0FFEE];
  uint256[3] coldPk = [uint256(0xDEAD), 0xBEEF, 0xCAFE];
  uint256[3] attackerPk = [uint256(0xBAD1), 0xBAD2, 0xBAD3];
  address[3] hot;
  address[3] cold;
  uint64[3] powers = [uint64(1), 2, 3];

  uint256[3] userPk = [uint256(0x1111), 0x2222, 0x3333];
  address[3] user;

  // Ghost: the epoch the bridge SHOULD be at, advanced only by a legitimately
  // finalized update or an authorized emergency unlock. Any other change is a bug.
  uint64 public expectedEpoch;
  uint256 public authorizedUpdates;

  // Withdrawal accounting ghosts (kept so lifecycle actions cannot corrupt them).
  uint256 public deposited;
  uint256 public paidOut;

  bool public attackerSetPending; // must stay false

  constructor(Bridge2 _bridge, MockUSDC _usdc) {
    bridge = _bridge;
    usdc = _usdc;
    for (uint256 i; i < 3; i++) {
      hot[i] = vm.addr(hotPk[i]);
      cold[i] = vm.addr(coldPk[i]);
      user[i] = vm.addr(userPk[i]);
    }
  }

  // ---- signing helpers -----------------------------------------------------

  function _domainSeparator() internal view returns (bytes32) {
    return keccak256(
      abi.encode(
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
        keccak256(bytes("Exchange")), keccak256(bytes("1")), block.chainid, address(0)
      )
    );
  }

  function _sign(uint256 pk, bytes32 data) internal view returns (Signature memory sig) {
    bytes32 dataHash = keccak256(
      abi.encode(keccak256("Agent(string source,bytes32 connectionId)"), keccak256(bytes("a")),
        keccak256(abi.encode(address(bridge), data)))
    );
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, keccak256(abi.encodePacked("\x19\x01", _domainSeparator(), dataHash)));
    sig = Signature(uint256(r), uint256(s), v);
  }

  function _activeHot() internal view returns (ValidatorSet memory vs) {
    vs.epoch = bridge.epoch();
    vs.validators = _toAddrArray(hot);
    vs.powers = _toU64Array(powers);
  }

  function _activeCold() internal view returns (ValidatorSet memory vs) {
    vs.epoch = bridge.epoch();
    vs.validators = _toAddrArray(cold);
    vs.powers = _toU64Array(powers);
  }

  function _quorum(uint256[3] memory pks, bytes32 data) internal view returns (Signature[] memory sigs) {
    sigs = new Signature[](3);
    sigs[0] = _sign(pks[0], data);
    sigs[1] = _sign(pks[1], data);
    sigs[2] = _sign(pks[2], data);
  }

  function _updateData(uint64 epoch) internal view returns (bytes32) {
    return keccak256(
      abi.encode("updateValidatorSet", epoch, _toAddrArray(hot), _toAddrArray(cold), _toU64Array(powers))
    );
  }

  function _unlockData(uint64 epoch, uint64 nonce) internal view returns (bytes32) {
    return keccak256(
      abi.encode("unlock", epoch, _toAddrArray(hot), _toAddrArray(cold), _toU64Array(powers), nonce)
    );
  }

  function _toAddrArray(address[3] memory a) internal pure returns (address[] memory out) {
    out = new address[](3);
    for (uint256 i; i < 3; i++) out[i] = a[i];
  }

  function _toU64Array(uint64[3] memory a) internal pure returns (uint64[] memory out) {
    out = new uint64[](3);
    for (uint256 i; i < 3; i++) out[i] = a[i];
  }

  function _req(uint64 epoch) internal view returns (ValidatorSetUpdateRequest memory r) {
    r.epoch = epoch;
    r.hotAddresses = _toAddrArray(hot);
    r.coldAddresses = _toAddrArray(cold);
    r.powers = _toU64Array(powers);
  }

  function _advance(uint256 seed) internal {
    if (seed % 2 == 0) {
      vm.warp(block.timestamp + 101 + (seed % 300));
      vm.roll(block.number + 1001 + (seed % 2000));
    } else {
      vm.warp(block.timestamp + (seed % 90)); // sometimes still inside dispute period
    }
  }

  // ---- authorized lifecycle actions ---------------------------------------

  // Hot quorum requests a validator-set update to a strictly higher epoch.
  function updateSet(uint64 epochSeed) external {
    uint64 target = bridge.epoch() + 1 + (epochSeed % 3);
    Signature[] memory sigs = _quorum(hotPk, _updateData(target));
    try bridge.updateValidatorSet(_req(target), _activeHot(), sigs) {} catch {}
  }

  function finalizeUpdate(uint256 seed) external {
    _advance(seed);
    uint64 before = bridge.epoch();
    vm.prank(hot[0]); // hot addresses are finalizers by construction
    try bridge.finalizeValidatorSetUpdate() {} catch {}
    if (bridge.epoch() != before) {
      // The only legal way epoch changes here is activating the pending update.
      (uint64 pendingEpoch, , , , , , ) = bridge.pendingValidatorSetUpdate();
      require(bridge.epoch() == pendingEpoch, "epoch set from nowhere");
      expectedEpoch = bridge.epoch();
      authorizedUpdates += 1;
    }
  }

  // Two lockers vote to pause the bridge (lockerThreshold == 2).
  function pause(uint256 seed) external {
    vm.prank(hot[seed % 2]);
    try bridge.voteEmergencyLock() {} catch {}
    vm.prank(hot[(seed + 1) % 2]);
    try bridge.voteEmergencyLock() {} catch {}
  }

  function unpauseVote(uint256 seed) external {
    vm.prank(hot[seed % 3]);
    try bridge.unvoteEmergencyLock() {} catch {}
  }

  // Cold quorum atomically installs a new (higher) epoch and unpauses.
  function emergencyUnlock(uint64 epochSeed, uint64 nonce) external {
    if (!bridge.paused()) return;
    uint64 target = bridge.epoch() + 1 + (epochSeed % 3);
    Signature[] memory sigs = _quorum(coldPk, _unlockData(target, nonce));
    uint64 before = bridge.epoch();
    try bridge.emergencyUnlock(_req(target), _activeCold(), sigs, nonce) {} catch {}
    if (bridge.epoch() != before) {
      require(bridge.epoch() == target, "unlock set an unexpected epoch");
      expectedEpoch = bridge.epoch();
      authorizedUpdates += 1;
    }
  }

  // ---- attacker lifecycle actions (must never change the active set) --------

  function attackerUpdateSet(uint64 epochSeed) external {
    uint64 target = bridge.epoch() + 1 + (epochSeed % 3);
    Signature[] memory sigs = _quorum(attackerPk, _updateData(target)); // non-validator keys
    (uint64 bEpoch, , uint64 bTime, , , , ) = bridge.pendingValidatorSetUpdate();
    bytes32 beforeHash = keccak256(abi.encode(bEpoch, bTime));
    try bridge.updateValidatorSet(_req(target), _activeHot(), sigs) {} catch {}
    (uint64 aEpoch, , uint64 aTime, , , , ) = bridge.pendingValidatorSetUpdate();
    bytes32 afterHash = keccak256(abi.encode(aEpoch, aTime));
    if (afterHash != beforeHash) attackerSetPending = true;
  }

  function attackerUnlock(uint64 epochSeed, uint64 nonce) external {
    if (!bridge.paused()) return;
    uint64 target = bridge.epoch() + 1 + (epochSeed % 3);
    Signature[] memory sigs = _quorum(attackerPk, _unlockData(target, nonce));
    try bridge.emergencyUnlock(_req(target), _activeCold(), sigs, nonce) {} catch {}
  }

  // ---- withdrawal actions (so lifecycle actions can't corrupt accounting) ---

  function deposit(uint96 amount, uint256 who) external {
    uint256 i = who % 3;
    uint256 amt = uint256(amount) % 1e24;
    address u = user[i];
    usdc.mint(u, amt);
    uint64 deadline = uint64(block.timestamp + 1 days);
    bytes32 permitHash = keccak256(
      abi.encode(
        keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)"),
        u, address(bridge), amt, usdc.nonces(u), deadline
      )
    );
    bytes32 permitDomain = keccak256(
      abi.encode(
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
        keccak256(bytes("USD Coin")), keccak256(bytes("1")), block.chainid, address(usdc)
      )
    );
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(userPk[i], keccak256(abi.encodePacked("\x19\x01", permitDomain, permitHash)));
    uint256 before = usdc.balanceOf(address(bridge));
    DepositWithPermit[] memory ds = new DepositWithPermit[](1);
    ds[0] = DepositWithPermit({user: u, usd: uint64(amt), deadline: deadline, signature: Signature(uint256(r), uint256(s), v)});
    try bridge.batchedDepositWithPermit(ds) {} catch {}
    deposited += usdc.balanceOf(address(bridge)) - before;
  }

  function requestWithdraw(uint64 usd, uint64 nonce) external {
    address u = address(this);
    uint64 amt = uint64(uint256(usd) % 1e18) + 1;
    bytes32 data = keccak256(abi.encode("requestWithdrawal", u, u, amt, nonce));
    Signature[] memory sigs = _quorum(hotPk, data);
    WithdrawalRequest[] memory reqs = new WithdrawalRequest[](1);
    reqs[0] = WithdrawalRequest({user: u, destination: u, usd: amt, nonce: nonce, signatures: sigs});
    try bridge.batchedRequestWithdrawals(reqs, _activeHot()) {} catch {}
  }

  function finalizeWithdrawal(bytes32 message) external {
    _advance(uint256(message) % 7);
    uint256 before = usdc.balanceOf(address(bridge));
    bytes32[] memory msgs = new bytes32[](1);
    msgs[0] = message;
    vm.prank(hot[0]);
    try bridge.batchedFinalizeWithdrawals(msgs) {} catch {}
    uint256 afterBal = usdc.balanceOf(address(bridge));
    if (afterBal < before) paidOut += before - afterBal;
  }
}

contract Bridge2LifecycleInvariants is Test {
  Bridge2 bridge;
  MockUSDC usdc;
  Bridge2LifecycleHandler handler;

  uint256[3] hotPk = [uint256(0xA11CE), 0xB0B, 0xC0FFEE];
  uint256[3] coldPk = [uint256(0xDEAD), 0xBEEF, 0xCAFE];
  address[3] hot;
  address[3] cold;
  uint64[3] powers = [uint64(1), 2, 3];

  function setUp() public {
    for (uint256 i; i < 3; i++) {
      hot[i] = vm.addr(hotPk[i]);
      cold[i] = vm.addr(coldPk[i]);
    }
    usdc = new MockUSDC();
    bridge = new Bridge2(
      _toAddrArray(hot), _toAddrArray(cold), _toU64Array(powers), address(usdc), 100, 100, 2
    );
    handler = new Bridge2LifecycleHandler(bridge, usdc);
    // The handler drives the bridge; its own token balances are irrelevant.
    targetContract(address(handler));
  }

  // The active epoch may only advance through an authorized path.
  function invariant_epoch_matches_expected() public view {
    assertEq(bridge.epoch(), handler.expectedEpoch(), "epoch changed without authorization");
  }

  // A pending update, if present, must always propose a strictly higher epoch
  // than the one currently active.
  function invariant_pending_epoch_ahead() public view {
    (uint64 pEpoch, , uint64 pUpdateTime, , , , ) = bridge.pendingValidatorSetUpdate();
    if (pUpdateTime != 0) {
      assertGt(pEpoch, bridge.epoch(), "pending update must be ahead of the active epoch");
    }
  }

  // A non-validator quorum must never be able to stage a pending update.
  function invariant_attacker_never_set_pending() public view {
    assertFalse(handler.attackerSetPending(), "non-validator quorum staged a pending update");
  }

  // USDC accounting must stay consistent across lifecycle operations.
  function invariant_funds_conserved() public view {
    assertEq(usdc.balanceOf(address(bridge)) + handler.paidOut(), handler.deposited(), "USDC not conserved");
  }

  function _toAddrArray(address[3] memory a) internal pure returns (address[] memory out) {
    out = new address[](3);
    for (uint256 i; i < 3; i++) out[i] = a[i];
  }

  function _toU64Array(uint64[3] memory a) internal pure returns (uint64[] memory out) {
    out = new uint64[](3);
    for (uint256 i; i < 3; i++) out[i] = a[i];
  }
}

// Targeted adversarial tests for the validator-set lifecycle. These prove the
// expected authorization boundaries directly (so the stateful harness above is
// known to be reachable, not vacuous) and record the exact behaviour.
contract Bridge2LifecycleTest is Test {
  Bridge2 bridge;
  MockUSDC usdc;

  uint256[3] hotPk = [uint256(0xA11CE), 0xB0B, 0xC0FFEE];
  uint256[3] coldPk = [uint256(0xDEAD), 0xBEEF, 0xCAFE];
  uint256 attackerPk = 0xBAD;
  address[3] hot;
  address[3] cold;
  uint64[3] powers = [uint64(1), 2, 3];

  function setUp() public {
    for (uint256 i; i < 3; i++) {
      hot[i] = vm.addr(hotPk[i]);
      cold[i] = vm.addr(coldPk[i]);
    }
    usdc = new MockUSDC();
    bridge = new Bridge2(_toAddrArray(hot), _toAddrArray(cold), _toU64Array(powers), address(usdc), 100, 100, 2);
  }

  function _domainSeparator() internal view returns (bytes32) {
    return keccak256(
      abi.encode(
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
        keccak256(bytes("Exchange")), keccak256(bytes("1")), block.chainid, address(0)
      )
    );
  }

  function _sign(uint256 pk, bytes32 data) internal view returns (Signature memory sig) {
    bytes32 dataHash = keccak256(
      abi.encode(keccak256("Agent(string source,bytes32 connectionId)"), keccak256(bytes("a")),
        keccak256(abi.encode(address(bridge), data)))
    );
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, keccak256(abi.encodePacked("\x19\x01", _domainSeparator(), dataHash)));
    sig = Signature(uint256(r), uint256(s), v);
  }

  function _req(uint64 epoch) internal view returns (ValidatorSetUpdateRequest memory r) {
    r.epoch = epoch;
    r.hotAddresses = _toAddrArray(hot);
    r.coldAddresses = _toAddrArray(cold);
    r.powers = _toU64Array(powers);
  }

  function _activeHot() internal view returns (ValidatorSet memory vs) {
    vs.epoch = bridge.epoch();
    vs.validators = _toAddrArray(hot);
    vs.powers = _toU64Array(powers);
  }

  function _activeCold() internal view returns (ValidatorSet memory vs) {
    vs.epoch = bridge.epoch();
    vs.validators = _toAddrArray(cold);
    vs.powers = _toU64Array(powers);
  }

  function _updateData(uint64 epoch) internal view returns (bytes32) {
    return keccak256(abi.encode("updateValidatorSet", epoch, _toAddrArray(hot), _toAddrArray(cold), _toU64Array(powers)));
  }

  function _sigs(uint256[3] memory pks, bytes32 data) internal view returns (Signature[] memory s) {
    s = new Signature[](3);
    s[0] = _sign(pks[0], data);
    s[1] = _sign(pks[1], data);
    s[2] = _sign(pks[2], data);
  }

  function _advancePastDispute() internal {
    vm.warp(block.timestamp + 101);
    vm.roll(block.number + 1001);
  }

  function test_update_and_finalize_advances_epoch() public {
    uint64 target = bridge.epoch() + 1;
    bridge.updateValidatorSet(_req(target), _activeHot(), _sigs(hotPk, _updateData(target)));
    (uint64 pEpoch, , uint64 pTime, , , , ) = bridge.pendingValidatorSetUpdate();
    assertEq(pEpoch, target, "pending update staged");
    assertGt(pTime, 0, "pending update has an update time");

    // Still inside the dispute period -> finalize reverts.
    vm.prank(hot[0]);
    vm.expectRevert("Still in dispute period");
    bridge.finalizeValidatorSetUpdate();

    _advancePastDispute();
    vm.prank(hot[0]);
    bridge.finalizeValidatorSetUpdate();
    assertEq(bridge.epoch(), target, "epoch advanced after dispute period");
  }

  function test_non_validator_signatures_cannot_stage_update() public {
    uint64 target = bridge.epoch() + 1;
    uint256[3] memory bad = [uint256(0xBAD1), 0xBAD2, 0xBAD3];
    // Precompute args before expectRevert (vm.sign inside args would otherwise
    // be the "next call" that expectRevert watches).
    ValidatorSetUpdateRequest memory r = _req(target);
    ValidatorSet memory active = _activeHot();
    Signature[] memory sigs = _sigs(bad, _updateData(target));
    vm.expectRevert("Submitted validator set signatures do not have enough power");
    bridge.updateValidatorSet(r, active, sigs);
  }

  function test_update_epoch_must_strictly_increase() public {
    // epoch == current (0) must be rejected.
    ValidatorSetUpdateRequest memory r = _req(0);
    ValidatorSet memory active = _activeHot();
    Signature[] memory sigs = _sigs(hotPk, _updateData(0));
    vm.expectRevert("New validator set epoch must be greater than the active epoch");
    bridge.updateValidatorSet(r, active, sigs);
  }

  function test_emergency_unlock_requires_paused_and_cold_quorum() public {
    uint64 target = bridge.epoch() + 1;
    uint64 nonce = 7;
    bytes32 data = keccak256(
      abi.encode("unlock", target, _toAddrArray(hot), _toAddrArray(cold), _toU64Array(powers), nonce)
    );

    // Not paused -> emergencyUnlock reverts.
    ValidatorSetUpdateRequest memory r = _req(target);
    ValidatorSet memory active = _activeCold();
    Signature[] memory coldSigs = _sigs(coldPk, data);
    vm.expectRevert("Pausable: not paused");
    bridge.emergencyUnlock(r, active, coldSigs, nonce);

    // Two lockers vote to pause (lockerThreshold == 2).
    vm.prank(hot[0]);
    bridge.voteEmergencyLock();
    vm.prank(hot[1]);
    bridge.voteEmergencyLock();
    assertTrue(bridge.paused(), "bridge must be paused after threshold votes");

    // Hot keys must not unlock (cold quorum required).
    uint256[3] memory bad = [uint256(0xBAD1), 0xBAD2, 0xBAD3];
    Signature[] memory badSigs = _sigs(bad, data);
    vm.expectRevert("Submitted validator set signatures do not have enough power");
    bridge.emergencyUnlock(r, active, badSigs, nonce);

    // Cold quorum unlocks, atomically installs the new epoch, and unpauses.
    bridge.emergencyUnlock(r, active, coldSigs, nonce);
    assertEq(bridge.epoch(), target, "unlock installs the new epoch");
    assertFalse(bridge.paused(), "unlock unpauses the bridge");
  }

  function test_pending_update_overwrite_is_expected_not_a_bypass() public {
    // A newer, higher epoch legitimately overwrites the pending update. This is
    // documented behaviour (the pending slot is single-slot), not a bypass: an
    // attacker still cannot stage anything without a hot quorum.
    uint64 e1 = bridge.epoch() + 1;
    bridge.updateValidatorSet(_req(e1), _activeHot(), _sigs(hotPk, _updateData(e1)));
    uint64 e2 = bridge.epoch() + 2;
    bridge.updateValidatorSet(_req(e2), _activeHot(), _sigs(hotPk, _updateData(e2)));
    (uint64 pEpoch, , , , , , ) = bridge.pendingValidatorSetUpdate();
    assertEq(pEpoch, e2, "pending update overwritten by the higher epoch");
  }

  function _toAddrArray(address[3] memory a) internal pure returns (address[] memory out) {
    out = new address[](3);
    for (uint256 i; i < 3; i++) out[i] = a[i];
  }

  function _toU64Array(uint64[3] memory a) internal pure returns (uint64[] memory out) {
    out = new uint64[](3);
    for (uint256 i; i < 3; i++) out[i] = a[i];
  }
}
