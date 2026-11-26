// SPDX-License-Identifier: MIT
pragma solidity ^0.8.9;

import {Test} from "forge-std/Test.sol";
import {Bridge2, ValidatorSet, Withdrawal, WithdrawalRequest, DepositWithPermit, Signature} from "../vendor/src/Bridge2.sol";
import {MockUSDC} from "./MockUSDC.sol";

// ---------------------------------------------------------------------------
// Stateful invariant harness for the real Hyperliquid Arbitrum bridge (Bridge2.sol).
//
// The handler drives the *real* code paths -- permit deposits, validator-signed
// withdrawals, finalization, invalidation and the emergency lock -- with
// randomised inputs. Each invariant below is INDEPENDENT of the handler's own
// bookkeeping and derived from contract state, so it can fail on its own:
//
//   1. funds conservation   : balance == deposits - payouts (derived from the
//                             token balance, not from a self-asserted counter)
//   2. quorum authorization : a withdrawal message is registered by the contract
//                             ONLY when the caller supplied a genuine hot-validator
//                             quorum (checked against the contract's own request map)
//   3. no double payout     : a message is finalized (paid) at most once
//   4. invalidation honoured: an invalidated-but-not-yet-finalized withdrawal is
//                             never paid afterwards
//
// Invariant (2) is the interesting one: it is checked by correlating the
// contract's `requestedWithdrawals` map against the handler's record of which
// messages it supplied a valid quorum for. A corrupted-signature attempt that the
// contract wrongly accepted would break it. Invariant (4) catches a state-machine
// bug where the invalidation flag is not consulted before a payout.
//
// NOTE on what is deliberately NOT asserted: "outstanding claims <= balance" is
// NOT a bridge invariant. The bridge is a custodian; a validator quorum may
// legitimately register a claim before the corresponding deposit is bridged in.
// An unfunded claim is harmless because `safeTransfer` reverts at finalization
// (and the finalizer swallows the revert), so no funds can leave. The real
// property -- that a payout is always funded -- is exactly invariant (1).
//
// Runs entirely in a local EVM (chain_id 1337 so the contract's block-number hook
// is used); nothing is broadcast.
// ---------------------------------------------------------------------------

contract Bridge2Handler is Test {
  Bridge2 bridge;
  MockUSDC usdc;

  uint256[3] hotPk = [uint256(0xA11CE), 0xB0B, 0xC0FFEE];
  uint256[3] coldPk = [uint256(0xDEAD), 0xBEEF, 0xCAFE];
  // Attacker keys that are NOT validators: signing with these must never reach
  // quorum. This models a real attacker who cannot produce validator signatures.
  uint256[3] attackerPk = [uint256(0xBAD1), 0xBAD2, 0xBAD3];
  address[3] hot;
  address[3] cold;
  uint64[3] powers = [uint64(1), 2, 3];

  // Depositors with known keys (for the EIP-2612 permit deposit path).
  uint256[3] userPk = [uint256(0x1111), 0x2222, 0x3333];
  address[3] user;

  uint256 public deposited;   // USDC credited to the bridge
  uint256 public paidOut;     // USDC paid out (balance delta)
  uint256 public finalizedCount;

  bytes32[] public legitMsgs; // messages the handler signed with a real quorum
  bytes32[] public badMsgs;   // messages the handler signed with a BROKEN quorum
  mapping(bytes32 => bool) public isLegit;
  mapping(bytes32 => bool) public isBad;
  mapping(bytes32 => bool) public isInvalidated; // handler's record of invalidations
  mapping(bytes32 => bool) public finalizedWhenInvalidated; // snapshot at invalidation

  constructor(Bridge2 _bridge, MockUSDC _usdc) {
    bridge = _bridge;
    usdc = _usdc;
    for (uint256 i; i < 3; i++) {
      hot[i] = vm.addr(hotPk[i]);
      cold[i] = vm.addr(coldPk[i]);
      user[i] = vm.addr(userPk[i]);
    }
  }

  // ---- signing helpers ----------------------------------------------------

  function _domainSeparator() internal view returns (bytes32) {
    return keccak256(
      abi.encode(
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
        keccak256(bytes("Exchange")),
        keccak256(bytes("1")),
        block.chainid,
        address(0)
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

  function _message(bytes32 data) internal view returns (bytes32) {
    return keccak256(
      abi.encode(keccak256("Agent(string source,bytes32 connectionId)"), keccak256(bytes("a")),
        keccak256(abi.encode(address(bridge), data)))
    );
  }

  function _withdrawalData(address u, address dest, uint64 usd, uint64 nonce) internal pure returns (bytes32) {
    return keccak256(abi.encode("requestWithdrawal", u, dest, usd, nonce));
  }

  function _toAddrArray(address[3] memory a) internal pure returns (address[] memory out) {
    out = new address[](3);
    for (uint256 i; i < 3; i++) out[i] = a[i];
  }

  function _toU64Array(uint64[3] memory a) internal pure returns (uint64[] memory out) {
    out = new uint64[](3);
    for (uint256 i; i < 3; i++) out[i] = a[i];
  }

  function _registered(bytes32 message) internal view returns (bool) {
    (,,,, uint64 rt,,) = bridge.requestedWithdrawals(message);
    return rt != 0;
  }

  // ---- actions ------------------------------------------------------------

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
    ds[0] = DepositWithPermit({
      user: u, usd: uint64(amt), deadline: deadline, signature: Signature(uint256(r), uint256(s), v)
    });
    try bridge.batchedDepositWithPermit(ds) {} catch {}
    deposited += usdc.balanceOf(address(bridge)) - before;
  }

  function requestWithdraw(uint64 usd, uint64 nonce, uint8 who, bool valid) external {
    address u = address(this);
    address dest = address(uint160(uint256(keccak256(abi.encode(who, usd, nonce))) | 1));
    uint64 amt = uint64(bound(usd, 1, 1e18));
    bytes32 data = _withdrawalData(u, dest, amt, nonce);
    bytes32 message = _message(data);

    Signature[] memory sigs = _quorum(hotPk, data);
    if (!valid) sigs = _quorum(attackerPk, data); // non-validator signatures

    WithdrawalRequest[] memory reqs = new WithdrawalRequest[](1);
    reqs[0] = WithdrawalRequest({user: u, destination: dest, usd: amt, nonce: nonce, signatures: sigs});
    try bridge.batchedRequestWithdrawals(reqs, _activeHot()) {} catch {}

    // Record the message as "legitimately requested" only if the contract
    // actually registered it AND we supplied a genuine quorum. The invariant
    // then checks the reverse direction: the contract must never register a
    // message we did NOT supply a valid quorum for.
    if (valid && _registered(message) && !isLegit[message]) {
      isLegit[message] = true;
      legitMsgs.push(message);
    }
    // Only treat a message as an "attack message" if it was never legitimately
    // requested; otherwise the registration came from the legit attempt above.
    if (!valid && !isLegit[message] && !isBad[message]) {
      isBad[message] = true;
      badMsgs.push(message);
    }
  }

  function finalize(uint256 warpSeconds, uint256 rollBlocks, uint256 idx) external {
    if (warpSeconds % 2 == 0) {
      vm.warp(block.timestamp + (warpSeconds % 400));
    } else {
      vm.warp(block.timestamp + 201 + (warpSeconds % 400));
    }
    vm.roll(block.number + (rollBlocks % 3000));

    if (legitMsgs.length == 0) return;
    bytes32 message = legitMsgs[idx % legitMsgs.length];
    uint256 before = usdc.balanceOf(address(bridge));
    bytes32[] memory msgs = new bytes32[](1);
    msgs[0] = message;
    vm.prank(hot[0]);
    try bridge.batchedFinalizeWithdrawals(msgs) {} catch {}
    uint256 afterBal = usdc.balanceOf(address(bridge));
    if (afterBal < before) {
      paidOut += before - afterBal;
      finalizedCount += 1;
    }
  }

  function invalidate(uint64 nonce, uint256 idx) external {
    if (legitMsgs.length == 0) return;
    bytes32 target = legitMsgs[idx % legitMsgs.length];
    bytes32[] memory msgs = new bytes32[](1);
    msgs[0] = target;
    bytes32 data = keccak256(abi.encode("invalidateWithdrawals", msgs, nonce));
    Signature[] memory sigs = _quorum(coldPk, data);
    try bridge.invalidateWithdrawals(msgs, nonce, _activeCold(), sigs) {} catch {}
    if (bridge.withdrawalsInvalidated(target)) {
      isInvalidated[target] = true;
      finalizedWhenInvalidated[target] = bridge.finalizedWithdrawals(target);
    }
  }

  function voteLock(uint256 who) external {
    vm.prank(hot[who % 3]);
    try bridge.voteEmergencyLock() {} catch {}
  }

  function unvoteLock(uint256 who) external {
    vm.prank(hot[who % 3]);
    try bridge.unvoteEmergencyLock() {} catch {}
  }

  // ---- views for the invariants ------------------------------------------

  function legitCount() external view returns (uint256) {
    return legitMsgs.length;
  }

  // The contract registered every message we supplied a valid quorum for.
  function missingRegistration() external view returns (bool) {
    for (uint256 i; i < legitMsgs.length; i++) {
      if (!_registered(legitMsgs[i])) return true;
    }
    return false;
  }

  function doubleFinalized() external view returns (bool) {
    uint256 n;
    for (uint256 i; i < legitMsgs.length; i++) {
      if (bridge.finalizedWithdrawals(legitMsgs[i])) n++;
    }
    // Each funded finalization drops the balance once, so finalizedCount equals
    // the number of distinct paid messages unless a message was paid twice.
    return finalizedCount > n;
  }

  // A message the handler signed with a BROKEN quorum must never be registered,
  // unless the same message was also legitimately requested (then the
  // registration is attributable to the valid request, not the attack).
  function badRegistered() external view returns (bool) {
    for (uint256 i; i < badMsgs.length; i++) {
      if (_registered(badMsgs[i]) && !isLegit[badMsgs[i]]) return true;
    }
    return false;
  }

  // A message marked invalidated must not be finalized unless it was already
  // finalized BEFORE the invalidation took effect (a legitimate ordering).
  function invalidatedPaidAfter() external view returns (bool) {
    for (uint256 i; i < legitMsgs.length; i++) {
      if (!isInvalidated[legitMsgs[i]]) continue;
      if (bridge.finalizedWithdrawals(legitMsgs[i]) && !finalizedWhenInvalidated[legitMsgs[i]]) {
        return true;
      }
    }
    return false;
  }

  function usdcBalance() external view returns (uint256) {
    return usdc.balanceOf(address(bridge));
  }
}

contract Bridge2Invariants is Test {
  Bridge2 bridge;
  MockUSDC usdc;
  Bridge2Handler handler;

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
    bridge = new Bridge2(_toAddrArray(hot), _toAddrArray(cold), _toU64Array(powers), address(usdc), 100, 100, 2);
    handler = new Bridge2Handler(bridge, usdc);
    targetContract(address(handler));
  }

  function _toAddrArray(address[3] memory a) internal pure returns (address[] memory out) {
    out = new address[](3);
    for (uint256 i; i < 3; i++) out[i] = a[i];
  }

  function _toU64Array(uint64[3] memory a) internal pure returns (uint64[] memory out) {
    out = new uint64[](3);
    for (uint256 i; i < 3; i++) out[i] = a[i];
  }

  // 1. Funds conservation: balance == deposits - payouts.
  function invariant_funds_conserved() public view {
    assertEq(handler.usdcBalance() + handler.paidOut(), handler.deposited(), "USDC not conserved");
  }

  // 2. Quorum authorization: a message signed with a BROKEN quorum must never be
  //    registered by the contract. This is the safety property -- an attacker who
  //    cannot produce validator signatures must not be able to create a claim.
  function invariant_broken_quorum_never_registered() public view {
    assertFalse(handler.badRegistered(), "withdrawal registered without a valid quorum");
  }

  // 3. No message is ever paid twice.
  function invariant_no_double_payout() public view {
    assertFalse(handler.doubleFinalized(), "a message was finalized twice");
  }

  // 4. An invalidated withdrawal that was NOT already finalized is never paid.
  function invariant_invalidated_never_finalized() public view {
    assertFalse(handler.invalidatedPaidAfter(), "an invalidated withdrawal was finalized");
  }
}
