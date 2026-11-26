// SPDX-License-Identifier: MIT
pragma solidity ^0.8.9;

import {Test} from "forge-std/Test.sol";
import {Bridge2, ValidatorSet, Withdrawal, WithdrawalRequest, DepositWithPermit, Signature} from "../vendor/src/Bridge2.sol";
import {MockUSDC} from "./MockUSDC.sol";

// ---------------------------------------------------------------------------
// Medusa property harness for the real Hyperliquid bridge (Bridge2.sol).
//
// Medusa fuzzes the *target contract* (this one): every external function here is
// a fuzzable action, and the `property_*` functions are the assertions. Medusa
// deploys this contract itself and calls setUp() via the `public` constructor-like
// path only if configured; instead we lazily initialise on first use so Medusa can
// deploy with no constructor args.
//
// This is an INDEPENDENT second engine over the same protocol paths as the
// Foundry suite: coverage-guided, corpus-based, multi-worker. A property here is
// considered to have failed only if Medusa reproduces it with a concrete sequence.
//
//   medusa fuzz --config medusa.json
// ---------------------------------------------------------------------------

contract Bridge2Medusa is Test {
  Bridge2 public bridge;
  MockUSDC public usdc;
  uint256[3] hotPk = [uint256(0xA11CE), 0xB0B, 0xC0FFEE];
  uint256[3] coldPk = [uint256(0xDEAD), 0xBEEF, 0xCAFE];
  // Non-validator attacker keys: signing with these must never reach quorum.
  uint256[3] attackerPk = [uint256(0xBAD1), 0xBAD2, 0xBAD3];
  address[3] hot;
  address[3] cold;
  uint64[3] powers = [uint64(1), 2, 3];

  uint256[3] userPk = [uint256(0x1111), 0x2222, 0x3333];
  address[3] user;

  uint256 public deposited;
  uint256 public paidOut;
  uint256 public finalizedCount;

  bytes32[] public legitMsgs;
  bytes32[] public badMsgs;
  mapping(bytes32 => bool) public isLegit;
  mapping(bytes32 => bool) public isBad;
  mapping(bytes32 => bool) public isInvalidated;
  mapping(bytes32 => bool) public finalizedWhenInvalidated;

  bool private ready;

  // Medusa deploys this contract itself and does not call Foundry's setUp(), so
  // initialise deterministically in the constructor to avoid evaluating the
  // properties against uninitialised state.
  constructor() {
    _setup();
  }

  function _setup() internal {
    if (ready) return;
    ready = true;
    // Bridge2 reads ArbSys.arbBlockNumber() (precompile address 100) unless
    // chainid == 1337. Neither Medusa nor Echidna lets us change the chain id
    // (Echidna 2.4 has no chainId cheatcode), so etch a minimal ArbSys stub that
    // returns the EVM block number: NUMBER(0x43) MSTORE PUSH1 20 PUSH1 00 RETURN.
    vm.etch(address(100), hex"4360005260206000f3");
    for (uint256 i; i < 3; i++) {
      hot[i] = vm.addr(hotPk[i]);
      cold[i] = vm.addr(coldPk[i]);
      user[i] = vm.addr(userPk[i]);
    }
    usdc = new MockUSDC();
    bridge = new Bridge2(_toAddrArray(hot), _toAddrArray(cold), _toU64Array(powers), address(usdc), 100, 100, 2);
  }

  // ---- signing helpers ----------------------------------------------------

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

  function _message(bytes32 data) internal view returns (bytes32) {
    return keccak256(
      abi.encode(keccak256("Agent(string source,bytes32 connectionId)"), keccak256(bytes("a")),
        keccak256(abi.encode(address(bridge), data)))
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

  function _registered(bytes32 message) internal view returns (bool) {
    (,,,, uint64 rt,,) = bridge.requestedWithdrawals(message);
    return rt != 0;
  }

  // ---- fuzzable actions ---------------------------------------------------

  function deposit(uint96 amount, uint256 who) external {
    _setup();
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

  function requestWithdraw(uint64 usd, uint64 nonce, uint8 who, bool valid) external {
    _setup();
    address u = address(this);
    address dest = address(uint160(uint256(keccak256(abi.encode(who, usd, nonce))) | 1));
    uint64 amt = uint64(uint256(usd) % 1e18) + 1;
    bytes32 data = keccak256(abi.encode("requestWithdrawal", u, dest, amt, nonce));
    bytes32 message = _message(data);

    Signature[] memory sigs = _quorum(hotPk, data);
    if (!valid) sigs = _quorum(attackerPk, data); // non-validator signatures

    WithdrawalRequest[] memory reqs = new WithdrawalRequest[](1);
    reqs[0] = WithdrawalRequest({user: u, destination: dest, usd: amt, nonce: nonce, signatures: sigs});
    try bridge.batchedRequestWithdrawals(reqs, _activeHot()) {} catch {}

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
    _setup();
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
    _setup();
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
    _setup();
    vm.prank(hot[who % 3]);
    try bridge.voteEmergencyLock() {} catch {}
  }

  function unvoteLock(uint256 who) external {
    _setup();
    vm.prank(hot[who % 3]);
    try bridge.unvoteEmergencyLock() {} catch {}
  }

  // ---- properties ---------------------------------------------------------
  // Medusa property testing: return true when the property holds.

  function property_funds_conserved() public view returns (bool) {
    return usdc.balanceOf(address(bridge)) + paidOut == deposited;
  }

  function property_broken_quorum_never_registered() public view returns (bool) {
    for (uint256 i; i < badMsgs.length; i++) {
      if (_registered(badMsgs[i]) && !isLegit[badMsgs[i]]) return false;
    }
    return true;
  }

  function property_no_double_payout() public view returns (bool) {
    uint256 n;
    for (uint256 i; i < legitMsgs.length; i++) {
      if (bridge.finalizedWithdrawals(legitMsgs[i])) n++;
    }
    return finalizedCount <= n;
  }

  function property_invalidated_never_finalized() public view returns (bool) {
    for (uint256 i; i < legitMsgs.length; i++) {
      if (!isInvalidated[legitMsgs[i]]) continue;
      if (bridge.finalizedWithdrawals(legitMsgs[i]) && !finalizedWhenInvalidated[legitMsgs[i]]) {
        return false;
      }
    }
    return true;
  }
}
