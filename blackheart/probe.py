"""Unprivileged-surface probe: the manual auth + fund-flow loop, encoded.

For each external selector, call it from an unprivileged EOA on the concrete EVM,
classify the outcome, and capture the revert data and any state/balance change.

A ``SUCCESS`` -- or a business revert -- from an unprivileged EOA is a LEAD, never
a finding. The revert data and the fund-flow diff are what separate a
caller-source self-service (safe) from a cross-account move (dangerous). This is
the exact step that resolved the RISEx ``withdraw`` lead: ``InsufficientBalance(
msg.sender, ...)`` named the caller as the source, so "anyone can withdraw any
account" was refuted -- the ``account`` argument was only the recipient.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, Optional

from .deployed import keccak256
from .evm_fuzz import run_bytecode
from .evmworld import World, execute_message

#: An address with no role and no balance: the ordinary, unprivileged attacker.
UNPRIVILEGED = 0x000000000000000000000000000000000000dEaD

SUCCESS = "SUCCESS"
REVERT = "REVERT"
HALT = "HALT"


@dataclass
class ProbeResult:
    """One selector's outcome when reached by an unprivileged caller."""

    selector: str
    outcome: str
    halt: str
    #: 0x-prefixed 4-byte selector of the custom error the call reverted with, if any.
    revert_error: Optional[str] = None
    #: True when the first 32-byte argument of that error equals the caller, i.e.
    #: the contract is naming *the caller* as the subject (the source, not a victim).
    revert_names_caller: bool = False
    return_data: str = "0x"
    state_diff: list[dict] = field(default_factory=list)
    #: Native-balance movers, when the call moves ether (not token balances).
    balance_source: Optional[str] = None
    balance_sink: Optional[str] = None
    sender: int = UNPRIVILEGED
    token_gain: int = 0

    @property
    def is_lead(self) -> bool:
        """A non-reverting reach from an unprivileged EOA is worth a human look."""
        return self.outcome == SUCCESS

    @property
    def writes(self) -> bool:
        """A successful call that actually changes state (storage or native balance).

        ``is_lead`` is the coarse "non-reverting reach"; ``writes`` is the precision
        signal -- a view or a no-op (deposit(0), withdraw(0)) reaches SUCCESS but
        changes nothing and is not a state-changing lead.
        """
        return self.outcome == SUCCESS and bool(self.state_diff)

    @property
    def value_lead(self) -> bool:
        """An unprivileged call where the sender's native balance rises net of
        value sent -- the actor received ETH it did not put in. A lead, not a finding."""
        if self.outcome != SUCCESS:
            return False
        me = self.sender & ((1 << 160) - 1)
        for change in self.state_diff:
            try:
                addr = int(str(change.get("address", "0x0")), 16) & ((1 << 160) - 1)
            except (ValueError, TypeError):
                continue
            delta = int(change.get("balance_to", 0)) - int(change.get("balance_from", 0))
            if addr == me and delta > 0:
                return True
        return self.token_gain > 0

    def to_dict(self) -> dict:
        return {
            "selector": self.selector,
            "outcome": self.outcome,
            "halt": self.halt,
            "revert_error": self.revert_error,
            "revert_names_caller": self.revert_names_caller,
            "return_data": self.return_data,
            "state_diff": self.state_diff,
            "balance_source": self.balance_source,
            "balance_sink": self.balance_sink,
            "value_lead": self.value_lead,
            "token_gain": self.token_gain,
            "is_lead": self.is_lead,
            "writes": self.writes,
        }


def _classify(halt: str) -> str:
    if halt in ("STOP", "RETURN"):
        return SUCCESS
    if halt == "REVERT":
        return REVERT
    return HALT


def _selector_hex(selector: str) -> str:
    s = selector.lower().removeprefix("0x")
    if len(s) != 8:
        raise ValueError(f"selector must be 4 bytes (8 hex chars): {selector!r}")
    return "0x" + s


def mapping_slot(key: int, slot: int) -> int:
    """Storage slot of ``mapping[key]`` for a mapping declared at ``slot``.

    Solidity uses ``keccak256(abi.encode(key, slot))``; both words are 32-byte
    left-padded, so an address key is padded exactly as Solidity pads it.
    """
    return int.from_bytes(keccak256(key.to_bytes(32, "big") + slot.to_bytes(32, "big")), "big")


def _result_from_tx(result, selector: str, sender: int) -> ProbeResult:
    data = result.return_data
    revert_error = None
    names_caller = False
    if not result.succeeded and len(data) >= 4:
        revert_error = "0x" + data[:4].hex()
        if len(data) >= 36:
            word = int.from_bytes(data[4:36], "big") & ((1 << 160) - 1)
            names_caller = word == (sender & ((1 << 160) - 1))

    source = sink = None
    for change in result.state_diff:
        before = change.get("balance_from", 0)
        after = change.get("balance_to", 0)
        if after < before:
            source = change["address"]
        elif after > before:
            sink = change["address"]

    return ProbeResult(
        selector=selector,
        outcome=_classify(str(result.halt)),
        halt=str(result.halt),
        revert_error=revert_error,
        revert_names_caller=names_caller,
        return_data="0x" + data.hex(),
        state_diff=result.state_diff,
        balance_source=source,
        balance_sink=sink,
        sender=sender,
    )


def probe_selector(
    code: bytes,
    selector: str,
    *,
    sender: int = UNPRIVILEGED,
    value: int = 0,
    storage: Optional[dict[int, int]] = None,
    env: Optional[dict[str, int]] = None,
    address: Optional[int] = None,
    args: bytes = b"",
) -> ProbeResult:
    """Run ``selector`` (bare 4-byte calldata, zero args) from ``sender``."""
    sel = _selector_hex(selector)
    kwargs = {} if address is None else {"address": address}
    result = run_bytecode(
        bytes(code),
        bytes.fromhex(sel[2:]) + bytes(args),
        caller=sender,
        value=value,
        storage=storage,
        env=env,
        **kwargs,
    )
    return _result_from_tx(result, sel, sender)


def probe_world(
    world: World,
    address: int,
    selector: str,
    *,
    sender: int = UNPRIVILEGED,
    value: int = 0,
    env: Optional[dict[str, int]] = None,
    value_slot: Optional[int] = None,
) -> ProbeResult:
    """Probe against a pre-built multi-account world (delegatecall/proxy targets).

    ``value_slot`` names the actor's token-balance storage slot on ``address``; when set,
    ``token_gain`` (and thus ``value_lead``) reflect that token balance rising too.
    """
    sel = _selector_hex(selector)
    result = execute_message(
        world, caller=sender, to=address, calldata=bytes.fromhex(sel[2:]), value=value, env=env
    )
    res = _result_from_tx(result, sel, sender)
    if value_slot is not None:
        delta = 0
        for change in res.state_diff:
            if int(change["address"], 16) != address:
                continue
            for slot in change.get("storage", []):
                if int(slot["slot"]) == value_slot:
                    delta += slot["to"] - slot["from"]
        res.token_gain = delta
    return res


def probe_over_entitlement(
    world: World,
    address: int,
    selector: str,
    *,
    sender: int = UNPRIVILEGED,
    gain_slot: int,
    expected_gain: int,
    value: int = 0,
    env: Optional[dict[str, int]] = None,
) -> tuple[ProbeResult, int, bool]:
    """Run the call and report whether ``gain_slot`` moved by more than ``expected_gain``.

    Over-extraction -- a reentrant callback that credits the caller more than one
    call should -- is the fund-flow signature of a payable reentrancy. The gain is
    read from the post-run state diff, so a fresh world per call is required (the
    caller passes ``case.world()``, never a shared instance). Native ETH moved by a
    ``CALL`` is not modeled by the EVM here (only ``CREATE`` transfers value), so
    the benchmark tracks a storage credit, which is how most token value is held.
    """
    result = probe_world(world, address, selector, sender=sender, value=value, env=env)
    gain = 0
    for change in result.state_diff:
        if int(change["address"], 16) != address:
            continue
        for slot in change["storage"]:
            if int(slot["slot"]) == gain_slot:
                gain += slot["to"] - slot["from"]
    return result, gain, gain > expected_gain


def probe_sequence(world: World, address: int, steps: list[tuple[int, str]], *,
                   env: Optional[dict[str, int]] = None) -> list[ProbeResult]:
    """Run ordered (sender, selector) messages against one persistent world.

    Real bounty bugs live in sequences: an unprotected init that a later privileged
    call depends on is invisible to a single-message probe, because the privileged
    effect is reachable only after the earlier step has run.
    """
    return [probe_world(world, address, sel, sender=sender, env=env) for sender, sel in steps]


def probe_eth_drain(world: World, address: int, selector: str, *, sender: int = UNPRIVILEGED,
                    entitlement: int, env: Optional[dict[str, int]] = None) -> tuple[ProbeResult, int, bool]:
    """Run one message and measure the sender's native-ETH gain against its entitlement.

    Needs evmworld to move value on CALL; a storage-only probe cannot see a drain
    that pays out in ETH rather than in a ledger slot.
    """
    result = probe_world(world, address, selector, sender=sender, env=env)
    gain = sum(c["balance_to"] - c["balance_from"]
               for c in result.state_diff if int(c["address"], 16) == sender)
    return result, gain, gain > entitlement


def probe(
    code: bytes,
    selectors: Iterable[str],
    *,
    sender: int = UNPRIVILEGED,
    value: int = 0,
    storage: Optional[dict[int, int]] = None,
    env: Optional[dict[str, int]] = None,
    args: bytes = b"",
) -> list[ProbeResult]:
    """Probe each selector independently from the same starting state."""
    return [
        probe_selector(code, s, sender=sender, value=value, storage=storage, env=env, args=args)
        for s in selectors
    ]
