"""Declarative, multi-transaction fork scenarios.

A single call is often not enough to prove an ordering or state bug. This module
turns a small JSON scenario into a standalone Foundry test, executes it on a
pinned fork through :mod:`blackheart.symbolic.poc_runner`, and reports the same
honest statuses: ``PASS`` (the assertions held), ``FAIL`` (the test ran and an
assertion did not hold), ``BLOCKED`` (the compatibility gate refused or forge is
absent) or ``INCOMPLETE`` (the build or output could not be interpreted).

The scenario is deliberately narrow and explicit:

* every call names its target, caller, calldata and value;
* every call can declare that it must revert;
* balances can be funded with ``vm.deal``;
* balance deltas are asserted after the whole sequence.

It does not sign or broadcast a transaction, and it does not invent a caller's
funds: a value-bearing call needs an explicit ``fund`` entry or the fork will
revert, which is a real result.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

from .symbolic.poc_runner import PocRunOutcome, Runner, run_poc_text

_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def _address(value: str, field_name: str) -> str:
    text = str(value or "").strip()
    if not text.startswith("0x") or len(text) != 42:
        raise ValueError(f"{field_name} must be a 20-byte 0x address")
    try:
        int(text, 16)
    except ValueError as exc:
        raise ValueError(f"{field_name} is not hexadecimal") from exc
    return text


def _integer(value: object, field_name: str) -> int:
    if isinstance(value, bool):
        raise ValueError(f"{field_name} must be an integer")
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{field_name} must be an integer") from exc
    if parsed < 0:
        raise ValueError(f"{field_name} must be non-negative")
    return parsed


def _hex_data(value: str, field_name: str) -> str:
    text = str(value or "").strip()
    if not text.startswith("0x"):
        raise ValueError(f"{field_name} must start with 0x")
    body = text[2:]
    if len(body) % 2:
        raise ValueError(f"{field_name} must have an even number of hex digits")
    try:
        bytes.fromhex(body)
    except ValueError as exc:
        raise ValueError(f"{field_name} is not hexadecimal") from exc
    return "0x" + body.lower()


def _solidity_address(value: str) -> str:
    return f"address(uint160({int(value, 16)}))"


@dataclass(frozen=True)
class ForkCall:
    """One transaction in a fork scenario."""

    target: str
    data: str
    caller: str = "0x0000000000000000000000000000000000000000"
    value: int = 0
    expect_revert: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(self, "target", _address(self.target, "call.target"))
        object.__setattr__(self, "caller", _address(self.caller, "call.caller"))
        object.__setattr__(self, "data", _hex_data(self.data, "call.data"))
        object.__setattr__(self, "value", _integer(self.value, "call.value"))


@dataclass(frozen=True)
class BalanceDelta:
    """The expected balance change for one address after the whole sequence."""

    address: str
    delta: int

    def __post_init__(self) -> None:
        object.__setattr__(self, "address", _address(self.address, "balance.address"))
        if isinstance(self.delta, bool):
            raise ValueError("balance.delta must be an integer")
        try:
            object.__setattr__(self, "delta", int(self.delta))
        except (TypeError, ValueError) as exc:
            raise ValueError("balance.delta must be an integer") from exc


@dataclass(frozen=True)
class ForkScenario:
    """A named sequence of calls and balance assertions on a pinned fork."""

    name: str
    calls: tuple[ForkCall, ...]
    fund: dict[str, int] = field(default_factory=dict)
    balance_deltas: tuple[BalanceDelta, ...] = ()
    test_name: str = "test_fork_scenario"

    def __post_init__(self) -> None:
        if not self.name:
            raise ValueError("scenario.name is required")
        if not self.calls:
            raise ValueError("scenario.calls must contain at least one call")
        if not _IDENTIFIER.match(self.test_name):
            raise ValueError("scenario.test_name must be a Solidity identifier")
        funded: dict[str, int] = {}
        for address, amount in self.fund.items():
            funded[_address(address, "fund.address")] = _integer(
                amount, "fund.amount")
        object.__setattr__(self, "fund", funded)


def scenario_from_dict(payload: dict) -> ForkScenario:
    """Parse the CLI/JSON shape into a validated scenario."""
    if not isinstance(payload, dict):
        raise ValueError("scenario must be a JSON object")
    raw_calls = payload.get("calls")
    if not isinstance(raw_calls, list) or not raw_calls:
        raise ValueError("scenario.calls must be a non-empty list")
    calls = []
    for index, item in enumerate(raw_calls):
        if not isinstance(item, dict):
            raise ValueError(f"call {index} must be an object")
        if "target" not in item or "data" not in item:
            raise ValueError(f"call {index} needs target and data")
        calls.append(ForkCall(
            target=str(item["target"]),
            data=str(item["data"]),
            caller=str(item.get("caller") or
                       "0x0000000000000000000000000000000000000000"),
            value=item.get("value", 0),
            expect_revert=bool(item.get("expect_revert", False)),
        ))
    raw_fund = payload.get("fund") or {}
    if not isinstance(raw_fund, dict):
        raise ValueError("scenario.fund must be an object")
    raw_deltas = payload.get("balance_deltas") or []
    if not isinstance(raw_deltas, list):
        raise ValueError("scenario.balance_deltas must be a list")
    deltas = []
    for index, item in enumerate(raw_deltas):
        if not isinstance(item, dict) or "address" not in item or "delta" not in item:
            raise ValueError(f"balance_deltas[{index}] needs address and delta")
        deltas.append(BalanceDelta(str(item["address"]), item["delta"]))
    return ForkScenario(
        name=str(payload.get("name") or "fork-scenario"),
        calls=tuple(calls),
        fund={str(k): v for k, v in raw_fund.items()},
        balance_deltas=tuple(deltas),
        test_name=str(payload.get("test_name") or "test_fork_scenario"),
    )


def render_fork_scenario_test(scenario: ForkScenario) -> str:
    """Render a standalone Solidity test; no forge-std import is required."""
    lines = [
        "// SPDX-License-Identifier: MIT",
        "pragma solidity ^0.8.24;",
        "",
        "interface Vm {",
        "    function deal(address who, uint256 amount) external;",
        "    function prank(address msgSender) external;",
        "}",
        "",
        "contract BlackheartForkScenarioTest {",
        '    Vm constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));',
        "",
        f"    function {scenario.test_name}() public {{",
    ]
    for address, amount in scenario.fund.items():
        lines.append(f"        vm.deal({_solidity_address(address)}, {amount});")
    for index, item in enumerate(scenario.balance_deltas):
        lines.append(
            f"        uint256 before_{index} = "
            f"{_solidity_address(item.address)}.balance;")
    for index, call in enumerate(scenario.calls):
        lines.append(f"        vm.prank({_solidity_address(call.caller)});")
        lines.append(
            f"        (bool ok_{index}, ) = {_solidity_address(call.target)}"
            f".call{{value: {call.value}}}(hex\"{call.data[2:]}\");")
        if call.expect_revert:
            lines.append(
                f'        require(!ok_{index}, "call {index} was expected to revert");')
        else:
            lines.append(
                f'        require(ok_{index}, "call {index} reverted");')
    for index, item in enumerate(scenario.balance_deltas):
        lines.append(
            f"        require(int256({_solidity_address(item.address)}.balance) "
            f"- int256(before_{index}) == int256({item.delta}), "
            f"\"balance delta {index} did not hold\");")
    lines.extend(["    }", "}", ""])
    return "\n".join(lines)


def run_fork_scenario(
    scenario: ForkScenario,
    *,
    compatibility,
    target_component: str,
    repository: str,
    commit: str = "",
    rpc_url: str = "",
    block: Optional[int] = None,
    timeout: int = 600,
    keep_dir: Optional[str] = None,
    runner: Optional[Runner] = None,
) -> PocRunOutcome:
    """Render and run the scenario through the compatibility-gated PoC runner."""
    if not rpc_url:
        return PocRunOutcome(
            "BLOCKED", "a fork scenario needs --rpc; nothing was run",
            scenario.test_name)
    source = render_fork_scenario_test(scenario)
    return run_poc_text(
        source, test_name=scenario.test_name, compatibility=compatibility,
        target_component=target_component, repository=repository, commit=commit,
        timeout=timeout, keep_dir=keep_dir, runner=runner,
        fork_url=rpc_url, fork_block=block)


def scenario_to_dict(scenario: ForkScenario) -> dict:
    return {
        "name": scenario.name,
        "test_name": scenario.test_name,
        "calls": [
            {"target": c.target, "data": c.data, "caller": c.caller,
             "value": c.value, "expect_revert": c.expect_revert}
            for c in scenario.calls
        ],
        "fund": dict(scenario.fund),
        "balance_deltas": [
            {"address": b.address, "delta": b.delta}
            for b in scenario.balance_deltas
        ],
    }
