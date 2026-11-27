"""A *second* external-source EVM target: OpenZeppelin Ethernaut.

Mission 04 asks whether the discovery engine generalizes beyond the single
application it was validated on in Mission 03 (Damn Vulnerable DeFi). This module
declares cases for a different, independently-maintained project with a different
architecture and different vulnerability classes:

  * **Different project.** OpenZeppelin Ethernaut (``github.com/OpenZeppelin/
    ethernaut``), a standard security-education CTF, not DVDF.
  * **Different architecture.** Each level is a *standalone* challenge contract
    (not a DeFi protocol with a token/pool/vault graph), and each level ships its
    own factory. There is no shared protocol surface to reason about.
  * **Different vulnerability classes.** Mission 03's DVDF cases were an ERC4626
    accounting desync, an arbitrary-call flash loan, and a forced-action receiver.
    These are a misnamed-constructor / access-control flaw and an integer
    underflow -- neither of which the DVDF cases exercised.

Same honesty rules as :mod:`evm_cases`: every case names the real upstream project
and pinned commit; the ground truth is recorded for the report but is **not** read
by the engine, which sees only the model, the operations and the invariants.

These are labelled ``validation`` (not ``blind``): they were declared by an author
who had read the public, documented solution, and were used to confirm the adapter
generalizes to a second application. They are **not** used to tune the engine's
search, and the engine is never told which level is vulnerable or where the bug is.
"""

from __future__ import annotations

from pathlib import Path

from .evm import (
    ContractSpec,
    EvmCase,
    EvmOp,
    Param,
    SetupCall,
    SnapshotRead,
    TransitionSpec,
)

#: OpenZeppelin Ethernaut, fetched by ``harnesses/ethernaut-external/fetch.sh``.
#: Pinned to a commit (not a moving branch) so the case is reproducible; the tree
#: is git-ignored and re-created by the fetch script.
_HERE = Path(__file__).resolve()
ETHERNAUT_ROOT = (_HERE.parents[3] / "harnesses" / "ethernaut-external"
                  / "vendor" / "ethernaut" / "contracts")
ETHERNAUT_CONTROL_ROOT = _HERE.parents[3] / "harnesses" / "ethernaut-external" / "controls"

#: Pinned commit of OpenZeppelin/ethernaut used by these cases. Recorded, not
#: invented: the fetch script checks the checkout resolves to this commit.
ETHERNAUT_COMMIT = "d05643a40aa98c45d66247c69ffceab8f44dd8cb"
ETHERNAUT_REPO = "https://github.com/OpenZeppelin/ethernaut"

E18 = 10 ** 18

ATTACKER = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"   # anvil account 0
DEPLOYER = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"   # anvil account 1


def _art(rel: str) -> str:
    return str(ETHERNAUT_ROOT / "out" / rel)


def _ctrl(rel: str) -> str:
    return str(ETHERNAUT_CONTROL_ROOT / "out" / rel)


# --------------------------------------------------------------------------- #
# Case 1 -- Fallout (validation): a misnamed constructor leaves ownership open
# --------------------------------------------------------------------------- #

def fallout_case(*, control: bool = False) -> EvmCase:
    """Ethernaut *Fallout*: the function meant to be the constructor is public.

    Documented flaw (public): the contract's ``Fal1out()`` was intended to be the
    constructor (an early Solidity convention) but the name is misspelled, so it is
    an ordinary public function. Anyone calls it, becomes ``owner``, and sweeps the
    contract's balance with the owner-only ``collectAllocations()``.

    Invariant the engine must break: custody -- the contract keeps enough ETH to
    cover the allocations it owes its users. ``control=True`` deploys our patched
    contract (``FalloutFixed``) whose ``Fal1out()`` is inert and whose ownership is
    set once in the real constructor.
    """
    owed = 5 * E18

    def inv_custody(s: dict) -> bool:
        if s.get("contract_balance") is None or s.get("owed") is None:
            return True
        return s["contract_balance"] >= s["owed"]

    contract_artifact = (_ctrl("FalloutFixed.sol/FalloutFixed.json") if control
                         else _art("Fallout.sol/Fallout.json"))

    return EvmCase(
        name="ethernaut-fallout" + ("-control" if control else ""),
        suite="control" if control else "validation",
        description="Ethernaut Fallout: misnamed constructor lets anyone become owner",
        root=ETHERNAUT_ROOT if not control else ETHERNAUT_CONTROL_ROOT,
        actors={"attacker": "0"},
        contracts=(ContractSpec("fallout", contract_artifact),),
        setup=(
            # the deployer (a user) has allocated ETH the contract must hold
            SetupCall(actor="1", target="fallout", signature="allocate()", value=owed),
        ),
        ops=(
            EvmOp("become_owner", "attacker", "fallout", "Fal1out()", args=(),
                  description="call the function that was meant to be the constructor"),
            EvmOp("drain", "attacker", "fallout", "collectAllocations()", args=(),
                  description="owner-only sweep of the contract's ETH balance"),
        ),
        snapshot=(
            SnapshotRead("contract_balance", "fallout", "", ret="eth_balance"),
            SnapshotRead("owed", "fallout", "allocatorBalance(address)", args=(DEPLOYER,)),
        ),
        invariants=(
            ("INV-CUSTODY", "the contract keeps enough ETH to cover owed allocations",
             inv_custody),
        ),
        sensitive=("become_owner", "drain"),
        ground_truth=(
            "Fal1out() is public and assigns owner, so anyone becomes owner and calls "
            "collectAllocations() to sweep the contract balance."
        ),
        reference="OpenZeppelin Ethernaut 'Fallout' (ethernaut.openzeppelin.com)",
    )


# --------------------------------------------------------------------------- #
# Case 2 -- Token (validation): an unchecked subtraction underflows
# --------------------------------------------------------------------------- #

def token_case(*, control: bool = False) -> EvmCase:
    """Ethernaut *Token*: ``transfer`` underflows on a large amount.

    Documented flaw (public): the contract is Solidity 0.6, so unsigned arithmetic
    wraps. ``require(balances[msg.sender] - _value >= 0)`` is always true, and
    ``balances[msg.sender] -= _value`` wraps to a near-2**256 balance when
    ``_value`` exceeds the sender's balance.

    Invariant the engine must break: supply conservation -- no single balance may
    exceed the total supply. ``control=True`` deploys our patched contract
    (``TokenFixed``) whose subtraction is checked, so an over-transfer reverts.
    """
    initial_supply = 1000
    attacker_start = 100

    def inv_supply(s: dict) -> bool:
        if s.get("attacker_balance") is None or s.get("total_supply") is None:
            return True
        return s["attacker_balance"] <= s["total_supply"]

    contract_artifact = (_ctrl("TokenFixed.sol/TokenFixed.json") if control
                         else _art("Token.sol/Token.json"))

    return EvmCase(
        name="ethernaut-token" + ("-control" if control else ""),
        suite="control" if control else "validation",
        description="Ethernaut Token: unchecked subtraction lets a balance underflow",
        root=ETHERNAUT_ROOT if not control else ETHERNAUT_CONTROL_ROOT,
        actors={"attacker": "0"},
        contracts=(
            ContractSpec("token", contract_artifact,
                         ctor_types=("uint256",), ctor_args=(initial_supply,)),
        ),
        setup=(
            SetupCall(actor="1", target="token", signature="transfer(address,uint256)",
                      args=(ATTACKER, attacker_start)),
        ),
        ops=(
            EvmOp("transfer", "attacker", "token", "transfer(address,uint256)",
                  args=(DEPLOYER, Param("amount")),
                  param_types={"amount": "uint256"},
                  domains={"amount": (attacker_start + 1,)},
                  description="transfer more than the sender holds"),
        ),
        snapshot=(
            SnapshotRead("attacker_balance", "token", "balanceOf(address)", args=(ATTACKER,)),
            SnapshotRead("total_supply", "token", "totalSupply()"),
        ),
        invariants=(
            ("INV-SUPPLY", "no single balance exceeds the total supply", inv_supply),
        ),
        sensitive=("transfer",),
        ground_truth=(
            "transfer(amount > balance) wraps the subtraction, giving the attacker a "
            "near-2**256 balance that exceeds the total supply."
        ),
        reference="OpenZeppelin Ethernaut 'Token' (ethernaut.openzeppelin.com)",
    )


# --------------------------------------------------------------------------- #
# Case 3 -- NaughtCoin (blind): a time-lock bypassed through an inherited path
# --------------------------------------------------------------------------- #

def naughtcoin_case(*, control: bool = False) -> EvmCase:
    """Ethernaut *NaughtCoin*: only one transfer path is time-locked.

    Documented flaw (public): the level locks the *player's* tokens for ten years
    by overriding ``transfer`` with a ``lockTokens`` modifier. The inherited
    ERC20 ``transferFrom`` is **not** overridden, so it carries no lock. The
    player approves a spender and the spender moves the entire locked balance out
    with ``transferFrom`` -- an authorization check applied on one entry point but
    not on the equivalent one.

    Invariant the engine must break: the lock holds -- the player's balance may not
    decrease before ``timeLock``. ``control=True`` deploys our patched contract
    (``NaughtCoinFixed``) whose ``transferFrom`` is guarded by the same lock, so the
    same sequence reverts and the invariant is preserved.
    """
    initial_supply = 1_000_000 * E18

    def inv_lock_holds(s: dict) -> bool:
        if s.get("player_balance") is None or s.get("initial_supply") is None:
            return True
        return s["player_balance"] >= s["initial_supply"]

    contract_artifact = (_ctrl("NaughtCoinFixed.sol/NaughtCoinFixed.json") if control
                         else _art("NaughtCoin.sol/NaughtCoin.json"))

    return EvmCase(
        name="ethernaut-naughtcoin" + ("-control" if control else ""),
        suite="control" if control else "blind",
        description="Ethernaut NaughtCoin: time-lock bypassed via inherited transferFrom",
        root=ETHERNAUT_ROOT if not control else ETHERNAUT_CONTROL_ROOT,
        actors={"attacker": "0"},
        contracts=(
            ContractSpec("coin", contract_artifact,
                         ctor_types=("address",), ctor_args=(ATTACKER,)),
        ),
        setup=(),
        ops=(
            EvmOp("approve_spender", "attacker", "coin", "approve(address,uint256)",
                  args=(Param("spender"), Param("amount")),
                  param_types={"spender": "address", "amount": "uint256"},
                  domains={"spender": (ATTACKER,), "amount": (initial_supply,)},
                  description="player approves a spender for the locked balance"),
            EvmOp("pull_via_transferFrom", "attacker", "coin", "transferFrom(address,address,uint256)",
                  args=(ATTACKER, DEPLOYER, Param("amount")),
                  param_types={"amount": "uint256"},
                  domains={"amount": (initial_supply,)},
                  description="spender moves the locked balance through the unlocked path"),
        ),
        snapshot=(
            SnapshotRead("player_balance", "coin", "balanceOf(address)", args=(ATTACKER,)),
            SnapshotRead("initial_supply", "coin", "INITIAL_SUPPLY()"),
        ),
        invariants=(
            ("INV-LOCK", "the player's locked balance may not decrease before timeLock",
             inv_lock_holds),
        ),
        sensitive=("pull_via_transferFrom",),
        transitions=(
            TransitionSpec(
                name="approval-enables-delegated-transfer",
                guard="a spender may only move the owner's balance after an approval",
                guard_roles=("attacker",),
                operation="approve_spender",
                description="the player approves a spender, enabling transferFrom",
            ),
        ),
        ground_truth=(
            "Only `transfer` is time-locked; the inherited `transferFrom` is not, so "
            "the player approves a spender and the spender drains the locked balance."
        ),
        reference="OpenZeppelin Ethernaut 'NaughtCoin' (ethernaut.openzeppelin.com)",
    )


# --------------------------------------------------------------------------- #
# The registry for this second external target
# --------------------------------------------------------------------------- #

VALIDATION_CASES = {
    "ethernaut-fallout": fallout_case,
    "ethernaut-token": token_case,
}

CONTROL_CASES = {
    "ethernaut-fallout": lambda: fallout_case(control=True),
    "ethernaut-token": lambda: token_case(control=True),
}

#: Cases added after Mission 04 as *blind* targets -- the engine is told the model,
#: the operations and the invariants, never the flaw or its location.
BLIND_CASES = {
    "ethernaut-naughtcoin": naughtcoin_case,
}

ALL_CASES = {**VALIDATION_CASES, **BLIND_CASES}
ALL_CONTROL_CASES = {**CONTROL_CASES, "ethernaut-naughtcoin": lambda: naughtcoin_case(control=True)}
