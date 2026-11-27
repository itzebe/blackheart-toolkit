"""A *third* external-source EVM target: Euler V1 (euler-legacy-xyz/euler-contracts).

Mission 08 asks whether the discovery engine generalizes to a target whose
architecture is nothing like the previous two: DVDF is a graph of small DeFi
contracts, Ethernaut is a set of standalone CTF challenges. Euler V1 is a single
**diamond-proxy** protocol -- one ``Euler`` core holds all storage, and every
module (Markets, EToken, DToken, RiskManager, ...) is reached through a proxy that
delegate-calls into the core. There is no per-market contract to point at: a
market is a *pair of proxies* the core creates at activation.

Same honesty rules as the other external cases: the target is the real upstream
project at a pinned commit; the ground truth is recorded for the report but is
**not** read by the engine, which sees only the model, the operations and the
invariants. This case is labelled ``blind``: it was declared without the engine
being told where (or whether) a flaw exists.

The whole protocol is deployed and configured by the harness's ``Bootstrap``
contract (``harnesses/euler-v1/src/Bootstrap.sol``), which reproduces the upstream
test harness's setup exactly. The engine drives the *real* proxies returned by
that bootstrap.
"""

from __future__ import annotations

from pathlib import Path

from .evm import (
    ContractSpec,
    EvmCase,
    EvmOp,
    Param,
    SetupCall,
    Ref,
    SnapshotRead,
    TransitionSpec,
)

#: Euler V1, fetched and vendored by ``harnesses/euler-v1/fetch.sh``.
#: Pinned to a commit (not a moving branch) so the case is reproducible; the tree
#: is git-ignored and re-created by the fetch script.
_HERE = Path(__file__).resolve()
_HARNESS = _HERE.parents[3] / "harnesses" / "euler-v1"
EULER_ROOT = _HARNESS / "vendor" / "euler-contracts"
EULER_CONTROL_ROOT = _HARNESS / "controls"

#: Pinned commit of euler-legacy-xyz/euler-contracts used by this case. Recorded, not
#: invented: fetch.sh checks the checkout resolves to this commit.
EULER_COMMIT = "24da0f2de98d984b0007133b2c251e7fbbda4115"
EULER_REPO = "https://github.com/euler-legacy-xyz/euler-contracts"

E18 = 10 ** 18
ZERO32 = "0x" + "00" * 32

# Anvil test accounts (see AnvilNode.ACCOUNTS); account 0 is the unprivileged
# attacker/victim, account 1 is the deployer.
USER = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"


def _vendor(rel: str) -> str:
    return str(EULER_ROOT / "out" / rel)


def _ctrl(rel: str) -> str:
    return str(EULER_CONTROL_ROOT / "out" / rel)


def _module_specs(e_token_artifact: str) -> tuple[ContractSpec, ...]:
    """The module implementations the Bootstrap installs.

    These are the *unmodified* upstream modules (except the eToken, which is the
    patched control in the control case); the harness only wires them together.
    """
    return (
        ContractSpec("impl_installer", _vendor("Installer.sol/Installer.json"),
                     ctor_types=("bytes32",), ctor_args=(ZERO32,)),
        ContractSpec("impl_markets", _vendor("Markets.sol/Markets.json"),
                     ctor_types=("bytes32",), ctor_args=(ZERO32,)),
        ContractSpec("impl_liquidation", _vendor("Liquidation.sol/Liquidation.json"),
                     ctor_types=("bytes32",), ctor_args=(ZERO32,)),
        ContractSpec("impl_governance", _vendor("Governance.sol/Governance.json"),
                     ctor_types=("bytes32",), ctor_args=(ZERO32,)),
        ContractSpec("impl_exec", _vendor("Exec.sol/Exec.json"),
                     ctor_types=("bytes32",), ctor_args=(ZERO32,)),
        ContractSpec("impl_etoken", e_token_artifact,
                     ctor_types=("bytes32",), ctor_args=(ZERO32,)),
        ContractSpec("impl_dtoken", _vendor("DToken.sol/DToken.json"),
                     ctor_types=("bytes32",), ctor_args=(ZERO32,)),
        ContractSpec("impl_irmDefault", _vendor("IRMDefault.sol/IRMDefault.json"),
                     ctor_types=("bytes32",), ctor_args=(ZERO32,)),
    )


def euler_donate_case(*, control: bool = False) -> EvmCase:
    """Euler V1: a balance-reducing path that skips the solvency check.

    The protocol's central safety invariant is that no operation may leave an
    account with liabilities exceeding its collateral (``requireLiquidity``).
    Every balance-reducing user path -- ``withdraw``, ``transfer``, ``burn``,
    ``transferFrom`` -- calls ``checkLiquidity`` after mutating state.
    ``donateToReserves`` reduces the caller's eToken balance (and therefore the
    account's collateral value) but does **not**. An account that has borrowed
    against its own deposit can donate that deposit to the reserves and walk away
    insolvent: the debt stays, the collateral is gone, and the protocol's own
    ``requireLiquidity`` would now revert on the state it just accepted.

    Invariant the engine must break: solvency -- for every account the protocol
    must keep collateral value >= liability value after any accepted operation.

    ``control=True`` installs our patched EToken (``ETokenFixed``), whose
    ``donateToReserves`` performs the missing check.
    """
    e_token_artifact = (_ctrl("ETokenFixed.sol/ETokenFixed.json") if control
                        else _vendor("EToken.sol/EToken.json"))

    bootstrap = ContractSpec(
        "bootstrap",
        str(_HARNESS / "out" / "Bootstrap.sol" / "Bootstrap.json"),
        ctor_types=("bytes32", "address", "address", "address", "address",
                    "address", "address", "address", "address", "address"),
        ctor_args=(ZERO32, Ref("token"), Ref("impl_installer"), Ref("impl_markets"),
                   Ref("impl_liquidation"), Ref("impl_governance"), Ref("impl_exec"),
                   Ref("impl_etoken"), Ref("impl_dtoken"), Ref("impl_irmDefault")),
    )

    return EvmCase(
        name="euler-v1-donate" + ("-control" if control else ""),
        suite="control" if control else "blind",
        description=("Euler V1 donateToReserves solvency bypass" if not control
                     else "Euler V1 donateToReserves solvency bypass (patched control)"),
        root=_HARNESS,
        actors={"user": "0"},
        contracts=(
            ContractSpec("token", str(_HARNESS / "out" / "MockERC20.sol" / "MockERC20.json"),
                         ctor_types=("string", "string", "uint8"),
                         ctor_args=("Test Token", "TST", 18)),
            *_module_specs(e_token_artifact),
            bootstrap,
            ContractSpec("euler", _vendor("Euler.sol/Euler.json"),
                         resolve_from=("bootstrap", "euler()")),
            ContractSpec("etoken", _vendor("EToken.sol/EToken.json"),
                         resolve_from=("bootstrap", "eTokenAddr()")),
            ContractSpec("dtoken", _vendor("DToken.sol/DToken.json"),
                         resolve_from=("bootstrap", "dTokenAddr()")),
        ),
        setup=(
            SetupCall(actor="0", target="token", signature="mint(address,uint256)",
                      args=(USER, 1000 * E18)),
            SetupCall(actor="0", target="token", signature="approve(address,uint256)",
                      args=(Ref("euler"), 2 ** 256 - 1)),
        ),
        ops=(
            EvmOp("deposit", "user", "etoken", "deposit(uint256,uint256)",
                  args=(0, Param("amount")),
                  param_types={"amount": "uint256"},
                  domains={"amount": (100 * E18,)},
                  description="deposit the underlying and receive eTokens"),
            EvmOp("borrow", "user", "dtoken", "borrow(uint256,uint256)",
                  args=(0, Param("amount")),
                  param_types={"amount": "uint256"},
                  domains={"amount": (1 * E18,)},
                  description="borrow against the deposited collateral"),
            EvmOp("donate", "user", "etoken", "donateToReserves(uint256,uint256)",
                  args=(0, Param("amount")),
                  param_types={"amount": "uint256"},
                  domains={"amount": (100 * E18,)},
                  description="donate the eToken balance to the reserves"),
        ),
        snapshot=(
            SnapshotRead("collateral_value", "bootstrap", "collateralValue(address)",
                         args=(USER,)),
            SnapshotRead("liability_value", "bootstrap", "liabilityValue(address)",
                         args=(USER,)),
        ),
        invariants=(
            ("INV-SOLVENCY",
             "an account's collateral value must cover its liability value",
             _inv_solvency),
        ),
        sensitive=("borrow", "donate"),
        transitions=(
            TransitionSpec(
                name="borrow-requires-collateral",
                guard="a borrow may only be taken after a deposit supplies collateral",
                guard_roles=("user",),
                operation="deposit",
                description="the user deposits collateral, enabling a borrow",
            ),
        ),
        ground_truth=(
            "`donateToReserves` reduces the caller's eToken balance (collateral) "
            "without calling `checkLiquidity`, unlike withdraw/transfer/burn. A "
            "borrower can donate the whole deposit to the reserves and remain "
            "underwater; the debt is not repaid and the account becomes "
            "liquidatable, so the loss is socialised to the pool."
        ),
        reference="euler-legacy-xyz/euler-contracts EToken.donateToReserves",
    )


def _inv_solvency(s: dict) -> bool:
    """The account's collateral value must cover its liability value.

    Evaluated from the protocol's *own* liquidity computation (``requireLiquidity``'s
    inputs), so a violation is a runtime fact about the deployed protocol, not a
    model prediction. A missing read (before the account exists) cannot be
    evaluated and is treated as holding.
    """
    coll = s.get("collateral_value")
    liab = s.get("liability_value")
    if coll is None or liab is None:
        return True
    return coll >= liab


# --------------------------------------------------------------------------- #
# The registry for this third external target
# --------------------------------------------------------------------------- #

BLIND_CASES = {
    "euler-v1-donate": euler_donate_case,
}

CONTROL_CASES = {
    "euler-v1-donate": lambda: euler_donate_case(control=True),
}

ALL_CASES = {**BLIND_CASES}
ALL_CONTROL_CASES = {**CONTROL_CASES}
