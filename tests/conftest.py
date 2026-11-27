"""Shared pytest fixtures."""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def pytest_collection_modifyitems(config, items):
    """Skip ``network`` tests unless the run asked for them.

    The ordinary suite must be offline and deterministic: a public API's latency,
    quota or outage is not a property of this codebase. Run them with
    ``pytest -m network``.
    """
    if config.getoption("-m") and "network" in config.getoption("-m"):
        return
    skip = pytest.mark.skip(reason="network test (run with -m network)")
    for item in items:
        if "network" in item.keywords:
            item.add_marker(skip)


@pytest.fixture
def repo_root() -> Path:
    return ROOT


@pytest.fixture(autouse=True)
def _repository_self_test_authority():
    """Run the suite under the repository's own compatibility record.

    The targets this suite executes are BLACKHEART's own fixtures, so the record
    is the repository self-test record -- the same one the fixture gates use. It
    is a *record*, not an exemption: it still passes the gate, and it is bound to
    this repository. The enforcement tests suspend it with
    ``blackheart.toolchain.enforce.no_authority`` (or a record bound to another
    target) to prove that an unauthorised execution is denied.
    """
    from blackheart.toolchain.enforce import (
        ExecutionTarget,
        authorized_execution,
        self_test_record,
    )

    with authorized_execution(
        self_test_record(),
        ExecutionTarget(name="repository self-test", repository="blackheart"),
        where="pytest",
    ):
        yield


def _ensure_forge_std(harness: Path) -> bool:
    """Best-effort bootstrap of a harness's forge-std dependency.

    The harness lib/ trees are git-ignored (see .gitignore), so a fresh checkout
    does not have them. Attempt a one-time fetch; return True if forge-std is
    present afterwards. Never raises: a failure here means the caller should skip.
    """
    if (harness / "lib" / "forge-std").is_dir():
        return True
    if shutil.which("forge") is None:
        return False
    try:
        subprocess.run(
            ["git", "init", "-q"], cwd=harness, capture_output=True, timeout=60
        )
        subprocess.run(
            ["forge", "install", "foundry-rs/forge-std"],
            cwd=harness, capture_output=True, timeout=300,
        )
        for junk in (".git", ".gitmodules", "foundry.lock"):
            p = harness / junk
            if p.is_dir():
                shutil.rmtree(p, ignore_errors=True)
            elif p.exists():
                p.unlink()
    except Exception:  # noqa: BLE001 - bootstrap is best-effort by design
        return False
    return (harness / "lib" / "forge-std").is_dir()


@pytest.fixture(scope="session")
def erc4626_harness_ready() -> bool:
    """True when the erc4626 Foundry harness can run (forge + forge-std present)."""
    return _ensure_forge_std(ROOT / "harnesses" / "erc4626")


#: path to the vendored external target (git-ignored; created by fetch.sh)
DVDF_VENDOR = ROOT / "harnesses" / "dvdf-external" / "vendor" / "dvdf"
DVDF_CONTROLS = ROOT / "harnesses" / "dvdf-external" / "controls"


def _dvdf_artifacts_present() -> bool:
    needed = [
        DVDF_VENDOR / "out" / "UnstoppableVault.sol" / "UnstoppableVault.json",
        DVDF_VENDOR / "out" / "TrusterLenderPool.sol" / "TrusterLenderPool.json",
        DVDF_VENDOR / "out" / "NaiveReceiverPool.sol" / "NaiveReceiverPool.json",
        DVDF_CONTROLS / "out" / "StoredAssetsVault.sol" / "StoredAssetsVault.json",
    ]
    return all(p.exists() for p in needed)


@pytest.fixture(scope="session")
def dvdf_ready() -> bool:
    """True when the external EVM harness can run: anvil + cast + built artifacts.

    The vendored tree and the control build are git-ignored and re-created by
    ``harnesses/dvdf-external/fetch.sh``; on a fresh checkout this returns False and
    the external-EVM tests skip (a skip is not a pass).
    """
    foundry_bin = Path("/home/openhands/.foundry/bin")
    have_tools = ((shutil.which("anvil") is not None and shutil.which("cast") is not None)
                  or ((foundry_bin / "anvil").exists() and (foundry_bin / "cast").exists()))
    if not have_tools:
        return False
    return _dvdf_artifacts_present()


#: path to the second vendored external target (git-ignored; created by fetch.sh)
ETHERNAUT_VENDOR = ROOT / "harnesses" / "ethernaut-external" / "vendor" / "ethernaut" / "contracts"
ETHERNAUT_CONTROLS = ROOT / "harnesses" / "ethernaut-external" / "controls"


def _ethernaut_artifacts_present() -> bool:
    needed = [
        ETHERNAUT_VENDOR / "out" / "Fallout.sol" / "Fallout.json",
        ETHERNAUT_VENDOR / "out" / "Token.sol" / "Token.json",
        ETHERNAUT_VENDOR / "out" / "NaughtCoin.sol" / "NaughtCoin.json",
        ETHERNAUT_CONTROLS / "out" / "FalloutFixed.sol" / "FalloutFixed.json",
        ETHERNAUT_CONTROLS / "out" / "TokenFixed.sol" / "TokenFixed.json",
        ETHERNAUT_CONTROLS / "out" / "NaughtCoinFixed.sol" / "NaughtCoinFixed.json",
    ]
    return all(p.exists() for p in needed)


@pytest.fixture(scope="session")
def ethernaut_ready() -> bool:
    """True when the second external target (Ethernaut) can run.

    Same contract as ``dvdf_ready``: the vendored tree and the control build are
    git-ignored and re-created by ``harnesses/ethernaut-external/fetch.sh``; on a
    fresh checkout this returns False and the Ethernaut tests skip (a skip is not a
    pass).
    """
    foundry_bin = Path("/home/openhands/.foundry/bin")
    have_tools = ((shutil.which("anvil") is not None and shutil.which("cast") is not None)
                  or ((foundry_bin / "anvil").exists() and (foundry_bin / "cast").exists()))
    if not have_tools:
        return False
    return _ethernaut_artifacts_present()


#: path to the third vendored external target (git-ignored; created by fetch.sh)
EULER_VENDOR = ROOT / "harnesses" / "euler-v1" / "vendor" / "euler-contracts"
EULER_CONTROLS = ROOT / "harnesses" / "euler-v1" / "controls"
EULER_HARNESS = ROOT / "harnesses" / "euler-v1"


def _euler_artifacts_present() -> bool:
    needed = [
        EULER_HARNESS / "out" / "Bootstrap.sol" / "Bootstrap.json",
        EULER_HARNESS / "out" / "MockERC20.sol" / "MockERC20.json",
        EULER_VENDOR / "out" / "Euler.sol" / "Euler.json",
        EULER_VENDOR / "out" / "EToken.sol" / "EToken.json",
        EULER_VENDOR / "out" / "DToken.sol" / "DToken.json",
        EULER_VENDOR / "out" / "Markets.sol" / "Markets.json",
        EULER_CONTROLS / "out" / "ETokenFixed.sol" / "ETokenFixed.json",
    ]
    return all(p.exists() for p in needed)


@pytest.fixture(scope="session")
def euler_ready() -> bool:
    """True when the third external target (Euler V1) can run.

    Same contract as ``dvdf_ready``: the vendored tree, the harness build and the
    control build are git-ignored and re-created by ``harnesses/euler-v1/fetch.sh``;
    on a fresh checkout this returns False and the Euler tests skip (a skip is not
    a pass).
    """
    foundry_bin = Path("/home/openhands/.foundry/bin")
    have_tools = ((shutil.which("anvil") is not None and shutil.which("cast") is not None)
                  or ((foundry_bin / "anvil").exists() and (foundry_bin / "cast").exists()))
    if not have_tools:
        return False
    return _euler_artifacts_present()
