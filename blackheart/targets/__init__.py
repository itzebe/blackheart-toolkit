"""Real-target fork harnesses (mission sections 2C, 3, 12).

This module is the bridge between the engine's *local models* (fast, offline,
used for engine validation) and the *real in-scope source* of an authorized
program. A :class:`ForkTarget` records, for one target:

  * where the real source lives (upstream repo + pinned commit),
  * the local Foundry harness that compiles it against real dependencies,
  * which scope asset / program it belongs to, and
  * the keyless RPC used to create a *local* mainnet fork.

Running a fork harness executes real adversarial tests against the real
contract on a fork. It is still **local**: `forge test` runs in-process, nothing
is broadcast, and no production state is touched. Programs that require
local-fork testing permit exactly this. Active/campaign testing against an
asset remains gated by ``blackheart.authz``.
"""

from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from ..exploit import FoundryRunner

# Keyless, free public RPC endpoints. Nothing here needs a paid key.
DEFAULT_MAINNET_RPC = "https://gateway.tenderly.co/public/mainnet"


@dataclass(frozen=True)
class ForkTarget:
    """A real, in-scope target with a local fork harness."""

    name: str
    program: str
    scope_url: str
    scope_asset: str
    upstream: str
    pinned_commit: str
    harness: str                       # path relative to the repo root
    # label -> Foundry contract name (the adversarial tests that matter).
    test_contracts: dict[str, str] = field(default_factory=dict)
    default_rpc: str = DEFAULT_MAINNET_RPC
    rpc_env: str = "BLACKHEART_ETH_RPC"
    notes: str = ""

    def harness_path(self, root: Path) -> Path:
        return root / self.harness


# The registry. Adding a target is a single entry here.
FORK_TARGETS: list[ForkTarget] = [
    ForkTarget(
        name="twyne-aave-wrapper",
        program="Twyne (Immunefi)",
        scope_url="https://immunefi.com/bug-bounty/twyne/information/",
        scope_asset="AaveV3 aToken Wrapper (0xTwyne/aave-v3-aToken-wrapper)",
        upstream="https://github.com/0xTwyne/aave-v3-aToken-wrapper",
        pinned_commit="797be33e22cce033f6d9c66650d9604ee48fc60d",
        harness="harnesses/twyne-aave-wrapper",
        test_contracts={
            "smoke": "TwyneWrapperSmokeTest",
            "adversarial": "TwyneWrapperAdversarialTest",
            "invariants": "TwyneWrapperInvariantsTest",
        },
        notes=(
            "Priority research question (mission section 6): aToken / wrapper-share "
            "accounting. Fork tests run against the real wrapper source + real Aave V3."
        ),
    ),
]

_BY_NAME = {t.name: t for t in FORK_TARGETS}


def available_fork_targets() -> list[str]:
    return [t.name for t in FORK_TARGETS]


def get_fork_target(name: str) -> ForkTarget:
    if name not in _BY_NAME:
        raise KeyError(
            f"unknown fork target: {name} (known: {', '.join(available_fork_targets())})"
        )
    return _BY_NAME[name]


def repo_root() -> Path:
    return Path(__file__).resolve().parent.parent.parent


def is_fetched(target: ForkTarget) -> bool:
    """True once the real source has been vendored by the fetch script."""
    vendor = target.harness_path(repo_root()) / "vendor"
    return (vendor / "src").is_dir() and (vendor / "lib" / "forge-std").is_dir()


def fetch(target: ForkTarget, timeout: int = 900) -> tuple[int, str]:
    """Vendor the real in-scope source (idempotent)."""
    harness = target.harness_path(repo_root())
    script = harness / "fetch.sh"
    proc = subprocess.run(
        ["bash", str(script)],
        cwd=harness,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    return proc.returncode, (proc.stdout or "") + (proc.stderr or "")


def runner(target: ForkTarget, forge_bin: str = "") -> FoundryRunner:
    if not forge_bin:
        from ..engines.solidity.base import resolve_tool
        found = resolve_tool("forge")
        forge_bin = found.binary if found is not None else "forge"
    return FoundryRunner(target.harness_path(repo_root()), forge_bin=forge_bin)


def rpc_url(target: ForkTarget) -> str:
    """The RPC URL for a fork target: the operator's env var, else a live one.

    The operator's ``rpc_env`` value always wins and is used verbatim. Otherwise a
    live endpoint is resolved (registry -> You.com -> probed fallback) and, if none
    answers, the target's declared default is returned as a last resort -- the
    caller still probes it and reports an unreachable endpoint honestly.
    """
    explicit = os.environ.get(target.rpc_env)
    if explicit:
        return explicit
    from ..rpc import resolve_mainnet_rpc

    return resolve_mainnet_rpc() or target.default_rpc
