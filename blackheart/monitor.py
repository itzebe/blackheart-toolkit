"""Deployed-code monitor: watch live contracts for post-audit drift.

The mission's recurring lesson on an audited protocol is that the *payable* bug
is almost never in the code that was audited -- it is in a change shipped after
the audit. This module watches for exactly that. It polls the real on-chain
runtime bytecode of a set of in-scope contracts, pins each observation, and
reports when the deployed code *changes* or when a proxy's implementation is
*re-pointed* to new code.

It deliberately does **not** trust a block explorer or a source repository for
"is this the same code": the deployed runtime bytecode is the ground truth, and
its keccak-256 is the fingerprint. A change in that fingerprint is the signal
worth investigating; a source diff is only meaningful once you know the code
changed.

Everything here is **read-only** (``eth_chainId``/``eth_blockNumber``/
``eth_getCode``/``eth_getStorageAt``) and **stdlib-only**. No transaction is ever
sent. An unreachable RPC, or an address that holds no code, is recorded as a
limitation -- never as a verified observation.

Usage from the CLI::

    blackheart monitor targets                       # show the registry
    blackheart monitor run                           # poll every target, report drift
    blackheart monitor run --json                    # machine-readable
    blackheart monitor run --target uma-oo-v3        # one target
    blackheart monitor baseline --out state.json     # write a pinned baseline
    blackheart monitor run --baseline state.json     # compare against it
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from .deployed import (
    ChainClient,
    RpcUnavailable,
    keccak256,
    verify_contract,
)
from .models import utcnow

__all__ = [
    "TARGETS",
    "DriftKind",
    "TargetSpec",
    "Observation",
    "MonitorReport",
    "monitor_target",
    "run_monitor",
    "load_state",
    "save_state",
    "sourcify_url",
    "DEFAULT_RPC",
]

#: A free, no-key archive-capable public mainnet endpoint (verified to serve
#: historical ``eth_getCode``). Overridable with ``--rpc`` or ``BLACKHEART_ETH_RPC``.
DEFAULT_RPC = "https://gateway.tenderly.co/public/mainnet"

#: Sourcify v2 base -- used only to *point a human at the source* once a change
#: is detected; the drift signal itself never depends on it.
_SOURCIFY_BASE = "https://sourcify.dev/server/v2/contract"


def sourcify_url(chain_id: int, address: str) -> str:
    """The Sourcify v2 metadata URL for a deployed contract (source, once verified)."""
    return f"{_SOURCIFY_BASE}/{chain_id}/{address}?fields=sources,compilation"


class DriftKind:
    """How a target's deployed code changed between two observations."""

    NEW = "new"                    # first time we have a pinned fingerprint
    UNCHANGED = "unchanged"        # same deployed code
    CODE_CHANGED = "code_changed"  # runtime bytecode fingerprint moved
    IMPL_CHANGED = "impl_changed"  # proxy re-pointed to a new implementation
    UNVERIFIED = "unverified"      # RPC could not read it -- not a drift, a gap


@dataclass(frozen=True)
class TargetSpec:
    """One watched contract: an address, what it is, and why it matters."""

    key: str
    chain_id: int
    address: str
    name: str
    kind: str  # "core" | "across" | "oval"
    proxy: bool = False
    note: str = ""

    def to_dict(self) -> dict:
        return {
            "key": self.key,
            "chain_id": self.chain_id,
            "address": self.address,
            "name": self.name,
            "kind": self.kind,
            "proxy": self.proxy,
            "note": self.note,
        }


#: The in-scope live-deployed contracts (UMA bounty scope: "All UMA, Oval, or
#: Across smart contracts that are deployed to mainnet"). Addresses are taken
#: from the repositories' own network files / broadcast artifacts, not memory.
TARGETS: tuple[TargetSpec, ...] = (
    # --- UMA core (packages/core/networks/1.json) ---
    TargetSpec("uma-oo-v3", 1, "0xfb55F43fB9F48F63f9269DB7Dde3BbBe1ebDC0dE",
               "OptimisticOracleV3", "core",
               note="deployed directly (not proxied); the primary OOv3"),
    TargetSpec("uma-oo-v2", 1, "0xA0Ae6609447e57a42c51B50EAe921D701823FFAe",
               "OptimisticOracleV2", "core"),
    TargetSpec("uma-oo-v1", 1, "0xc43767f4592df265b4a9f1a398b97ff24f38c6a6",
               "OptimisticOracle", "core"),
    TargetSpec("uma-voting-v2", 1, "0x004395edb43EFca9885CEdad51EC9fAf93Bd34ac",
               "VotingV2 (DVM)", "core",
               note="holds staked UMA; also the OOv3 cached oracle"),
    TargetSpec("uma-store", 1, "0x54f44eA3D2e7aA0ac089c4d8F7C93C27844057BF",
               "Store", "core", note="final fees + who gets them"),
    TargetSpec("uma-oracle-hub", 1, "0x8fE658AeB8d55fd1F3E157Ff8B316E232ffFF372",
               "OracleHub", "core", note="cross-chain oracle parent"),
    TargetSpec("uma-proposer-v2", 1, "0x50efaC9619225d7fB4703C5872da978849B6E7cC",
               "ProposerV2", "core"),
    TargetSpec("uma-optimistic-governor", 1, "0x28CeBFE94a03DbCA9d17143e9d2Bd1155DC26D5d",
               "OptimisticGovernor", "core",
               note="moves value via a Gnosis Safe on OOv3 assertions"),
    # --- Across (broadcast/DeploySpokePoolPeriphery.s.sol/1) ---
    TargetSpec("across-spoke-mainnet", 1, "0x5c7BCd6E7De5423a257D81B442095A1a6ced35C5",
               "SpokePool (Ethereum)", "across", proxy=True,
               note="ERC-1967 proxy; impl re-pointing is the interesting event"),
    TargetSpec("across-hub-pool", 1, "0xc186fA914353c44b2E33eBE05f21846F1048bEda",
               "HubPool", "across",
               note="mainnet liquidity pool; holds bridged assets"),
    TargetSpec("across-periphery", 1, "0x4e9ef0a5fe749079dd11e68aad5d75fccfaaf9af",
               "SpokePoolPeriphery", "across",
               note="newest post-audit surface (relative timestamps)"),
)


@dataclass
class Observation:
    """A single, timestamped reading of one target's deployed code."""

    key: str
    name: str
    address: str
    chain_id: int
    verified: bool = False
    block_number: Optional[int] = None
    code_sha256: str = ""
    code_size: int = 0
    proxy: bool = False
    implementation: str = ""
    implementation_code_sha256: str = ""
    retrieved_at: str = field(default_factory=utcnow)
    limitations: list[str] = field(default_factory=list)

    def fingerprint(self) -> str:
        """The identity of the *executing* code: the impl's hash for a proxy."""
        if self.proxy and self.implementation_code_sha256:
            return self.implementation_code_sha256
        return self.code_sha256

    def to_dict(self) -> dict:
        return {
            "key": self.key,
            "name": self.name,
            "address": self.address,
            "chain_id": self.chain_id,
            "verified": self.verified,
            "block_number": self.block_number,
            "code_sha256": self.code_sha256,
            "code_size": self.code_size,
            "proxy": self.proxy,
            "implementation": self.implementation,
            "implementation_code_sha256": self.implementation_code_sha256,
            "fingerprint": self.fingerprint(),
            "retrieved_at": self.retrieved_at,
            "limitations": list(self.limitations),
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Observation":
        known = {f for f in cls.__dataclass_fields__}  # type: ignore[attr-defined]
        return cls(**{k: v for k, v in data.items() if k in known})


@dataclass
class MonitorReport:
    """The result of one monitoring pass over the registry."""

    rpc_url: str
    observations: list[Observation] = field(default_factory=list)
    retrieved_at: str = field(default_factory=utcnow)

    def to_dict(self) -> dict:
        return {
            "rpc_url": self.rpc_url,
            "retrieved_at": self.retrieved_at,
            "observations": [o.to_dict() for o in self.observations],
        }


def _hash_code(code: str) -> str:
    """keccak-256 of runtime bytecode, as hex (matches on-chain codehash)."""
    raw = code[2:] if isinstance(code, str) and code.startswith("0x") else (code or "")
    try:
        return "0x" + keccak256(bytes.fromhex(raw)).hex()
    except ValueError:
        return ""


def _impl_code_hash(client: ChainClient, implementation: str) -> str:
    """Fingerprint a proxy's implementation code, honestly ('' if unreadable)."""
    try:
        code = client.call("eth_getCode", [implementation, "latest"])
    except RpcUnavailable:
        return ""
    if not isinstance(code, str) or code in ("", "0x"):
        return ""
    return _hash_code(code)


def monitor_target(
    target: TargetSpec,
    rpc_url: str,
    *,
    client: Optional[ChainClient] = None,
) -> Observation:
    """Read one target's deployed code (and, for a proxy, its implementation).

    Read-only. Reuses :func:`blackheart.deployed.verify_contract` for the
    honest, evidence-carrying read, then adds the implementation fingerprint for
    proxies so an impl re-pointing is visible even when the proxy bytecode itself
    does not move.
    """
    client = client or ChainClient(rpc_url)
    contract = verify_contract(target.address, rpc_url, detect_proxy=True, client=client)

    obs = Observation(
        key=target.key,
        name=target.name,
        address=target.address,
        chain_id=contract.chain_id if contract.chain_id is not None else target.chain_id,
        verified=contract.verified,
        block_number=contract.block_number,
        code_sha256=_hash_code(contract.code) if contract.is_contract else "",
        code_size=contract.code_size,
        proxy=contract.proxy,
        implementation=contract.implementation or contract.beacon,
        limitations=list(contract.limitations),
    )
    if contract.proxy and obs.implementation:
        obs.implementation_code_sha256 = _impl_code_hash(client, obs.implementation)
    return obs


def run_monitor(
    rpc_url: str = DEFAULT_RPC,
    *,
    targets: Optional[tuple[TargetSpec, ...]] = None,
    baseline: Optional[dict[str, Observation]] = None,
    client: Optional[ChainClient] = None,
) -> tuple[MonitorReport, dict[str, str]]:
    """Poll every target and classify each against ``baseline``.

    Returns the report plus a ``{key: DriftKind}`` map. ``baseline`` is keyed by
    target key (see :func:`load_state`); a missing entry is ``NEW``.
    """
    specs = targets if targets is not None else TARGETS
    report = MonitorReport(rpc_url=rpc_url)
    drifts: dict[str, str] = {}
    baseline = baseline or {}

    for spec in specs:
        obs = monitor_target(spec, rpc_url, client=client)
        report.observations.append(obs)
        drifts[spec.key] = _classify(obs, baseline.get(spec.key))
    return report, drifts


def _classify(obs: Observation, prior: Optional[Observation]) -> str:
    if not obs.verified:
        return DriftKind.UNVERIFIED
    if prior is None or not prior.verified:
        return DriftKind.NEW
    if not prior.fingerprint():
        return DriftKind.NEW
    # A proxy whose implementation address moved is the sharpest signal.
    if obs.proxy and prior.proxy and obs.implementation and prior.implementation:
        if obs.implementation.lower() != prior.implementation.lower():
            return DriftKind.IMPL_CHANGED
    if obs.fingerprint() != prior.fingerprint():
        return DriftKind.CODE_CHANGED
    return DriftKind.UNCHANGED


# --------------------------------------------------------------------------- #
# Baseline state (JSON on disk; keyed by target)
# --------------------------------------------------------------------------- #

def load_state(path: str | Path) -> dict[str, Observation]:
    """Load a pinned baseline. A missing or unreadable file is an empty baseline."""
    p = Path(path)
    if not p.is_file():
        return {}
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    observations = data.get("observations", data) if isinstance(data, dict) else {}
    out: dict[str, Observation] = {}
    if isinstance(observations, list):
        for entry in observations:
            if isinstance(entry, dict) and entry.get("key"):
                out[entry["key"]] = Observation.from_dict(entry)
    elif isinstance(observations, dict):
        for key, entry in observations.items():
            if isinstance(entry, dict):
                out[key] = Observation.from_dict({**entry, "key": key})
    return out


def save_state(report: MonitorReport, path: str | Path) -> None:
    """Write a monitor report to disk as a pinned baseline (pretty JSON)."""
    p = Path(path)
    if p.parent and not p.parent.exists():
        p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(report.to_dict(), indent=2), encoding="utf-8")
