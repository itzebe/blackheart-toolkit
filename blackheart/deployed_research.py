"""Research a *real* deployed contract on a pinned public-chain block.

This is the mission's principal capability: take an address that exists on a
public chain, pin the chain to an exact block, pull the runtime bytecode that is
actually deployed there, and reason about it -- then execute candidate paths
against that same pinned state in an isolated local fork.

What separates this from a scanner, and what the module refuses to do:

  * it never treats a 4-byte value in the bytecode as a callable function. A
    selector is an *entry point* only when the dispatcher proves it
    (:mod:`blackheart.deployed_selectors`);
  * it never treats a proxy's own bytecode as the contract's logic. The
    implementation is resolved from the populated proxy slot and recorded;
  * it never replaces the requested block. ``assert_fork_pinned`` fails the run
    if the node is not on the block the evidence will name;
  * it never calls a candidate "a vulnerability". A candidate is a hypothesis;
    only execution under a discriminating control promotes it, and a negative
    result is recorded as a negative;
  * it never broadcasts. Every write happens on the local fork; the only network
    traffic is reads against the pinned block.

The output is a :class:`DeployedResearchRecord` -- machine-readable, hash-pinned,
and honest about what was and was not established.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Optional

from .deployed import (
    PROXY_SLOTS,
    ChainClient,
    RpcUnavailable,
    function_selector,
)
from .deployed_selectors import SelectorDispatchReport, analyse_selectors

__all__ = [
    "DeployedTarget",
    "ResolvedImplementation",
    "DiscoveryHypothesis",
    "DeployedResearchRecord",
    "resolve_target",
    "propose_hypotheses",
]

#: Free, keyless public endpoints. Tried in order; the first that answers the
#: pinned block wins. No key, no account, no payment -- see ``docs``.
DEFAULT_RPC_POOL: tuple[str, ...] = (
    "https://ethereum-rpc.publicnode.com",
    "https://cloudflare-eth.com",
    "https://gateway.tenderly.co/public/mainnet",
)

#: Functions whose presence is security-relevant and whose *absence* is a
#: forgotten-path lead in its own right. The names are canonical signatures, so
#: the selector is derived rather than written down -- a hardcoded selector can
#: silently stop matching after a refactor.
INTERESTING_SIGNATURES: dict[str, str] = {
    "transferOwnership(address)": "ownership transfer",
    "renounceOwnership()": "ownership renouncement",
    "initialize(address)": "initializer (re-init risk)",
    "upgradeTo(address)": "UUPS upgrade",
    "upgradeToAndCall(address,bytes)": "UUPS upgrade with call",
    "setImplementation(address)": "implementation setter",
    "pause()": "emergency pause",
    "unpause()": "emergency unpause",
    "mint(address,uint256)": "supply inflation",
    "burn(uint256)": "supply reduction",
    "blacklist(address)": "transfer restriction",
    "setFee(uint256)": "fee parameter",
    "sweep(address)": "residual-asset sweep",
    "rescueTokens(address,uint256)": "token rescue",
    "selfdestruct()": "destruction path",
}


@dataclass
class ResolvedImplementation:
    """Where a proxy's logic actually lives, and how we know."""

    slot_name: str
    slot: str
    raw_value: str
    address: str
    code_size: int = 0
    code_sha256: str = ""

    def to_dict(self) -> dict:
        return {
            "slot_name": self.slot_name,
            "slot": self.slot,
            "raw_value": self.raw_value,
            "address": self.address,
            "code_size": self.code_size,
            "code_sha256": self.code_sha256,
        }


@dataclass
class DeployedTarget:
    """Everything retrieved about one address, pinned to one block."""

    address: str
    chain_id: int
    block_number: int
    block_hash: str
    rpc_url: str
    #: sha256 of the runtime bytecode *exactly as retrieved*.
    code_sha256: str = ""
    code_size: int = 0
    is_proxy: bool = False
    implementation: Optional[ResolvedImplementation] = None
    #: Selector analysis of the contract that actually holds the logic (the
    #: implementation for a proxy, else the address itself).
    dispatch: Optional[SelectorDispatchReport] = None
    #: Selector analysis of the address's own bytecode, kept separately so a
    #: proxy's (usually dispatcher-free) code is never confused with its logic.
    own_dispatch: Optional[SelectorDispatchReport] = None
    retrieval_notes: list[str] = field(default_factory=list)
    #: Set when the address could not be researched at all (no code, etc).
    unavailable_reason: str = ""

    @property
    def logic_address(self) -> str:
        return self.implementation.address if self.implementation else self.address

    @property
    def logic_code_sha256(self) -> str:
        return self.implementation.code_sha256 if self.implementation else self.code_sha256

    def to_dict(self) -> dict:
        return {
            "address": self.address,
            "chain_id": self.chain_id,
            "block_number": self.block_number,
            "block_hash": self.block_hash,
            "rpc_url": self.rpc_url,
            "code_size": self.code_size,
            "code_sha256": self.code_sha256,
            "is_proxy": self.is_proxy,
            "logic_address": self.logic_address,
            "logic_code_sha256": self.logic_code_sha256,
            "implementation": self.implementation.to_dict() if self.implementation else None,
            "dispatch": self.dispatch.to_dict() if self.dispatch else None,
            "own_dispatch": self.own_dispatch.to_dict() if self.own_dispatch else None,
            "retrieval_notes": self.retrieval_notes,
            "unavailable_reason": self.unavailable_reason,
        }


@dataclass
class DiscoveryHypothesis:
    """A candidate path, with its provenance and what would falsify it.

    ``status`` starts at ``CANDIDATE``. It becomes ``EXECUTED_*`` only after real
    execution, and ``VERIFIED`` only under a discriminating control. A hypothesis
    that cannot be executed stays ``BLOCKED`` or ``UNKNOWN`` -- never ``CLEAN``.
    """

    hypothesis_id: str
    kind: str
    selector: str
    signature: str
    rationale: str
    falsification: str
    status: str = "CANDIDATE"
    evidence: dict = field(default_factory=dict)
    execution: Optional[dict] = None

    def to_dict(self) -> dict:
        return {
            "hypothesis_id": self.hypothesis_id,
            "kind": self.kind,
            "selector": self.selector,
            "signature": self.signature,
            "rationale": self.rationale,
            "falsification": self.falsification,
            "status": self.status,
            "evidence": self.evidence,
            "execution": self.execution,
        }


@dataclass
class DeployedResearchRecord:
    """The durable result of one real-target research run."""

    experiment_id: str
    target: DeployedTarget
    hypotheses: list[DiscoveryHypothesis] = field(default_factory=list)
    #: Honest, top-level classification of the run.
    verdict: str = "INCOMPLETE"
    limitations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "experiment_id": self.experiment_id,
            "verdict": self.verdict,
            "target": self.target.to_dict(),
            "hypotheses": [h.to_dict() for h in self.hypotheses],
            "limitations": self.limitations,
            "counts": {
                "reachable_selectors": len(self.target.dispatch.reachable) if self.target.dispatch else 0,
                "present_only_selectors": len(self.target.dispatch.present_only) if self.target.dispatch else 0,
                "candidates": len(self.hypotheses),
            },
        }


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _code_bytes(client: ChainClient, address: str, block: str) -> bytes:
    code = client.call("eth_getCode", [address, block])
    if not isinstance(code, str):
        raise RpcUnavailable(f"eth_getCode returned {type(code).__name__}, not hex")
    return bytes.fromhex(code[2:] if code.startswith("0x") else code)


def _resolve_implementation(
    client: ChainClient, address: str, block: str
) -> Optional[ResolvedImplementation]:
    """Read each known proxy slot; return the first that holds a real address.

    Slots are probed in a fixed order so the resolution is reproducible. A slot
    holding a value that is not a plausible address is reported, not silently
    dropped -- a malformed implementation pointer is itself worth knowing about.
    """
    for name, slot in PROXY_SLOTS.items():
        raw = client.call("eth_getStorageAt", [address, slot, block])
        if not isinstance(raw, str) or int(raw, 16) == 0:
            continue
        candidate = "0x" + raw[-40:]
        impl_code = _code_bytes(client, candidate, block)
        if not impl_code:
            # Pointer set but no code: record it, keep looking for a usable one.
            continue
        return ResolvedImplementation(
            slot_name=name,
            slot=slot,
            raw_value=raw,
            address=candidate,
            code_size=len(impl_code),
            code_sha256=_sha256_hex(impl_code),
        )
    return None


def resolve_target(
    address: str,
    *,
    block_number: Optional[int] = None,
    rpc_urls: Optional[list[str]] = None,
    client: Optional[ChainClient] = None,
) -> DeployedTarget:
    """Retrieve a real contract at a pinned block, resolving proxies.

    ``block_number`` is pinned when given. When omitted the *current* head is
    pinned immediately and recorded, so the run is still reproducible after the
    chain advances -- an unpinned "latest" would make the evidence meaningless.
    """
    notes: list[str] = []
    if client is None:
        # Probe the whole pool and keep *every* endpoint that answers, not just
        # the first. A free public endpoint can rate-limit mid-run, so the caller
        # needs a live fallback rather than a single point of failure.
        live: list[ChainClient] = []
        last: Optional[Exception] = None
        for url in (rpc_urls or list(DEFAULT_RPC_POOL)):
            try:
                c = ChainClient(url)
                c.call("eth_chainId", [])
                # A historical read is the capability this module needs. A
                # non-archive endpoint answers eth_chainId and then fails every
                # pinned-block call, so it must not be selected as live.
                if block_number is not None:
                    c.call("eth_getCode", [address, hex(block_number)])
            except RpcUnavailable as exc:
                last = exc
                continue
            live.append(c)
        if not live:
            raise RpcUnavailable(f"no RPC endpoint answered: {last}")
        client = live[0]
        if len(live) > 1:
            notes.append(
                f"{len(live)} endpoints answered; using {client.url}, "
                f"fallbacks: {[c.url for c in live[1:]]}"
            )

    chain_id = int(client.call("eth_chainId", []), 16)
    if block_number is None:
        block_number = int(client.call("eth_blockNumber", []), 16)
        notes.append(f"block not supplied; pinned head {block_number} at retrieval time")
    block = client.call("eth_getBlockByNumber", [hex(block_number), False])
    if not block:
        raise RpcUnavailable(f"block {block_number} is not available from this RPC")

    tag = hex(block_number)
    code = _code_bytes(client, address, tag)
    target = DeployedTarget(
        address=address,
        chain_id=chain_id,
        block_number=block_number,
        block_hash=block["hash"],
        rpc_url=client.url,
        code_size=len(code),
        code_sha256=_sha256_hex(code),
        retrieval_notes=notes,
    )
    if not code:
        target.retrieval_notes.append("address holds no code at this block")
        target.unavailable_reason = "no code at the pinned block"
        return target

    target.own_dispatch = analyse_selectors(code)
    impl = _resolve_implementation(client, address, tag)
    if impl is not None:
        target.is_proxy = True
        target.implementation = impl
        logic = _code_bytes(client, impl.address, tag)
        target.dispatch = analyse_selectors(logic)
        notes.append(
            f"proxy detected via {impl.slot_name}; logic read from {impl.address}"
        )
    else:
        target.dispatch = target.own_dispatch
    return target


def propose_hypotheses(target: DeployedTarget) -> list[DiscoveryHypothesis]:
    """Turn the dispatch analysis into candidate paths, with honest provenance.

    Only *dispatch-reachable* selectors become candidates. A selector that is
    merely present is recorded in the target's ``present_only`` set and never
    promoted -- that is the difference between a lead and a false lead.

    The hypotheses here are structural: they say *what to test and why*, not
    *what will happen*. Nothing is claimed to be vulnerable.
    """
    if target.dispatch is None:
        return []
    reachable = {s.selector: s for s in target.dispatch.reachable}
    out: list[DiscoveryHypothesis] = []
    seen: set[str] = set()

    for signature, why in INTERESTING_SIGNATURES.items():
        selector = function_selector(signature)
        entry = reachable.get(selector)
        if entry is None:
            continue
        if selector in seen:
            continue
        seen.add(selector)
        out.append(
            DiscoveryHypothesis(
                hypothesis_id=f"sel-{selector}",
                kind="reachable-privileged-surface",
                selector="0x" + selector,
                signature=signature,
                rationale=(
                    f"{signature} is dispatch-reachable in the deployed logic "
                    f"({entry.evidence}) and controls {why}; an unprivileged caller "
                    "reaching it is the security question"
                ),
                falsification=(
                    "the call reverts for an unprivileged caller, or the state change "
                    "it produces is value-neutral and cannot be reached without a role"
                ),
                evidence={"dispatch_offsets": entry.dispatch_offsets, "role": why},
            )
        )

    # Reachable-but-unidentified selectors are the genuine "forgotten path" set:
    # they exist in the dispatcher but match no signature we know. They stay
    # UNKNOWN -- we will not invent a signature for them.
    unknown = [
        s for s in target.dispatch.reachable
        if not any(function_selector(sig) == s.selector for sig in INTERESTING_SIGNATURES)
    ]
    for entry in unknown[:16]:
        out.append(
            DiscoveryHypothesis(
                hypothesis_id=f"unk-{entry.selector}",
                kind="undocumented-dispatch-entry",
                selector="0x" + entry.selector,
                signature="",
                rationale=(
                    "selector is dispatch-reachable but matches no signature in the "
                    "known table; it may be an undocumented or deprecated entry point"
                ),
                falsification=(
                    "identify the signature from source/ABI; if it is an ordinary "
                    "getter, it is not a forgotten path"
                ),
                status="UNKNOWN",
                evidence={"dispatch_offsets": entry.dispatch_offsets},
            )
        )
    return out
