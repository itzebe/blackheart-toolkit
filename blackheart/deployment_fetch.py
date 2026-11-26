"""Deployment fetch: one cached, honest read of a live contract and its source.

:mod:`blackheart.deployed` reads the chain facts; :mod:`blackheart.verified_source`
reads the published source. This module composes them for a research loop that
asks the same questions repeatedly, and it adds the one thing a loop needs: a
cache keyed by ``(chain, address, block)``. An unchanged address at the same block
is never re-fetched, and an unreachable RPC is a recorded limitation, never a
clean read.

Nothing here sends a transaction. Every path is read-only.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

from .deployed import ChainClient, DeployedContract, verify_contract
from .verified_source import Attestation, attest as attest_source


@dataclass
class DeploymentFetch:
    """The result of reading one deployment, with its gap stated."""

    status: str  # "OK" | "NO_CODE" | "RPC_UNAVAILABLE" | "ERROR"
    address: str
    chain: str = ""
    contract: Optional[DeployedContract] = None
    source: Optional[Attestation] = None
    reason: str = ""

    @property
    def ok(self) -> bool:
        return self.status == "OK"

    def to_dict(self) -> dict:
        return {
            "status": self.status,
            "address": self.address,
            "chain": self.chain,
            "reason": self.reason,
            "contract": self.contract.to_dict() if self.contract else None,
            "source": self.source.to_dict() if self.source else None,
        }


class DeploymentCache:
    """A bounded in-memory cache keyed by ``(chain, address, block)``."""

    def __init__(self, max_entries: int = 512) -> None:
        self.max_entries = max_entries
        self._store: dict[tuple, DeploymentFetch] = {}
        self.hits = 0
        self.misses = 0

    def get(self, key: tuple) -> Optional[DeploymentFetch]:
        value = self._store.get(key)
        if value is None:
            self.misses += 1
        else:
            self.hits += 1
        return value

    def put(self, key: tuple, value: DeploymentFetch) -> None:
        if len(self._store) >= self.max_entries and key not in self._store:
            self._store.pop(next(iter(self._store)))
        self._store[key] = value

    def __len__(self) -> int:
        return len(self._store)


def _cache_key(chain: str, address: str, at_block: Optional[int]) -> tuple:
    return (str(chain).lower(), address.lower(), at_block)


def fetch_contract(
    address: str,
    *,
    rpc_url: Optional[str] = None,
    chain: str = "mainnet",
    at_block: Optional[int] = None,
    client: Optional[Any] = None,
    cache: Optional[DeploymentCache] = None,
) -> DeploymentFetch:
    """Read the on-chain facts for ``address``, resolving an RPC when needed."""
    key = _cache_key(chain, address, at_block)
    if cache is not None:
        hit = cache.get(key)
        if hit is not None:
            return hit

    if client is None:
        from .rpc import resolve_rpc

        resolution = resolve_rpc(chain, explicit=rpc_url)
        if not resolution.ok:
            return DeploymentFetch(
                "RPC_UNAVAILABLE", address, str(chain),
                reason=resolution.error or "no RPC endpoint answered for this chain")
        rpc_url = resolution.url
        client = ChainClient(resolution.url)

    try:
        contract = verify_contract(address, rpc_url or "injected", at_block=at_block,
                                   client=client)
    except Exception as exc:  # an injected client may raise anything
        return DeploymentFetch("ERROR", address, str(chain), reason=f"fetch failed: {exc}")

    if any(lim.startswith("RPC unavailable") for lim in contract.limitations):
        status = "RPC_UNAVAILABLE"
    elif contract.verified:
        status = "OK"
    else:
        status = "NO_CODE"
    result = DeploymentFetch(status, address, str(chain), contract=contract,
                             reason="" if contract.verified else "; ".join(contract.limitations))
    if cache is not None:
        cache.put(key, result)
    return result


def fetch_source(address: str, chain_id: int, *, client: Optional[Any] = None) -> Attestation:
    """Fetch verified source for a deployment (Sourcify by default)."""
    return attest_source(chain_id, address, client=client)


def attest_deployment(
    address: str,
    *,
    rpc_url: Optional[str] = None,
    chain: str = "mainnet",
    at_block: Optional[int] = None,
    client: Optional[Any] = None,
    source_client: Optional[Any] = None,
    cache: Optional[DeploymentCache] = None,
) -> DeploymentFetch:
    """Read the deployment and, when it is a contract, its verified source."""
    result = fetch_contract(address, rpc_url=rpc_url, chain=chain, at_block=at_block,
                            client=client, cache=cache)
    if result.contract is not None and result.contract.chain_id:
        result.source = fetch_source(address, result.contract.chain_id, client=source_client)
    return result
