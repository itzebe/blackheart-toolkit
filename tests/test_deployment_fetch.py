"""Deployment fetch must cache, and must never turn a failure into a clean read."""

from __future__ import annotations

from blackheart.deployed import RpcUnavailable
from blackheart.deployment_fetch import (
    DeploymentCache,
    attest_deployment,
    fetch_contract,
)
from blackheart.watch.source import SourceBundle


class FakeChain:
    def __init__(self, *, code="0x6001600255", chain_id="0x1", block="0x10") -> None:
        self.code = code
        self.chain_id = chain_id
        self.block = block
        self.calls: list[str] = []

    def call(self, method, params):
        self.calls.append(method)
        if method == "eth_chainId":
            return self.chain_id
        if method == "eth_blockNumber":
            return self.block
        if method == "eth_getCode":
            return self.code
        if method == "eth_getStorageAt":
            return "0x" + "00" * 32
        raise AssertionError(f"unexpected RPC method {method}")


class DownChain:
    def call(self, method, params):
        raise RpcUnavailable("connection refused")


def test_fetch_reads_a_verified_contract():
    result = fetch_contract("0xABC", client=FakeChain())
    assert result.ok
    assert result.contract.verified
    assert result.contract.code_size == 5


def test_fetch_caches_by_chain_address_and_block():
    chain = FakeChain()
    cache = DeploymentCache()
    first = fetch_contract("0xABC", chain="1", client=chain, cache=cache)
    calls_after_first = len(chain.calls)
    second = fetch_contract("0xABC", chain="1", client=chain, cache=cache)
    assert first is second
    assert len(chain.calls) == calls_after_first, "a cached read must not re-fetch"
    assert cache.hits == 1


def test_an_unreachable_rpc_is_reported_not_clean():
    result = fetch_contract("0xABC", client=DownChain())
    assert result.status == "RPC_UNAVAILABLE"
    assert not result.ok


def test_an_address_without_code_is_no_code():
    result = fetch_contract("0xABC", client=FakeChain(code="0x"))
    assert result.status == "NO_CODE"
    assert not result.ok


def test_attest_deployment_attaches_verified_source():
    class SourceClient:
        def fetch(self, chain_id, address):
            return SourceBundle(chain_id=chain_id, address=address, ok=True,
                                status="verified", files={"A.sol": "contract A {}"})

    result = attest_deployment("0xABC", client=FakeChain(), source_client=SourceClient())
    assert result.ok
    assert result.source is not None and result.source.verified


def test_cache_is_bounded():
    cache = DeploymentCache(max_entries=1)
    cache.put(("a", "b", None), fetch_contract("0xABC", client=FakeChain()))
    cache.put(("c", "d", None), fetch_contract("0xDEF", client=FakeChain()))
    assert len(cache) == 1
