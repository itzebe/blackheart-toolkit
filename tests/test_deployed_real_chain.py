"""Real-chain tests: pinned fork, real bytecode, real execution.

These are the only tests that prove the capability is real rather than modelled.
They need two things the sandbox may not have -- an `anvil` binary and a reachable
public RPC -- so they skip when either is missing. **A skip is not a pass**: the
release report must count these separately and say so.
"""

from __future__ import annotations

import os

import pytest

from blackheart.deployed import ChainClient, RpcUnavailable
from blackheart.deployed_research import resolve_target

#: Try several free public endpoints. A single endpoint rate-limits under a
#: burst of calls, and a test that fails because of that is a flaky test, not a
#: finding. The pool mirrors ``deployed_research.DEFAULT_RPC_POOL``.
RPC_POOL = [
    u for u in [
        os.environ.get("BLACKHEART_ETH_RPC"),
        "https://ethereum-rpc.publicnode.com",
        "https://cloudflare-eth.com",
        "https://gateway.tenderly.co/public/mainnet",
    ] if u
]
#: A pinned block whose state is immutable, so the test is reproducible forever.
BLOCK = 26_455_778
USDC = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
WETH = "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"


def _live_rpc() -> str | None:
    """First endpoint that answers, or None. Probed once and cached."""
    global _LIVE
    if "_LIVE" not in globals():
        _LIVE = None
        if _enabled():
            for url in RPC_POOL:
                try:
                    c = ChainClient(url)
                    # Probe the capability the tests actually need -- serving
                    # code at a *historical* block -- not merely eth_chainId. A
                    # non-archive endpoint passes a chainId probe and then fails
                    # every real call, which would read as a flaky test.
                    c.call("eth_getCode", [USDC, hex(BLOCK)])
                    _LIVE = url
                    break
                except Exception:  # noqa: BLE001
                    continue
    return _LIVE


def _rpc_up() -> bool:
    return _live_rpc() is not None


def _enabled() -> bool:
    """Live-chain tests are opt-in: CI must not depend on an external RPC.

    Without the flag they skip, so a hermetic CI run is deterministic. With it,
    an unreachable RPC is still a skip (never a failure), because the absence of
    a network is not a defect in the code under test.
    """
    return os.environ.get("BLACKHEART_LIVE_CHAIN") == "1"


pytestmark = [
    pytest.mark.slow,
    pytest.mark.skipif(
        not _enabled(), reason="set BLACKHEART_LIVE_CHAIN=1 to run live-chain tests"
    ),
    pytest.mark.skipif(not _rpc_up(), reason=f"no reachable RPC in {RPC_POOL}"),
]


def _have_anvil() -> bool:
    from blackheart.statespace.runtime.evm import _foundry_bin

    return _foundry_bin("anvil") is not None


def test_real_contract_is_pinned_and_hashed():
    t = resolve_target(USDC, block_number=BLOCK, rpc_urls=[_live_rpc()])
    assert t.block_number == BLOCK
    assert t.code_size > 0
    assert len(t.code_sha256) == 64
    # The same block twice must give byte-identical evidence.
    again = resolve_target(USDC, block_number=BLOCK, rpc_urls=[_live_rpc()])
    assert again.code_sha256 == t.code_sha256
    assert again.block_hash == t.block_hash


def test_real_proxy_implementation_is_resolved():
    t = resolve_target(USDC, block_number=BLOCK, rpc_urls=[_live_rpc()])
    assert t.is_proxy is True
    assert t.implementation is not None
    # The implementation is a different, much larger contract than the proxy.
    assert t.implementation.address.lower() != USDC.lower()
    assert t.implementation.code_size > t.code_size


def test_real_abi_functions_are_proven_dispatch_reachable():
    t = resolve_target(USDC, block_number=BLOCK, rpc_urls=[_live_rpc()])
    from blackheart.deployed import function_selector

    reachable = {s.selector for s in t.dispatch.reachable}
    for sig in ("transfer(address,uint256)", "balanceOf(address)", "approve(address,uint256)"):
        assert function_selector(sig) in reachable


def test_non_proxy_contract_exposes_its_own_dispatch():
    t = resolve_target(WETH, block_number=BLOCK, rpc_urls=[_live_rpc()])
    assert t.is_proxy is False
    assert t.implementation is None
    from blackheart.deployed import function_selector

    reachable = {s.selector for s in t.dispatch.reachable}
    assert function_selector("deposit()") in reachable
    assert function_selector("withdraw(uint256)") in reachable


@pytest.mark.skipif(not _have_anvil(), reason="anvil not on PATH")
def test_pinned_fork_executes_real_deployed_code():
    from blackheart.statespace.runtime.evm import AnvilNode

    node = AnvilNode(fork_url=_live_rpc(), fork_block=BLOCK)
    node.start()
    try:
        pin = node.assert_fork_pinned()
        assert pin["block_number"] == BLOCK
        assert pin["chain_id"] == 1
        code = node.rpc.call("eth_getCode", [WETH, "latest"])
        assert len(code) > 2
        # A real call against real deployed state.
        name = node.rpc.call(
            "eth_call", [{"to": WETH, "data": "0x06fdde03"}, "latest"]
        )
        assert "Wrapped Ether" in bytes.fromhex(name[2:]).decode("latin-1")
    finally:
        node.stop()


@pytest.mark.skipif(not _have_anvil(), reason="anvil not on PATH")
def test_fork_rejects_a_substituted_block():
    """The pin must fail loudly rather than silently fork 'latest'."""
    from blackheart.statespace.runtime.evm import AnvilNode

    node = AnvilNode(fork_url=_live_rpc(), fork_block=BLOCK)
    node.start()
    try:
        # Simulate the upstream refusing the block: the node ends up elsewhere.
        node.fork_block = BLOCK - 10_000
        with pytest.raises(Exception) as exc:
            node.assert_fork_pinned()
        assert "refusing to label" in str(exc.value)
    finally:
        node.stop()


@pytest.mark.skipif(not _have_anvil(), reason="anvil not on PATH")
def test_real_multicontract_state_transition_on_the_fork():
    from blackheart.deployed_multicontract import SequenceStep, run_sequence
    from blackheart.statespace.runtime.evm import AnvilNode

    node = AnvilNode(fork_url=_live_rpc(), fork_block=BLOCK)
    node.start()
    try:
        account = AnvilNode.ACCOUNTS[0]
        node.rpc.call("anvil_setBalance", [account, hex(10**20)])
        before = int(node.rpc.call(
            "eth_call",
            [{"to": WETH, "data": "0x70a08231" + "00" * 12 + account[2:]}, "latest"],
        ), 16)
        result = run_sequence(
            node,
            [SequenceStep("wrap 1 ETH", WETH, "0xd0e30db0", account, value=10**18)],
            observe=[("after", WETH, "0x70a08231" + "00" * 12 + account[2:])],
        )
        assert result.completed is True
        after = int(result.observations[0].values["raw"], 16)
        assert after - before == 10**18
    finally:
        node.stop()


def test_unreachable_rpc_is_reported_not_faked():
    with pytest.raises(RpcUnavailable):
        resolve_target(USDC, block_number=BLOCK, rpc_urls=["http://127.0.0.1:1"])
