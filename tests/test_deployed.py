"""Deployed-contract intelligence tests (mission Phase Two).

These tests never touch the network: they drive :func:`verify_contract` with a fake
:class:`ChainClient`. That keeps the suite hermetic while still asserting the
honesty rules the mission demands -- no code means not verified, an unreachable RPC
is a recorded limitation, an EIP-7702 designator is an EOA (not a contract), and a
standard proxy slot is detected and resolved.
"""

from __future__ import annotations

import json

from blackheart.deployed import (
    PROXY_SLOTS,
    ChainClient,
    RpcUnavailable,
    _is_eip7702_designator,
    function_selector,
    keccak256,
    selector_present,
    verify_contract,
)

# A short but valid-looking runtime code blob (STOP-padded), and the zero word.
_CODE = "0x6080604052600436106100"
_ZERO_WORD = "0x" + "00" * 32


class FakeClient(ChainClient):
    """A ChainClient whose JSON-RPC replies are scripted per method."""

    def __init__(self, *, code: str = _CODE, storage: dict[str, str] | None = None,
                 chain_id: int = 1, block: int = 12345, raise_on: set[str] | None = None):
        super().__init__("fake://rpc")
        self._code = code
        self._storage = storage or {}
        self._chain_id = chain_id
        self._block = block
        self._raise_on = raise_on or set()
        self.calls: list[tuple[str, list]] = []

    def call(self, method: str, params: list) -> object:
        self.calls.append((method, params))
        if method in self._raise_on:
            raise RpcUnavailable(f"fake: {method} failed")
        if method == "eth_chainId":
            return hex(self._chain_id)
        if method == "eth_blockNumber":
            return hex(self._block)
        if method == "eth_getCode":
            return self._code
        if method == "eth_getStorageAt":
            return self._storage.get(params[1].lower(), _ZERO_WORD)
        raise RpcUnavailable(f"fake: unhandled {method}")


def _addr_word(addr: str) -> str:
    return "0x" + "00" * 12 + addr[2:].lower()


# --------------------------------------------------------------------------- #
# Core honesty rules
# --------------------------------------------------------------------------- #

def test_real_code_is_verified_and_hashed() -> None:
    res = verify_contract("0xabc", "fake://", client=FakeClient())
    assert res.verified and res.is_contract
    assert res.code_size == 11
    assert len(res.code_sha256) == 64
    assert res.chain_id == 1 and res.block_number == 12345


def test_empty_code_is_not_a_contract_and_not_verified() -> None:
    res = verify_contract("0xabc", "fake://", client=FakeClient(code="0x"))
    assert res.verified is False
    assert res.is_contract is False
    assert any("no runtime code" in lim for lim in res.limitations)


def test_unreachable_rpc_is_a_recorded_limitation_not_a_success() -> None:
    client = FakeClient(raise_on={"eth_chainId"})
    res = verify_contract("0xabc", "fake://", client=client)
    assert res.verified is False
    assert any("RPC unavailable" in lim for lim in res.limitations)


def test_reads_only_never_sends_a_transaction() -> None:
    client = FakeClient()
    verify_contract("0xabc", "fake://", client=client)
    methods = {m for m, _ in client.calls}
    assert methods <= {"eth_chainId", "eth_blockNumber", "eth_getCode", "eth_getStorageAt"}
    assert not any(m.startswith("eth_send") for m in methods)


# --------------------------------------------------------------------------- #
# EIP-7702: an EOA is not a contract
# --------------------------------------------------------------------------- #

def test_eip7702_designator_detected_as_helper() -> None:
    designator = "0xef0100" + "11" * 20
    assert _is_eip7702_designator(designator) is True
    assert _is_eip7702_designator("0x6080") is False
    assert _is_eip7702_designator("0xef0100" + "11" * 19) is False  # wrong length


def test_eip7702_account_is_not_reported_as_a_contract() -> None:
    delegate = "0x5a7fc11397e9a8ad41bf10bf13f22b0a63f96f6d"
    res = verify_contract("0xabc", "fake://",
                          client=FakeClient(code="0xef0100" + delegate[2:]))
    assert res.verified is False
    assert res.is_contract is False
    assert res.eip7702_delegate == delegate
    assert any("EIP-7702" in lim for lim in res.limitations)


# --------------------------------------------------------------------------- #
# Proxy detection
# --------------------------------------------------------------------------- #

def test_eip1967_proxy_is_detected_and_resolved() -> None:
    impl = "0x43506849d7c04f9138d1a2050bbf3a0c054402dd"
    storage = {PROXY_SLOTS["eip1967"].lower(): _addr_word(impl)}
    res = verify_contract("0xabc", "fake://", client=FakeClient(storage=storage))
    assert res.proxy and res.proxy_kind == "eip1967"
    assert res.implementation == impl


def test_eip1967_admin_slot_is_recorded_without_faking_a_proxy() -> None:
    admin = "0x1111111111111111111111111111111111111111"
    storage = {PROXY_SLOTS["eip1967_admin"].lower(): _addr_word(admin)}
    res = verify_contract("0xabc", "fake://", client=FakeClient(storage=storage))
    assert res.admin == admin
    # An admin slot alone does not make it a proxy (no implementation slot).
    assert res.implementation == ""


def test_beacon_slot_is_detected() -> None:
    beacon = "0x2222222222222222222222222222222222222222"
    storage = {PROXY_SLOTS["eip1967_beacon"].lower(): _addr_word(beacon)}
    res = verify_contract("0xabc", "fake://", client=FakeClient(storage=storage))
    assert res.beacon == beacon and res.proxy


def test_zero_storage_slots_do_not_create_a_proxy() -> None:
    res = verify_contract("0xabc", "fake://", client=FakeClient())
    assert res.proxy is False and res.implementation == ""


def test_no_proxy_detection_skips_storage_reads() -> None:
    client = FakeClient()
    verify_contract("0xabc", "fake://", client=client, detect_proxy=False)
    assert not any(m == "eth_getStorageAt" for m, _ in client.calls)


# --------------------------------------------------------------------------- #
# Provenance + serialisation
# --------------------------------------------------------------------------- #

def test_evidence_records_every_read_with_block_and_source() -> None:
    res = verify_contract("0xabc", "fake://", client=FakeClient())
    assert res.evidence
    ev = res.evidence[0]
    assert ev.method == "eth_getCode"
    assert ev.block_number == 12345
    assert ev.source_url == "fake://"
    assert ev.retrieved_at


def test_result_is_json_serialisable() -> None:
    res = verify_contract("0xabc", "fake://", client=FakeClient())
    blob = json.dumps(res.to_dict())
    data = json.loads(blob)
    assert data["verified"] is True
    assert data["evidence"]


def test_at_block_is_used_in_the_request() -> None:
    client = FakeClient()
    verify_contract("0xabc", "fake://", client=client, at_block=999)
    getcode = [p for m, p in client.calls if m == "eth_getCode"][0]
    assert getcode[1] == hex(999)


# --------------------------------------------------------------------------- #
# Untrusted RPC responses must be recorded, never crash the caller
# --------------------------------------------------------------------------- #

class _ScriptedClient(ChainClient):
    """A client whose raw replies are fixed values, to model a hostile/broken RPC."""

    def __init__(self, replies: dict[str, object]):
        super().__init__("scripted://")
        self._replies = replies

    def call(self, method: str, params: list) -> object:
        return self._replies.get(method, "0x")


def _base_replies(**over: object) -> dict[str, object]:
    base: dict[str, object] = {"eth_chainId": "0x1", "eth_blockNumber": "0x10",
                               "eth_getCode": _CODE, "eth_getStorageAt": _ZERO_WORD}
    base.update(over)
    return base


def test_malformed_chain_id_is_a_limitation_not_a_crash() -> None:
    res = verify_contract("0xabc", "fake://",
                          client=_ScriptedClient(_base_replies(eth_chainId="zzz")))
    assert res.verified is False
    assert any("RPC unavailable" in lim for lim in res.limitations)


def test_non_quantity_block_number_is_a_limitation_not_a_crash() -> None:
    res = verify_contract("0xabc", "fake://",
                          client=_ScriptedClient(_base_replies(eth_blockNumber=None)))
    assert res.verified is False
    assert any("RPC unavailable" in lim for lim in res.limitations)


def test_non_string_code_is_a_limitation_not_a_crash() -> None:
    res = verify_contract("0xabc", "fake://",
                          client=_ScriptedClient(_base_replies(eth_getCode=123)))
    assert res.verified is False
    assert any("non-string" in lim for lim in res.limitations)


def test_malformed_storage_word_does_not_crash_or_fake_a_proxy() -> None:
    # A non-hex storage word must not raise, and must not be read as an address.
    res = verify_contract("0xabc", "fake://", client=_ScriptedClient(
        _base_replies(eth_getStorageAt="0x" + "zz" * 32)))
    assert res.proxy is False and res.implementation == ""


def test_json_rpc_null_error_is_not_treated_as_an_error() -> None:
    """A legal success response carries ``"error": null``; it must not fail closed."""
    import urllib.request

    class _Resp:
        def __init__(self, body: bytes): self._b = body
        def read(self): return self._b
        def __enter__(self): return self
        def __exit__(self, *a): return False

    body = b'{"jsonrpc":"2.0","id":1,"result":"0x1","error":null}'
    orig = urllib.request.urlopen
    urllib.request.urlopen = lambda req, timeout=20: _Resp(body)
    try:
        assert ChainClient("http://x").call("eth_chainId", []) == "0x1"
    finally:
        urllib.request.urlopen = orig


def test_json_rpc_non_object_body_is_a_recorded_rpc_error() -> None:
    import urllib.request

    class _Resp:
        def read(self): return b"[]"
        def __enter__(self): return self
        def __exit__(self, *a): return False

    orig = urllib.request.urlopen
    urllib.request.urlopen = lambda req, timeout=20: _Resp()
    try:
        try:
            ChainClient("http://x").call("eth_chainId", [])
        except RpcUnavailable:
            pass
        else:
            raise AssertionError("a non-object body must raise RpcUnavailable")
    finally:
        urllib.request.urlopen = orig


# --------------------------------------------------------------------------- #
# Keccak-256 and function selectors (pure-Python, no dependency)
# --------------------------------------------------------------------------- #

def test_keccak256_matches_known_vectors() -> None:
    assert keccak256(b"").hex() == (
        "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
    )
    assert keccak256(b"abc").hex() == (
        "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"
    )


def test_function_selector_matches_known_erc20_selectors() -> None:
    assert function_selector("transfer(address,uint256)") == "a9059cbb"
    assert function_selector("approve(address,uint256)") == "095ea7b3"
    assert function_selector("balanceOf(address)") == "70a08231"


def test_selector_present_is_case_and_prefix_insensitive() -> None:
    code = "0x6080604052" + "a9059cbb" + "0000"
    assert selector_present(code, "a9059cbb") is True
    assert selector_present(code, "0xa9059cbb") is True
    assert selector_present(code, "0xA9059CBB") is True
    assert selector_present(code, "deadbeef") is False


def test_selectors_are_distinct_per_signature() -> None:
    """Different signatures must not collide on the same 4-byte selector."""
    a = function_selector("setLiquidateIncentiveShareBps(uint256)")
    b = function_selector("setLiquidationIncentive(uint256)")
    assert a != b


# --------------------------------------------------------------------------- #
# CLI surface
# --------------------------------------------------------------------------- #

class _FakeCliClient(ChainClient):
    def __init__(self, code: str):
        super().__init__("fake://")
        self._code = code

    def call(self, method: str, params: list) -> object:
        if method == "eth_chainId":
            return hex(1)
        if method == "eth_blockNumber":
            return hex(100)
        if method == "eth_getCode":
            return self._code
        if method == "eth_getStorageAt":
            return _ZERO_WORD
        raise RpcUnavailable(method)


def test_deployed_cli_reports_selectors(tmp_path, capsys, monkeypatch) -> None:
    from blackheart import deployed as deployed_mod
    from blackheart.cli import main

    # A contract whose bytecode contains the transfer selector.
    code = "0x6080" + function_selector("transfer(address,uint256)") + "00"
    monkeypatch.setattr(deployed_mod, "ChainClient",
                        lambda url, timeout=20: _FakeCliClient(code))
    rc = main(["deployed", "0xabc", "--rpc", "fake://",
               "--selectors", "transfer(address,uint256);approve(address,uint256)",
               "--json"])
    out = json.loads(capsys.readouterr().out)
    assert rc == 0
    present = {s["signature"]: s["present"] for s in out["selectors"]}
    assert present["transfer(address,uint256)"] is True
    assert present["approve(address,uint256)"] is False


def test_deployed_cli_exits_nonzero_when_not_a_contract(monkeypatch, capsys) -> None:
    from blackheart import deployed as deployed_mod
    from blackheart.cli import main

    monkeypatch.setattr(deployed_mod, "ChainClient",
                        lambda url, timeout=20: _FakeCliClient("0x"))
    rc = main(["deployed", "0xabc", "--rpc", "fake://"])
    assert rc == 1
    assert "verified     False" in capsys.readouterr().out
