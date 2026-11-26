"""Acceptance bar for ``blackheart debug tx`` (offline; transport injected)."""

from __future__ import annotations

import json
from pathlib import Path

from blackheart.debug_tx import (
    HttpClient, RpcError, build_debug, decode_calldata, render_call_tree,
)
from blackheart.solidity.abi import parse_abi

ABI = [{
    "type": "function", "name": "transfer",
    "inputs": [{"type": "address", "name": "to"}, {"type": "uint256", "name": "amount"}],
    "outputs": [{"type": "bool", "name": ""}], "stateMutability": "nonpayable",
}]


def _calldata() -> str:
    return "0xa9059cbb" + "0" * 24 + "0000000000000000000000000000000000000001" + format(1000, "064x")


TX = {"hash": "0xabc",
      "from": "0x1111111111111111111111111111111111111111",
      "to": "0x2222222222222222222222222222222222222222",
      "value": "0x0", "input": _calldata(), "blockNumber": "0x10"}
RECEIPT = {"blockNumber": "0x10", "gasUsed": "0x5000", "status": "0x1"}
TRACE = {"type": "CALL", "from": TX["from"], "to": TX["to"], "value": "0x0",
         "gas": "0x5208", "gasUsed": "0x5000",
         "calls": [{"type": "STATICCALL", "from": TX["to"],
                    "to": "0x3333333333333333333333333333333333333333",
                    "gas": "0x1000", "gasUsed": "0x800",
                    "error": "execution reverted", "revertReason": "nope"}]}


def _client(trace_ok: bool = True, tx=TX) -> HttpClient:
    def transport(method: str, params: list):
        if method == "eth_getTransactionByHash":
            return tx
        if method == "eth_getTransactionReceipt":
            return RECEIPT
        if method == "debug_traceTransaction":
            if not trace_ok:
                raise RpcError("trace disabled")
            return TRACE
        raise RpcError(f"unexpected {method}")
    return HttpClient("http://fake", transport=transport)


def test_decode_transfer_calldata() -> None:
    decoded = decode_calldata(_calldata(), parse_abi(ABI))
    assert decoded["matched"] is True
    assert decoded["function"] == "transfer"
    assert decoded["args"][1] == 1000
    assert decoded["args"][0].endswith("0001")


def test_build_debug_renders_call_tree(tmp_path: Path) -> None:
    abi = tmp_path / "abi.json"
    abi.write_text(json.dumps(ABI), encoding="utf-8")
    payload = build_debug("0xabc", client=_client(), abi_path=str(abi))
    assert payload["status"] == "OK"
    assert payload["decoded_input"]["matched"] is True
    tree = "\n".join(payload["call_tree"])
    assert "CALL" in tree and "STATICCALL" in tree and "execution reverted" in tree
    assert payload["receipt"]["status"] == "0x1"


def test_trace_unavailable_is_reported_not_hidden() -> None:
    payload = build_debug("0xabc", client=_client(trace_ok=False))
    assert payload["status"] == "TRACE_UNAVAILABLE"
    assert payload["call_tree"] == []
    assert payload["trace_error"]
    assert payload["receipt"]["status"] == "0x1"


def test_missing_transaction_is_not_found() -> None:
    payload = build_debug("0xabc", client=_client(tx=None))
    assert payload["status"] == "NOT_FOUND"


def test_render_tree_is_nested_and_marks_reverts() -> None:
    lines = render_call_tree(TRACE)
    assert lines[0].startswith("CALL")
    assert lines[1].startswith("  STATICCALL")
    assert "!!" in lines[1]
