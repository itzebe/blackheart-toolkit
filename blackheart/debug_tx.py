"""Transaction replay and explanation, read-only.

Fetches a transaction and its receipt over JSON-RPC, asks the node for a
``callTracer`` trace, decodes calldata against a supplied ABI (selector via the
pure-Python keccak in :mod:`blackheart.deployed`), and renders a call tree with
gas, value and revert reasons.

It never sends a transaction and never signs anything. ``debug_traceTransaction``
is not enabled on every node; when it is unavailable the result says
``TRACE_UNAVAILABLE`` and still returns the receipt and decoded input. A trace is
a description of what happened, not a finding.
"""

from __future__ import annotations

import json
import urllib.request
from pathlib import Path
from typing import Any, Callable, Optional

DISCLAIMER = (
    "Read-only replay. A trace describes what one transaction did; it is not a "
    "finding, and a reverted call is not evidence of a vulnerability."
)


class RpcError(RuntimeError):
    """A JSON-RPC transport or node error, surfaced rather than swallowed."""


class HttpClient:
    """A minimal JSON-RPC client. ``transport`` is injectable for offline tests."""

    def __init__(self, url: str, *, timeout: int = 20,
                 transport: Optional[Callable[[str, list], Any]] = None) -> None:
        self.url = url
        self.timeout = timeout
        self._transport = transport

    def call(self, method: str, params: list) -> Any:
        if self._transport is not None:
            return self._transport(method, params)
        payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method,
                              "params": params}).encode("utf-8")
        request = urllib.request.Request(
            self.url, data=payload, headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                body = json.loads(response.read().decode("utf-8", "replace"))
        except Exception as exc:  # noqa: BLE001 - a transport failure is reported
            raise RpcError(f"{method} failed: {type(exc).__name__}: {exc}") from exc
        if isinstance(body, dict) and body.get("error"):
            raise RpcError(f"{method}: {body['error']}")
        return body.get("result") if isinstance(body, dict) else None


def fetch(client: HttpClient, tx_hash: str) -> dict[str, Any]:
    """Fetch tx, receipt and a callTracer trace. Each failure is recorded, never raised."""
    out: dict[str, Any] = {"tx": None, "receipt": None, "trace": None,
                           "trace_error": "", "error": ""}
    try:
        out["tx"] = client.call("eth_getTransactionByHash", [tx_hash])
    except RpcError as exc:
        out["error"] = str(exc)
        return out
    try:
        out["receipt"] = client.call("eth_getTransactionReceipt", [tx_hash])
    except RpcError as exc:
        out["trace_error"] = f"receipt: {exc}"
    try:
        out["trace"] = client.call(
            "debug_traceTransaction", [tx_hash, {"tracer": "callTracer"}])
    except RpcError as exc:
        out["trace_error"] = f"trace: {exc}"
    return out


def _to_int(value: Any) -> int:
    if isinstance(value, int):
        return value
    try:
        return int(str(value), 16)
    except (TypeError, ValueError):
        return 0


def render_call_tree(trace: Any, depth: int = 0) -> list[str]:
    """Render a callTracer result as an indented ASCII tree."""
    if not isinstance(trace, dict):
        return []
    lines: list[str] = []
    kind = str(trace.get("type", "CALL"))
    src = trace.get("from", "")
    dst = trace.get("to", "")
    line = f"{'  ' * depth}{kind} {src} -> {dst}"
    value = _to_int(trace.get("value"))
    if value:
        line += f" value={value}"
    gas = _to_int(trace.get("gas"))
    used = _to_int(trace.get("gasUsed"))
    if gas or used:
        line += f" gas={used}/{gas}"
    error = trace.get("error") or trace.get("revertReason") or ""
    if error:
        line += f" !! {error}"
    lines.append(line)
    for child in trace.get("calls", []) or []:
        lines.extend(render_call_tree(child, depth + 1))
    return lines


def decode_calldata(data: str, functions: list[Any]) -> dict[str, Any]:
    """Best-effort decode of static arguments against a supplied ABI."""
    if not data or not data.startswith("0x") or len(data) < 10:
        return {"matched": False, "selector": "", "note": "no calldata"}
    selector = data[2:10].lower()
    body = data[10:]
    from .deployed import function_selector

    for function in functions:
        try:
            candidate = function_selector(function.signature()).lower()
        except Exception:  # noqa: BLE001 - an undescribable signature is skipped
            continue
        if candidate != selector:
            continue
        args: list[Any] = []
        for index, spec in enumerate(function.inputs):
            word = body[index * 64:(index + 1) * 64]
            if len(word) < 64:
                break
            kind = str(spec.get("type", ""))
            if kind == "address":
                args.append("0x" + word[-40:])
            elif kind == "bool":
                args.append(bool(int(word, 16)))
            elif kind.startswith("uint") or kind.startswith("int"):
                args.append(int(word, 16))
            else:
                args.append({"type": kind, "raw": word})
        return {"matched": True, "function": function.name,
                "signature": function.signature(), "args": args, "raw": data}
    return {"matched": False, "selector": "0x" + selector, "raw": data}


def build_debug(tx_hash: str, *, rpc: Optional[str] = None,
                abi_path: Optional[str] = None, chain: str = "mainnet",
                timeout: int = 20, client: Optional[HttpClient] = None) -> dict[str, Any]:
    """Resolve an RPC, replay one transaction and render it. Never sends a transaction."""
    from .rpc import resolve_rpc

    if client is None:
        resolved = resolve_rpc(chain, explicit=rpc, timeout=timeout)
        if not resolved.ok:
            return {"status": "RPC_UNAVAILABLE", "tx_hash": tx_hash,
                    "error": resolved.error, "tried": resolved.tried,
                    "discipline": DISCLAIMER}
        client = HttpClient(resolved.url, timeout=timeout)
        rpc_url = resolved.url
    else:
        rpc_url = getattr(client, "url", "")

    data = fetch(client, tx_hash)
    if not data.get("tx"):
        return {"status": "NOT_FOUND", "tx_hash": tx_hash, "rpc": rpc_url,
                "error": data.get("error", "transaction not found"),
                "discipline": DISCLAIMER}

    functions: list[Any] = []
    if abi_path:
        raw = json.loads(Path(abi_path).expanduser().read_text(encoding="utf-8"))
        if isinstance(raw, dict):
            raw = raw.get("abi", [])
        from .solidity.abi import parse_abi
        functions = parse_abi(raw)

    decoded = decode_calldata((data.get("tx") or {}).get("input", ""), functions)
    tree = render_call_tree(data.get("trace")) if data.get("trace") else []
    status = "OK" if data.get("trace") else "TRACE_UNAVAILABLE"
    return {
        "status": status,
        "tx_hash": tx_hash,
        "rpc": rpc_url,
        "tx": data.get("tx"),
        "receipt": data.get("receipt"),
        "decoded_input": decoded,
        "call_tree": tree,
        "trace_error": data.get("trace_error", ""),
        "discipline": DISCLAIMER,
    }


def render_markdown(payload: dict[str, Any]) -> str:
    status = payload.get("status", "")
    lines = ["# Transaction replay", ""]
    lines.append(f"- status: **{status}**")
    lines.append(f"- tx: `{payload.get('tx_hash', '')}`")
    if payload.get("rpc"):
        lines.append(f"- rpc: `{payload['rpc']}`")
    if payload.get("error"):
        lines.append(f"- error: {payload['error']}")
    tx = payload.get("tx") or {}
    if tx:
        lines.append(f"- from: `{tx.get('from', '')}` -> `{tx.get('to', '')}`")
        lines.append(f"- value: {_to_int(tx.get('value'))} wei")
        lines.append(f"- input: `{str(tx.get('input', ''))[:74]}`")
    receipt = payload.get("receipt") or {}
    if receipt:
        lines.append(f"- block: {_to_int(receipt.get('blockNumber'))} | "
                     f"gasUsed: {_to_int(receipt.get('gasUsed'))} | "
                     f"success: {_to_int(receipt.get('status')) == 1}")
    decoded = payload.get("decoded_input") or {}
    if decoded.get("matched"):
        lines.append(f"- call: `{decoded.get('signature', '')}` args={decoded.get('args')}")
    elif decoded.get("selector"):
        lines.append(f"- call: selector `{decoded['selector']}` (no matching ABI)")
    lines.append("")
    tree = payload.get("call_tree") or []
    if tree:
        lines.append("## Call tree")
        lines.append("")
        lines.append("```")
        lines.extend(tree)
        lines.append("```")
    elif payload.get("trace_error"):
        lines.append(f"> Trace unavailable: {payload['trace_error']}")
        lines.append("> The receipt and decoded input are still shown; enable "
                     "debug_traceTransaction on the node for the call tree.")
    lines.append("")
    lines.append(f"> {DISCLAIMER}")
    lines.append("")
    return "\n".join(lines)
