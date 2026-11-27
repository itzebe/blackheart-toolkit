"""Fork-run PnL harness: replay a call sequence on a live anvil fork and price the attacker.

The fork is spawned by the caller/test; this module talks to it over JSON-RPC and measures the
attacker's net ETH and token deltas across the sequence. The ETH delta already nets gas (the
balance is read after the transactions are mined), so it is the attacker's real net PnL.
"""

import json
import time
import urllib.request
from dataclasses import dataclass, field

from blackheart.deployed import keccak256


@dataclass
class ForkPnl:
    eth_delta: int = 0
    token_delta: int = 0
    steps: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"eth_delta": self.eth_delta, "token_delta": self.token_delta,
                "steps": list(self.steps)}


def _rpc(url: str, method: str, params: list) -> dict:
    payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    req = urllib.request.Request(
        url, data=payload,
        headers={"content-type": "application/json", "User-Agent": "blackheart-fork/1"},
    )
    return json.loads(urllib.request.urlopen(req, timeout=20).read())


def _eth_balance(url: str, addr: str, block: str = "latest") -> int:
    return int(_rpc(url, "eth_getBalance", [addr, block])["result"], 16)


def _token_balance(url: str, token: str, holder: str, block: str = "latest") -> int:
    data = "0x70a08231" + "0" * 24 + holder[2:].lower()  # balanceOf(address)
    res = _rpc(url, "eth_call", [{"to": token, "data": data}, block])
    return int(res.get("result", "0x0"), 16)


def _wait_receipt(url: str, txhash: str, tries: int = 100):
    for _ in range(tries):
        rec = _rpc(url, "eth_getTransactionReceipt", [txhash]).get("result")
        if rec:
            return rec
        time.sleep(0.1)
    return None


def _settle(fn, tries: int = 30):
    v = fn()
    for _ in range(tries):
        time.sleep(0.1)
        n = fn()
        if n == v:
            return v
        v = n
    return v


def run_fork_sequence(url: str, attacker: str, steps: list, *, token=None) -> ForkPnl:
    """Replay ``(to, data, value)`` steps from ``attacker`` and price its net ETH + token deltas."""
    eth0 = _eth_balance(url, attacker)
    tok0 = _token_balance(url, token, attacker) if token else 0
    hashes = []
    for to, data, value in steps:
        tx = {"from": attacker, "to": to, "data": data, "value": hex(value),
              "gas": hex(1_000_000)}
        hashes.append(_rpc(url, "eth_sendTransaction", [tx])["result"])
        _wait_receipt(url, hashes[-1])
    eth1 = _settle(lambda: _eth_balance(url, attacker))
    tok1 = _settle(lambda: _token_balance(url, token, attacker)) if token else 0
    return ForkPnl(eth_delta=eth1 - eth0, token_delta=tok1 - tok0, steps=hashes)


def screen_candidates(url, target, attacker, candidates, *, token=None):
    """Run each (data, value) candidate independently (snapshot/revert) and price the attacker."""
    results = []
    snap = _rpc(url, "evm_snapshot", [])["result"]
    for data, value in candidates:
        pnl = run_fork_sequence(url, attacker, [(target, data, value)], token=token)
        results.append({"data": data, "value": value,
                        "eth_delta": pnl.eth_delta, "token_delta": pnl.token_delta,
                        "extracts_eth": pnl.eth_delta > 0})
        _rpc(url, "evm_revert", [snap])
        snap = _rpc(url, "evm_snapshot", [])["result"]
    return results


def _is_static(t: str) -> bool:
    if t in ("address", "bool"):
        return True
    if t in ("string", "bytes") or t.endswith("[]") or t.startswith("tuple"):
        return False
    return t.startswith("uint") or t.startswith("int") or t.startswith("bytes")


_MAX_WORD = (1 << 256) - 1


def candidates_from_abi(abi, boundary=False):
    """Turn a verified ABI into candidate (calldata, value) calls with static args.

    With ``boundary=True`` each function also gets 0 / 1 / max value vectors per argument, so
    unchecked-arithmetic bugs (e.g. a withdraw with no balance check) are reachable; the default
    keeps zero-valued args. Dynamic inputs (bytes/string/arrays/tuples) are listed in ``skipped``.
    """
    out = []
    skipped = []
    for entry in abi:
        if entry.get("type") != "function":
            continue
        inputs = entry.get("inputs", [])
        types = [i.get("type", "") for i in inputs]
        sig = f"{entry['name']}({','.join(types)})"
        if any(not _is_static(t) for t in types):
            skipped.append(sig)
            continue
        sel = keccak256(sig.encode())[:4].hex()
        if boundary and types:
            vectors = ([0] * len(types), [1] * len(types), [_MAX_WORD] * len(types))
        else:
            vectors = ([0] * len(types),)
        for vals in vectors:
            out.append({"signature": sig,
                        "calldata": "0x" + sel
                        + "".join(format(v & _MAX_WORD, "064x") for v in vals)})
    return out, skipped


def _http_json(url: str) -> dict:
    req = urllib.request.Request(
        url, headers={"User-Agent": "blackheart-fork/1", "accept": "application/json"})
    return json.loads(urllib.request.urlopen(req, timeout=20).read())


def fetch_abi(chain_id: int, address: str):
    """Fetch a verified ABI from Sourcify (v2). Returns [] when unavailable -- never guessed."""
    url = f"https://sourcify.dev/server/v2/contract/{chain_id}/{address}?fields=abi"
    try:
        return _http_json(url).get("abi") or []
    except Exception:
        return []


def screen_target_fork(url, target, attacker, *, abi=None, chain_id=1, token=None):
    """ABI -> candidates -> independent fork screen. Fetches the verified ABI when ``abi`` is None."""
    if abi is None:
        abi = fetch_abi(chain_id, target)
    cands, _skipped = candidates_from_abi(abi)
    return screen_candidates(url, target, attacker, [(c["calldata"], 0) for c in cands], token=token)
