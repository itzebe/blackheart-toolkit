"""Deployed-contract intelligence: verify a contract on a real chain, honestly.

The mission's Phase Two requires that deployment facts be *discovered and
independently verified*, never assumed, and that a contract is never described as
verified without evidence. This module does exactly that for an EVM contract:

  * reads the runtime bytecode (``eth_getCode``) at a recorded block,
  * hashes it (so the exact deployed artifact is pinned),
  * detects common proxy patterns by reading their storage slots,
  * resolves the implementation address where a standard slot is populated,
  * records the block number, chain id and a retrieval timestamp.

It is **stdlib-only** (``urllib``) so it adds no dependency, and it is honest by
construction: if the RPC is unreachable, or the address holds no code, the result
says so -- it never fabricates a "verified" state. Nothing here sends a
transaction; every call is a read.
"""

from __future__ import annotations

import hashlib
import json
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Optional

from .models import utcnow

__all__ = [
    "PROXY_SLOTS",
    "RpcUnavailable",
    "ContractEvidence",
    "DeployedContract",
    "ChainClient",
    "verify_contract",
    "keccak256",
    "function_selector",
    "selector_present",
]

# Well-known proxy implementation storage slots. Reading these is how a proxy is
# detected *without* trusting a block explorer.
PROXY_SLOTS: dict[str, str] = {
    # EIP-1967 implementation slot (keccak256("eip1967.proxy.implementation") - 1)
    "eip1967": "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc",
    # EIP-1967 beacon slot (keccak256("eip1967.proxy.beacon") - 1)
    "eip1967_beacon": "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50",
    # EIP-1967 admin slot (keccak256("eip1967.proxy.admin") - 1)
    "eip1967_admin": "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103",
    # EIP-1822 UUPS proxiable slot (keccak256("PROXIABLE") - 1)
    "eip1822": "0xc5f16f0fcc639fa48a6947836d9850f504798523bf8c9a3a87d5876cf622bcf7",
    # OpenZeppelin legacy/unstructured slot used by some older proxies.
    "oz_legacy": "0x7050c9e0f4ca769c69bd3a8ef740bc37934f8e2c036e5a723fd8ee048ed3f8c3",
}

#: keccak256("eip1967.proxy.implementation") - 1, and the rest, are precomputed
#: above; a reader can re-derive them with any keccak implementation.


class RpcUnavailable(RuntimeError):
    """The RPC endpoint could not be reached (a recorded limitation, not a bug)."""


@dataclass
class ContractEvidence:
    """One raw observation from the chain, with everything needed to re-check it."""

    method: str
    params: list[Any]
    result: Any
    block_number: int
    source_url: str
    retrieved_at: str = field(default_factory=utcnow)

    def to_dict(self) -> dict:
        return {
            "method": self.method,
            "params": self.params,
            "result": self.result,
            "block_number": self.block_number,
            "source_url": self.source_url,
            "retrieved_at": self.retrieved_at,
        }


@dataclass
class DeployedContract:
    """The verified deployment facts for one address on one chain.

    ``verified`` is True only when real code was read back. A contract with no
    code, or an unreachable RPC, is reported honestly rather than as a success.
    """

    address: str
    chain_id: Optional[int] = None
    block_number: Optional[int] = None
    code: str = ""
    code_sha256: str = ""
    code_size: int = 0
    is_contract: bool = False
    proxy: bool = False
    proxy_kind: str = ""
    implementation: str = ""
    admin: str = ""
    beacon: str = ""
    eip7702_delegate: str = ""
    verified: bool = False
    rpc_url: str = ""
    evidence: list[ContractEvidence] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "address": self.address,
            "chain_id": self.chain_id,
            "block_number": self.block_number,
            "code_sha256": self.code_sha256,
            "code_size": self.code_size,
            "is_contract": self.is_contract,
            "proxy": self.proxy,
            "proxy_kind": self.proxy_kind,
            "implementation": self.implementation,
            "admin": self.admin,
            "beacon": self.beacon,
            "eip7702_delegate": self.eip7702_delegate,
            "verified": self.verified,
            "rpc_url": self.rpc_url,
            "limitations": list(self.limitations),
            "evidence": [e.to_dict() for e in self.evidence],
        }


def _strip0x(value: str) -> str:
    if not isinstance(value, str):
        return ""
    return value[2:] if value.startswith("0x") else value


def _address_from_word(word: str) -> str:
    """A 32-byte storage word holds an address in its low 20 bytes."""
    word = _strip0x(word or "")
    if len(word) < 40:
        return ""
    try:
        value = int(word[-40:], 16)
    except ValueError:
        return ""
    return "" if value == 0 else "0x" + word[-40:]


def _parse_hex_int(value: Any, what: str) -> int:
    """Parse a JSON-RPC quantity, failing as a *recorded limitation* if malformed.

    The response is untrusted input: a broken or hostile endpoint must be reported,
    never crash the caller. Accepts a ``0x``-prefixed hex string (the spec) or a bare
    integer; anything else raises :class:`RpcUnavailable`.
    """
    if isinstance(value, bool):  # bool is an int subclass -- reject it explicitly
        raise RpcUnavailable(f"{what} returned a boolean, not a quantity: {value!r}")
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(_strip0x(value), 16)
        except ValueError:
            raise RpcUnavailable(f"{what} returned a malformed hex quantity: {value!r}") from None
    raise RpcUnavailable(f"{what} returned a non-quantity: {value!r}")


#: EIP-7702 delegation designator prefix: 0xef0100 followed by a 20-byte address.
_EIP7702_PREFIX = "ef0100"


def _is_eip7702_designator(code: str) -> bool:
    """True for a 23-byte ``0xef0100 || address`` EIP-7702 delegation designator."""
    raw = _strip0x(code or "").lower()
    return len(raw) == 46 and raw.startswith(_EIP7702_PREFIX)


# --------------------------------------------------------------------------- #
# Keccak-256 (pure Python, no dependency)
# --------------------------------------------------------------------------- #
#
# EVM function selectors are the first 4 bytes of keccak256(signature). No keccak
# library is available in a stdlib-only environment, so this is a correct, if
# unoptimised, Keccak-f[1600] implementation. It is verified against known vectors
# in the test suite (``keccak256(b"")`` == the empty-string digest, and the ERC-20
# ``transfer(address,uint256)`` selector == 0xa9059cbb).

_KECCAK_ROUND_CONSTANTS = (
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
)
_KECCAK_ROTATION = (
    (0, 36, 3, 41, 18),
    (1, 44, 10, 45, 2),
    (62, 6, 43, 15, 61),
    (28, 55, 25, 21, 56),
    (27, 20, 39, 8, 14),
)
_MASK64 = (1 << 64) - 1


def _rotl64(x: int, n: int) -> int:
    n %= 64
    return ((x << n) | (x >> (64 - n))) & _MASK64 if n else x


def _keccak_f1600(state: list[int]) -> None:
    for rnd in range(24):
        # Theta
        c = [state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20]
             for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rotl64(c[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(5):
                state[x + 5 * y] ^= d[x]
        # Rho and Pi
        b = [0] * 25
        for x in range(5):
            for y in range(5):
                b[y + 5 * ((2 * x + 3 * y) % 5)] = _rotl64(state[x + 5 * y],
                                                            _KECCAK_ROTATION[x][y])
        # Chi
        for x in range(5):
            for y in range(5):
                state[x + 5 * y] = b[x + 5 * y] ^ (
                    (~b[(x + 1) % 5 + 5 * y] & _MASK64) & b[(x + 2) % 5 + 5 * y])
        # Iota
        state[0] ^= _KECCAK_ROUND_CONSTANTS[rnd]


def keccak256(data: bytes) -> bytes:
    """Keccak-256 (the Ethereum variant; padding 0x01, not SHA3's 0x06)."""
    rate = 136  # 1088 bits
    # pad10*1 with the Keccak domain byte 0x01
    padded = bytearray(data)
    padded.append(0x01)
    while len(padded) % rate != rate - 1:
        padded.append(0x00)
    padded.append(0x80)

    state = [0] * 25
    for offset in range(0, len(padded), rate):
        block = padded[offset:offset + rate]
        for i in range(rate // 8):
            state[i] ^= int.from_bytes(block[i * 8:i * 8 + 8], "little")
        _keccak_f1600(state)
    return b"".join(state[i].to_bytes(8, "little") for i in range(4))[:32]


def function_selector(signature: str) -> str:
    """The 4-byte EVM function selector for a canonical signature, as hex."""
    return keccak256(signature.encode("utf-8")).hex()[:8]


def selector_present(code: str, selector: str) -> bool:
    """True if a function selector appears *anywhere* in the runtime bytecode.

    This is a raw substring scan, and it is deliberately kept that way: it answers
    a fingerprint question, and changing it would silently change the meaning of
    every caller. It is **not** evidence that a function is callable. A 4-byte
    value occurs in bytecode as a PUSH4 constant, inside an error string, or in an
    ABI table, with no dispatcher anywhere near it.

    For "can an external caller reach this function?", use
    :func:`blackheart.deployed_selectors.analyse_selectors`, which reports a
    selector as reachable only when a ``PUSH4`` operand feeds an ``EQ`` whose
    result guards a ``JUMPI``. Reporting a data-only selector as callable is a
    false lead, and a false lead costs an investigation its budget.
    """
    sel = selector[2:] if selector.startswith("0x") else selector
    return sel.lower() in _strip0x(code or "").lower()


class ChainClient:
    """A minimal, stdlib-only JSON-RPC client with honest error reporting."""

    def __init__(self, url: str, timeout: int = 20) -> None:
        self.url = url
        self.timeout = timeout
        self._id = 0

    def call(self, method: str, params: list[Any]) -> Any:
        self._id += 1
        payload = json.dumps({
            "jsonrpc": "2.0", "id": self._id, "method": method, "params": params,
        }).encode("utf-8")
        req = urllib.request.Request(
            self.url, data=payload,
            headers={"content-type": "application/json", "user-agent": "blackheart/1"},
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                body = json.loads(resp.read().decode("utf-8"))
        except (urllib.error.URLError, OSError, ValueError) as exc:
            raise RpcUnavailable(f"{self.url}: {exc}") from exc
        if not isinstance(body, dict):
            raise RpcUnavailable(f"{self.url}: RPC returned a non-object body: {body!r}")
        # ``error`` is present-and-null on a legal success response, so test for a
        # *non-null* error rather than the key's mere presence.
        if body.get("error") is not None:
            raise RpcUnavailable(f"{self.url}: RPC error {body['error']}")
        return body.get("result")

    def batch_call(self, calls: list[tuple[str, list[Any]]]) -> list[Any]:
        """Run independent JSON-RPC calls in one HTTP request, preserving order.

        A batch is an optimization, not a different trust boundary: any missing
        or errored response fails the whole batch, so a caller can never read a
        partial snapshot as complete.
        """
        if not calls:
            return []
        start = self._id + 1
        self._id += len(calls)
        payload = json.dumps([
            {"jsonrpc": "2.0", "id": start + index,
             "method": method, "params": params}
            for index, (method, params) in enumerate(calls)
        ]).encode("utf-8")
        req = urllib.request.Request(
            self.url, data=payload,
            headers={"content-type": "application/json", "user-agent": "blackheart/1"},
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                body = json.loads(resp.read().decode("utf-8"))
        except (urllib.error.URLError, OSError, ValueError) as exc:
            raise RpcUnavailable(f"{self.url}: {exc}") from exc
        if not isinstance(body, list):
            raise RpcUnavailable(f"{self.url}: batch RPC returned {body!r}")
        by_id = {item.get("id"): item for item in body if isinstance(item, dict)}
        results: list[Any] = []
        for index in range(len(calls)):
            item = by_id.get(start + index)
            if item is None:
                raise RpcUnavailable(f"{self.url}: batch response missing id {start + index}")
            if item.get("error") is not None:
                raise RpcUnavailable(f"{self.url}: RPC error {item['error']}")
            results.append(item.get("result"))
        return results


def verify_contract(
    address: str,
    rpc_url: str,
    *,
    at_block: Optional[int] = None,
    detect_proxy: bool = True,
    client: Optional[ChainClient] = None,
) -> DeployedContract:
    """Read and verify the deployment facts for ``address`` on ``rpc_url``.

    Reads only: chain id, block number, ``eth_getCode`` and (optionally) the
    standard proxy slots. Never sends a transaction. On an unreachable RPC the
    result records the limitation and leaves ``verified`` False.
    """
    client = client or ChainClient(rpc_url)
    out = DeployedContract(address=address, rpc_url=rpc_url)
    block_tag = hex(at_block) if at_block is not None else "latest"

    try:
        chain_id = client.call("eth_chainId", [])
        out.chain_id = _parse_hex_int(chain_id, "eth_chainId")
        block_hex = client.call("eth_blockNumber", [])
        out.block_number = _parse_hex_int(block_hex, "eth_blockNumber")
        code = client.call("eth_getCode", [address, block_tag])
    except RpcUnavailable as exc:
        out.limitations.append(f"RPC unavailable: {exc}")
        return out

    if not isinstance(code, str):
        out.limitations.append(f"eth_getCode returned a non-string body: {code!r}")
        return out

    out.evidence.append(ContractEvidence("eth_getCode", [address, block_tag], code,
                                         out.block_number, rpc_url))
    code = code or "0x"
    out.code = code
    out.code_size = max(0, (len(_strip0x(code))) // 2)
    out.code_sha256 = hashlib.sha256(code.encode("utf-8")).hexdigest()

    # EIP-7702: an account may carry a 23-byte delegation designator
    # (0xef0100 || 20-byte address) instead of real runtime code. This is an EOA
    # that delegates execution -- it is NOT a deployed contract, and calling it
    # one would be wrong. Detected explicitly so the distinction is honest.
    if _is_eip7702_designator(code):
        out.eip7702_delegate = "0x" + _strip0x(code)[6:46]
        out.is_contract = False
        out.verified = False
        out.limitations.append(
            "account carries an EIP-7702 delegation designator, not deployed "
            f"runtime code; it delegates to {out.eip7702_delegate}"
        )
        return out

    out.is_contract = out.code_size > 0
    out.verified = out.is_contract
    if not out.is_contract:
        out.limitations.append("address holds no runtime code at the recorded block "
                               "(not a contract, or not yet deployed)")
        return out

    if detect_proxy:
        for kind, slot in PROXY_SLOTS.items():
            try:
                word = client.call("eth_getStorageAt", [address, slot, block_tag])
            except RpcUnavailable as exc:
                out.limitations.append(f"proxy slot {kind} unread: {exc}")
                continue
            out.evidence.append(ContractEvidence("eth_getStorageAt", [address, slot, block_tag],
                                                 word, out.block_number, rpc_url))
            addr = _address_from_word(word or "")
            if not addr:
                continue
            if kind in ("eip1967", "eip1822", "oz_legacy"):
                out.proxy = True
                out.proxy_kind = kind
                out.implementation = addr
            elif kind == "eip1967_beacon":
                out.proxy = True
                out.proxy_kind = out.proxy_kind or "eip1967_beacon"
                out.beacon = addr
            elif kind == "eip1967_admin":
                out.admin = addr
    return out
