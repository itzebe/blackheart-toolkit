"""Live, read-only market data for the economic models.

The market module is deterministic: it prices reserves the caller supplies. This
module fetches those reserves from a real chain with ``eth_call`` and labels the
result honestly:

* ``LIVE`` -- at least one pair answered and a quote was computed;
* ``UNAVAILABLE`` -- no RPC or no pair answered; no number is invented;
* ``INCOMPLETE`` -- a pair answered with a malformed reserve payload.

Only the standard Uniswap-V2 ``getReserves()`` shape is decoded. A V3 pool has a
different interface and is reported as unsupported rather than guessed. The
fetch is read-only: no transaction is signed or sent.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from ..deployed import ChainClient, RpcUnavailable
from .market import ConstantProductPool, SandwichResult, simulate_sandwich

GET_RESERVES = "0x0902f1ac"  # getReserves()


@dataclass
class LivePool:
    address: str
    reserve0: int
    reserve1: int
    fee_bps: int = 30
    label: str = ""
    block: Optional[int] = None

    def pool(self, *, zero_for_one: bool = True) -> ConstantProductPool:
        if zero_for_one:
            return ConstantProductPool(self.reserve0, self.reserve1, self.fee_bps)
        return ConstantProductPool(self.reserve1, self.reserve0, self.fee_bps)

    def to_dict(self) -> dict:
        return {"address": self.address, "reserve0": self.reserve0,
                "reserve1": self.reserve1, "fee_bps": self.fee_bps,
                "label": self.label, "block": self.block}


@dataclass
class LiveQuote:
    venue: str
    address: str
    amount_out: int
    zero_for_one: bool

    def to_dict(self) -> dict:
        return {"venue": self.venue, "address": self.address,
                "amount_out": self.amount_out, "zero_for_one": self.zero_for_one}


@dataclass
class LiveMarketReport:
    status: str  # LIVE | UNAVAILABLE | INCOMPLETE
    pools: list[LivePool] = field(default_factory=list)
    quotes: list[LiveQuote] = field(default_factory=list)
    reason: str = ""
    errors: list[str] = field(default_factory=list)

    @property
    def best(self) -> Optional[LiveQuote]:
        return max(self.quotes, key=lambda q: q.amount_out) if self.quotes else None

    def to_dict(self) -> dict:
        best = self.best
        return {"status": self.status,
                "pools": [p.to_dict() for p in self.pools],
                "quotes": [q.to_dict() for q in self.quotes],
                "best": best.to_dict() if best else None,
                "reason": self.reason, "errors": list(self.errors)}


def _decode_uint(hex_text: str, index: int) -> int:
    raw = bytes.fromhex(hex_text.removeprefix("0x"))
    if len(raw) < (index + 1) * 32:
        raise ValueError(f"reserve payload is {len(raw)} bytes, expected 96")
    return int.from_bytes(raw[index * 32:(index + 1) * 32], "big")


def decode_reserves(result: Any) -> tuple[int, int]:
    """Decode a Uniswap-V2 ``getReserves()`` return payload."""
    if not isinstance(result, str) or not result.startswith("0x"):
        raise ValueError(f"eth_call returned {result!r}")
    return _decode_uint(result, 0), _decode_uint(result, 1)


def fetch_v2_pool(client: Any, address: str, *, fee_bps: int = 30,
                  label: str = "", block: Optional[int] = None) -> LivePool:
    """Read one V2 pair's reserves. Raises ``ValueError`` on a malformed reply."""
    tag = hex(block) if block is not None else "latest"
    result = client.call("eth_call", [{"to": address, "data": GET_RESERVES}, tag])
    reserve0, reserve1 = decode_reserves(result)
    return LivePool(address, reserve0, reserve1, fee_bps, label or address, block)


def fetch_live_market(
    rpc_url: str,
    pairs: list[tuple[str, int, str]],
    *,
    amount_in: int,
    block: Optional[int] = None,
    client: Any = None,
    timeout: int = 20,
) -> LiveMarketReport:
    """Fetch reserves for ``(address, fee_bps, label)`` pairs and quote one trade."""
    if not rpc_url and client is None:
        return LiveMarketReport("UNAVAILABLE", reason="no RPC endpoint was supplied")
    if not pairs:
        return LiveMarketReport("UNAVAILABLE", reason="no pair was supplied")
    client = client or ChainClient(rpc_url, timeout=timeout)
    pools: list[LivePool] = []
    errors: list[str] = []
    malformed = False
    for address, fee_bps, label in pairs:
        try:
            pools.append(fetch_v2_pool(client, address, fee_bps=fee_bps,
                                       label=label, block=block))
        except (RpcUnavailable, ValueError, TypeError, OSError) as exc:
            errors.append(f"{address}: {exc}")
            malformed = malformed or isinstance(exc, ValueError)
    if not pools:
        status = "INCOMPLETE" if malformed else "UNAVAILABLE"
        return LiveMarketReport(status, reason="no pair returned usable reserves",
                                errors=errors)
    quotes = [LiveQuote(p.label, p.address, p.pool().amount_out(amount_in), True)
              for p in pools]
    return LiveMarketReport("LIVE", pools, quotes,
                            reason=f"{len(pools)} live pair(s) answered", errors=errors)


def live_sandwich(pool: LivePool, *, victim_amount_in: int,
                  attacker_amount_in: int, zero_for_one: bool = True) -> SandwichResult:
    """Run the deterministic sandwich model against one live reserve snapshot."""
    return simulate_sandwich(pool.pool(zero_for_one=zero_for_one),
                             victim_amount_in=victim_amount_in,
                             attacker_amount_in=attacker_amount_in)
