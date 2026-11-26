"""Live, read-only Uniswap-V3 pool truth.

The deterministic V3 model needs initialized ranges, not just one active
liquidity number. This module reads ``slot0``, ``liquidity``, ``tickSpacing``,
``fee`` and the tick bitmap over ``eth_call``, then reconstructs the initialized
tick ranges and their active liquidity.

It is deliberately conservative:

* only ticks found in the scanned bitmap window are used;
* the window is bounded and the result is marked ``INCOMPLETE`` when the boundary
  word still has initialized bits, so a truncated scan is never called complete;
* no range is invented for a gap or for an uninitialized tick;
* the fetch is read-only. No transaction is signed or sent.

A live snapshot is still not a live opportunity: :mod:`blackheart.value.live_v3`
prices the swap, while :mod:`blackheart.value.live_v3_fork` executes the same
candidate on a pinned anvil/forge fork. Gas and inclusion are operator-supplied
inputs, never invented; queue position and competing searchers remain outside.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from decimal import Decimal, ROUND_DOWN, ROUND_HALF_UP, localcontext
from functools import lru_cache
from typing import Any, Optional

from ..deployed import ChainClient, RpcUnavailable
from .market import (
    Q96, V3MultiPool, V3MultiSandwichResult, V3Range,
    simulate_v3_multi_sandwich,
)

MIN_TICK = -887272
MAX_TICK = 887272
MIN_SQRT_RATIO = 4295128739
MAX_SQRT_RATIO = 1461446703485210103287273052203988822378723970342

SLOT0 = "0x3850c7bd"
LIQUIDITY = "0x1a686502"
TICK_SPACING = "0xd0c93a7c"
FEE = "0xddca3f43"
TOKEN0 = "0x0dfe1681"
TOKEN1 = "0xd21220a7"
DECIMALS = "0x313ce567"
TICK_BITMAP = "0x5339c296"
TICKS = "0xf30dba93"
BPS = 10_000
#: WETH9 deployments where ``balanceOf`` is storage slot 3, so a fork test can
#: fund the input token without a chain-specific holder or a state override.
WETH_ADDRESSES = {
    "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2",  # Ethereum
    "0x82af49447d8a07e3bd95bd0d56f35241523fbab1",  # Arbitrum
    "0x4200000000000000000000000000000000000006",  # Optimism / Base
    "0x7ceb23fd6bc0add59e62ac25578270cff1b9f619",  # Polygon
}


def _word(value: int) -> str:
    return f"{value & ((1 << 256) - 1):064x}"


def _tag(block: Optional[int]) -> str:
    return hex(block) if block is not None else "latest"


def _call(client: Any, address: str, selector: str, arg: Optional[int] = None,
          block: Optional[int] = None) -> str:
    data = selector + (_word(arg) if arg is not None else "")
    result = client.call("eth_call", [{"to": address, "data": data}, _tag(block)])
    if not isinstance(result, str) or not result.startswith("0x"):
        raise ValueError(f"eth_call returned {result!r}")
    return result


def _call_many(client: Any, address: str, selector: str, args: list[int],
               block: Optional[int]) -> list[str]:
    """Call one selector for many arguments, batching when the client supports it."""
    if not args:
        return []
    if hasattr(client, "batch_call"):
        def run(chunk: list[int]) -> list[str]:
            calls = [("eth_call", [{"to": address, "data": selector + _word(arg)},
                                   _tag(block)]) for arg in chunk]
            try:
                results = client.batch_call(calls)
                if len(results) != len(chunk):
                    raise RpcUnavailable("batch returned the wrong result count")
                return results
            except RpcUnavailable:
                # Some free endpoints cap a batch at three calls. Retry small
                # before giving up on batching entirely.
                out: list[str] = []
                for start in range(0, len(chunk), 3):
                    small = chunk[start:start + 3]
                    small_calls = [
                        ("eth_call", [{"to": address,
                                       "data": selector + _word(arg)}, _tag(block)])
                        for arg in small]
                    try:
                        small_results = client.batch_call(small_calls)
                        if len(small_results) != len(small):
                            raise RpcUnavailable(
                                "batch returned the wrong result count")
                        out.extend(small_results)
                    except RpcUnavailable:
                        out.extend(_call(client, address, selector, arg, block)
                                   for arg in small)
                return out

        out: list[str] = []
        for start in range(0, len(args), 50):
            out.extend(run(args[start:start + 50]))
        return out
    return [_call(client, address, selector, arg, block) for arg in args]


def _words(result: str, count: int) -> list[int]:
    raw = bytes.fromhex(result.removeprefix("0x"))
    if len(raw) < count * 32:
        raise ValueError(f"return payload is {len(raw)} bytes, expected at least {count * 32}")
    return [int.from_bytes(raw[i * 32:(i + 1) * 32], "big") for i in range(count)]


def _signed(value: int, bits: int) -> int:
    value &= (1 << bits) - 1
    return value - (1 << bits) if value & (1 << (bits - 1)) else value


def _address(word: int) -> str:
    return "0x" + f"{word & ((1 << 160) - 1):040x}"


@lru_cache(maxsize=8192)
def sqrt_ratio_at_tick(tick: int) -> int:
    """``sqrt(1.0001 ** tick) * 2**96`` rounded to the nearest integer.

    Decimal is used because a float loses too many low bits of the Q96 price at
    the edge of the tick range. The exact Uniswap constants are used for the
    global bounds in :class:`LiveV3Pool`, so rounding here never widens them.
    """
    if not MIN_TICK <= tick <= MAX_TICK:
        raise ValueError(f"tick {tick} is outside [{MIN_TICK}, {MAX_TICK}]")
    with localcontext() as ctx:
        ctx.prec = 120
        ratio = (Decimal(10001) / Decimal(10000)) ** tick
        return int((ratio.sqrt() * Decimal(Q96)).to_integral_value(
            rounding=ROUND_HALF_UP))


@dataclass(frozen=True)
class V3Tick:
    tick: int
    liquidity_gross: int
    liquidity_net: int

    def to_dict(self) -> dict:
        return {"tick": self.tick,
                "liquidity_gross": self.liquidity_gross,
                "liquidity_net": self.liquidity_net,
                "sqrt_price_x96": sqrt_ratio_at_tick(self.tick)}


@dataclass
class LiveV3Pool:
    address: str
    sqrt_price_x96: int
    tick: int
    active_liquidity: int
    tick_spacing: int
    fee_pips: int
    token0: str = ""
    token1: str = ""
    decimals0: int = 18
    decimals1: int = 18
    ticks: tuple[V3Tick, ...] = ()
    block: Optional[int] = None
    label: str = ""
    max_words: int = 16
    truncated: bool = False
    status: str = "LIVE"
    reason: str = ""
    errors: list[str] = field(default_factory=list)

    def _liquidity_between(self, lower: int, upper: int) -> int:
        """Active liquidity in ``[lower, upper]`` from the current tick.

        ``liquidity()`` is the active liquidity at ``slot0.tick``. Crossing an
        initialized tick upward adds ``liquidityNet``; crossing it downward
        subtracts it. A range above the current tick therefore adds every net at
        ``(current, lower]``; a range below subtracts every net at
        ``[upper, current]``.
        """
        if lower >= self.tick:
            return self.active_liquidity + sum(
                item.liquidity_net for item in self.ticks
                if self.tick < item.tick <= lower)
        if upper <= self.tick:
            return self.active_liquidity - sum(
                item.liquidity_net for item in self.ticks
                if upper <= item.tick <= self.tick)
        return self.active_liquidity

    def ranges(self) -> tuple[V3Range, ...]:
        """The initialized ranges with positive reconstructed liquidity."""
        if not self.ticks:
            return ()
        ordered = sorted(self.ticks, key=lambda item: item.tick)
        out: list[V3Range] = []
        for lower, upper in zip(ordered, ordered[1:]):
            liquidity = self._liquidity_between(lower.tick, upper.tick)
            if liquidity > 0:
                out.append(V3Range(sqrt_ratio_at_tick(lower.tick),
                                   sqrt_ratio_at_tick(upper.tick), liquidity))
        # A position above the last scanned initialized tick continues to the
        # global upper bound. The same is not assumed below the first tick: an
        # unscanned lower boundary would make that guess unsafe.
        last = ordered[-1].tick
        if self.tick >= last and self.active_liquidity > 0:
            out.append(V3Range(sqrt_ratio_at_tick(last), MAX_SQRT_RATIO,
                               self.active_liquidity))
        return tuple(out)

    def model(self) -> V3MultiPool:
        ranges = self.ranges()
        if not ranges:
            raise ValueError(
                "no initialized liquidity range was reconstructed; the pool may "
                "be empty, the bitmap window too small, or the RPC payload malformed")
        price = self.sqrt_price_x96
        # At an initialized tick the pool price and the reconstructed boundary
        # can differ by one wei of Q96. Snap only that exact-boundary case so a
        # half-open range does not select the wrong side of the tick.
        if any(item.tick == self.tick for item in self.ticks):
            exact = sqrt_ratio_at_tick(self.tick)
            if abs(price - exact) <= 2:
                price = exact
        return V3MultiPool(price, ranges, self.fee_pips)

    def to_dict(self) -> dict:
        ranges = self.ranges()
        return {
            "status": self.status,
            "address": self.address,
            "label": self.label,
            "block": self.block,
            "sqrt_price_x96": self.sqrt_price_x96,
            "tick": self.tick,
            "active_liquidity": self.active_liquidity,
            "tick_spacing": self.tick_spacing,
            "fee_pips": self.fee_pips,
            "token0": self.token0,
            "token1": self.token1,
            "decimals0": self.decimals0,
            "decimals1": self.decimals1,
            "ticks": [item.to_dict() for item in self.ticks],
            "ranges": [{"sqrt_lower_x96": r.sqrt_lower_x96,
                        "sqrt_upper_x96": r.sqrt_upper_x96,
                        "liquidity": r.liquidity} for r in ranges],
            "max_words": self.max_words,
            "truncated": self.truncated,
            "reason": self.reason,
            "errors": list(self.errors),
            "note": ("read-only snapshot; gas, bribe and inclusion can be priced "
                     "with --gas-*; queue position and competing flow remain outside"),
        }


def fetch_live_v3_pool(
    rpc_url: str,
    address: str,
    *,
    block: Optional[int] = None,
    max_words: int = 16,
    tick_spacing: Optional[int] = None,
    fee_pips: Optional[int] = None,
    label: str = "",
    client: Any = None,
    timeout: int = 20,
) -> LiveV3Pool:
    """Read one V3 pool and reconstruct its initialized tick ranges.

    ``max_words`` is the number of bitmap words scanned on each side of the
    current word. The result is marked ``INCOMPLETE`` when a boundary word still
    contains initialized ticks, because a larger window could change the ranges.
    """
    if not rpc_url and client is None:
        raise ValueError("no RPC endpoint was supplied")
    if max_words < 0:
        raise ValueError("max_words must be non-negative")
    client = client or ChainClient(rpc_url, timeout=timeout)
    if block is None:
        # Pin one block for every call: a multi-call snapshot at ``latest`` can
        # straddle a block boundary and mix two different pool states.
        try:
            raw_block = client.call("eth_blockNumber", [])
            block = int(raw_block, 16) if isinstance(raw_block, str) else int(raw_block)
        except (RpcUnavailable, ValueError, TypeError):
            block = None

    slot = _words(_call(client, address, SLOT0, block=block), 2)
    sqrt_price_x96 = slot[0]
    tick = _signed(slot[1], 24)
    active = _words(_call(client, address, LIQUIDITY, block=block), 1)[0]
    spacing = tick_spacing
    if spacing is None:
        spacing = _signed(_words(_call(client, address, TICK_SPACING, block=block), 1)[0], 24)
    if spacing <= 0:
        raise ValueError(f"pool reported invalid tick spacing {spacing}")
    fee = fee_pips
    if fee is None:
        fee = _words(_call(client, address, FEE, block=block), 1)[0]
    token0 = _address(_words(_call(client, address, TOKEN0, block=block), 1)[0])
    token1 = _address(_words(_call(client, address, TOKEN1, block=block), 1)[0])
    # token0/token1 are separate contracts; read each one explicitly.
    errors: list[str] = []
    try:
        decimals0 = _words(_call(client, token0, DECIMALS, block=block), 1)[0]
    except (RpcUnavailable, ValueError, TypeError, OSError) as exc:
        errors.append(f"token0 decimals unavailable: {exc}")
    try:
        decimals1 = _words(_call(client, token1, DECIMALS, block=block), 1)[0]
    except (RpcUnavailable, ValueError, TypeError, OSError) as exc:
        errors.append(f"token1 decimals unavailable: {exc}")

    compressed = tick // spacing if tick >= 0 else -((-tick) // spacing)
    current_word = compressed // 256
    word_positions = list(range(current_word - max_words,
                                current_word + max_words + 1))
    bitmaps = _call_many(client, address, TICK_BITMAP, word_positions, block)
    found_ticks: list[int] = []
    truncated = False
    for word_pos, payload in zip(word_positions, bitmaps):
        bitmap = _words(payload, 1)[0]
        if not bitmap:
            continue
        if word_pos in (current_word - max_words, current_word + max_words):
            truncated = True
        for bit in range(256):
            if not (bitmap >> bit) & 1:
                continue
            found = (word_pos * 256 + bit) * spacing
            if MIN_TICK <= found <= MAX_TICK:
                found_ticks.append(found)
    tick_payloads = _call_many(client, address, TICKS, found_ticks, block)
    ticks = {
        found: V3Tick(found, _words(payload, 2)[0],
                      _signed(_words(payload, 2)[1], 128))
        for found, payload in zip(found_ticks, tick_payloads)
    }

    ordered = tuple(ticks[key] for key in sorted(ticks))
    result = LiveV3Pool(
        address=address,
        sqrt_price_x96=sqrt_price_x96,
        tick=tick,
        active_liquidity=active,
        tick_spacing=spacing,
        fee_pips=fee,
        token0=token0,
        token1=token1,
        decimals0=decimals0,
        decimals1=decimals1,
        ticks=ordered,
        block=block,
        label=label or address,
        max_words=max_words,
        truncated=truncated,
        errors=errors,
    )
    if truncated:
        result.status = "INCOMPLETE"
        result.reason = (
            f"bitmap window of {2 * max_words + 1} word(s) reached an initialized "
            "boundary; increase --max-words for a complete range snapshot")
    elif not result.ranges():
        result.status = "INCOMPLETE"
        result.reason = "no positive initialized range was reconstructed"
    return result


def live_v3_sandwich(
    pool: LiveV3Pool,
    direction: str,
    *,
    victim_amount_in: int,
    attacker_amount_in: int,
) -> V3MultiSandwichResult:
    """Price a sandwich against the live reconstructed ranges."""
    return simulate_v3_multi_sandwich(
        pool.model(), direction,
        victim_amount_in=victim_amount_in,
        attacker_amount_in=attacker_amount_in)


@dataclass(frozen=True)
class LiveV3Economics:
    """Gas, bribe, inclusion, failure, capital and competition accounting.

    ``gross_profit`` and ``expected_net_profit`` are in the profit token's
    smallest units. Gas is paid in native wei; it is converted only when the
    operator supplies ``native_price`` (profit-token units per 1 native) or when
    the profit token is WETH, where one native unit is one WETH unit. Otherwise
    the result is deliberately unpriced rather than treating gas as zero.
    ``failed_tx_cost_profit_token`` is paid when the candidate is not included;
    ``capital_cost_profit_token`` is paid in both states. A competitor bid above
    our bribe means we are outbid: inclusion becomes zero and the expected value
    is the failure-state value.
    """

    gross_profit: int
    profit_token: str = ""
    profit_token_decimals: int = 18
    gas_units: int = 0
    gas_price_wei: int = 0
    gas_cost_wei: int = 0
    gas_cost_profit_token: Optional[int] = None
    bribe_bps: int = 0
    bribe_profit_token: int = 0
    inclusion_bps: int = BPS
    success_gross: int = 0
    failed_tx_cost_profit_token: int = 0
    capital_cost_profit_token: int = 0
    competitor_bid_profit_token: int = 0
    outbid: bool = False
    winning_bid_profit_token: int = 0
    expected_bribe_profit_token: int = 0
    net_if_included_profit: Optional[int] = None
    net_if_failed_profit: int = 0
    expected_net_profit: Optional[int] = None
    priced: bool = False
    reason: str = ""
    native_price: str = ""

    @property
    def profitable(self) -> bool:
        return bool(self.priced and self.expected_net_profit is not None
                    and self.expected_net_profit > 0 and not self.outbid)

    def to_dict(self) -> dict:
        return {
            "gross_profit": self.gross_profit,
            "profit_token": self.profit_token,
            "profit_token_decimals": self.profit_token_decimals,
            "gas": {
                "gas_units": self.gas_units,
                "gas_price_wei": self.gas_price_wei,
                "cost_wei": self.gas_cost_wei,
                "cost_profit_token": self.gas_cost_profit_token,
            },
            "bribe_bps": self.bribe_bps,
            "bribe_profit_token": self.bribe_profit_token,
            "inclusion_bps": self.inclusion_bps,
            "success_gross": self.success_gross,
            "failed_tx_cost_profit_token": self.failed_tx_cost_profit_token,
            "capital_cost_profit_token": self.capital_cost_profit_token,
            "competitor_bid_profit_token": self.competitor_bid_profit_token,
            "outbid": self.outbid,
            "winning_bid_profit_token": self.winning_bid_profit_token,
            "expected_bribe_profit_token": self.expected_bribe_profit_token,
            "net_if_included_profit": self.net_if_included_profit,
            "net_if_failed_profit": self.net_if_failed_profit,
            "expected_net_profit": self.expected_net_profit,
            "priced": self.priced,
            "profitable": self.profitable,
            "native_price": self.native_price,
            "reason": self.reason,
        }


def _profit_side(pool: LiveV3Pool, direction: str) -> tuple[str, int]:
    if direction == "token0->token1":
        return pool.token0, pool.decimals0
    if direction == "token1->token0":
        return pool.token1, pool.decimals1
    raise ValueError("direction must be 'token0->token1' or 'token1->token0'")


def price_live_v3_sandwich(
    result: V3MultiSandwichResult,
    pool: LiveV3Pool,
    direction: str,
    *,
    gas_units: int = 0,
    gas_price_wei: int = 0,
    bribe_bps: int = 0,
    inclusion_bps: int = BPS,
    gas_cost_profit_token: Optional[int] = None,
    native_price: Optional[Decimal | str | float] = None,
    failed_tx_cost_profit_token: int = 0,
    capital_cost_profit_token: int = 0,
    competitor_bid_profit_token: int = 0,
) -> LiveV3Economics:
    """Attach gas, bribe and inclusion economics to a measured sandwich.

    The model reports gross profit. A result is not called profitable here until
    the gas cost is expressed in the profit token; if it cannot be, ``priced``
    is false and the reason is recorded.
    """
    if gas_units < 0 or gas_price_wei < 0:
        raise ValueError("gas_units and gas_price_wei must be non-negative")
    if not 0 <= bribe_bps <= BPS:
        raise ValueError("bribe_bps must be in [0, 10000]")
    if not 0 <= inclusion_bps <= BPS:
        raise ValueError("inclusion_bps must be in [0, 10000]")
    if (failed_tx_cost_profit_token < 0 or capital_cost_profit_token < 0
            or competitor_bid_profit_token < 0):
        raise ValueError("failed, capital and competitor costs must be non-negative")
    token, decimals = _profit_side(pool, direction)
    gross = result.attacker_profit
    bribe = max(0, gross) * bribe_bps // BPS
    outbid = competitor_bid_profit_token > bribe
    p = 0 if outbid else inclusion_bps
    success_gross = gross * p // BPS
    gas_wei = gas_units * gas_price_wei
    gas_cost: Optional[int]
    reason: str
    native_text = ""
    if gas_cost_profit_token is not None:
        if gas_cost_profit_token < 0:
            raise ValueError("gas_cost_profit_token must be non-negative")
        gas_cost = gas_cost_profit_token
        reason = "gas cost supplied directly in profit-token units"
    elif gas_units or gas_price_wei:
        if native_price is not None:
            native_text = str(native_price)
            price = Decimal(native_price)
            if price < 0:
                raise ValueError("native_price must be non-negative")
            gas_cost = int((Decimal(gas_wei) / Decimal(10 ** 18) * price
                            * Decimal(10 ** decimals)).to_integral_value(
                                rounding=ROUND_DOWN))
            reason = (f"gas converted at {native_text} {token or 'profit token'} "
                      "per native unit")
        elif token.lower() in WETH_ADDRESSES and decimals == 18:
            gas_cost = gas_wei
            reason = "profit token is WETH; gas is 1:1 with native"
        else:
            gas_cost = None
            reason = ("gas is not priced: pass --native-price (profit-token units "
                      "per native) or --gas-cost (profit-token units)")
    else:
        gas_cost = 0
        reason = "no gas cost supplied; net equals gross"
    priced = gas_cost is not None
    winning_bid = max(bribe, competitor_bid_profit_token)
    net_included = (gross - gas_cost - winning_bid - capital_cost_profit_token
                    if priced else None)
    net_failed = -failed_tx_cost_profit_token - capital_cost_profit_token
    expected = ((p * net_included + (BPS - p) * net_failed) // BPS
                if priced else None)
    if outbid:
        reason = (reason + "; outbid by a competitor, so inclusion is zero")
    return LiveV3Economics(
        gross_profit=gross,
        profit_token=token,
        profit_token_decimals=decimals,
        gas_units=gas_units,
        gas_price_wei=gas_price_wei,
        gas_cost_wei=gas_wei,
        gas_cost_profit_token=gas_cost,
        bribe_bps=bribe_bps,
        bribe_profit_token=bribe,
        inclusion_bps=inclusion_bps,
        success_gross=success_gross,
        failed_tx_cost_profit_token=failed_tx_cost_profit_token,
        capital_cost_profit_token=capital_cost_profit_token,
        competitor_bid_profit_token=competitor_bid_profit_token,
        outbid=outbid,
        winning_bid_profit_token=winning_bid,
        expected_bribe_profit_token=bribe * p // BPS,
        net_if_included_profit=net_included,
        net_if_failed_profit=net_failed,
        expected_net_profit=expected,
        priced=priced,
        reason=reason,
        native_price=native_text,
    )


@dataclass(frozen=True)
class LiveV3PricedSandwich:
    result: V3MultiSandwichResult
    economics: LiveV3Economics

    def to_dict(self) -> dict:
        return {
            "sandwich": self.result.to_dict(),
            "economics": self.economics.to_dict(),
            "net_profitable": self.economics.profitable,
            "note": ("a profitable model is not a live opportunity; the fork "
                     "validator is the execution check"),
        }


def live_v3_priced_sandwich(
    pool: LiveV3Pool,
    direction: str,
    *,
    victim_amount_in: int,
    attacker_amount_in: int,
    **economics: Any,
) -> LiveV3PricedSandwich:
    result = live_v3_sandwich(
        pool, direction, victim_amount_in=victim_amount_in,
        attacker_amount_in=attacker_amount_in)
    return LiveV3PricedSandwich(
        result, price_live_v3_sandwich(result, pool, direction, **economics))


@dataclass(frozen=True)
class LiveV3SandwichSearch:
    tested: int
    best: Optional[V3MultiSandwichResult]
    economics: Optional[LiveV3Economics] = None

    @property
    def profitable(self) -> bool:
        if self.economics is not None:
            return self.economics.profitable
        return bool(self.best and self.best.net_profitable)

    def to_dict(self) -> dict:
        return {
            "tested": self.tested,
            "profitable": self.profitable,
            "gross_profitable": bool(self.best and self.best.net_profitable),
            "net_profitable": self.profitable,
            "best": self.best.to_dict() if self.best else None,
            "economics": self.economics.to_dict() if self.economics else None,
            "note": ("geometric search over attacker size; a negative best is an "
                     "honest no-profit result, not a missing measurement"),
        }


def search_live_v3_sandwich(
    pool: LiveV3Pool,
    direction: str,
    *,
    victim_amount_in: int,
    samples: int = 24,
    max_multiple: int = 10,
    gas_units: int = 0,
    gas_price_wei: int = 0,
    bribe_bps: int = 0,
    inclusion_bps: int = BPS,
    gas_cost_profit_token: Optional[int] = None,
    native_price: Optional[Decimal | str | float] = None,
    failed_tx_cost_profit_token: int = 0,
    capital_cost_profit_token: int = 0,
    competitor_bid_profit_token: int = 0,
) -> LiveV3SandwichSearch:
    """Search attacker sizes for the largest measured sandwich profit.

    The range is geometric from ``victim/1000`` to ``victim*max_multiple`` so a
    small or a large attacker is represented without assuming an optimum.
    """
    if victim_amount_in <= 0:
        raise ValueError("victim_amount_in must be positive")
    if samples < 1 or max_multiple < 1:
        raise ValueError("samples and max_multiple must be positive")
    low = max(1, victim_amount_in // 1000)
    high = max(low + 1, victim_amount_in * max_multiple)
    amounts = {low, victim_amount_in}
    for index in range(samples):
        ratio = (high / low) ** (index / max(1, samples - 1))
        amounts.add(max(low, min(high, int(low * ratio))))
    model = pool.model()
    results = [
        simulate_v3_multi_sandwich(
            model, direction, victim_amount_in=victim_amount_in,
            attacker_amount_in=amount)
        for amount in sorted(amounts)
    ]
    best = max(results, key=lambda item: item.attacker_profit)
    has_costs = bool(gas_units or gas_price_wei or bribe_bps
                     or inclusion_bps != BPS
                     or gas_cost_profit_token is not None
                     or native_price is not None
                     or failed_tx_cost_profit_token or capital_cost_profit_token
                     or competitor_bid_profit_token)
    economics = (price_live_v3_sandwich(
        best, pool, direction, gas_units=gas_units,
        gas_price_wei=gas_price_wei, bribe_bps=bribe_bps,
        inclusion_bps=inclusion_bps,
        gas_cost_profit_token=gas_cost_profit_token,
        native_price=native_price,
        failed_tx_cost_profit_token=failed_tx_cost_profit_token,
        capital_cost_profit_token=capital_cost_profit_token,
        competitor_bid_profit_token=competitor_bid_profit_token)
        if has_costs else None)
    return LiveV3SandwichSearch(tested=len(results), best=best,
                                economics=economics)
