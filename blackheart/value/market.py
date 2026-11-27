"""Live economic and ordering models for a priced sequence.

The universal value engine says how much an actor gained. This module asks the
next question: would that gain survive the market and the ordering?

* a constant-product pool, with fees and integer arithmetic;
* a sandwich simulation that measures attacker profit and victim loss instead
  of assuming either;
* gas and builder-bribe costs, so ``net`` is not ``gross``;
* a liquidation-bonus model, the common case where the gross is positive.

A negative result is a result: an unprofitable sandwich is reported as
unprofitable, never rounded up to a finding.
"""

from __future__ import annotations
from typing import Optional

from dataclasses import dataclass, field

BPS = 10_000


@dataclass
class ConstantProductPool:
    reserve_in: int
    reserve_out: int
    fee_bps: int = 30

    def amount_out(self, amount_in: int) -> int:
        if amount_in <= 0 or self.reserve_in <= 0 or self.reserve_out <= 0:
            return 0
        effective = amount_in * (BPS - self.fee_bps)
        return (effective * self.reserve_out) // (
            self.reserve_in * BPS + effective)

    def spot_price(self) -> float:
        return self.reserve_out / self.reserve_in if self.reserve_in else 0.0

    def swap_in(self, amount_in: int) -> int:
        out = self.amount_out(amount_in)
        self.reserve_in += amount_in
        self.reserve_out -= out
        return out

    def swap_out(self, amount_out: int) -> int:
        """Sell ``amount_out`` of the output token back into the pool."""
        if amount_out <= 0 or self.reserve_out <= 0:
            return 0
        effective = amount_out * (BPS - self.fee_bps)
        amount_in = (effective * self.reserve_in) // (
            self.reserve_out * BPS + effective)
        self.reserve_out += amount_out
        self.reserve_in -= amount_in
        return amount_in


@dataclass
class SandwichResult:
    attacker_spent: int
    attacker_received: int
    victim_out_without_frontrun: int
    victim_out_with_frontrun: int
    gross_profit: int
    victim_loss: int

    @property
    def profitable(self) -> bool:
        return self.gross_profit > 0

    def to_dict(self) -> dict:
        return {
            "attacker_spent": self.attacker_spent,
            "attacker_received": self.attacker_received,
            "victim_out_without_frontrun": self.victim_out_without_frontrun,
            "victim_out_with_frontrun": self.victim_out_with_frontrun,
            "gross_profit": self.gross_profit,
            "victim_loss": self.victim_loss,
            "profitable": self.profitable,
        }


def simulate_sandwich(pool: ConstantProductPool, *,
                      victim_amount_in: int, attacker_amount_in: int) -> SandwichResult:
    """Front-run, let the victim swap, then back-run; measure both sides."""
    baseline = ConstantProductPool(pool.reserve_in, pool.reserve_out, pool.fee_bps)
    victim_without = baseline.amount_out(victim_amount_in)

    work = ConstantProductPool(pool.reserve_in, pool.reserve_out, pool.fee_bps)
    bought = work.swap_in(attacker_amount_in)
    victim_with = work.amount_out(victim_amount_in)
    work.swap_in(victim_amount_in)
    received = work.swap_out(bought)
    return SandwichResult(
        attacker_spent=attacker_amount_in,
        attacker_received=received,
        victim_out_without_frontrun=victim_without,
        victim_out_with_frontrun=victim_with,
        gross_profit=received - attacker_amount_in,
        victim_loss=max(0, victim_without - victim_with),
    )


Q96 = 1 << 96


@dataclass
class V3Pool:
    """A Uniswap-V3-style pool inside one tick range.

    The model is exact integer arithmetic for the range it declares: it does not
    cross a tick, so an input that reaches the boundary is clamped and reported
    as ``crossed_boundary``. That is deliberately narrow -- a cross-tick result
    without the tick bitmap would be an invented price, not a measured one.
    """

    sqrt_price_x96: int
    liquidity: int
    fee_pips: int = 3_000
    sqrt_lower_x96: int = 1
    sqrt_upper_x96: int = (1 << 160) - 1
    #: Set by the last ``swap_in``; not part of the pool's identity.
    last_crossed: bool = field(default=False, compare=False, repr=False)

    def __post_init__(self) -> None:
        if self.sqrt_price_x96 <= 0 or self.liquidity <= 0:
            raise ValueError("a V3 pool needs a positive price and liquidity")
        if not 0 <= self.fee_pips < 1_000_000:
            raise ValueError("fee_pips must be in [0, 1_000_000)")
        if not 0 < self.sqrt_lower_x96 <= self.sqrt_price_x96 <= self.sqrt_upper_x96:
            raise ValueError("sqrt price must lie inside the declared tick range")

    def copy(self) -> "V3Pool":
        return V3Pool(self.sqrt_price_x96, self.liquidity, self.fee_pips,
                      self.sqrt_lower_x96, self.sqrt_upper_x96)

    def spot_price(self) -> float:
        """Token1 per token0, from the Q96 square root price."""
        return (self.sqrt_price_x96 / Q96) ** 2

    def amount_out(self, direction: str, amount_in: int) -> tuple[int, int, bool]:
        """Return ``(amount_out, next_sqrt_price_x96, crossed_boundary)``."""
        if direction not in ("token0->token1", "token1->token0"):
            raise ValueError("direction must be 'token0->token1' or 'token1->token0'")
        if amount_in <= 0:
            return 0, self.sqrt_price_x96, False
        effective = amount_in * (1_000_000 - self.fee_pips) // 1_000_000
        if effective <= 0:
            return 0, self.sqrt_price_x96, False
        crossed = False
        if direction == "token0->token1":
            # x = L*Q96/sqrtP; x' = x + amount0; sqrtP' = L*Q96/x'.
            denominator = self.liquidity * Q96 + effective * self.sqrt_price_x96
            next_sqrt = (self.liquidity * Q96 * self.sqrt_price_x96) // denominator
            if next_sqrt < self.sqrt_lower_x96:
                next_sqrt = self.sqrt_lower_x96
                crossed = True
            out = (self.liquidity * (self.sqrt_price_x96 - next_sqrt)) // Q96
        else:
            # y = L*sqrtP/Q96; y' = y + amount1; sqrtP' = sqrtP + amount1*Q96/L.
            next_sqrt = self.sqrt_price_x96 + (effective * Q96) // self.liquidity
            if next_sqrt > self.sqrt_upper_x96:
                next_sqrt = self.sqrt_upper_x96
                crossed = True
            out = (self.liquidity * (next_sqrt - self.sqrt_price_x96) * Q96) // (
                next_sqrt * self.sqrt_price_x96)
        return max(0, out), next_sqrt, crossed

    def swap_in(self, direction: str, amount_in: int) -> int:
        out, next_sqrt, crossed = self.amount_out(direction, amount_in)
        self.sqrt_price_x96 = next_sqrt
        self.last_crossed = crossed
        return out

    def swap_out(self, direction: str, amount_out: int) -> int:
        """Sell ``amount_out`` of the output token back, in the reverse direction."""
        reverse = ("token1->token0" if direction == "token0->token1"
                   else "token0->token1")
        return self.swap_in(reverse, amount_out)


@dataclass
class V3SandwichResult:
    direction: str
    attacker_in: int
    victim_in: int
    attacker_profit: int
    victim_out_without: int
    victim_out_with: int
    victim_loss: int
    crossed_boundary: bool
    profitable: bool

    @property
    def net_profitable(self) -> bool:
        return self.profitable and self.victim_loss > 0

    def to_dict(self) -> dict:
        return {
            "direction": self.direction,
            "attacker_in": self.attacker_in,
            "victim_in": self.victim_in,
            "attacker_profit": self.attacker_profit,
            "victim_out_without": self.victim_out_without,
            "victim_out_with": self.victim_out_with,
            "victim_loss": self.victim_loss,
            "crossed_boundary": self.crossed_boundary,
            "profitable": self.profitable,
            "net_profitable": self.net_profitable,
        }


def simulate_v3_sandwich(pool: V3Pool, direction: str, *,
                         victim_amount_in: int,
                         attacker_amount_in: int) -> V3SandwichResult:
    """Front-run, victim, back-run inside one V3 tick range."""
    if victim_amount_in <= 0 or attacker_amount_in <= 0:
        raise ValueError("victim_amount_in and attacker_amount_in must be positive")
    baseline = pool.copy()
    victim_without = baseline.swap_in(direction, victim_amount_in)

    work = pool.copy()
    acquired = work.swap_in(direction, attacker_amount_in)
    crossed = work.last_crossed
    victim_with = work.swap_in(direction, victim_amount_in)
    crossed = crossed or work.last_crossed
    returned = work.swap_out(direction, acquired)
    crossed = crossed or work.last_crossed
    return V3SandwichResult(
        direction=direction,
        attacker_in=attacker_amount_in,
        victim_in=victim_amount_in,
        attacker_profit=returned - attacker_amount_in,
        victim_out_without=victim_without,
        victim_out_with=victim_with,
        victim_loss=max(0, victim_without - victim_with),
        crossed_boundary=crossed,
        profitable=returned > attacker_amount_in and victim_without > victim_with,
    )


@dataclass
class GasCost:
    gas_units: int
    gas_price_wei: int
    native_price_usd: float = 0.0

    @property
    def cost_wei(self) -> int:
        return max(0, self.gas_units) * max(0, self.gas_price_wei)

    @property
    def cost_usd(self) -> float:
        return self.cost_wei / 1e18 * max(0.0, self.native_price_usd)

    def to_dict(self) -> dict:
        return {"gas_units": self.gas_units, "gas_price_wei": self.gas_price_wei,
                "cost_wei": self.cost_wei, "cost_usd": self.cost_usd}


@dataclass
class NetProfit:
    gross_wei: int
    gas_wei: int = 0
    bribe_wei: int = 0

    @property
    def net_wei(self) -> int:
        return self.gross_wei - self.gas_wei - self.bribe_wei

    @property
    def profitable(self) -> bool:
        return self.net_wei > 0

    def to_dict(self) -> dict:
        return {"gross_wei": self.gross_wei, "gas_wei": self.gas_wei,
                "bribe_wei": self.bribe_wei, "net_wei": self.net_wei,
                "profitable": self.profitable}


def bribe_for(gross_wei: int, bribe_bps: int) -> int:
    return max(0, gross_wei) * max(0, bribe_bps) // BPS


@dataclass
class LiquidationEconomics:
    collateral_value_wei: int
    debt_wei: int
    bonus_bps: int = 800
    gas: GasCost | None = None
    bribe_bps: int = 0

    @property
    def gross_wei(self) -> int:
        seized = self.collateral_value_wei * (BPS + self.bonus_bps) // BPS
        return seized - self.debt_wei

    @property
    def net(self) -> NetProfit:
        gas_wei = self.gas.cost_wei if self.gas else 0
        return NetProfit(self.gross_wei, gas_wei, bribe_for(self.gross_wei,
                                                            self.bribe_bps))

    def to_dict(self) -> dict:
        return {"gross_wei": self.gross_wei, "bonus_bps": self.bonus_bps,
                "gas": self.gas.to_dict() if self.gas else None,
                "net": self.net.to_dict()}


@dataclass
class LendingCurve:
    """A kinked-free utilisation curve, in basis points, not a live oracle."""

    total_supply: int
    total_borrow: int
    base_rate_bps: int = 0
    slope_bps: int = 8_000
    reserve_factor_bps: int = 1_000

    @property
    def utilization_bps(self) -> int:
        if self.total_supply <= 0:
            return 0
        return min(BPS, max(0, self.total_borrow) * BPS // self.total_supply)

    @property
    def borrow_rate_bps(self) -> int:
        return self.base_rate_bps + self.slope_bps * self.utilization_bps // BPS

    @property
    def supply_rate_bps(self) -> int:
        return (self.borrow_rate_bps * self.utilization_bps
                * (BPS - self.reserve_factor_bps) // (BPS * BPS))

    def to_dict(self) -> dict:
        return {"utilization_bps": self.utilization_bps,
                "borrow_rate_bps": self.borrow_rate_bps,
                "supply_rate_bps": self.supply_rate_bps}


@dataclass(frozen=True)
class Level:
    price: int
    size: int


@dataclass(frozen=True)
class Fill:
    filled: int
    notional: int

    @property
    def average_price(self) -> float:
        return self.notional / self.filled if self.filled else 0.0


def walk_levels(levels: list[Level], amount: int) -> Fill:
    """Consume price levels in order; an exhausted book fills only what exists."""
    remaining = max(0, amount)
    filled = 0
    notional = 0
    for level in levels:
        take = min(remaining, max(0, level.size))
        filled += take
        notional += take * max(0, level.price)
        remaining -= take
        if remaining == 0:
            break
    return Fill(filled, notional)


@dataclass
class OrderBook:
    """A static order book: asks ascending, bids descending. No matching engine."""

    asks: list[Level]
    bids: list[Level]

    def __post_init__(self) -> None:
        self.asks = sorted(self.asks, key=lambda level: level.price)
        self.bids = sorted(self.bids, key=lambda level: -level.price)

    @staticmethod
    def _consume(levels: list[Level], amount: int) -> Fill:
        remaining = max(0, amount)
        filled = 0
        notional = 0
        for index, level in enumerate(levels):
            take = min(remaining, max(0, level.size))
            levels[index] = Level(level.price, level.size - take)
            filled += take
            notional += take * max(0, level.price)
            remaining -= take
            if remaining == 0:
                break
        return Fill(filled, notional)

    def buy(self, amount: int) -> Fill:
        return self._consume(self.asks, amount)

    def sell(self, amount: int) -> Fill:
        return self._consume(self.bids, amount)

    def copy(self) -> "OrderBook":
        return OrderBook([Level(l.price, l.size) for l in self.asks],
                         [Level(l.price, l.size) for l in self.bids])


@dataclass
class OrderBookSandwich:
    attacker_spent: int
    attacker_received: int
    victim_without: int
    victim_with: int
    gross_profit: int
    victim_loss: int

    @property
    def profitable(self) -> bool:
        return self.gross_profit > 0

    def to_dict(self) -> dict:
        return {"attacker_spent": self.attacker_spent,
                "attacker_received": self.attacker_received,
                "victim_without": self.victim_without,
                "victim_with": self.victim_with,
                "gross_profit": self.gross_profit,
                "victim_loss": self.victim_loss,
                "profitable": self.profitable}


def simulate_orderbook_sandwich(book: OrderBook, *, victim_amount_in: int,
                                attacker_amount_in: int) -> OrderBookSandwich:
    """Buy ahead of the victim, then sell the bought base into the bids."""
    baseline = book.copy()
    victim_without = baseline.buy(victim_amount_in).notional

    work = book.copy()
    bought = work.buy(attacker_amount_in)
    victim_with = work.buy(victim_amount_in).notional
    sold = work.sell(bought.filled)
    return OrderBookSandwich(
        attacker_spent=bought.notional,
        attacker_received=sold.notional,
        victim_without=victim_without,
        victim_with=victim_with,
        gross_profit=sold.notional - bought.notional,
        victim_loss=max(0, victim_with - victim_without),
    )


@dataclass(frozen=True)
class VenueQuote:
    venue: str
    amount_out: int


@dataclass
class VenueChoice:
    venue: str
    amount_out: int
    worst_amount_out: int

    @property
    def improvement(self) -> int:
        return max(0, self.amount_out - self.worst_amount_out)

    def to_dict(self) -> dict:
        return {"venue": self.venue, "amount_out": self.amount_out,
                "worst_amount_out": self.worst_amount_out,
                "improvement": self.improvement}


def best_venue(quotes: list[VenueQuote]) -> VenueChoice | None:
    """Pick the best quoted output; equal quotes keep the first venue."""
    if not quotes:
        return None
    best = max(quotes, key=lambda quote: quote.amount_out)
    worst = min(quotes, key=lambda quote: quote.amount_out)
    return VenueChoice(best.venue, best.amount_out, worst.amount_out)


@dataclass
class BundleAuction:
    """A builder bundle's economics, including failure and competition.

    ``failed_tx_cost_wei`` is the total cost paid when the bundle is not
    included; it is an operator input because a failed transaction's cost
    depends on what was submitted and how it reverted. ``capital_cost_wei`` is
    paid in both states. A competitor bid above our bribe means we are outbid:
    the inclusion probability becomes zero and the expected value is the
    failure-state value, not the gross.
    """

    gross_wei: int
    gas_wei: int = 0
    priority_fee_wei: int = 0
    builder_bribe_wei: int = 0
    inclusion_probability_bps: int = BPS
    failed_tx_cost_wei: int = 0
    capital_cost_wei: int = 0
    competitor_bid_wei: int = 0
    competitor_count: int = 0

    @property
    def outbid(self) -> bool:
        return self.competitor_bid_wei > self.builder_bribe_wei

    @property
    def winning_bid_wei(self) -> int:
        return max(self.builder_bribe_wei, self.competitor_bid_wei)

    @property
    def effective_inclusion_bps(self) -> int:
        if self.outbid:
            return 0
        return max(0, min(BPS, self.inclusion_probability_bps))

    @property
    def net_if_included_wei(self) -> int:
        return (self.gross_wei - self.gas_wei - self.priority_fee_wei
                - self.winning_bid_wei - self.capital_cost_wei)

    @property
    def net_if_failed_wei(self) -> int:
        return -self.failed_tx_cost_wei - self.capital_cost_wei

    @property
    def net_wei(self) -> int:
        return self.net_if_included_wei

    @property
    def expected_wei(self) -> int:
        p = self.effective_inclusion_bps
        return (p * self.net_if_included_wei
                + (BPS - p) * self.net_if_failed_wei) // BPS

    @property
    def profitable(self) -> bool:
        return self.expected_wei > 0 and not self.outbid

    def to_dict(self) -> dict:
        return {
            "gross_wei": self.gross_wei, "gas_wei": self.gas_wei,
            "priority_fee_wei": self.priority_fee_wei,
            "builder_bribe_wei": self.builder_bribe_wei,
            "competitor_bid_wei": self.competitor_bid_wei,
            "competitor_count": self.competitor_count,
            "outbid": self.outbid,
            "winning_bid_wei": self.winning_bid_wei,
            "net_wei": self.net_wei,
            "net_if_included_wei": self.net_if_included_wei,
            "net_if_failed_wei": self.net_if_failed_wei,
            "failed_tx_cost_wei": self.failed_tx_cost_wei,
            "capital_cost_wei": self.capital_cost_wei,
            "expected_wei": self.expected_wei,
            "inclusion_probability_bps": self.inclusion_probability_bps,
            "effective_inclusion_bps": self.effective_inclusion_bps,
            "profitable": self.profitable,
        }


@dataclass(frozen=True)
class V3Range:
    """One initialized Uniswap-V3 tick range and the liquidity active inside it.

    Ranges must be non-overlapping and sorted by price. A gap between two ranges
    is allowed and means zero liquidity there; a swap that reaches it stops with
    unspent input rather than inventing a price.
    """

    sqrt_lower_x96: int
    sqrt_upper_x96: int
    liquidity: int

    def __post_init__(self) -> None:
        if self.sqrt_lower_x96 <= 0:
            raise ValueError("sqrt_lower_x96 must be positive")
        if self.sqrt_upper_x96 <= self.sqrt_lower_x96:
            raise ValueError("sqrt_upper_x96 must exceed sqrt_lower_x96")
        if self.liquidity <= 0:
            raise ValueError("range liquidity must be positive")


def _ceil_div(numerator: int, denominator: int) -> int:
    return -(-numerator // denominator)


@dataclass
class V3MultiPool:
    """A Uniswap-V3-style pool with multiple initialized ranges.

    The model crosses ticks in the declared ranges: it moves the price to a
    range boundary, changes the active liquidity to the next range, and keeps
    spending the remaining input. It is exact integer arithmetic inside those
    ranges; it does not invent liquidity for a gap or for a tick with no
    declared range. A swap that reaches the global bound (or a gap) stops and
    reports the unspent input, exactly as the pool would.
    """

    sqrt_price_x96: int
    ranges: tuple[V3Range, ...]
    fee_pips: int = 3_000
    sqrt_min_x96: int = 1
    sqrt_max_x96: int = (1 << 160) - 1
    last_crossed: bool = field(default=False, compare=False, repr=False)
    last_ticks_crossed: int = field(default=0, compare=False, repr=False)
    last_consumed_in: int = field(default=0, compare=False, repr=False)

    def __post_init__(self) -> None:
        if self.sqrt_price_x96 <= 0:
            raise ValueError("sqrt_price_x96 must be positive")
        if not 0 <= self.fee_pips < 1_000_000:
            raise ValueError("fee_pips must be in [0, 1_000_000)")
        if not self.ranges:
            raise ValueError("a multi-range V3 pool needs at least one range")
        ordered = tuple(sorted(self.ranges, key=lambda r: r.sqrt_lower_x96))
        previous_upper = 0
        for item in ordered:
            if item.sqrt_lower_x96 < previous_upper:
                raise ValueError("V3 ranges must not overlap")
            previous_upper = item.sqrt_upper_x96
        self.ranges = ordered
        if not self.sqrt_min_x96 <= self.sqrt_price_x96 <= self.sqrt_max_x96:
            raise ValueError("sqrt price must lie inside the global bounds")

    def copy(self) -> "V3MultiPool":
        return V3MultiPool(self.sqrt_price_x96, self.ranges, self.fee_pips,
                           self.sqrt_min_x96, self.sqrt_max_x96)

    def spot_price(self) -> float:
        return (self.sqrt_price_x96 / Q96) ** 2

    def active_liquidity(self, price: Optional[int] = None) -> int:
        price = self.sqrt_price_x96 if price is None else price
        return sum(r.liquidity for r in self.ranges
                   if r.sqrt_lower_x96 <= price < r.sqrt_upper_x96)

    def _range_index(self, price: int) -> Optional[int]:
        for index, item in enumerate(self.ranges):
            if item.sqrt_lower_x96 <= price < item.sqrt_upper_x96:
                return index
        return None

    def _range_ending_at(self, price: int) -> Optional[int]:
        candidates = [i for i, r in enumerate(self.ranges)
                      if r.sqrt_upper_x96 == price and r.sqrt_lower_x96 < price]
        return max(candidates, key=lambda i: self.ranges[i].sqrt_lower_x96) \
            if candidates else None

    def _range_starting_at(self, price: int) -> Optional[int]:
        candidates = [i for i, r in enumerate(self.ranges)
                      if r.sqrt_lower_x96 == price and r.sqrt_upper_x96 > price]
        return min(candidates, key=lambda i: self.ranges[i].sqrt_upper_x96) \
            if candidates else None

    def swap_in(self, direction: str, amount_in: int) -> int:
        """Exact-input swap across the declared ranges; returns output amount."""
        if direction not in ("token0->token1", "token1->token0"):
            raise ValueError("direction must be 'token0->token1' or 'token1->token0'")
        self.last_crossed = False
        self.last_ticks_crossed = 0
        self.last_consumed_in = 0
        if amount_in <= 0:
            return 0
        effective = amount_in * (1_000_000 - self.fee_pips) // 1_000_000
        if effective <= 0:
            return 0
        remaining = effective
        price = self.sqrt_price_x96
        output = 0
        index = self._range_index(price)
        if direction == "token0->token1":
            # At an upper boundary the active liquidity is the range below; a
            # token0 input moves the price down into it immediately.
            ending = self._range_ending_at(price)
            if ending is not None:
                index = ending
        else:
            starting = self._range_starting_at(price)
            if starting is not None:
                index = starting
        while remaining > 0 and index is not None:
            item = self.ranges[index]
            liquidity = item.liquidity
            if direction == "token0->token1":
                lower = max(item.sqrt_lower_x96, self.sqrt_min_x96)
                if price <= lower:
                    nxt = self._range_ending_at(lower)
                    if nxt is None or nxt == index:
                        break
                    price = lower
                    index = nxt
                    self.last_crossed = True
                    self.last_ticks_crossed += 1
                    continue
                needed = _ceil_div(liquidity * Q96 * (price - lower), price * lower)
                if remaining >= needed:
                    output += (liquidity * (price - lower)) // Q96
                    remaining -= needed
                    price = lower
                    self.last_crossed = True
                    self.last_ticks_crossed += 1
                    nxt = self._range_ending_at(lower)
                    if nxt is None or nxt == index:
                        index = None
                        break
                    index = nxt
                    continue
                denominator = liquidity * Q96 + remaining * price
                next_price = (liquidity * Q96 * price) // denominator
                output += (liquidity * (price - next_price)) // Q96
                price = next_price
                remaining = 0
            else:
                upper = min(item.sqrt_upper_x96, self.sqrt_max_x96)
                if price >= upper:
                    nxt = self._range_starting_at(upper)
                    if nxt is None or nxt == index:
                        break
                    price = upper
                    index = nxt
                    self.last_crossed = True
                    self.last_ticks_crossed += 1
                    continue
                needed = _ceil_div(liquidity * (upper - price), Q96)
                if remaining >= needed:
                    output += (liquidity * (upper - price) * Q96) // (upper * price)
                    remaining -= needed
                    price = upper
                    self.last_crossed = True
                    self.last_ticks_crossed += 1
                    nxt = self._range_starting_at(upper)
                    if nxt is None or nxt == index:
                        index = None
                        break
                    index = nxt
                    continue
                next_price = price + (remaining * Q96) // liquidity
                output += (liquidity * (next_price - price) * Q96) // (
                    next_price * price)
                price = next_price
                remaining = 0
        self.sqrt_price_x96 = price
        if self.fee_pips < 1_000_000:
            refund = (remaining * 1_000_000) // (1_000_000 - self.fee_pips)
            self.last_consumed_in = max(0, amount_in - refund)
        else:
            self.last_consumed_in = amount_in
        return max(0, output)

    def swap_out(self, direction: str, amount_out: int) -> int:
        reverse = ("token1->token0" if direction == "token0->token1"
                   else "token0->token1")
        return self.swap_in(reverse, amount_out)


@dataclass
class V3MultiSandwichResult:
    direction: str
    attacker_in: int
    attacker_spent: int
    victim_in: int
    attacker_profit: int
    victim_out_without: int
    victim_out_with: int
    victim_loss: int
    ticks_crossed: int
    profitable: bool

    @property
    def net_profitable(self) -> bool:
        return self.profitable and self.victim_loss > 0

    def to_dict(self) -> dict:
        return {
            "direction": self.direction,
            "attacker_in": self.attacker_in,
            "attacker_spent": self.attacker_spent,
            "victim_in": self.victim_in,
            "attacker_profit": self.attacker_profit,
            "victim_out_without": self.victim_out_without,
            "victim_out_with": self.victim_out_with,
            "victim_loss": self.victim_loss,
            "ticks_crossed": self.ticks_crossed,
            "profitable": self.profitable,
            "net_profitable": self.net_profitable,
        }


def simulate_v3_multi_sandwich(pool: V3MultiPool, direction: str, *,
                               victim_amount_in: int,
                               attacker_amount_in: int) -> V3MultiSandwichResult:
    """Front-run, victim, back-run across multiple V3 ranges."""
    if victim_amount_in <= 0 or attacker_amount_in <= 0:
        raise ValueError("victim_amount_in and attacker_amount_in must be positive")
    baseline = pool.copy()
    victim_without = baseline.swap_in(direction, victim_amount_in)

    work = pool.copy()
    acquired = work.swap_in(direction, attacker_amount_in)
    front_spent = work.last_consumed_in
    ticks = work.last_ticks_crossed
    victim_with = work.swap_in(direction, victim_amount_in)
    ticks += work.last_ticks_crossed
    returned = work.swap_out(direction, acquired)
    ticks += work.last_ticks_crossed
    return V3MultiSandwichResult(
        direction=direction,
        attacker_in=attacker_amount_in,
        attacker_spent=front_spent,
        victim_in=victim_amount_in,
        attacker_profit=returned - front_spent,
        victim_out_without=victim_without,
        victim_out_with=victim_with,
        victim_loss=max(0, victim_without - victim_with),
        ticks_crossed=ticks,
        profitable=returned > front_spent and victim_without > victim_with,
    )
