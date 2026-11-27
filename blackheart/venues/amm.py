"""Constant-product AMM pricing and the sandwich it permits.

This is the smallest economic venue that turns a transaction *ordering* into a
measurable transfer of value. It is deliberately exact: integer reserves, integer
fees in basis points, floor division on the output -- the same arithmetic an
on-chain pool performs. A sandwich is reported as attacker profit and victim loss
in the two assets, never as a single invented "impact score".
"""

from __future__ import annotations

from dataclasses import dataclass

BPS = 10_000


@dataclass(frozen=True)
class Pool:
    reserve_x: int
    reserve_y: int
    fee_bps: int = 30

    def __post_init__(self) -> None:
        if self.reserve_x <= 0 or self.reserve_y <= 0:
            raise ValueError("a pool needs positive reserves")
        if not 0 <= self.fee_bps < BPS:
            raise ValueError("fee_bps must be in [0, 10000)")

    def reserves(self, direction: str) -> tuple[int, int]:
        if direction == "x->y":
            return self.reserve_x, self.reserve_y
        if direction == "y->x":
            return self.reserve_y, self.reserve_x
        raise ValueError("direction must be 'x->y' or 'y->x'")

    def with_reserves(self, reserve_x: int, reserve_y: int) -> "Pool":
        return Pool(reserve_x, reserve_y, self.fee_bps)


def get_amount_out(amount_in: int, reserve_in: int, reserve_out: int,
                   fee_bps: int = 30) -> int:
    """The exact output of a constant-product swap with a basis-point fee."""
    if amount_in <= 0 or reserve_in <= 0 or reserve_out <= 0:
        return 0
    amount_in_with_fee = amount_in * (BPS - fee_bps)
    numerator = amount_in_with_fee * reserve_out
    denominator = reserve_in * BPS + amount_in_with_fee
    return numerator // denominator


def swap(pool: Pool, direction: str, amount_in: int) -> tuple[int, Pool]:
    """Return ``(amount_out, pool_after)`` for one swap."""
    reserve_in, reserve_out = pool.reserves(direction)
    amount_out = get_amount_out(amount_in, reserve_in, reserve_out, pool.fee_bps)
    if direction == "x->y":
        return amount_out, pool.with_reserves(pool.reserve_x + amount_in,
                                              pool.reserve_y - amount_out)
    return amount_out, pool.with_reserves(pool.reserve_x - amount_out,
                                          pool.reserve_y + amount_in)


def multi_hop(pools: list[Pool], directions: list[str],
              amount_in: int) -> tuple[int, tuple[Pool, ...]]:
    """Swap through several pools in order; return the output and the new pools."""
    if len(pools) != len(directions):
        raise ValueError("pools and directions must have the same length")
    if not pools:
        return amount_in, ()
    amount = amount_in
    after: list[Pool] = []
    for pool, direction in zip(pools, directions):
        amount, pool_after = swap(pool, direction, amount)
        after.append(pool_after)
    return amount, tuple(after)


def gas_cost(gas_units: int, gas_price_wei: int) -> int:
    """Gas cost in the profit's own unit; the caller converts the native price."""
    if gas_units < 0 or gas_price_wei < 0:
        raise ValueError("gas units and price must not be negative")
    return gas_units * gas_price_wei


@dataclass(frozen=True)
class SandwichResult:
    direction: str
    attacker_in: int
    victim_in: int
    attacker_profit: int
    victim_out_without: int
    victim_out_with: int
    victim_loss: int
    profitable: bool
    gas_units: int = 0
    gas_price_wei: int = 0
    net_profit: int = 0

    @property
    def net_profitable(self) -> bool:
        return self.net_profit > 0 and self.victim_loss > 0

    def to_dict(self) -> dict:
        return {
            "direction": self.direction,
            "attacker_in": self.attacker_in,
            "victim_in": self.victim_in,
            "attacker_profit": self.attacker_profit,
            "victim_out_without": self.victim_out_without,
            "victim_out_with": self.victim_out_with,
            "victim_loss": self.victim_loss,
            "profitable": self.profitable,
            "gas_units": self.gas_units,
            "gas_price_wei": self.gas_price_wei,
            "net_profit": self.net_profit,
            "net_profitable": self.net_profitable,
        }


def sandwich(pool: Pool, direction: str, victim_in: int, attacker_in: int,
             *, gas_units: int = 0, gas_price_wei: int = 0) -> SandwichResult:
    """Front-run, let the victim trade, then unwind -- and account both sides.

    The attacker trades in the victim's direction first, so the victim executes
    at the worse price the attacker created, then sells the acquired asset back.
    ``attacker_profit`` is denominated in the attacker's input asset;
    ``victim_loss`` in the victim's output asset.
    """
    if victim_in <= 0 or attacker_in <= 0:
        raise ValueError("victim_in and attacker_in must be positive")
    reverse = "y->x" if direction == "x->y" else "x->y"

    victim_out_without = get_amount_out(victim_in, *pool.reserves(direction), pool.fee_bps)
    acquired, after_front = swap(pool, direction, attacker_in)
    victim_out_with, after_victim = swap(after_front, direction, victim_in)
    returned, _ = swap(after_victim, reverse, acquired)

    profit = returned - attacker_in
    loss = victim_out_without - victim_out_with
    return SandwichResult(
        direction=direction,
        attacker_in=attacker_in,
        victim_in=victim_in,
        attacker_profit=profit,
        victim_out_without=victim_out_without,
        victim_out_with=victim_out_with,
        victim_loss=loss,
        profitable=profit > 0 and loss > 0,
        gas_units=gas_units,
        gas_price_wei=gas_price_wei,
        net_profit=profit - gas_cost(gas_units, gas_price_wei),
    )
