"""A declared adversarial race for an ordering opportunity.

``OrderFlowAuction`` prices one bid against a static ladder. This module adds the
two facts a real race has: a searcher must arrive inside the block window, and a
competitor's bid only matters if that competitor arrives too. The result names
the winner, our rank, and the expected value of our bid under the declared
ladder. Builder policy, private order flow, bundle merging and a competitor's
response to our bid remain unmodelled.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..value.orderflow import OrderFlowAuction


@dataclass(frozen=True)
class Searcher:
    name: str
    bid_wei: int
    latency_ms: int = 0
    capital_wei: int = 0

    def to_dict(self) -> dict:
        return {
            "name": self.name, "bid_wei": self.bid_wei,
            "latency_ms": self.latency_ms, "capital_wei": self.capital_wei,
        }


@dataclass
class RaceResult:
    winner: str
    included: bool
    our_rank: int
    our_expected_profit_wei: int
    our_bid_wei: int
    eligible_searchers: list[str] = field(default_factory=list)
    excluded_searchers: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "winner": self.winner,
            "included": self.included,
            "our_rank": self.our_rank,
            "our_expected_profit_wei": self.our_expected_profit_wei,
            "our_bid_wei": self.our_bid_wei,
            "eligible_searchers": list(self.eligible_searchers),
            "excluded_searchers": list(self.excluded_searchers),
            "notes": list(self.notes),
        }


def simulate_race(
    searchers: list[Searcher] | tuple[Searcher, ...],
    *,
    victim_value_wei: int,
    block_time_ms: int = 12_000,
    our_name: str = "us",
) -> RaceResult:
    """Race the declared searchers; the highest bid that arrives in time wins.

    A searcher whose latency exceeds ``block_time_ms`` is excluded, not treated
    as a slow bid. Ties are broken by lower latency, then by name, so the result
    is deterministic. ``our_expected_profit_wei`` is the auction's expected value
    against every eligible competitor, not the gross victim value.
    """
    if victim_value_wei <= 0:
        raise ValueError("victim_value_wei must be positive")
    if block_time_ms <= 0:
        raise ValueError("block_time_ms must be positive")
    ours = next((s for s in searchers if s.name == our_name), None)
    if ours is None:
        raise ValueError(f"no searcher named {our_name!r}")
    eligible = [s for s in searchers if s.latency_ms <= block_time_ms]
    excluded = [s.name for s in searchers if s.latency_ms > block_time_ms]
    if not eligible:
        return RaceResult(
            "", False, len(searchers) + 1, 0, ours.bid_wei,
            [], excluded, ["no declared searcher arrived inside the block window"],
        )
    ordered = sorted(eligible, key=lambda s: (-s.bid_wei, s.latency_ms, s.name))
    winner = ordered[0]
    rank = next(i for i, s in enumerate(ordered, 1) if s.name == our_name)
    competitors = tuple(s.bid_wei for s in eligible if s.name != our_name)
    auction = OrderFlowAuction(
        gross_wei=victim_value_wei, our_bid_wei=ours.bid_wei,
        competitor_bids_wei=competitors,
    )
    return RaceResult(
        winner.name, winner.name == our_name, rank,
        auction.expected_wei, ours.bid_wei,
        [s.name for s in eligible], excluded,
        [
            "a bid is paid only when included; latency above the block window "
            "is exclusion, not a penalty",
            "builder policy, private order flow and bundle merging are not modelled",
        ],
    )


__all__ = ["Searcher", "RaceResult", "simulate_race"]
