"""Competitive order-flow economics.

A bundle does not compete with one static bid. A builder sees several searchers
and includes the bundle that pays it most. This module prices that choice with a
small, explicit bid ladder:

* every competitor bid is declared, never inferred from a name;
* our inclusion probability is the base inclusion probability times the fraction
  of declared bids strictly below ours (a tie loses);
* the bid is paid only when included, while the failure cost and the capital cost
  are paid in both states;
* ``optimal_bid`` searches only the thresholds where the win probability changes,
  so it cannot invent a better price by bidding more for the same outcome.

It is a static auction, not a mempool observation. Latency, private order flow,
builder policy, bundle merging and a competitor's response to our bid remain
unmodelled, and the result says so.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Iterable, Optional

BPS = 10_000


def _non_negative(value: int, name: str) -> int:
    if isinstance(value, bool):
        raise ValueError(f"{name} must be an integer")
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must be an integer") from exc
    if parsed < 0:
        raise ValueError(f"{name} must be non-negative")
    return parsed


@dataclass(frozen=True)
class BidOutcome:
    """The economics of one bid against the declared competitors."""

    bid_wei: int
    win_probability_bps: int
    net_if_included_wei: int
    net_if_failed_wei: int
    expected_wei: int

    @property
    def wins(self) -> bool:
        return self.win_probability_bps > 0

    def to_dict(self) -> dict:
        return {
            "bid_wei": self.bid_wei,
            "win_probability_bps": self.win_probability_bps,
            "net_if_included_wei": self.net_if_included_wei,
            "net_if_failed_wei": self.net_if_failed_wei,
            "expected_wei": self.expected_wei,
            "wins": self.wins,
        }


@dataclass(frozen=True)
class OrderFlowAuction:
    """A static first-price builder auction with an explicit competitor ladder.

    ``inclusion_probability_bps`` is the probability that the builder includes us
    when we win the bid ladder (for example, because of timing or bundle
    validity). It multiplies the fraction of competitors we outbid.
    """

    gross_wei: int
    our_bid_wei: int = 0
    gas_wei: int = 0
    failed_tx_cost_wei: int = 0
    capital_cost_wei: int = 0
    competitor_bids_wei: tuple[int, ...] = ()
    inclusion_probability_bps: int = BPS

    def __post_init__(self) -> None:
        object.__setattr__(self, "gross_wei", _non_negative(self.gross_wei, "gross_wei"))
        object.__setattr__(self, "our_bid_wei", _non_negative(self.our_bid_wei, "our_bid_wei"))
        object.__setattr__(self, "gas_wei", _non_negative(self.gas_wei, "gas_wei"))
        object.__setattr__(self, "failed_tx_cost_wei",
                           _non_negative(self.failed_tx_cost_wei, "failed_tx_cost_wei"))
        object.__setattr__(self, "capital_cost_wei",
                           _non_negative(self.capital_cost_wei, "capital_cost_wei"))
        bids = tuple(_non_negative(bid, "competitor_bid_wei")
                     for bid in self.competitor_bids_wei)
        object.__setattr__(self, "competitor_bids_wei", bids)
        base = _non_negative(self.inclusion_probability_bps,
                             "inclusion_probability_bps")
        if base > BPS:
            raise ValueError("inclusion_probability_bps must be <= 10000")
        object.__setattr__(self, "inclusion_probability_bps", base)

    @property
    def competitor_count(self) -> int:
        return len(self.competitor_bids_wei)

    @property
    def winning_competitor_bid_wei(self) -> int:
        return max(self.competitor_bids_wei, default=0)

    @property
    def behind_top_bid(self) -> bool:
        """Whether a declared competitor bid at least as much as we did."""
        return bool(self.competitor_bids_wei) and (
            self.our_bid_wei <= self.winning_competitor_bid_wei)

    @property
    def outbid(self) -> bool:
        """Whether every declared competitor bid at least as much as we did."""
        return bool(self.competitor_bids_wei) and self.win_probability_bps == 0

    @property
    def win_probability_bps(self) -> int:
        if not self.competitor_bids_wei:
            return self.inclusion_probability_bps
        beaten = sum(1 for bid in self.competitor_bids_wei
                     if bid < self.our_bid_wei)
        return (self.inclusion_probability_bps * beaten) // len(self.competitor_bids_wei)

    @property
    def net_if_included_wei(self) -> int:
        return (self.gross_wei - self.gas_wei - self.our_bid_wei
                - self.capital_cost_wei)

    @property
    def net_if_failed_wei(self) -> int:
        return -self.failed_tx_cost_wei - self.capital_cost_wei

    @property
    def expected_wei(self) -> int:
        p = self.win_probability_bps
        return (p * self.net_if_included_wei
                + (BPS - p) * self.net_if_failed_wei) // BPS

    @property
    def profitable(self) -> bool:
        return self.expected_wei > 0

    def outcome(self, bid_wei: int) -> BidOutcome:
        return self._at(bid_wei).bid_outcome()

    def bid_outcome(self) -> BidOutcome:
        return BidOutcome(
            bid_wei=self.our_bid_wei,
            win_probability_bps=self.win_probability_bps,
            net_if_included_wei=self.net_if_included_wei,
            net_if_failed_wei=self.net_if_failed_wei,
            expected_wei=self.expected_wei,
        )

    def _at(self, bid_wei: int) -> "OrderFlowAuction":
        return replace(self, our_bid_wei=_non_negative(bid_wei, "bid_wei"))

    def _candidate_bids(self) -> list[int]:
        # Only these bids change the win probability: zero, and one wei above
        # each declared competitor. Bidding higher for the same outcome is
        # strictly worse, so it cannot be optimal.
        return sorted({0, *(bid + 1 for bid in self.competitor_bids_wei)})

    def optimal_bid(self) -> BidOutcome:
        best = self._at(0)
        for candidate in self._candidate_bids():
            current = self._at(candidate)
            if current.expected_wei > best.expected_wei:
                best = current
            elif (current.expected_wei == best.expected_wei
                  and current.our_bid_wei < best.our_bid_wei):
                best = current
        return best.bid_outcome()

    def to_dict(self) -> dict:
        return {
            "gross_wei": self.gross_wei,
            "our_bid_wei": self.our_bid_wei,
            "gas_wei": self.gas_wei,
            "failed_tx_cost_wei": self.failed_tx_cost_wei,
            "capital_cost_wei": self.capital_cost_wei,
            "competitor_bids_wei": list(self.competitor_bids_wei),
            "competitor_count": self.competitor_count,
            "winning_competitor_bid_wei": self.winning_competitor_bid_wei,
            "behind_top_bid": self.behind_top_bid,
            "outbid": self.outbid,
            "inclusion_probability_bps": self.inclusion_probability_bps,
            "win_probability_bps": self.win_probability_bps,
            "net_if_included_wei": self.net_if_included_wei,
            "net_if_failed_wei": self.net_if_failed_wei,
            "expected_wei": self.expected_wei,
            "profitable": self.profitable,
            "optimal_bid": self.optimal_bid().to_dict(),
            "limitation": (
                "static declared bid ladder; latency, private order flow, "
                "builder policy and a competitor's response are not modelled"),
        }


def bids_from_single(bid_wei: int, count: int) -> tuple[int, ...]:
    """Expand the CLI's single competitor bid into a declared ladder."""
    bid = _non_negative(bid_wei, "competitor_bid_wei")
    n = _non_negative(count, "competitor_count")
    if bid <= 0:
        return ()
    return tuple([bid] * max(1, n))


def parse_bids(raw: Optional[str]) -> tuple[int, ...]:
    """Parse a JSON list of competitor bids; an empty value means no bidders."""
    import json

    if not raw:
        return ()
    payload = json.loads(raw)
    if not isinstance(payload, list):
        raise ValueError("competitor bids must be a JSON list")
    return tuple(_non_negative(item, "competitor_bid_wei") for item in payload)


def simulate_orderflow(
    gross_wei: int,
    *,
    our_bid_wei: int = 0,
    gas_wei: int = 0,
    failed_tx_cost_wei: int = 0,
    capital_cost_wei: int = 0,
    competitor_bids_wei: Iterable[int] = (),
    inclusion_probability_bps: int = BPS,
) -> OrderFlowAuction:
    return OrderFlowAuction(
        gross_wei=gross_wei, our_bid_wei=our_bid_wei, gas_wei=gas_wei,
        failed_tx_cost_wei=failed_tx_cost_wei,
        capital_cost_wei=capital_cost_wei,
        competitor_bids_wei=tuple(competitor_bids_wei),
        inclusion_probability_bps=inclusion_probability_bps,
    )
