"""A competitive bid ladder must price the bid, the loss and the optimum."""

from __future__ import annotations

import json

import pytest

from blackheart.value.orderflow import (
    OrderFlowAuction, bids_from_single, parse_bids, simulate_orderflow,
)


def test_no_competitor_uses_the_base_inclusion_probability():
    auction = OrderFlowAuction(gross_wei=1000, our_bid_wei=10, gas_wei=5,
                               inclusion_probability_bps=8000)
    assert auction.win_probability_bps == 8000
    assert auction.outbid is False
    assert auction.net_if_included_wei == 985
    assert auction.expected_wei == (8000 * 985) // 10_000


def test_a_higher_bid_wins_and_a_tie_loses():
    win = OrderFlowAuction(gross_wei=1000, our_bid_wei=101,
                           competitor_bids_wei=(100,))
    assert win.outbid is False
    assert win.win_probability_bps == 10_000
    assert win.net_if_included_wei == 899

    tie = OrderFlowAuction(gross_wei=1000, our_bid_wei=100,
                           competitor_bids_wei=(100,))
    assert tie.outbid is True
    assert tie.win_probability_bps == 0
    assert tie.expected_wei == 0

    lose = OrderFlowAuction(gross_wei=1000, our_bid_wei=99,
                            competitor_bids_wei=(100,), failed_tx_cost_wei=7,
                            capital_cost_wei=3)
    assert lose.outbid is True
    assert lose.expected_wei == -10


def test_multiple_competitors_use_the_fraction_strictly_below_our_bid():
    auction = OrderFlowAuction(
        gross_wei=1000, our_bid_wei=101,
        competitor_bids_wei=(50, 100, 150),
        inclusion_probability_bps=9000,
        failed_tx_cost_wei=4, capital_cost_wei=2)
    assert auction.competitor_count == 3
    assert auction.winning_competitor_bid_wei == 150
    assert auction.behind_top_bid is True
    assert auction.outbid is False
    assert auction.win_probability_bps == 6000  # 2/3 of 9000
    included = 1000 - 101 - 2
    failed = -4 - 2
    assert auction.net_if_included_wei == included
    assert auction.expected_wei == (6000 * included + 4000 * failed) // 10_000


def test_optimal_bid_stops_at_the_threshold_that_wins():
    auction = OrderFlowAuction(gross_wei=1000, competitor_bids_wei=(100, 200))
    optimal = auction.optimal_bid()
    assert optimal.bid_wei == 201
    assert optimal.win_probability_bps == 10_000
    assert optimal.expected_wei == 799
    assert auction.outcome(201).expected_wei == 799
    assert auction.outcome(500).expected_wei == 500


def test_optimal_bid_is_zero_when_winning_would_lose_money():
    auction = OrderFlowAuction(gross_wei=50, competitor_bids_wei=(100,))
    optimal = auction.optimal_bid()
    assert optimal.bid_wei == 0
    assert optimal.expected_wei == 0
    assert auction.outcome(101).expected_wei == -51


def test_a_failed_bundle_has_a_negative_expected_value_and_is_not_profitable():
    auction = OrderFlowAuction(gross_wei=100, our_bid_wei=1,
                               competitor_bids_wei=(2,), failed_tx_cost_wei=10,
                               capital_cost_wei=5)
    assert auction.profitable is False
    assert auction.expected_wei == -15


def test_single_bid_expansion_and_json_parsing():
    assert bids_from_single(0, 10) == ()
    assert bids_from_single(5, 0) == (5,)
    assert bids_from_single(5, 3) == (5, 5, 5)
    assert parse_bids("") == ()
    assert parse_bids("[1, 2, 3]") == (1, 2, 3)
    with pytest.raises(ValueError, match="JSON list"):
        parse_bids('{"bid": 1}')


def test_orderflow_facade_is_the_same_model():
    auction = simulate_orderflow(1000, our_bid_wei=11,
                                 competitor_bids_wei=(10,))
    assert auction.win_probability_bps == 10_000
    assert auction.expected_wei == 989


def test_cli_orderflow_prices_a_bid_ladder(capsys):
    from blackheart import cli

    rc = cli.main(["closure", "market", "--model", "orderflow",
                   "--gross", "1000", "--bribe", "101",
                   "--competitor-bids", "[100, 200]",
                   "--failed-tx-cost", "5", "--capital-cost", "2"])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["competitor_count"] == 2
    assert payload["behind_top_bid"] is True
    assert payload["outbid"] is False
    assert payload["win_probability_bps"] == 5000
    assert payload["optimal_bid"]["bid_wei"] == 201
    assert payload["limitation"].startswith("static declared bid ladder")


def test_cli_orderflow_expands_a_single_competitor_bid(capsys):
    from blackheart import cli

    rc = cli.main(["closure", "market", "--model", "orderflow",
                   "--gross", "1000", "--bribe", "101",
                   "--competitor-bid", "100", "--competitor-count", "3"])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["competitor_bids_wei"] == [100, 100, 100]
    assert payload["win_probability_bps"] == 10_000
