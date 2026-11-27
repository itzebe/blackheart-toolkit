"""Market and ordering models measure profit instead of assuming it."""

from __future__ import annotations

import json

from blackheart.value.market import (
    ConstantProductPool,
    GasCost,
    LiquidationEconomics,
    NetProfit,
    bribe_for,
    simulate_sandwich,
)


def test_a_constant_product_swap_is_deterministic():
    pool = ConstantProductPool(1_000_000, 2_000_000, fee_bps=0)
    assert pool.amount_out(1_000) == 1_998  # integer floor
    out = pool.swap_in(1_000)
    assert out == 1_998
    assert pool.reserve_in == 1_001_000
    assert pool.reserve_out == 1_998_002


def test_a_sandwich_measures_victim_loss_and_does_not_invent_profit():
    pool = ConstantProductPool(10**18, 10**18, fee_bps=0)
    result = simulate_sandwich(pool, victim_amount_in=10**17,
                              attacker_amount_in=10**16)
    assert result.victim_loss > 0
    assert result.gross_profit > 0
    assert result.profitable


def test_liquidation_bonus_can_be_profitable_after_gas():
    ecom = LiquidationEconomics(
        collateral_value_wei=1_000, debt_wei=900, bonus_bps=800,
        gas=GasCost(gas_units=10, gas_price_wei=1),
    )
    assert ecom.gross_wei == 180
    assert ecom.net.net_wei == 170
    assert ecom.net.profitable


def test_gas_and_bribe_are_subtracted_from_gross():
    net = NetProfit(gross_wei=1_000, gas_wei=100, bribe_wei=bribe_for(1_000, 500))
    assert net.net_wei == 850
    assert net.profitable


def test_lending_curve_is_utilization_driven():
    from blackheart.value.market import LendingCurve
    curve = LendingCurve(total_supply=1000, total_borrow=800, base_rate_bps=100,
                         slope_bps=9000)
    assert curve.utilization_bps == 8000
    assert curve.borrow_rate_bps == 7300
    assert curve.supply_rate_bps < curve.borrow_rate_bps


def test_order_book_walks_levels_and_reports_partial_fills():
    from blackheart.value.market import Level, OrderBook
    book = OrderBook(asks=[Level(110, 5), Level(100, 5)], bids=[Level(90, 10)])
    fill = book.buy(8)
    assert fill.filled == 8
    assert fill.notional == 5 * 100 + 3 * 110
    assert fill.average_price == fill.notional / 8
    assert book.buy(100).filled == 2


def test_order_book_sandwich_is_honest_about_the_spread():
    from blackheart.value.market import Level, OrderBook, simulate_orderbook_sandwich
    book = OrderBook(asks=[Level(100, 5), Level(110, 5), Level(120, 10)],
                     bids=[Level(95, 10), Level(90, 10)])
    result = simulate_orderbook_sandwich(book, victim_amount_in=8, attacker_amount_in=8)
    assert result.victim_with > result.victim_without
    assert result.gross_profit < 0  # a static book has a spread; no free round trip
    assert not result.profitable


def test_best_venue_keeps_the_best_quote_and_reports_improvement():
    from blackheart.value.market import VenueQuote, best_venue
    choice = best_venue([VenueQuote("a", 100), VenueQuote("b", 130),
                         VenueQuote("c", 90)])
    assert choice.venue == "b"
    assert choice.improvement == 40
    assert best_venue([]) is None


def test_bundle_auction_prices_priority_fee_and_bribe():
    from blackheart.value.market import BundleAuction
    auction = BundleAuction(gross_wei=1000, gas_wei=100, priority_fee_wei=50,
                            builder_bribe_wei=200, inclusion_probability_bps=5000)
    assert auction.net_wei == 650
    assert auction.expected_wei == 325
    assert auction.profitable


def test_bundle_auction_prices_failure_and_capital_costs():
    from blackheart.value.market import BundleAuction
    auction = BundleAuction(
        gross_wei=1000, gas_wei=100, priority_fee_wei=50,
        builder_bribe_wei=200, inclusion_probability_bps=5000,
        failed_tx_cost_wei=30, capital_cost_wei=20)
    assert auction.net_if_included_wei == 630
    assert auction.net_if_failed_wei == -50
    assert auction.expected_wei == 290
    assert auction.profitable


def test_a_competitor_above_the_bribe_wins_the_slot():
    from blackheart.value.market import BundleAuction
    auction = BundleAuction(
        gross_wei=1000, gas_wei=100, priority_fee_wei=50,
        builder_bribe_wei=200, inclusion_probability_bps=5000,
        failed_tx_cost_wei=30, capital_cost_wei=20,
        competitor_bid_wei=300, competitor_count=2)
    assert auction.outbid is True
    assert auction.effective_inclusion_bps == 0
    assert auction.winning_bid_wei == 300
    assert auction.expected_wei == -50
    assert not auction.profitable


def test_a_lower_competitor_does_not_raise_the_winning_bid():
    from blackheart.value.market import BundleAuction
    auction = BundleAuction(
        gross_wei=1000, gas_wei=100, priority_fee_wei=50,
        builder_bribe_wei=200, inclusion_probability_bps=5000,
        competitor_bid_wei=100, competitor_count=2)
    assert auction.outbid is False
    assert auction.winning_bid_wei == 200
    assert auction.expected_wei == 325


def test_v3_single_range_exact_input_matches_the_closed_form():
    from blackheart.value.market import Q96, V3Pool

    # sqrtP = 1, L = 1e18, no fee, amountIn = 1e18. The pool holds one token0,
    # so x' = 2 and sqrtP' = L / x' = 1/2; amountOut = L * (1 - 1/2) = L / 2.
    pool = V3Pool(Q96, 10**18, fee_pips=0)
    out, next_sqrt, crossed = pool.amount_out("token0->token1", 10**18)
    assert out == 5 * 10**17
    assert next_sqrt == Q96 // 2
    assert crossed is False


def test_v3_boundary_is_reported_not_crossed():
    from blackheart.value.market import Q96, V3Pool

    pool = V3Pool(Q96, 10**18, fee_pips=0, sqrt_upper_x96=Q96 + Q96 // 2)
    out, next_sqrt, crossed = pool.amount_out("token1->token0", 10**18)
    assert crossed is True
    assert next_sqrt == Q96 + Q96 // 2
    assert out > 0


def test_v3_sandwich_accounts_profit_and_victim_loss():
    from blackheart.value.market import Q96, V3Pool, simulate_v3_sandwich

    pool = V3Pool(Q96, 10**24, fee_pips=3_000,
                  sqrt_lower_x96=Q96 // 1_000)
    result = simulate_v3_sandwich(
        pool, "token0->token1", victim_amount_in=10**22, attacker_amount_in=10**20)
    assert result.victim_out_without > result.victim_out_with
    assert result.victim_loss == result.victim_out_without - result.victim_out_with
    assert result.attacker_profit > 0
    assert result.profitable is True


def test_v3_multi_crosses_down_into_the_next_range():
    from blackheart.value.market import Q96, V3MultiPool, V3Range

    pool = V3MultiPool(
        Q96,
        (V3Range(Q96 // 2, Q96, 10**18), V3Range(Q96, 2 * Q96, 2 * 10**18)),
        fee_pips=0,
    )
    out = pool.swap_in("token0->token1", 10**18)
    # At the boundary the downward direction uses the lower range; the full
    # input moves the price from 1.0 to 0.5 and removes exactly that liquidity.
    assert out == 5 * 10**17
    assert pool.sqrt_price_x96 == Q96 // 2
    assert pool.last_ticks_crossed == 1
    assert pool.last_consumed_in == 10**18


def test_v3_multi_crosses_up_into_the_next_range():
    from blackheart.value.market import Q96, V3MultiPool, V3Range

    pool = V3MultiPool(
        Q96,
        (V3Range(Q96 // 2, Q96, 10**18), V3Range(Q96, 2 * Q96, 2 * 10**18)),
        fee_pips=0,
    )
    # 5e18 token1 crosses the upper boundary of the second range; the swap must
    # stop at the global bound with unspent input rather than invent liquidity.
    out = pool.swap_in("token1->token0", 5 * 10**18)
    assert out > 0
    assert pool.sqrt_price_x96 == 2 * Q96
    assert pool.last_ticks_crossed == 1
    assert 0 < pool.last_consumed_in < 5 * 10**18


def test_v3_multi_sandwich_prices_crossing_and_keeps_attacker_spend_honest():
    from blackheart.value.market import Q96, V3MultiPool, V3Range, simulate_v3_multi_sandwich

    pool = V3MultiPool(
        Q96,
        (V3Range(Q96 // 2, Q96, 10**18), V3Range(Q96, 2 * Q96, 2 * 10**18)),
        fee_pips=3_000,
    )
    result = simulate_v3_multi_sandwich(
        pool, "token1->token0", victim_amount_in=10**20, attacker_amount_in=10**19)
    assert result.attacker_spent <= result.attacker_in
    assert result.attacker_profit == result.to_dict()["attacker_profit"]
    assert result.victim_loss >= 0


def test_v3_multi_continues_through_two_boundaries_with_new_liquidity():
    from blackheart.value.market import Q96, V3MultiPool, V3Range

    pool = V3MultiPool(
        Q96,
        (V3Range(Q96 // 2, Q96, 10**18), V3Range(Q96, 2 * Q96, 2 * 10**18),
         V3Range(2 * Q96, 4 * Q96, 3 * 10**18)),
        fee_pips=0,
    )
    # At a shared boundary only the range above it is active; the lower range's
    # liquidity must not be double-counted.
    assert pool.active_liquidity() == 2 * 10**18
    # Start inside the second range and push upward with enough input to cross
    # into the third range; the active liquidity must switch to 3e18.
    out = pool.swap_in("token1->token0", 4 * 10**18)
    assert out > 0
    assert pool.sqrt_price_x96 > 2 * Q96
    assert pool.last_ticks_crossed >= 1
    assert pool.active_liquidity() == 3 * 10**18



def test_cli_bundle_prices_failure_and_competition(capsys):
    from blackheart import cli

    rc = cli.main([
        "closure", "market", "--model", "bundle",
        "--gross", "1000", "--gas", "100", "--priority-fee", "50",
        "--bribe", "200", "--inclusion-bps", "5000",
        "--failed-tx-cost", "30", "--capital-cost", "20",
        "--competitor-bid", "300", "--competitor-count", "2",
    ])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["outbid"] is True
    assert payload["winning_bid_wei"] == 300
    assert payload["expected_wei"] == -50
    assert payload["profitable"] is False
