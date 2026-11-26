"""AMM pricing is exact and the sandwich is accounted on both sides."""

from __future__ import annotations

import pytest

from blackheart.venues.amm import (Pool, gas_cost, get_amount_out, multi_hop,
                                   sandwich)


def test_constant_product_output_matches_the_formula():
    # 100k into a 1M/1M pool with no fee -> 1M * 100k / 1.1M
    assert get_amount_out(100_000, 1_000_000, 1_000_000, 0) == 90_909
    assert get_amount_out(0, 1_000_000, 1_000_000, 30) == 0


def test_a_zero_fee_sandwich_is_profitable_and_costs_the_victim():
    result = sandwich(Pool(1_000_000, 1_000_000, 0), "x->y", 100_000, 100_000)
    assert result.attacker_profit == 18_032
    assert result.victim_out_without == 90_909
    assert result.victim_out_with == 75_757
    assert result.victim_loss == 15_152
    assert result.profitable


def test_a_fee_reduces_but_does_not_hide_the_sandwich():
    result = sandwich(Pool(1_000_000, 1_000_000, 30), "x->y", 100_000, 100_000)
    assert result.attacker_profit > 0
    assert result.victim_loss > 0
    assert result.profitable


def test_the_reverse_direction_is_symmetric():
    result = sandwich(Pool(1_000_000, 1_000_000, 0), "y->x", 100_000, 100_000)
    assert result.direction == "y->x"
    assert result.attacker_profit == 18_032
    assert result.victim_loss == 15_152


def test_invalid_pools_and_amounts_are_rejected():
    with pytest.raises(ValueError):
        Pool(0, 1_000_000)
    with pytest.raises(ValueError):
        Pool(1_000_000, 1_000_000, 10_000)
    with pytest.raises(ValueError):
        sandwich(Pool(1_000_000, 1_000_000), "x->y", 0, 100)
    with pytest.raises(ValueError):
        sandwich(Pool(1_000_000, 1_000_000), "sideways", 100, 100)


def test_the_result_is_json_shaped():
    payload = sandwich(Pool(1_000_000, 1_000_000, 0), "x->y", 100_000, 100_000).to_dict()
    assert payload["profitable"] is True
    assert payload["victim_loss"] == 15_152


def test_multi_hop_chains_the_output_of_one_pool_into_the_next():
    output, after = multi_hop([Pool(1_000_000, 1_000_000, 0),
                               Pool(1_000_000, 1_000_000, 0)],
                              ["x->y", "x->y"], 100_000)
    assert output == 83_333
    assert len(after) == 2


def test_multi_hop_rejects_a_mismatched_path():
    with pytest.raises(ValueError):
        multi_hop([Pool(1_000_000, 1_000_000)], [], 100)


def test_an_empty_path_is_the_identity():
    assert multi_hop([], [], 123) == (123, ())


def test_gas_is_charged_against_the_gross_profit():
    assert gas_cost(1_000, 2) == 2_000
    result = sandwich(Pool(1_000_000, 1_000_000, 0), "x->y", 100_000, 100_000,
                      gas_units=1_000, gas_price_wei=2)
    assert result.net_profit == result.attacker_profit - 2_000
    assert result.net_profitable is True


def test_a_gas_bill_larger_than_the_profit_makes_the_sandwich_unprofitable():
    result = sandwich(Pool(1_000_000, 1_000_000, 0), "x->y", 100_000, 100_000,
                      gas_units=1_000_000, gas_price_wei=1_000)
    assert result.profitable is True          # gross ordering effect still exists
    assert result.net_profit < 0
    assert result.net_profitable is False
