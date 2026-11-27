"""Live reserves are fetched read-only, and an unavailable endpoint is named."""

from __future__ import annotations

from blackheart.value.live import (
    decode_reserves, fetch_live_market, fetch_v2_pool, live_sandwich,
)


def _word(value: int) -> str:
    return f"{value:064x}"


def _reserves(r0: int, r1: int) -> str:
    return "0x" + _word(r0) + _word(r1) + _word(0)


class FakeClient:
    def __init__(self, values):
        self.values = values
        self.calls = []

    def call(self, method, params):
        self.calls.append((method, params))
        value = self.values[params[0]["to"]]
        if isinstance(value, Exception):
            raise value
        return value


def test_reserves_decode_and_quote():
    assert decode_reserves(_reserves(1000, 2000)) == (1000, 2000)
    client = FakeClient({"0xpair": _reserves(1000, 2000)})
    pool = fetch_v2_pool(client, "0xpair", block=7)
    assert (pool.reserve0, pool.reserve1) == (1000, 2000)
    assert client.calls[0][1][1] == hex(7)
    assert pool.pool().amount_out(10) > 0


def test_live_market_picks_the_best_of_several_pairs():
    client = FakeClient({"0xa": _reserves(1000, 2000), "0xb": _reserves(1000, 3000)})
    report = fetch_live_market("", [("0xa", 30, "A"), ("0xb", 30, "B")],
                               amount_in=10, client=client)
    assert report.status == "LIVE"
    assert report.best.venue == "B"
    assert report.to_dict()["best"]["amount_out"] > 0


def test_an_unavailable_endpoint_invents_nothing():
    report = fetch_live_market("", [], amount_in=10, client=FakeClient({}))
    assert report.status == "UNAVAILABLE"
    assert report.best is None
    assert "no pair" in report.reason


def test_a_malformed_reserve_payload_is_incomplete():
    client = FakeClient({"0xa": "0x1234"})
    report = fetch_live_market("", [("0xa", 30, "A")], amount_in=10, client=client)
    assert report.status == "INCOMPLETE"
    assert report.errors


def test_live_sandwich_uses_the_fetched_snapshot():
    pool = fetch_v2_pool(FakeClient({"0xa": _reserves(1000, 2000)}), "0xa")
    result = live_sandwich(pool, victim_amount_in=10, attacker_amount_in=10)
    assert result.victim_out_without_frontrun > 0
    assert result.attacker_spent == 10
