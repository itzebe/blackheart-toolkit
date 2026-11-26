"""Live V3 reconstruction is read-only, bounded and honest about truncation."""

from __future__ import annotations

import json
import subprocess
from decimal import Decimal
from pathlib import Path

import pytest

from blackheart.value.live_v3 import (
    BPS, LiveV3Pool, V3Tick,
    DECIMALS, FEE, LIQUIDITY, MAX_SQRT_RATIO, MAX_TICK, MIN_SQRT_RATIO, Q96,
    SLOT0, TICK_BITMAP, TICK_SPACING, TICKS, TOKEN0, TOKEN1, fetch_live_v3_pool,
    live_v3_priced_sandwich, live_v3_sandwich, price_live_v3_sandwich,
    search_live_v3_sandwich, sqrt_ratio_at_tick,
)
from blackheart.value.live_v3_fork import (
    RESULT_FILE, TEST_NAME, render_live_v3_fork_test,
    run_live_v3_fork_validation,
)
from blackheart.value.market import V3MultiSandwichResult

POOL = "0xpool"
TOKEN_A = "0x" + "11" * 20
TOKEN_B = "0x" + "22" * 20


def _word(value: int) -> str:
    return f"{value & ((1 << 256) - 1):064x}"


def _signed_arg(data: str) -> int:
    raw = int(data[10:], 16)
    return raw - (1 << 256) if raw >= (1 << 255) else raw


class FakeV3Client:
    def __init__(self, *, tick: int = 0, spacing: int = 60,
                 active: int = 2 * 10**18, fee: int = 3000,
                 ticks: dict[int, tuple[int, int]] | None = None,
                 sqrt_price: int = Q96):
        self.tick = tick
        self.spacing = spacing
        self.active = active
        self.fee = fee
        self.sqrt_price = sqrt_price
        self.ticks = ticks or {}
        self.bitmap: dict[int, int] = {}
        for found in self.ticks:
            compressed = found // spacing if found >= 0 else -((-found) // spacing)
            word = compressed // 256
            bit = compressed % 256
            self.bitmap[word] = self.bitmap.get(word, 0) | (1 << bit)
        self.calls = []

    def call(self, method, params):
        self.calls.append((method, params))
        if method == "eth_blockNumber":
            return "0x10"
        target = params[0]["to"]
        data = params[0]["data"]
        selector = data[:10]
        if target == TOKEN_A and selector == DECIMALS:
            return "0x" + _word(18)
        if target == TOKEN_B and selector == DECIMALS:
            return "0x" + _word(6)
        if target != POOL:
            raise AssertionError(f"unexpected target {target}")
        if selector == SLOT0:
            return "0x" + _word(self.sqrt_price) + _word(self.tick) + _word(0) * 6
        if selector == LIQUIDITY:
            return "0x" + _word(self.active)
        if selector == TICK_SPACING:
            return "0x" + _word(self.spacing)
        if selector == FEE:
            return "0x" + _word(self.fee)
        if selector == TOKEN0:
            return "0x" + _word(int(TOKEN_A, 16))
        if selector == TOKEN1:
            return "0x" + _word(int(TOKEN_B, 16))
        if selector == TICK_BITMAP:
            return "0x" + _word(self.bitmap.get(_signed_arg(data), 0))
        if selector == TICKS:
            gross, net = self.ticks[_signed_arg(data)]
            return "0x" + _word(gross) + _word(net) + _word(0) * 6
        raise AssertionError(f"unexpected selector {selector}")


def _two_range_client():
    return FakeV3Client(ticks={
        -120: (10**18, 10**18),
        0: (10**18, 10**18),
        120: (2 * 10**18, -2 * 10**18),
    })


def test_sqrt_ratio_is_exact_at_zero_and_ordered():
    assert sqrt_ratio_at_tick(0) == Q96
    assert sqrt_ratio_at_tick(-60) < sqrt_ratio_at_tick(0) < sqrt_ratio_at_tick(60)
    assert sqrt_ratio_at_tick(-887272) >= MIN_SQRT_RATIO - 1
    assert sqrt_ratio_at_tick(887272) <= MAX_SQRT_RATIO + 1
    with pytest.raises(ValueError):
        sqrt_ratio_at_tick(MAX_TICK + 1)


def test_fetch_reconstructs_initialized_ranges_and_active_liquidity():
    pool = fetch_live_v3_pool("", POOL, client=_two_range_client(), max_words=4)
    assert pool.status == "LIVE"
    assert pool.truncated is False
    assert pool.block == 16
    assert pool.tick_spacing == 60
    assert pool.fee_pips == 3000
    assert pool.token0 == TOKEN_A
    assert pool.decimals1 == 6
    ranges = pool.ranges()
    assert [(r.liquidity) for r in ranges] == [10**18, 2 * 10**18]
    assert pool.model().active_liquidity() == 2 * 10**18


def test_a_boundary_word_with_bits_marks_the_snapshot_incomplete():
    pool = fetch_live_v3_pool("", POOL, client=_two_range_client(), max_words=0)
    assert pool.truncated is True
    assert pool.status == "INCOMPLETE"
    assert "increase --max-words" in pool.reason


def test_an_empty_pool_does_not_invent_a_range():
    pool = fetch_live_v3_pool("", POOL, client=FakeV3Client(active=0), max_words=2)
    assert pool.ranges() == ()
    assert pool.status == "INCOMPLETE"
    with pytest.raises(ValueError):
        pool.model()


def test_live_v3_sandwich_uses_the_reconstructed_ranges():
    pool = fetch_live_v3_pool("", POOL, client=_two_range_client(), max_words=4)
    result = live_v3_sandwich(pool, "token1->token0",
                              victim_amount_in=10**20, attacker_amount_in=10**19)
    assert result.attacker_spent <= result.attacker_in
    assert result.victim_loss >= 0


def test_a_malformed_slot0_payload_is_an_error():
    class Bad(FakeV3Client):
        def call(self, method, params):
            if method == "eth_call" and params[0]["data"][:10] == SLOT0:
                return "0x1234"
            return super().call(method, params)

    with pytest.raises(ValueError):
        fetch_live_v3_pool("", POOL, client=Bad(), max_words=1)


def test_no_endpoint_is_an_error_not_a_fabricated_snapshot():
    with pytest.raises(ValueError):
        fetch_live_v3_pool("", POOL, client=None)


def test_live_v3_is_reachable_from_the_cli(monkeypatch, capsys):
    from blackheart import cli

    pool = LiveV3Pool(
        address=POOL, sqrt_price_x96=Q96, tick=0, active_liquidity=2 * 10**18,
        tick_spacing=60, fee_pips=3000,
        ticks=(V3Tick(-120, 10**18, 10**18), V3Tick(0, 10**18, 10**18),
               V3Tick(120, 2 * 10**18, -2 * 10**18)),
        label="test")
    monkeypatch.setattr("blackheart.value.live_v3.fetch_live_v3_pool",
                        lambda *a, **k: pool)
    rc = cli.main(["closure", "market", "--model", "live-v3",
                   "--rpc", "http://fake", "--pair", POOL + ":test",
                   "--victim", "1000",
                   "--attacker", "100", "--direction", "token1->token0"])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] == "LIVE"
    assert payload["ranges"]
    assert "sandwich" in payload


def test_live_v3_without_rpc_is_unavailable_not_a_fabricated_pool(capsys):
    from blackheart import cli

    rc = cli.main(["closure", "market", "--model", "live-v3", "--pair", POOL])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] == "UNAVAILABLE"
    assert payload["reason"] == "no RPC endpoint was supplied"


def test_fetch_uses_the_batch_path_when_the_client_supports_it():
    class BatchFake(FakeV3Client):
        def __init__(self):
            super().__init__(ticks={
                -120: (10**18, 10**18), 0: (10**18, 10**18),
                120: (2 * 10**18, -2 * 10**18),
            })
            self.batches = []

        def batch_call(self, calls):
            self.batches.append(len(calls))
            return [self.call(method, params) for method, params in calls]

    client = BatchFake()
    pool = fetch_live_v3_pool("", POOL, client=client, max_words=4)
    assert client.batches
    assert max(client.batches) <= 50
    assert [r.liquidity for r in pool.ranges()] == [10**18, 2 * 10**18]


def test_exact_tick_boundary_price_does_not_select_the_wrong_range():
    pool = LiveV3Pool(
        address=POOL, sqrt_price_x96=Q96 - 1, tick=0, active_liquidity=2 * 10**18,
        tick_spacing=60, fee_pips=3000,
        ticks=(V3Tick(-120, 10**18, 10**18), V3Tick(0, 10**18, 10**18),
               V3Tick(120, 2 * 10**18, -2 * 10**18)))
    assert pool.model().active_liquidity() == 2 * 10**18


def test_chain_client_batch_call_preserves_order(monkeypatch):
    from blackheart.deployed import ChainClient

    class Response:
        def __init__(self, payload):
            self.payload = payload

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def read(self):
            return json.dumps(self.payload).encode()

    def fake_urlopen(request, timeout):
        calls = json.loads(request.data)
        return Response([{"jsonrpc": "2.0", "id": item["id"],
                          "result": f"r{item['id']}"} for item in reversed(calls)])

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    client = ChainClient("http://fake")
    assert client.batch_call([("eth_chainId", []), ("eth_blockNumber", [])]) == [
        "r1", "r2"]


def test_a_batch_limit_falls_back_to_three_call_batches():
    from blackheart.deployed import RpcUnavailable

    class LimitedBatch(FakeV3Client):
        def __init__(self):
            super().__init__(ticks={
                -120: (10**18, 10**18), 0: (10**18, 10**18),
                120: (2 * 10**18, -2 * 10**18),
            })
            self.sizes = []

        def batch_call(self, calls):
            self.sizes.append(len(calls))
            if len(calls) > 3:
                raise RpcUnavailable("batch limit")
            return [self.call(method, params) for method, params in calls]

    client = LimitedBatch()
    pool = fetch_live_v3_pool("", POOL, client=client, max_words=4)
    assert max(client.sizes) > 3
    assert min(client.sizes) <= 3
    assert [r.liquidity for r in pool.ranges()] == [10**18, 2 * 10**18]


def test_sandwich_search_reports_the_best_measured_size():
    pool = fetch_live_v3_pool("", POOL, client=_two_range_client(), max_words=4)
    search = search_live_v3_sandwich(
        pool, "token1->token0", victim_amount_in=10**20, samples=8)
    assert search.tested >= 3
    assert search.best is not None
    assert search.to_dict()["tested"] == search.tested


def test_optimize_is_reachable_from_the_cli(monkeypatch, capsys):
    from blackheart import cli

    pool = fetch_live_v3_pool("", POOL, client=_two_range_client(), max_words=4)
    monkeypatch.setattr("blackheart.value.live_v3.fetch_live_v3_pool",
                        lambda *a, **k: pool)
    rc = cli.main(["closure", "market", "--model", "live-v3",
                   "--rpc", "http://fake", "--pair", POOL,
                   "--victim", str(10**20), "--optimize"])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["sandwich_search"]["tested"] >= 3
    assert payload["sandwich"]["attacker_in"] > 0



def _economic_result(profit: int = 10**15, loss: int = 10**12) -> V3MultiSandwichResult:
    return V3MultiSandwichResult(
        direction="token1->token0", attacker_in=10**17,
        attacker_spent=10**17, victim_in=10**18,
        attacker_profit=profit, victim_out_without=10**12,
        victim_out_with=10**12 - loss, victim_loss=loss,
        ticks_crossed=1, profitable=profit > 0)


def _economic_pool() -> LiveV3Pool:
    return LiveV3Pool(
        address=POOL, sqrt_price_x96=Q96, tick=0, active_liquidity=2 * 10**18,
        tick_spacing=60, fee_pips=3000,
        token0="0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", decimals0=6,
        token1="0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2", decimals1=18,
        ticks=(V3Tick(-120, 10**18, 10**18), V3Tick(0, 10**18, 10**18),
               V3Tick(120, 2 * 10**18, -2 * 10**18)),
        block=123, label="economic")


def test_gas_is_charged_against_gross_profit_in_weth_units():
    econ = price_live_v3_sandwich(
        _economic_result(), _economic_pool(), "token1->token0",
        gas_units=100_000, gas_price_wei=10**9)
    assert econ.priced is True
    assert econ.gas_cost_wei == 10**14
    assert econ.gas_cost_profit_token == 10**14
    assert econ.expected_net_profit == 10**15 - 10**14
    assert econ.profitable is True


def test_native_price_converts_gas_into_a_stablecoin_profit_token():
    result = _economic_result(profit=1_000_000, loss=1)
    econ = price_live_v3_sandwich(
        result, _economic_pool(), "token0->token1",
        gas_units=100_000, gas_price_wei=10**9,
        native_price=Decimal("3000"))
    assert econ.profit_token_decimals == 6
    assert econ.gas_cost_profit_token == 300_000
    assert econ.expected_net_profit == 700_000
    assert econ.profitable is True


def test_unconvertible_gas_is_unpriced_not_treated_as_zero():
    result = _economic_result(profit=1_000_000, loss=1)
    econ = price_live_v3_sandwich(
        result, _economic_pool(), "token0->token1",
        gas_units=100_000, gas_price_wei=10**9)
    assert econ.priced is False
    assert econ.expected_net_profit is None
    assert econ.profitable is False
    assert "--native-price" in econ.reason


def test_inclusion_probability_and_bribe_are_applied_to_successful_gross():
    econ = price_live_v3_sandwich(
        _economic_result(profit=10_000, loss=1), _economic_pool(),
        "token1->token0", inclusion_bps=5_000, bribe_bps=1_000,
        gas_cost_profit_token=0)
    assert econ.success_gross == 5_000
    assert econ.bribe_profit_token == 1_000
    assert econ.expected_bribe_profit_token == 500
    assert econ.expected_net_profit == 4_500


def test_failed_tx_and_capital_costs_are_expected_value_terms():
    econ = price_live_v3_sandwich(
        _economic_result(profit=1_000, loss=1), _economic_pool(),
        "token1->token0", inclusion_bps=5_000, gas_cost_profit_token=100,
        failed_tx_cost_profit_token=50, capital_cost_profit_token=10)
    assert econ.net_if_included_profit == 890
    assert econ.net_if_failed_profit == -60
    assert econ.expected_net_profit == 415


def test_a_competitor_above_our_bribe_zeroes_inclusion():
    econ = price_live_v3_sandwich(
        _economic_result(profit=1_000, loss=1), _economic_pool(),
        "token1->token0", bribe_bps=0, competitor_bid_profit_token=1,
        failed_tx_cost_profit_token=50, capital_cost_profit_token=10)
    assert econ.outbid is True
    assert econ.expected_net_profit == -60
    assert econ.profitable is False
    assert "outbid" in econ.reason


def test_a_competitor_below_our_bribe_does_not_change_the_bid():
    econ = price_live_v3_sandwich(
        _economic_result(profit=1_000, loss=1), _economic_pool(),
        "token1->token0", bribe_bps=1_000, competitor_bid_profit_token=50)
    assert econ.outbid is False
    assert econ.winning_bid_profit_token == 100
    assert econ.expected_net_profit == 900


def test_explicit_gas_cost_avoids_a_conversion_assumption():
    econ = price_live_v3_sandwich(
        _economic_result(profit=100), _economic_pool(), "token1->token0",
        gas_cost_profit_token=40)
    assert econ.priced is True
    assert econ.gas_cost_profit_token == 40
    assert econ.expected_net_profit == 60


def test_priced_sandwich_wrapper_keeps_gross_and_net_separate():
    priced = live_v3_priced_sandwich(
        _economic_pool(), "token1->token0",
        victim_amount_in=10**20, attacker_amount_in=10**19,
        gas_cost_profit_token=1)
    payload = priced.to_dict()
    assert payload["sandwich"]["attacker_profit"] == priced.result.attacker_profit
    assert payload["economics"]["expected_net_profit"] is not None
    assert "net_profitable" in payload


def test_search_attaches_economics_only_when_costs_are_supplied():
    pool = fetch_live_v3_pool("", POOL, client=_two_range_client(), max_words=4)
    plain = search_live_v3_sandwich(pool, "token1->token0",
                                    victim_amount_in=10**20, samples=4)
    assert plain.economics is None
    costed = search_live_v3_sandwich(
        pool, "token1->token0", victim_amount_in=10**20, samples=4,
        gas_units=100_000, gas_price_wei=10**9,
        gas_cost_profit_token=0)
    assert costed.economics is not None
    assert costed.profitable == costed.economics.profitable


def test_cli_exposes_gas_economics(monkeypatch, capsys):
    from blackheart import cli

    pool = _economic_pool()
    monkeypatch.setattr("blackheart.value.live_v3.fetch_live_v3_pool",
                        lambda *a, **k: pool)
    rc = cli.main(["closure", "market", "--model", "live-v3",
                   "--rpc", "http://fake", "--pair", POOL,
                   "--victim", str(10**20), "--attacker", str(10**19),
                   "--direction", "token1->token0",
                   "--gas-units", "100000", "--gas-price-wei", "1000000000",
                   "--bribe-bps", "500", "--inclusion-bps", "9000",
                   "--failed-tx-cost", "1000", "--capital-cost", "500",
                   "--competitor-bid", "0"])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["economics"]["priced"] is True
    assert payload["economics"]["inclusion_bps"] == 9000
    assert payload["economics"]["failed_tx_cost_profit_token"] == 1000
    assert payload["economics"]["capital_cost_profit_token"] == 500


def test_fork_renderer_uses_weth_slot_and_the_measured_direction():
    source = render_live_v3_fork_test(
        _economic_pool(), "token1->token0", victim_amount_in=10**18,
        attacker_amount_in=10**17)
    assert "BALANCE_SLOT = 3" in source
    assert (f"TOKEN_IN = address(uint160({int('C02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2', 16)}))"
            in source)
    assert (f"TOKEN_OUT = address(uint160({int('A0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48', 16)}))"
            in source)
    assert "FEE = 3000" in source
    assert "exactInputSingle" in source
    assert "vm.store" in source


def test_fork_renderer_refuses_an_unknown_token_slot():
    pool = LiveV3Pool(
        address=POOL, sqrt_price_x96=Q96, tick=0, active_liquidity=10**18,
        tick_spacing=60, fee_pips=3000, token0=TOKEN_A, token1=TOKEN_B,
        decimals0=6, decimals1=18)
    with pytest.raises(ValueError, match="balance slot"):
        render_live_v3_fork_test(pool, "token0->token1",
                                 victim_amount_in=10**18,
                                 attacker_amount_in=10**17)


def _forge_json(test_name: str, bucket: str = "passed") -> str:
    return json.dumps({
        f"test/LiveV3Fork.t.sol:LiveV3ForkTest": {
            "passed": [f"{test_name}()"] if bucket == "passed" else [],
            "failed": [f"{test_name}()"] if bucket == "failed" else [],
            "skipped": [],
        }
    })


def _fake_runner(profit: int, loss: int, *, bucket: str = "passed"):
    def runner(command, cwd, timeout):
        if bucket == "passed":
            Path(cwd, RESULT_FILE).write_text(
                f"attacker_profit={profit};victim_loss={loss};returned=0",
                encoding="utf-8")
        return subprocess.CompletedProcess(
            command, 0 if bucket == "passed" else 1,
            stdout=_forge_json(TEST_NAME, bucket), stderr="")

    return runner


def test_fork_validation_matches_the_model_within_tolerance():
    pool = _economic_pool()
    expected = _economic_result(profit=1000, loss=20)
    outcome = run_live_v3_fork_validation(
        pool, "token1->token0", rpc_url="http://fake", victim_amount_in=10**18,
        attacker_amount_in=10**17, expected=expected,
        runner=_fake_runner(1000, 20))
    assert outcome.status == "PASS"
    assert outcome.measured_attacker_profit == 1000
    assert outcome.to_dict()["measured"]["victim_loss"] == 20


def test_fork_validation_reports_divergence_instead_of_hiding_it():
    pool = _economic_pool()
    expected = _economic_result(profit=1000, loss=20)
    outcome = run_live_v3_fork_validation(
        pool, "token1->token0", rpc_url="http://fake", victim_amount_in=10**18,
        attacker_amount_in=10**17, expected=expected,
        runner=_fake_runner(5000, 20))
    assert outcome.status == "DIVERGED"
    assert outcome.measured_attacker_profit == 5000


def test_fork_validation_reports_a_failing_test():
    pool = _economic_pool()
    expected = _economic_result()
    outcome = run_live_v3_fork_validation(
        pool, "token1->token0", rpc_url="http://fake", victim_amount_in=10**18,
        attacker_amount_in=10**17, expected=expected,
        runner=_fake_runner(0, 0, bucket="failed"))
    assert outcome.status == "FAIL"


def test_fork_validation_blocks_without_an_rpc_or_pinned_block():
    pool = _economic_pool()
    expected = _economic_result()
    assert run_live_v3_fork_validation(
        pool, "token1->token0", rpc_url="", victim_amount_in=10**18,
        attacker_amount_in=10**17, expected=expected).status == "BLOCKED"
    pool.block = None
    assert run_live_v3_fork_validation(
        pool, "token1->token0", rpc_url="http://fake", victim_amount_in=10**18,
        attacker_amount_in=10**17, expected=expected).status == "BLOCKED"
