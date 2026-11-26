"""Deployed-code monitor tests.

Hermetic: every test drives the monitor with a fake :class:`ChainClient`, so no
network is touched. The tests assert the properties the module promises -- a code
change is ``CODE_CHANGED``, a proxy re-pointing is ``IMPL_CHANGED``, an unreadable
target is ``UNVERIFIED`` (a gap, never a drift), and a baseline round-trips.
"""

from __future__ import annotations

import argparse
import json

from blackheart.deployed import ChainClient, RpcUnavailable
from blackheart.monitor import (
    TARGETS,
    DriftKind,
    Observation,
    MonitorReport,
    TargetSpec,
    _classify,
    _hash_code,
    load_state,
    monitor_target,
    run_monitor,
    save_state,
    sourcify_url,
)

_CODE_A = "0x6080604052600436106100"
_CODE_B = "0x6080604052600436106101"
_ZERO_WORD = "0x" + "00" * 32
_IMPL_SLOT = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"


class FakeChain(ChainClient):
    """A ChainClient keyed by address, for hermetic monitor tests."""

    def __init__(self, code_by_addr: dict[str, str] | None = None,
                 storage_by_addr: dict[str, dict[str, str]] | None = None,
                 fail: bool = False):
        super().__init__("fake://rpc")
        self._code = {a.lower(): c for a, c in (code_by_addr or {}).items()}
        self._storage = {a.lower(): s for a, s in (storage_by_addr or {}).items()}
        self._fail = fail

    def call(self, method: str, params: list) -> object:
        if self._fail:
            raise RpcUnavailable("fake: endpoint down")
        if method == "eth_chainId":
            return hex(1)
        if method == "eth_blockNumber":
            return hex(1000)
        if method == "eth_getCode":
            return self._code.get(params[0].lower(), "0x")
        if method == "eth_getStorageAt":
            return self._storage.get(params[0].lower(), {}).get(params[1].lower(), _ZERO_WORD)
        raise RpcUnavailable(f"fake: unhandled {method}")


def _addr_word(addr: str) -> str:
    return "0x" + "00" * 12 + addr[2:].lower()


# --------------------------------------------------------------------------- #
# Registry + hashing
# --------------------------------------------------------------------------- #

def test_registry_is_well_formed() -> None:
    keys = [t.key for t in TARGETS]
    assert len(keys) == len(set(keys)), "target keys must be unique"
    for t in TARGETS:
        assert t.address.startswith("0x") and len(t.address) == 42
        assert t.chain_id == 1
        assert t.kind in {"core", "across", "oval"}
    # The primary OOv3 and the newest post-audit Across surface must be watched.
    assert any(t.address.lower() == "0xfb55f43fb9f48f63f9269db7dde3bbbe1ebdc0de" for t in TARGETS)


def test_hash_code_matches_keccak_of_runtime_bytes() -> None:
    # keccak256(b"") is a fixed vector; an empty code hashes to it.
    assert _hash_code("0x") == "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
    # A non-empty code hashes deterministically and differs from empty.
    h = _hash_code(_CODE_A)
    assert h.startswith("0x") and len(h) == 66
    assert h != _hash_code(_CODE_B)


def test_sourcify_url_shape() -> None:
    url = sourcify_url(1, "0xABC")
    assert url.startswith("https://sourcify.dev/server/v2/contract/1/0xABC")


# --------------------------------------------------------------------------- #
# Observation + classification
# --------------------------------------------------------------------------- #

def _obs(key="t", code="0x" + "aa" * 20, size=20, verified=True, proxy=False,
         impl="", impl_hash="") -> Observation:
    return Observation(key=key, name=key, address="0x" + "11" * 20, chain_id=1,
                       verified=verified, code_sha256=code, code_size=size,
                       proxy=proxy, implementation=impl, implementation_code_sha256=impl_hash)


def test_classify_new_when_no_prior() -> None:
    assert _classify(_obs(), None) == DriftKind.NEW


def test_classify_unchanged_when_fingerprint_equal() -> None:
    assert _classify(_obs(), _obs()) == DriftKind.UNCHANGED


def test_classify_code_changed() -> None:
    assert _classify(_obs(code="0x" + "bb" * 20), _obs()) == DriftKind.CODE_CHANGED


def test_classify_impl_changed_for_proxy() -> None:
    prior = _obs(proxy=True, impl="0x" + "aa" * 20, impl_hash="0x" + "01" * 20)
    now = _obs(proxy=True, impl="0x" + "bb" * 20, impl_hash="0x" + "02" * 20)
    assert _classify(now, prior) == DriftKind.IMPL_CHANGED


def test_classify_unverified_is_a_gap_not_a_drift() -> None:
    assert _classify(_obs(verified=False), _obs()) == DriftKind.UNVERIFIED


# --------------------------------------------------------------------------- #
# monitor_target + run_monitor (hermetic)
# --------------------------------------------------------------------------- #

def test_monitor_target_reads_and_hashes_code() -> None:
    spec = TargetSpec("t", 1, "0x" + "11" * 20, "Test", "core")
    client = FakeChain(code_by_addr={spec.address: _CODE_A})
    obs = monitor_target(spec, "fake://", client=client)
    assert obs.verified and obs.code_size == len(_CODE_A[2:]) // 2
    assert obs.code_sha256 == _hash_code(_CODE_A)
    assert obs.fingerprint() == obs.code_sha256


def test_monitor_target_resolves_proxy_implementation() -> None:
    proxy = "0x" + "11" * 20
    impl = "0x" + "22" * 20
    spec = TargetSpec("p", 1, proxy, "Proxy", "across", proxy=True)
    client = FakeChain(
        code_by_addr={proxy: _CODE_A, impl: _CODE_B},
        storage_by_addr={proxy: {_IMPL_SLOT: _addr_word(impl)}},
    )
    obs = monitor_target(spec, "fake://", client=client)
    assert obs.proxy and obs.implementation.lower() == impl.lower()
    # The proxy's *identity* is the implementation's code, not its own bytecode.
    assert obs.fingerprint() == _hash_code(_CODE_B)


def test_run_monitor_detects_drift_end_to_end() -> None:
    a = "0x" + "11" * 20
    b = "0x" + "22" * 20
    specs = (TargetSpec("a", 1, a, "A", "core"), TargetSpec("b", 1, b, "B", "core"))

    # Baseline: a has code A, b has code B.
    base_report, _ = run_monitor("fake://", targets=specs,
                                 client=FakeChain({a: _CODE_A, b: _CODE_B}))
    baseline = {o.key: o for o in base_report.observations}

    # Now b's code changed.
    report, drifts = run_monitor("fake://", targets=specs, baseline=baseline,
                                 client=FakeChain({a: _CODE_A, b: _CODE_A + "00"}))
    assert drifts["a"] == DriftKind.UNCHANGED
    assert drifts["b"] == DriftKind.CODE_CHANGED


def test_run_monitor_marks_unreachable_rpc_unverified() -> None:
    specs = (TargetSpec("a", 1, "0x" + "11" * 20, "A", "core"),)
    report, drifts = run_monitor("fake://", targets=specs, client=FakeChain(fail=True))
    assert drifts["a"] == DriftKind.UNVERIFIED
    assert not report.observations[0].verified
    assert report.observations[0].limitations


# --------------------------------------------------------------------------- #
# Baseline persistence
# --------------------------------------------------------------------------- #

def test_state_round_trips(tmp_path) -> None:
    specs = (TargetSpec("a", 1, "0x" + "11" * 20, "A", "core"),)
    report, _ = run_monitor("fake://", targets=specs, client=FakeChain({"0x" + "11" * 20: _CODE_A}))
    path = tmp_path / "baseline.json"
    save_state(report, path)
    loaded = load_state(path)
    assert loaded["a"].code_sha256 == report.observations[0].code_sha256
    assert loaded["a"].fingerprint() == report.observations[0].fingerprint()


def test_load_state_tolerates_missing_and_corrupt(tmp_path) -> None:
    assert load_state(tmp_path / "nope.json") == {}
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    assert load_state(bad) == {}


# --------------------------------------------------------------------------- #
# CLI wiring
# --------------------------------------------------------------------------- #

def _ns(**kw) -> argparse.Namespace:
    return argparse.Namespace(**kw)


def test_cli_targets_lists_registry(capsys) -> None:
    from blackheart.cli import cmd_monitor_targets

    rc = cmd_monitor_targets(_ns(json=True))
    assert rc == 0
    data = json.loads(capsys.readouterr().out)
    assert len(data) == len(TARGETS)
    assert all({"key", "address", "chain_id"} <= set(d) for d in data)


def test_cli_run_returns_nonzero_on_drift(monkeypatch, capsys) -> None:
    from blackheart import cli

    a = "0x" + "11" * 20
    specs = (TargetSpec("a", 1, a, "A", "core"),)
    monkeypatch.setattr("blackheart.monitor.TARGETS", specs)
    monkeypatch.setattr("blackheart.monitor.run_monitor",
                        lambda rpc, targets=None, baseline=None, client=None: (
                            MonitorReport(rpc_url=rpc, observations=[_obs("a", code="0x" + "bb" * 20)]),
                            {"a": DriftKind.CODE_CHANGED},
                        ))
    rc = cli.cmd_monitor_run(_ns(rpc="fake://", targets=None, baseline=None, save=None, json=False))
    assert rc == 1
    assert "DRIFT" in capsys.readouterr().out


def test_cli_run_returns_zero_when_clean(monkeypatch, capsys) -> None:
    from blackheart import cli

    monkeypatch.setattr("blackheart.monitor.run_monitor",
                        lambda rpc, targets=None, baseline=None, client=None: (
                            MonitorReport(rpc_url=rpc, observations=[_obs("a")]),
                            {"a": DriftKind.UNCHANGED},
                        ))
    rc = cli.cmd_monitor_run(_ns(rpc="fake://", targets=None, baseline=None, save=None, json=False))
    assert rc == 0
    assert "no code drift" in capsys.readouterr().out


def test_cli_run_returns_two_on_rpc_gap(monkeypatch, capsys) -> None:
    """An unreadable chain must NOT be reported as clean (exit 2, not 0)."""
    from blackheart import cli

    monkeypatch.setattr("blackheart.monitor.run_monitor",
                        lambda rpc, targets=None, baseline=None, client=None: (
                            MonitorReport(rpc_url=rpc,
                                          observations=[_obs("a", verified=False, code="", size=0)]),
                            {"a": DriftKind.UNVERIFIED},
                        ))
    rc = cli.cmd_monitor_run(_ns(rpc="fake://", targets=None, baseline=None, save=None, json=False))
    assert rc == 2
    assert "INCOMPLETE" in capsys.readouterr().out


def test_committed_baseline_covers_the_registry() -> None:
    """The pinned baseline shipped with the repo must match the target registry."""
    from pathlib import Path

    path = Path(__file__).resolve().parents[1] / "monitoring" / "uma-drift-baseline.json"
    assert path.is_file(), "committed baseline is missing"
    loaded = load_state(path)
    assert set(loaded) == {t.key for t in TARGETS}
    for obs in loaded.values():
        assert obs.verified and obs.fingerprint().startswith("0x")
