"""Execution routing must label the engine and fall back honestly."""

from __future__ import annotations

from blackheart.execution import route


def test_local_engine_is_selected_when_anvil_is_absent(monkeypatch):
    monkeypatch.setattr(route, "anvil_available", lambda: False)
    engine, reason = route.select_engine("auto")
    assert engine == "local-evm"
    assert "anvil" in reason


def test_local_execution_carries_the_engine_label(monkeypatch):
    monkeypatch.setattr(route, "anvil_available", lambda: False)
    result = route.run_routed(b"\x00", prefer="auto")
    assert result.engine == "local-evm"
    assert result.result["succeeded"] is True
    assert result.result["halt"] == "STOP"
    assert "anvil" in result.reason


def test_explicit_local_request_never_claims_a_chain(monkeypatch):
    monkeypatch.setattr(route, "anvil_available", lambda: True)
    engine, reason = route.select_engine("local")
    assert engine == "local-evm"
    assert "requested" in reason


def test_anvil_selection_is_reported_when_available(monkeypatch):
    monkeypatch.setattr(route, "anvil_available", lambda: True)
    engine, reason = route.select_engine("auto")
    assert engine == "anvil"
    assert "eth_call" in reason


def test_a_broken_anvil_falls_back_to_local_with_a_reason(monkeypatch):
    class BrokenNode:
        def start(self):
            raise OSError("no binary")

        def stop(self):
            pass

    monkeypatch.setattr(route, "anvil_available", lambda: True)
    monkeypatch.setattr(route, "AnvilNode", BrokenNode)
    result = route.run_routed(b"\x00", prefer="auto")
    assert result.engine == "local-evm"
    assert result.result["succeeded"] is True
    assert "could not start" in result.reason
