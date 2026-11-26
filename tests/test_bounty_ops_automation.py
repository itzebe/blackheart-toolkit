"""Regression tests for the Twyne daily bounty-operations monitor.

The monitor must be fail-closed, read-only, and self-contained. These tests
never touch the network or real state: KV env vars are absent, and the local
state dir is redirected to a tmp path.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

_MONITOR = Path(__file__).resolve().parents[1] / "automations" / "twyne-bounty-ops" / "main.py"


def _load(tmp_path, monkeypatch):
    spec = importlib.util.spec_from_file_location("bh_twyne_monitor", _MONITOR)
    module = importlib.util.module_from_spec(spec)
    sys.modules["bh_twyne_monitor"] = module
    spec.loader.exec_module(module)
    # No KV store in tests; redirect local state to tmp.
    monkeypatch.setattr(module, "STATE_DIR", tmp_path / "state")
    monkeypatch.setattr(module, "EVIDENCE_DIR", tmp_path / "evidence")
    monkeypatch.delenv("AUTOMATION_KV_TOKEN", raising=False)
    monkeypatch.delenv("AUTOMATION_API_URL", raising=False)
    return module


CONFIG = {
    "program": "Twyne (Immunefi)",
    "platform": "immunefi",
    "scope_url": "https://immunefi.com/bug-bounty/twyne/information/",
    "program_url": "https://immunefi.com/bug-bounty/twyne/",
    "recorded_facts": {
        "nigerian_eligible": True,
        "payout_feasible": True,
        "zero_cost": True,
        "poc_required": True,
    },
    "assets": {
        "0xTwyne/aave-v3-aToken-wrapper": "AUTHORIZED",
        "0xTwyne/twyne-contracts-v1": "PASSIVE_ONLY",
    },
}

ACTIVE_FACTS = {
    "program_present": True,
    "program_active": True,
    "repos": [
        "github.com/0xTwyne/aave-v3-aToken-wrapper",
        "github.com/0xTwyne/twyne-contracts-v1",
    ],
    "addresses": [],
    "safe_harbor": True,
    "poc_required": True,
    "kyc_required": False,
    "reward_cap": "50,000",
}


def test_scope_config_matches_recorded_evidence(tmp_path, monkeypatch):
    module = _load(tmp_path, monkeypatch)
    cfg = json.loads(module.CONFIG_PATH.read_text(encoding="utf-8"))
    assert cfg["assets"]["0xTwyne/aave-v3-aToken-wrapper"] == "AUTHORIZED"
    assert cfg["assets"]["0xTwyne/twyne-contracts-v1"] == "PASSIVE_ONLY"


def test_monitor_is_self_contained(tmp_path, monkeypatch):
    """No import of the BLACKHEART package: it must run in a bare sandbox."""
    _load(tmp_path, monkeypatch)
    source = _MONITOR.read_text(encoding="utf-8")
    assert "import blackheart" not in source
    assert "from blackheart" not in source


def test_fails_closed_when_scope_cannot_be_fetched(tmp_path, monkeypatch, capsys):
    module = _load(tmp_path, monkeypatch)

    def _boom(*_a, **_k):
        raise OSError("network down")

    monkeypatch.setattr(module, "http_get", _boom)
    monkeypatch.setattr(module, "refresh_authorization", lambda *a, **k: {"evidence": ["x"]})
    monkeypatch.setattr(sys, "argv", ["main.py"])

    rc = module.main()
    assert rc == 2
    assert "scope fetch failed" in capsys.readouterr().out


def test_authorized_asset_requires_presence_in_fresh_scope(tmp_path, monkeypatch):
    module = _load(tmp_path, monkeypatch)
    facts = dict(ACTIVE_FACTS, repos=["github.com/0xTwyne/twyne-contracts-v1"])
    decisions = module.revalidate_assets(CONFIG, facts)
    assert decisions["0xTwyne/aave-v3-aToken-wrapper"]["status"] == "UNKNOWN"


def test_passive_only_is_never_promoted(tmp_path, monkeypatch):
    module = _load(tmp_path, monkeypatch)
    decisions = module.revalidate_assets(CONFIG, ACTIVE_FACTS)
    assert decisions["0xTwyne/twyne-contracts-v1"]["status"] == "PASSIVE_ONLY"


def test_inactive_program_blocks_everything(tmp_path, monkeypatch):
    module = _load(tmp_path, monkeypatch)
    facts = dict(ACTIVE_FACTS, program_active=False)
    decisions = module.revalidate_assets(CONFIG, facts)
    assert all(d["status"] == "UNKNOWN" for d in decisions.values())


def test_diff_snapshot_reports_changes(tmp_path, monkeypatch):
    module = _load(tmp_path, monkeypatch)
    assert module.diff_snapshot(None, ACTIVE_FACTS) == ["no previous snapshot; baseline established"]
    changes = module.diff_snapshot({"reward_cap": "50,000"}, {"reward_cap": "10,000"})
    assert any("reward_cap" in c for c in changes)


def test_load_save_state_local_roundtrip(tmp_path, monkeypatch):
    module = _load(tmp_path, monkeypatch)
    assert module.load_state("snapshot") is None
    module.save_state("snapshot", {"reward_cap": "50,000"})
    assert module.load_state("snapshot") == {"reward_cap": "50,000"}


def test_refreshed_record_satisfies_the_real_gate(tmp_path, monkeypatch):
    """The record the monitor writes must pass the actual authorization gate.

    Regression guard: an earlier revision dropped the eligibility/payout facts
    the gate requires, so every refresh would have produced a record that blocks
    active testing.
    """
    module = _load(tmp_path, monkeypatch)
    from blackheart.authz import program_checks_pass
    from blackheart.models import AuthorizationRecord

    pages = {CONFIG["scope_url"]: "<html>Twyne bug bounty</html>"}
    record = module.refresh_authorization(CONFIG, ACTIVE_FACTS, pages, [])
    ok, blockers = program_checks_pass(AuthorizationRecord(**record))
    assert ok, blockers

