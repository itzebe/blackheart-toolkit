"""Cross-project portability of the external-intelligence capability.

The capability is a permanent BLACKHEART feature, not a one-repository change: a
project initialised or provisioned through BLACKHEART must receive the You.com
configuration, report missing credentials honestly, and never have a secret
written into its files. These tests drive the whole lifecycle on isolated,
clean project roots.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from blackheart.intelligence.bootstrap import bootstrap_project, load_project_config
from blackheart.intelligence.providers import ProviderRegistry


def _assert_mcp_valid_and_secretless(root: Path) -> dict:
    mcp = root / ".openhands" / "mcp.json"
    assert mcp.is_file(), "mcp.json was not written"
    data = json.loads(mcp.read_text(encoding="utf-8"))       # valid JSON
    servers = data["mcpServers"]
    assert "youdotcom" in servers
    entry = servers["youdotcom"]
    assert entry["url"].startswith("https://api.you.com/mcp")
    text = mcp.read_text(encoding="utf-8")
    assert "${YDC_API_KEY}" in text                          # references, not a value
    return data


# --------------------------------------------------------------------------- #
# Two independent clean roots
# --------------------------------------------------------------------------- #

def test_two_clean_roots_each_receive_the_capability(tmp_path):
    root_a = tmp_path / "proj-a"
    root_b = tmp_path / "proj-b"
    root_a.mkdir()
    root_b.mkdir()
    res_a = bootstrap_project(root_a)
    res_b = bootstrap_project(root_b)
    assert res_a.mcp_written and res_b.mcp_written
    _assert_mcp_valid_and_secretless(root_a)
    _assert_mcp_valid_and_secretless(root_b)
    # No secret leaks into either root, even when the env has one.
    for root in (root_a, root_b):
        for f in root.rglob("*"):
            if f.is_file():
                assert "ydc-" not in f.read_text(encoding="utf-8", errors="ignore")


def test_env_example_references_the_canonical_variable(tmp_path, monkeypatch):
    monkeypatch.setenv("YDC_API_KEY", "ydc-should-not-be-written")
    bootstrap_project(tmp_path)
    env = (tmp_path / ".openhands" / "intelligence.env.example").read_text()
    assert "YDC_API_KEY" in env
    assert "ydc-should-not-be-written" not in env


def test_no_secret_is_written_when_a_key_is_present(tmp_path, monkeypatch):
    monkeypatch.setenv("YDC_API_KEY", "ydc-live-secret-abcdef")
    bootstrap_project(tmp_path)
    for f in (tmp_path / ".openhands").rglob("*"):
        if f.is_file():
            assert "ydc-live-secret-abcdef" not in f.read_text(errors="ignore")


# --------------------------------------------------------------------------- #
# Idempotency, upgrades, repeated runs
# --------------------------------------------------------------------------- #

def test_repeated_bootstrap_is_idempotent(tmp_path):
    bootstrap_project(tmp_path)
    first = (tmp_path / ".openhands" / "mcp.json").read_text()
    res = bootstrap_project(tmp_path)
    second = (tmp_path / ".openhands" / "mcp.json").read_text()
    assert first == second
    assert res.mcp_written is False


def test_existing_project_upgrade_preserves_other_servers(tmp_path):
    # An existing project with its own MCP servers must keep them and gain ours.
    mcp = tmp_path / ".openhands" / "mcp.json"
    mcp.parent.mkdir(parents=True)
    mcp.write_text(json.dumps({"mcpServers": {
        "their-tool": {"type": "http", "url": "https://their.example/mcp"},
    }}))
    bootstrap_project(tmp_path)
    data = json.loads(mcp.read_text())
    assert data["mcpServers"]["their-tool"]["url"] == "https://their.example/mcp"
    assert "youdotcom" in data["mcpServers"]


def test_preexisting_openhands_dir_is_merged_not_clobbered(tmp_path):
    # A project that already has .openhands/ with unrelated content.
    oh = tmp_path / ".openhands"
    oh.mkdir()
    (oh / "intelligence.json").write_text(json.dumps({"disable": {}}))
    (oh / "notes.txt").write_text("keep me")
    bootstrap_project(tmp_path)
    assert (oh / "notes.txt").read_text() == "keep me"
    data = json.loads((oh / "mcp.json").read_text())
    assert "youdotcom" in data["mcpServers"]


# --------------------------------------------------------------------------- #
# Failure and recovery
# --------------------------------------------------------------------------- #

def test_corrupt_mcp_json_is_repaired(tmp_path):
    mcp = tmp_path / ".openhands" / "mcp.json"
    mcp.parent.mkdir(parents=True)
    mcp.write_text("{ this is not json")
    res = bootstrap_project(tmp_path)
    assert res.mcp_written is True
    data = json.loads(mcp.read_text())          # now valid
    assert "youdotcom" in data["mcpServers"]
    assert any("unreadable" in n for n in res.notes)


def test_recovery_after_a_failed_bootstrap(tmp_path, monkeypatch):
    import blackheart.intelligence.bootstrap as bs

    real_write = Path.write_text
    calls = {"n": 0}

    def flaky_write(self, *a, **k):
        if self.name == "mcp.json" and calls["n"] == 0:
            calls["n"] += 1
            raise OSError("disk full")
        return real_write(self, *a, **k)

    monkeypatch.setattr(Path, "write_text", flaky_write)
    try:
        bootstrap_project(tmp_path)
    except OSError:
        pass
    monkeypatch.setattr(Path, "write_text", real_write)
    res = bootstrap_project(tmp_path)             # second run succeeds
    assert res.mcp_written is True
    _assert_mcp_valid_and_secretless(tmp_path)


# --------------------------------------------------------------------------- #
# Paths with spaces
# --------------------------------------------------------------------------- #

def test_install_into_a_path_with_spaces(tmp_path):
    root = tmp_path / "my project with spaces"
    root.mkdir()
    res = bootstrap_project(root)
    assert res.mcp_written
    _assert_mcp_valid_and_secretless(root)


# --------------------------------------------------------------------------- #
# Inheritance + honest reporting through the registry
# --------------------------------------------------------------------------- #

def test_project_without_a_key_reports_unavailable_not_fake(tmp_path, monkeypatch):
    monkeypatch.delenv("YDC_API_KEY", raising=False)
    bootstrap_project(tmp_path)
    reg = ProviderRegistry(project_root=str(tmp_path))
    you = reg.get("you.com")
    assert you.available() is False              # honest: no key, no fake success
    # The keyless fallbacks remain genuinely usable.
    assert reg.get("duckduckgo").available() is True
    assert reg.get("wikipedia").available() is True


def test_project_uses_a_configured_key_without_copying_it(tmp_path, monkeypatch):
    monkeypatch.setenv("YDC_API_KEY", "ydc-from-env")
    bootstrap_project(tmp_path)
    reg = ProviderRegistry(project_root=str(tmp_path))
    assert reg.get("you.com").available() is True
    # The key came from the environment; it was never written into the project.
    for f in (tmp_path / ".openhands").rglob("*"):
        if f.is_file():
            assert "ydc-from-env" not in f.read_text(errors="ignore")


def test_project_disable_requires_an_explicit_reason(tmp_path):
    cfg = tmp_path / ".openhands" / "intelligence.json"
    cfg.parent.mkdir(parents=True)
    cfg.write_text(json.dumps({"disable": {"you.com": "   ", "wikipedia": "policy"}}))
    loaded = load_project_config(tmp_path)
    assert "you.com" not in loaded["disable"]     # blank reason -> ignored
    assert loaded["disable"]["wikipedia"] == "policy"


def test_registry_honours_explicit_project_disable(tmp_path):
    cfg = tmp_path / ".openhands" / "intelligence.json"
    cfg.parent.mkdir(parents=True)
    cfg.write_text(json.dumps({"disable": {"you.com": "project policy: no external key"}}))
    reg = ProviderRegistry(project_root=str(tmp_path))
    assert "you.com" not in reg.names()
    assert "you.com" in reg.disabled
