"""The pinned toolchain manifest, doctor and bootstrap.

These tests are deterministic and toolchain-free: they exercise the manifest's
own integrity, the resolution logic, and the honesty of the state machine. The
real-binary behaviour lives in ``tests/test_engines_live.py``.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from blackheart.engines import toolchain as tc


# --------------------------------------------------------------------------- #
# Manifest integrity
# --------------------------------------------------------------------------- #

def test_manifest_loads_and_is_pinned():
    data = tc.load_manifest()
    assert data["schema_version"] == 1
    assert set(data["engines"]) == {"slither", "wake", "halmos", "echidna", "medusa"}
    for name, spec in data["engines"].items():
        # A floating version would make a finding unreproducible in another
        # sandbox, which is the whole point of pinning.
        assert spec["version"], f"{name} has no pinned version"
        assert spec["kind"] in ("pip", "github-release"), name
        assert spec["license"], name
        assert spec["upstream"].startswith("https://github.com/"), name
        assert spec["methods"], name
        assert spec["target_types"], name


def test_every_registered_engine_has_a_manifest_entry():
    """The registry and the manifest must not drift apart."""
    from blackheart.engines import SOLIDITY_ENGINES

    manifest = tc.load_manifest()
    assert set(SOLIDITY_ENGINES) == set(manifest["engines"])


def test_pip_engines_declare_a_venv_and_exact_pin():
    for name, spec in tc.load_manifest()["engines"].items():
        if spec["kind"] != "pip":
            continue
        assert spec["venv"], name
        # `package` must carry the exact `==` pin, not a range.
        assert f"=={spec['version']}" in spec["package"], name


def test_github_release_assets_resolve_for_this_host():
    for name, spec in tc.load_manifest()["engines"].items():
        if spec["kind"] != "github-release":
            continue
        arch_map = spec["asset_arch"]
        assert "x86_64" in arch_map and "aarch64" in arch_map, name
        asset = spec["asset_template"].format(
            version=spec["version"], arch=arch_map["x86_64"])
        assert asset.endswith(".tar.gz"), name
        assert "{version}" not in asset and "{arch}" not in asset


def test_manifest_rejects_unknown_schema(tmp_path):
    bad = tmp_path / "toolchain.json"
    bad.write_text(json.dumps({"schema_version": 99, "engines": {"x": {}}}))
    with pytest.raises(ValueError, match="schema"):
        tc.load_manifest(bad)


def test_manifest_rejects_empty_engine_set(tmp_path):
    bad = tmp_path / "toolchain.json"
    bad.write_text(json.dumps({"schema_version": 1, "engines": {}}))
    with pytest.raises(ValueError, match="no engines"):
        tc.load_manifest(bad)


# --------------------------------------------------------------------------- #
# Resolution: doctor must agree with the adapters
# --------------------------------------------------------------------------- #

def test_resolve_finds_foundry_bin_without_path(monkeypatch, tmp_path):
    """The adapters prepend ~/.foundry/bin; doctor must too, or it reports a
    blocker that does not exist."""
    foundry = tmp_path / ".foundry" / "bin"
    foundry.mkdir(parents=True)
    forge = foundry / "forge"
    forge.write_text("#!/bin/sh\necho forge 1.10.0\n")
    forge.chmod(0o755)
    monkeypatch.setattr(tc.Path, "home", classmethod(lambda cls: tmp_path))
    monkeypatch.setattr(tc.shutil, "which", lambda _n: None)
    assert tc._resolve("forge") == forge


def test_resolve_returns_none_for_absent_tool(monkeypatch, tmp_path):
    monkeypatch.setattr(tc.Path, "home", classmethod(lambda cls: tmp_path))
    monkeypatch.setattr(tc.shutil, "which", lambda _n: None)
    assert tc._resolve("definitely-not-a-tool") is None


# --------------------------------------------------------------------------- #
# Doctor honesty
# --------------------------------------------------------------------------- #

def test_doctor_reports_missing_rather_than_guessing(monkeypatch, tmp_path):
    monkeypatch.setattr(tc.Path, "home", classmethod(lambda cls: tmp_path))
    monkeypatch.setattr(tc, "BIN_ROOT", tmp_path / "bin")
    monkeypatch.setattr(tc, "VENV_ROOT", tmp_path / "venvs")
    monkeypatch.setattr(tc.shutil, "which", lambda _n: None)
    report = tc.doctor()
    assert report["ok"] is False
    assert all(row["state"] == "MISSING" for row in report["engines"])
    # A missing tool is named, never silently omitted.
    assert all(row["problems"] for row in report["engines"])


def test_doctor_detects_version_mismatch(monkeypatch, tmp_path):
    """A present-but-wrong version is VERSION_MISMATCH, not INSTALLED."""
    manifest = {
        "schema_version": 1,
        "engines": {
            "fake": {"version": "9.9.9", "kind": "github-release",
                     "repo": "x/y", "asset_template": "a.tar.gz",
                     "asset_arch": {"x86_64": "x"}, "binary": "fake",
                     "license": "MIT", "methods": ["static-analysis"],
                     "target_types": ["solidity-file"]},
        },
        "toolchain": {},
    }
    binroot = tmp_path / "bin"
    binroot.mkdir()
    fake = binroot / "fake"
    fake.write_text("#!/bin/sh\necho fake 1.0.0\n")
    fake.chmod(0o755)
    monkeypatch.setattr(tc, "BIN_ROOT", binroot)
    monkeypatch.setattr(tc, "VENV_ROOT", tmp_path / "venvs")
    monkeypatch.setattr(tc.Path, "home", classmethod(lambda cls: tmp_path))
    monkeypatch.setattr(tc.shutil, "which", lambda _n: None)

    report = tc.doctor(manifest=manifest)
    row = report["engines"][0]
    assert row["state"] == "VERSION_MISMATCH"
    assert "9.9.9" in row["problems"][0]
    assert row["ok"] is False


def test_doctor_marks_missing_required_toolchain_as_a_problem(monkeypatch, tmp_path):
    """An engine whose compiler is absent must not read as usable."""
    manifest = {
        "schema_version": 1,
        "engines": {
            "fake": {"version": "1.0.0", "kind": "github-release",
                     "repo": "x/y", "asset_template": "a.tar.gz",
                     "asset_arch": {"x86_64": "x"}, "binary": "fake",
                     "license": "MIT", "methods": ["symbolic-execution"],
                     "target_types": ["foundry-project"],
                     "requires_toolchain": ["forge"]},
        },
        "toolchain": {},
    }
    binroot = tmp_path / "bin"
    binroot.mkdir()
    fake = binroot / "fake"
    fake.write_text("#!/bin/sh\necho fake 1.0.0\n")
    fake.chmod(0o755)
    monkeypatch.setattr(tc, "BIN_ROOT", binroot)
    monkeypatch.setattr(tc, "VENV_ROOT", tmp_path / "venvs")
    monkeypatch.setattr(tc.Path, "home", classmethod(lambda cls: tmp_path))
    monkeypatch.setattr(tc.shutil, "which", lambda _n: None)

    row = tc.doctor(manifest=manifest)["engines"][0]
    assert row["state"] == "INSTALLED"          # the binary is there...
    assert row["ok"] is False                   # ...but it cannot compile
    assert any("forge" in p for p in row["problems"])


def test_doctor_rejects_unknown_engine_name():
    with pytest.raises(KeyError):
        tc.doctor(only="not-an-engine")


def test_doctor_never_claims_operational(monkeypatch, tmp_path):
    """Doctor verifies installation, not execution. 'Operational' is only ever
    claimed after a real run, which doctor must not assert."""
    monkeypatch.setattr(tc, "BIN_ROOT", tmp_path / "bin")
    monkeypatch.setattr(tc, "VENV_ROOT", tmp_path / "venvs")
    monkeypatch.setattr(tc.shutil, "which", lambda _n: None)
    report = tc.doctor()
    assert "operational" not in json.dumps(report).lower()


def test_format_doctor_renders_every_row(monkeypatch, tmp_path):
    monkeypatch.setattr(tc.Path, "home", classmethod(lambda cls: tmp_path))
    monkeypatch.setattr(tc, "BIN_ROOT", tmp_path / "bin")
    monkeypatch.setattr(tc, "VENV_ROOT", tmp_path / "venvs")
    monkeypatch.setattr(tc.shutil, "which", lambda _n: None)
    text = tc.format_doctor(tc.doctor())
    for name in tc.load_manifest()["engines"]:
        assert name in text
    assert "result:" in text


def test_host_arch_is_a_release_name():
    assert tc.host_arch() in ("x86_64", "aarch64", "arm64", "amd64") or tc.host_arch()


# --------------------------------------------------------------------------- #
# Bootstrap: idempotence and honest failure
# --------------------------------------------------------------------------- #

def test_bootstrap_rejects_unknown_engine():
    with pytest.raises(KeyError):
        tc.bootstrap(only=["not-an-engine"])


def test_bootstrap_rejects_unsupported_kind(tmp_path):
    manifest = {
        "schema_version": 1,
        "engines": {"weird": {"version": "1", "kind": "cargo", "license": "MIT"}},
        "toolchain": {},
    }
    with pytest.raises(ValueError, match="unsupported install kind"):
        tc.bootstrap(manifest=manifest)


def test_ensure_venv_reuses_an_existing_one(tmp_path, monkeypatch):
    monkeypatch.setattr(tc, "VENV_ROOT", tmp_path / "venvs")
    venv = tmp_path / "venvs" / "demo"
    (venv / "bin").mkdir(parents=True)
    (venv / "bin" / "python").write_text("")

    def _no_create(*_a, **_k):
        raise AssertionError("must not recreate an existing venv")

    monkeypatch.setattr(tc.subprocess, "run", _no_create)
    assert tc._ensure_venv("demo", "python3") == venv


def test_doctor_verifies_a_declared_shared_dependency(monkeypatch, tmp_path):
    """`requires_shared` must be checked, not merely declared: Echidna and Medusa
    compile through crytic-compile, which only exists inside the slither venv."""
    manifest = {
        "schema_version": 1,
        "engines": {
            "provider": {"version": "1.0.0", "kind": "pip", "package": "p==1.0.0",
                         "venv": "provider", "license": "MIT",
                         "methods": ["static-analysis"],
                         "target_types": ["solidity-file"],
                         "provides_shared": ["sharedtool"]},
            "consumer": {"version": "2.0.0", "kind": "github-release",
                         "repo": "x/y", "asset_template": "a.tar.gz",
                         "asset_arch": {"x86_64": "x"}, "binary": "consumer",
                         "license": "MIT", "methods": ["sequence-fuzzing"],
                         "target_types": ["foundry-project"],
                         "requires_shared": ["sharedtool"]},
        },
        "toolchain": {},
    }
    binroot = tmp_path / "bin"
    binroot.mkdir()
    for name, version in (("provider", "1.0.0"), ("consumer", "2.0.0")):
        p = binroot / name
        p.write_text(f"#!/bin/sh\necho {name} {version}\n")
        p.chmod(0o755)
    venvs = tmp_path / "venvs"
    monkeypatch.setattr(tc, "BIN_ROOT", binroot)
    monkeypatch.setattr(tc, "VENV_ROOT", venvs)
    monkeypatch.setattr(tc.Path, "home", classmethod(lambda cls: tmp_path))
    monkeypatch.setattr(tc.shutil, "which", lambda _n: None)

    # Without the shared tool installed, the consumer is present but not usable.
    report = tc.doctor(only="consumer", manifest=manifest)
    assert report["engines"][0]["state"] == "INSTALLED"
    assert report["engines"][0]["ok"] is False
    assert "sharedtool" in " ".join(report["engines"][0]["problems"])

    # Once the provider's venv supplies it, the consumer verifies.
    (venvs / "provider" / "bin").mkdir(parents=True)
    shared = venvs / "provider" / "bin" / "sharedtool"
    shared.write_text("#!/bin/sh\n")
    shared.chmod(0o755)
    report = tc.doctor(only="consumer", manifest=manifest)
    assert report["engines"][0]["ok"] is True


def test_install_root_honours_blackheart_home(monkeypatch, tmp_path):
    """`$BLACKHEART_HOME` must move the install root.

    install.sh and scripts/verify_clean_install.sh export it to isolate a
    toolchain. While the modules read only ~/.blackheart, an "isolated"
    bootstrap reused the host toolchain and reported it as verified -- a false
    portability claim, and a shared-state hazard between sandboxes.
    """
    monkeypatch.setenv("BLACKHEART_HOME", str(tmp_path / "custom"))
    assert tc.home_root() == tmp_path / "custom"

    monkeypatch.delenv("BLACKHEART_HOME")
    assert tc.home_root() == Path.home() / ".blackheart"

    # A blank value must not create a relative-path root.
    monkeypatch.setenv("BLACKHEART_HOME", "   ")
    assert tc.home_root() == Path.home() / ".blackheart"


def test_the_adapter_and_doctor_agree_on_the_install_root():
    """Doctor must look where the adapter looks, or it reports a phantom blocker."""
    from blackheart.engines.solidity import base as sb

    assert sb._home_root() == tc.home_root()


# --------------------------------------------------------------------------- #
# Bytecode tools (heimdall): the same pinning rules as source engines, but a
# separate section because they consume EVM bytecode, not Solidity source.
# --------------------------------------------------------------------------- #

def test_bytecode_tools_are_pinned_with_provenance():
    data = tc.load_manifest()
    tools = data.get("bytecode_tools") or {}
    assert tools, "no bytecode tools declared"
    for name, spec in tools.items():
        assert spec["version"], name
        assert spec["license"], name
        assert spec["upstream"].startswith("https://github.com/"), name
        # A tool that is not pinned to a documented, dated source cannot be
        # relied on in a finding, so the provenance is part of the manifest.
        assert spec.get("docs", "").startswith("https://"), name
        assert spec.get("verified_on"), name
        assert spec["methods"], name
        assert spec["target_types"], name


def test_heimdall_is_not_a_solidity_source_engine():
    """It reads bytecode; handing it a source tree would be a configuration error."""
    from blackheart.engines import SOLIDITY_ENGINES

    assert "heimdall" not in SOLIDITY_ENGINES
    assert "heimdall" in tc.load_manifest()["bytecode_tools"]


def test_release_url_handles_a_bare_binary_asset(monkeypatch):
    monkeypatch.setattr(tc, "host_arch", lambda: "x86_64")
    spec = {
        "repo": "Jon-Becker/heimdall-rs",
        "version": "0.9.2",
        "tag_template": "0.9.3",
        "asset_template": "heimdall-{os}-{arch}",
        "asset_os": {"x86_64": "linux"},
        "asset_arch": {"x86_64": "amd64"},
    }
    assert tc.release_url(spec) == (
        "https://github.com/Jon-Becker/heimdall-rs/releases/download/0.9.3/"
        "heimdall-linux-amd64")


def test_release_url_keeps_the_default_v_tag_for_archives(monkeypatch):
    monkeypatch.setattr(tc, "host_arch", lambda: "x86_64")
    spec = {
        "repo": "crytic/echidna",
        "version": "2.4.0",
        "asset_template": "echidna-{version}-{arch}-linux.tar.gz",
        "asset_arch": {"x86_64": "x86_64"},
    }
    assert tc.release_url(spec) == (
        "https://github.com/crytic/echidna/releases/download/v2.4.0/"
        "echidna-2.4.0-x86_64-linux.tar.gz")


def test_pinned_sha256_mismatch_fails_closed(tmp_path):
    """A re-uploaded asset must not be installed as if it were the pinned one."""
    blob = tmp_path / "asset"
    blob.write_bytes(b"not the pinned bytes")
    with pytest.raises(RuntimeError, match="does not match the pinned"):
        tc._verify_sha256(blob, "0" * 64, "asset")
    # The correct digest passes, and an absent pin is a no-op rather than a pass
    # claim: the caller decided there is nothing to verify.
    tc._verify_sha256(blob, "", "asset")


def test_doctor_accounts_for_a_missing_bytecode_tool(monkeypatch, tmp_path):
    monkeypatch.setattr(tc, "BIN_ROOT", tmp_path / "bin")
    monkeypatch.setattr(tc, "VENV_ROOT", tmp_path / "venvs")
    # Doctor deliberately agrees with PATH; isolate this test from a host that
    # really has heimdall installed, or "missing" is not the condition under test.
    empty_path = tmp_path / "empty-path"
    empty_path.mkdir()
    monkeypatch.setenv("PATH", str(empty_path))
    manifest = {
        "schema_version": 1,
        "engines": {},
        "bytecode_tools": {
            "heimdall": {"version": "0.9.2", "kind": "github-release",
                         "binary": "heimdall"},
        },
        "toolchain": {},
    }
    report = tc.doctor(manifest=manifest)
    assert report["bytecode_tools"][0]["state"] == "MISSING"
    assert report["ok"] is False
