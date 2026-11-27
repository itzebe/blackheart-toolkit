"""The toolchain registry must be honest about what it ships.

These tests do not require the tools to be installed: they assert the *registry*
is well-formed and that the live-protocol set is wired into verification. A
missing tool must be reported `missing`, never `functional`.
"""

from __future__ import annotations

from blackheart.engines.solidity.base import _candidate_dirs
from blackheart.tools import (
    DEFAULT_TOOLCHAIN,
    ISOLATED_TOOLS,
    LIVE_TOOLCHAIN,
    RUST_TOOLCHAIN,
    ToolRegistry,
    ToolSpec,
)


def _all_specs() -> list[ToolSpec]:
    return (
        list(DEFAULT_TOOLCHAIN)
        + list(LIVE_TOOLCHAIN)
        + list(RUST_TOOLCHAIN)
        + list(ISOLATED_TOOLS)
    )


def test_registry_has_no_duplicate_names() -> None:
    names = [s.name for s in _all_specs()]
    assert len(names) == len(set(names)), f"duplicate tool names: {names}"


def test_every_spec_is_well_formed() -> None:
    for spec in _all_specs():
        assert spec.name, spec
        assert spec.category, spec
        assert spec.version_cmd, spec
        assert spec.functional_cmd, spec
        assert spec.functional_expect, spec


def test_live_toolchain_covers_the_live_attack_surfaces() -> None:
    cats = {s.category for s in LIVE_TOOLCHAIN}
    # web/API/infra/recon/secrets are the surfaces PART E asks us to research.
    assert {"web", "api", "recon", "infra", "secrets"} <= cats

    # Required scanners may live in either set; check the union.
    names = {s.name for s in _all_specs()}
    for required in ("ffuf", "gobuster", "dalfox", "sqlmap", "nuclei",
                     "httpx", "subfinder", "katana", "dnsx", "naabu",
                     "gitleaks", "trivy"):
        assert required in names, f"{required} missing from the toolchain"


def test_verify_all_includes_live_toolchain() -> None:
    # verify_all must iterate the live tools; a missing binary is `missing`,
    # never `functional`. We check the spec set, not the host's tool state.
    spec_names = {s.name for s in ToolRegistry.specs()}
    live_names = {s.name for s in LIVE_TOOLCHAIN}
    assert live_names <= spec_names


def test_default_toolchain_covers_the_solidity_engines() -> None:
    # The mission names these engines explicitly; each must be a registered,
    # version-pinned spec so a fresh runtime verifies them honestly.
    by_name = {s.name: s for s in DEFAULT_TOOLCHAIN}
    for required in ("forge", "cast", "anvil", "echidna", "medusa",
                     "halmos", "slither", "wake"):
        assert required in by_name, f"{required} missing from DEFAULT_TOOLCHAIN"
        assert by_name[required].pinned, f"{required} has no pinned version"


def test_retired_upstream_tools_are_not_pinned() -> None:
    """A registry entry nobody can install is a lie about the toolchain.

    aderyn was removed after upstream retired it and withdrew every download
    (`aderyn-installer.sh` in the 0.6.8 release now only prints that message and
    exits 1), which left `install.sh` fetching a 404 and `tools verify` reporting
    a permanent MISSING for a tool that will never come back.
    """
    names = {s.name for s in ToolRegistry.specs()}
    assert "aderyn" not in names


def test_a_tool_installed_only_in_an_engine_venv_is_found(monkeypatch, tmp_path) -> None:
    """`engines bootstrap` installs into venvs that are deliberately off PATH.

    Resolving with `shutil.which` alone reported those engines as MISSING while
    the engine layer ran them happily -- two subsystems disagreeing about what
    "installed" means.
    """
    venv_bin = tmp_path / "venvs" / "wake" / "bin"
    venv_bin.mkdir(parents=True)
    tool = venv_bin / "wake"
    tool.write_text("#!/bin/sh\necho 'wake 4.22.2'\n")
    tool.chmod(0o755)

    monkeypatch.setattr("shutil.which", lambda _name: None)
    monkeypatch.setattr(
        "blackheart.engines.solidity.base._candidate_dirs",
        lambda name: [(venv_bin, "venv")] if name == "wake" else [],
        raising=True,
    )
    assert ToolRegistry._resolve("wake") == str(tool)


def test_resolution_of_an_absolute_tool_path_is_verbatim(tmp_path) -> None:
    """Mythril's spec carries `{venv}/bin/myth`; that must not be re-resolved."""
    tool = tmp_path / "myth"
    tool.write_text("#!/bin/sh\n")
    tool.chmod(0o755)
    assert ToolRegistry._resolve(str(tool)) == str(tool)
    assert ToolRegistry._resolve(str(tmp_path / "absent")) == ""


def test_rust_toolchain_is_registered() -> None:
    """A Polkadot-SDK / runtime target is unreadable without these.

    The EVM engines cannot consume Rust, so the registry has to name the tools
    the Rust compatibility entry promises; otherwise `compat check` can be
    satisfied on paper while nothing on the host can compile the target.
    """
    names = {s.name for s in RUST_TOOLCHAIN}
    assert {"rustc", "cargo", "cargo-fuzz", "cargo-audit", "cargo-deny"} <= names
    for spec in RUST_TOOLCHAIN:
        assert spec.version_cmd and spec.functional_cmd
        assert spec.functional_expect, f"{spec.name} has no functional expectation"


def test_venv_expansion_is_per_tool_not_mythrils(monkeypatch) -> None:
    """`{venv}` used to expand to mythril's directory for *every* tool.

    A second isolated tool would then have been pointed at mythril's interpreter
    and reported either missing or -- worse -- verified against the wrong venv.
    """
    monkeypatch.delenv("BLACKHEART_ARJUN_VENV", raising=False)
    monkeypatch.delenv("BLACKHEART_MYTHRIL_VENV", raising=False)
    arjun = ToolRegistry._venv_for(ToolSpec("arjun", "api", ["x"], ["x"], "x"))
    myth = ToolRegistry._venv_for(
        ToolSpec("myth", "solidity", ["x"], ["x"], "x", venv="mythril"))
    assert arjun.endswith("/venvs/arjun")
    assert myth.endswith("/venvs/mythril")

    monkeypatch.setenv("BLACKHEART_MYTHRIL_VENV", "/opt/mythril")
    assert ToolRegistry._venv_for(
        ToolSpec("myth", "solidity", ["x"], ["x"], "x", venv="mythril")) == "/opt/mythril"


def test_resolver_searches_the_language_install_roots() -> None:
    """forge lives in ~/.foundry/bin and the go tools in ~/go/bin, neither on PATH.

    Resolving only through PATH made `anvil` report missing on a host where it was
    installed, which is the same defect class that hid every engine earlier.
    """
    dirs = [str(d) for d, _ in _candidate_dirs("rustc")]
    assert any(d.endswith("/.cargo/bin") for d in dirs)
    assert any(d.endswith("/go/bin") for d in dirs)
    assert any(d.endswith("/.foundry/bin") for d in dirs)
