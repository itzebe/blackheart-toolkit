"""Harness dependency provisioning, without needing a toolchain to run.

`harnesses/*/lib/` is git-ignored and re-created by a fetch script, so a fresh
clone has no `forge-std`. A harness whose dependencies cannot be fetched cannot
compile, and every engine pointed at it fails to compile rather than reporting a
finding -- a toolchain error that reads like a clean scan.

That is not hypothetical: the adversarial harness, which the live engine tests
and `blackheart adversarial` both drive, shipped no fetch script, so halmos
failed with `import "forge-std/Test.sol"` unresolved and the live test failed
for a reason that had nothing to do with the target.

These tests are deterministic and run without Foundry installed.
"""

from __future__ import annotations

import os
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
ADVERSARIAL = REPO_ROOT / "harnesses" / "adversarial"


def test_adversarial_harness_declares_its_dependencies():
    """The harness the engine tests drive must be able to re-create its libs."""
    fetch = ADVERSARIAL / "fetch.sh"
    assert fetch.is_file(), (
        "harnesses/adversarial/fetch.sh is missing; without it a fresh clone "
        "cannot resolve forge-std and every engine fails to compile the harness")
    assert os.access(fetch, os.X_OK), "harnesses/adversarial/fetch.sh is not executable"

    text = fetch.read_text(encoding="utf-8")
    assert "forge-std" in text, "the fetch script does not install forge-std"
    # A floating branch would make a counterexample irreproducible.
    assert "v1.9.0" in text or "--branch" in text, (
        "the forge-std checkout is not pinned to a revision")


def test_adversarial_harness_actually_imports_forge_std():
    """Guard the test above: if nothing imports forge-std, it proves nothing."""
    imports = [
        p for p in ADVERSARIAL.rglob("*.sol")
        if p.is_file() and "forge-std" in p.read_text(encoding="utf-8", errors="replace")
    ]
    assert imports, "the adversarial harness no longer imports forge-std; revisit fetch.sh"


# --------------------------------------------------------------------------- #
# Engine invocation: resolution and report parsing, without running an engine.
# --------------------------------------------------------------------------- #

def test_engine_argv_is_resolved_through_the_engine_layer(monkeypatch):
    """A bare engine name must resolve to the venv binary, not to PATH.

    Every engine test used to skip and every `blackheart adversarial` run used to
    report `not found on PATH`, because the driver resolved with `shutil.which`
    while `engines bootstrap` installs into venvs that are deliberately off PATH.
    """
    from blackheart import adversarial
    from blackheart.engines.solidity import base

    monkeypatch.setattr(base, "resolve_tool",
                        lambda tool, **_kw: base.ToolPaths(f"/venv/bin/{tool}", "/venv/bin"))
    monkeypatch.setattr(base, "toolchain_bin_dirs", lambda: ["/foundry/bin"])

    argv, env = adversarial._resolve_argv(["echidna", "test/Echidna.sol"])
    assert argv[0] == "/venv/bin/echidna"
    assert argv[1] == "test/Echidna.sol"
    # crytic-compile shells out to forge/solc from inside the engine.
    assert env["PATH"].split(":")[0] == "/foundry/bin"


def test_slither_report_is_read_from_json_not_text():
    """Slither 0.11's text report names only a wiki anchor, not the detector id.

    A text grep for `reentrancy-no-eth` therefore finds nothing even when the
    detector fired, which is why the driver reads the JSON report.
    """
    import json as _json

    from blackheart.adversarial import _slither_detectors

    report = {
        "results": {
            "detectors": [
                {"check": "reentrancy-no-eth",
                 "elements": [{"type": "function", "name": "withdraw",
                               "type_specific_fields": {"parent": {"name": "VulnerableVault"}}}]},
            ]
        }
    }
    combined = "'forge clean' running...\nINFO:Detectors:\n" + _json.dumps(report) + "\nINFO:Done\n"
    detectors = _slither_detectors(combined)
    assert [d["check"] for d in detectors] == ["reentrancy-no-eth"]
    assert detectors[0]["elements"][0]["type_specific_fields"]["parent"]["name"] == "VulnerableVault"
    assert _slither_detectors("no json here") == []


def test_the_adversarial_harness_disables_dynamic_test_linking():
    """forge's virtual `foundry-pp/` sources break crytic-compile.

    Echidna, Medusa and Slither all compile through crytic-compile, which reads
    forge's build-info. With dynamic test linking on, that build-info references
    `foundry-pp/DeployHelper<sha>.sol` files that are never written to disk, so
    compilation fails and the engine never runs.
    """
    config = (ADVERSARIAL / "foundry.toml").read_text(encoding="utf-8")
    assert "dynamic_test_linking = false" in config
