"""Live execution tests for the Solidity engines.

Every test here runs a real engine binary against the repository's adversarial
harness and skips when that engine is not installed on the host. That split is
deliberate: the deterministic adapter contract is covered by
``tests/test_solidity_engines.py`` (which needs no toolchain), and this file is
the evidence that an engine can actually produce a finding -- the difference
between "installed" and "operational".

Run with ``BLACKHEART_LIVE_ENGINES=1`` to require them: the session fixture then
fails instead of skipping when a binary is missing, which is what the release
gate uses. Without the variable, a missing tool is a skip, never a pass.
"""

from __future__ import annotations

import os
import shutil

import pytest

from blackheart.engines import EngineUnavailable, get_adapter
from blackheart.engines.contract import EngineState

pytestmark = pytest.mark.live

HARNESS = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                       "harnesses", "adversarial")

#: Set by the release gate to turn "engine not installed" from a skip into a
#: failure, so a green run cannot hide a missing toolchain.
REQUIRE_LIVE = os.environ.get("BLACKHEART_LIVE_ENGINES") == "1"


def _installed(name: str) -> bool:
    return get_adapter(name, "/tmp").detect_installation()


def _require(name: str) -> None:
    if not _installed(name):
        if REQUIRE_LIVE:
            pytest.fail(f"{name} is required by BLACKHEART_LIVE_ENGINES=1 but is "
                        f"not installed; run `blackheart engines bootstrap`")
        pytest.skip(f"{name} not installed on this host")


@pytest.fixture(scope="module")
def harness_root() -> str:
    if not os.path.isdir(HARNESS):
        pytest.skip("adversarial harness is absent")
    return HARNESS


@pytest.mark.parametrize("name,method", [
    ("slither", "static-analysis"),
    ("wake", "static-analysis"),
    ("halmos", "symbolic-execution"),
    ("echidna", "property-fuzzing"),
    ("medusa", "sequence-fuzzing"),
])
def test_engine_health_is_honest_about_this_host(name, method, tmp_path):
    """Health is derived from a real probe, never from the adapter existing."""
    adapter = get_adapter(name, tmp_path)
    health = adapter.verify_health()
    if not _installed(name):
        assert health.state is EngineState.MISSING
        return
    assert health.state in (EngineState.INSTALLED,
                            EngineState.CONFIGURATION_ERROR)
    assert health.version or health.state is EngineState.CONFIGURATION_ERROR
    assert method in adapter.analysis_methods()


@pytest.mark.slow
def test_slither_finds_the_known_vulnerable_contract(harness_root, tmp_path):
    _require("slither")
    adapter = get_adapter("slither", tmp_path)
    result = adapter.execute_scan(harness_root, timeout_s=900)

    assert result.state is EngineState.COMPLETED, result.metadata.note
    findings = adapter.normalize_findings(result)
    assert findings, "slither produced no findings against the vulnerable harness"
    assert all(f.source_engine == "slither" for f in findings)
    assert all(f.source_location for f in findings), "a location was lost"


@pytest.mark.slow
def test_wake_finds_detections_and_keeps_provenance(harness_root, tmp_path):
    _require("wake")
    adapter = get_adapter("wake", tmp_path)
    result = adapter.execute_scan(harness_root, timeout_s=900)

    assert result.state is EngineState.COMPLETED, result.metadata.note
    findings = adapter.normalize_findings(result)
    assert findings, "wake produced no detections against the vulnerable harness"
    assert all(f.source_engine == "wake" for f in findings)


@pytest.mark.slow
def test_halmos_produces_a_symbolic_counterexample(harness_root, tmp_path):
    _require("halmos")
    adapter = get_adapter("halmos", tmp_path)
    result = adapter.execute_scan(harness_root, timeout_s=900)

    assert result.state is EngineState.COMPLETED, result.metadata.note
    findings = adapter.normalize_findings(result)
    assert findings, "halmos produced no counterexample against the harness"
    # A symbolic result must never be recorded as a concrete reproduction.
    assert all(f.reproduction_status == "symbolic-counterexample" for f in findings)


@pytest.mark.slow
def test_echidna_falsifies_a_property_with_a_replayable_sequence(harness_root, tmp_path):
    _require("echidna")
    adapter = get_adapter("echidna", tmp_path)
    result = adapter.execute_scan(harness_root, timeout_s=900, test_limit=8000)

    assert result.state is EngineState.COMPLETED, result.metadata.note
    findings = adapter.normalize_findings(result)
    assert findings, "echidna produced no falsified property"
    falsified = findings[0]
    assert falsified.reproduction_status == "observed"
    assert falsified.reproduction, "the minimised sequence was not preserved"
    assert "unresolved" not in falsified.title, "the property name was not recovered"


@pytest.mark.slow
def test_medusa_falsifies_a_property_and_deduplicates(harness_root, tmp_path):
    _require("medusa")
    adapter = get_adapter("medusa", tmp_path)
    result = adapter.execute_scan(harness_root, timeout_s=900, test_limit=3000)

    assert result.state is EngineState.COMPLETED, result.metadata.note
    findings = adapter.normalize_findings(result)
    assert findings, "medusa produced no failing sequence"
    # Corpus files are not findings: one violated property is one finding.
    names = [f.title for f in findings]
    assert len(names) == len(set(names)), f"duplicate findings: {names}"


def test_a_missing_binary_fails_rather_than_reporting_a_clean_scan(tmp_path):
    """The failure path: no binary must never read as "no vulnerabilities".

    The contract is to *raise* EngineUnavailable, not to return an empty
    result: an empty result is indistinguishable from a clean scan, which is
    exactly the mistake this guards against.
    """
    adapter = get_adapter("slither", tmp_path)
    if _installed("slither"):
        pytest.skip("slither is installed; the missing-binary path cannot be probed")
    with pytest.raises(EngineUnavailable):
        adapter.execute_scan(str(tmp_path), timeout_s=30)
