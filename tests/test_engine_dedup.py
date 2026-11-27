"""Deduplication, cross-engine corroboration and its persistence.

The rule under test: the same defect seen by two engines is *one* cluster and is
corroborated; two different defects at the same line stay two clusters. Getting
this wrong in either direction is a real failure -- over-merging hides a bug,
under-merging inflates the finding count with the same bug counted twice.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from blackheart.engines.contract import ExecutionMetadata, ExecutionResult
from blackheart.engines.orchestrator import (
    EngineOrchestrator,
    OrchestrationResult,
    _defect_class,
    _structural_key,
)
from blackheart.engines.schema import NormalizedFinding


def _finding(**over) -> NormalizedFinding:
    base = dict(
        source_engine="slither",
        engine_version="0.11.3",
        target_id="/t",
        component="Vault",
        category="reentrancy",
        title="reentrancy-no-eth",
        description="reentrancy in Vault.withdraw",
        source_location="src/Vault.sol:35",
        severity="high",
        confidence="medium",
        cwe="CWE-841",
    )
    base.update(over)
    return NormalizedFinding(**base).finalize()


def _run(orch: EngineOrchestrator, findings: list[NormalizedFinding]):
    result = OrchestrationResult(target="/t")
    result.candidates = findings
    orch._coordinate(result)
    return result


@pytest.fixture
def orch(tmp_path):
    return EngineOrchestrator(tmp_path)


# --------------------------------------------------------------------------- #
# Structural key
# --------------------------------------------------------------------------- #

def test_same_defect_same_key_regardless_of_wording():
    a = _finding(description="reentrancy in withdraw", severity="high")
    b = _finding(source_engine="wake", engine_version="4.22.2",
                 description="external call before state update",
                 severity="medium", title="reentrancy")
    assert _structural_key(a) == _structural_key(b)


def test_different_class_at_same_location_stays_distinct():
    """One line can carry two unrelated bugs; merging them hides one."""
    reentrancy = _finding(category="reentrancy", title="reentrancy-no-eth")
    unchecked = _finding(category="silent-transfer-failure", title="unchecked-transfer",
                         description="unchecked transfer return")
    assert _structural_key(reentrancy) != _structural_key(unchecked)


def test_same_class_at_different_locations_stays_distinct():
    a = _finding(source_location="src/Vault.sol:35", description="reentrancy in withdraw")
    b = _finding(source_location="src/Vault.sol:72", description="reentrancy in repay")
    assert _structural_key(a) != _structural_key(b)


def test_different_component_stays_distinct():
    assert _structural_key(_finding(component="Vault")) != \
        _structural_key(_finding(component="Market"))


def test_locationless_finding_uses_property_name():
    a = _finding(category="property-violation", source_location="", component="",
                 title="falsified property: echidna_no_value_extraction")
    b = _finding(category="sequence-violation", source_location="", component="",
                 source_engine="medusa",
                 title="falsified property: echidna_no_value_extraction (2 call(s))")
    assert _defect_class(a) == _defect_class(b) == "property-violation"
    assert _structural_key(a) == _structural_key(b)
    assert _structural_key(a) != ""


def test_unidentifiable_finding_is_never_merged():
    """No location and no property name: the key is empty, so it cannot collide."""
    anon = _finding(category="property-violation", source_location="", component="",
                    title="something went wrong")
    assert _structural_key(anon) == ""


def test_different_properties_stay_distinct():
    a = _finding(category="property-violation", source_location="", component="",
                 title="falsified property: prop_one")
    b = _finding(category="property-violation", source_location="", component="",
                 title="falsified property: prop_two")
    assert _structural_key(a) != _structural_key(b)


# --------------------------------------------------------------------------- #
# Clustering
# --------------------------------------------------------------------------- #

def test_same_defect_from_two_engines_is_one_corroborated_cluster(orch):
    result = _run(orch, [
        _finding(source_engine="slither", description="reentrancy in withdraw"),
        _finding(source_engine="wake", engine_version="4.22.2",
                 description="state written after external call"),
    ])
    assert len(result.clusters) == 1
    cluster = result.clusters[0]
    assert cluster.corroborated is True
    assert set(cluster.sources) == {"slither", "wake"}
    assert len(cluster.members) == 2


def test_duplicate_is_recorded_not_silently_absorbed(orch):
    result = _run(orch, [
        _finding(source_engine="slither", description="reentrancy in withdraw"),
        _finding(source_engine="wake", description="state written after call"),
    ])
    duplicate = result.clusters[0].members[1]
    assert duplicate.duplicate_of == result.clusters[0].representative.finding_id


def test_two_distinct_defects_are_two_clusters(orch):
    result = _run(orch, [
        _finding(category="reentrancy", title="reentrancy-no-eth"),
        _finding(category="silent-transfer-failure", title="unchecked-transfer",
                 description="unchecked transfer"),
    ])
    assert len(result.clusters) == 2
    assert not any(c.corroborated for c in result.clusters)


def test_one_engine_alone_is_never_corroborated(orch):
    result = _run(orch, [
        _finding(source_location="src/Vault.sol:35", description="reentrancy in withdraw"),
        _finding(source_location="src/Vault.sol:72", description="reentrancy in repay"),
    ])
    assert len(result.clusters) == 2
    assert all(not c.corroborated for c in result.clusters)


def test_corroboration_never_confirms(orch):
    """Two engines agreeing raises confidence; it must not set CONFIRMED."""
    result = _run(orch, [
        _finding(source_engine="slither"),
        _finding(source_engine="wake", engine_version="4.22.2"),
    ])
    cluster = result.clusters[0]
    assert cluster.corroborated
    assert cluster.disposition != "CONFIRMED"


def test_engine_cannot_self_promote_its_own_claim(orch):
    """An engine's own CONFIRMED claim is demoted and kept only as provenance."""
    finding = _finding()
    finding.disposition = "CONFIRMED"
    result = _run(orch, [finding])
    assert result.candidates[0].disposition == "NEEDS_MORE_EVIDENCE"
    assert result.candidates[0].raw.get("engine_disposition_claim") == "CONFIRMED"


def test_duplicate_clusters_do_not_inflate_the_count(orch):
    """N engines reporting one defect is one finding, not N."""
    findings = [_finding(source_engine=e, engine_version="1")
                for e in ("slither", "wake", "medusa", "echidna")]
    result = _run(orch, findings)
    assert len(result.clusters) == 1
    assert len(result.clusters[0].members) == 4


# --------------------------------------------------------------------------- #
# Persistence
# --------------------------------------------------------------------------- #

def test_corroboration_survives_a_reload(orch, tmp_path):
    """A saved run must still report corroboration when read back.

    Rebuilding state from the cluster representatives alone would erase the
    cross-engine agreement, so the CLI would deny what the run recorded.
    """
    from blackheart.engines import session

    result = _run(orch, [
        _finding(source_engine="slither", description="reentrancy in withdraw"),
        _finding(source_engine="wake", engine_version="4.22.2",
                 description="state written after external call"),
    ])
    assert result.clusters[0].corroborated is True

    (tmp_path / session.STATE_FILENAME).write_text(
        json.dumps(result.to_dict(), indent=2, default=str), encoding="utf-8")

    reloaded = session.load_state(tmp_path)
    assert reloaded is not None
    assert len(reloaded.clusters) == 1
    assert reloaded.clusters[0].corroborated is True
    assert set(reloaded.clusters[0].sources) == {"slither", "wake"}
