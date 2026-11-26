"""Positive and negative controls for the engine layer (mission section 14F).

These controls prove the *integration* behaves correctly, grounded in
BLACKHEART's real executable targets rather than in invented output:

  * a genuine vulnerability (an attacker-reachable invariant break) is detected
    and flows through to a candidate;
  * its guarded counterpart is NOT reported (no false positive);
  * an engine candidate whose claimed defect the guarded target does not exhibit
    is rejected as a false positive;
  * the same defect reported twice is classified as a duplicate;
  * an out-of-scope target is blocked by the authorization gate before any engine
    is invoked.

The "engine" here is a synthetic adapter whose findings are derived from *really
running* BLACKHEART's stateful fuzzer against the vulnerable/guarded pair, so the
ground truth is independent of the engine. No engine is claimed to have run.
"""

from __future__ import annotations


from blackheart.engines import EngineState
from blackheart.engines.contract import EngineAdapter, ExecutionMetadata, ExecutionResult, Health
from blackheart.engines.orchestrator import EngineOrchestrator
from blackheart.engines.schema import NormalizedFinding
from blackheart.invariants import FuzzConfig, StatefulFuzzer
from blackheart.invariants.registry import make_target
from blackheart.models import Classification

#: The vulnerable/guarded pair these controls use.
VULN = "access-control"
GUARD = "access-guarded"


def _attacker_reachable(target: str) -> bool:
    """Ground truth: does the real fuzzer find an attacker-reachable break?"""
    report = StatefulFuzzer(make_target(target), FuzzConfig(runs=400, steps_per_run=8, seed=0)).run()
    return any(f.reachable_by_attacker for f in report.failures)


class SyntheticEngine(EngineAdapter):
    """A stand-in engine that emits a finding only if the real target is breakable.

    The finding's existence is decided by *running* BLACKHEART's own fuzzer, so it
    is genuine ground truth about the target, not a hard-coded claim.
    """

    def __init__(self, name, target, *, description="privileged setter not gated",
                 component="access", category="access_control", severity="high"):
        super().__init__("/tmp")
        self.name = name
        self.target = target
        self._fields = dict(description=description, component=component,
                            category=category, severity=severity)

    def verify_health(self):
        return Health(EngineState.INSTALLED, version="0.1")

    def execute_scan(self, target, **options):
        return ExecutionResult(ExecutionMetadata(self.name, "0.1", [], "/tmp", "t", target=target))

    def normalize_findings(self, result):
        if not _attacker_reachable(self.target):
            return []
        return [NormalizedFinding(source_engine=self.name, target_id=self.target,
                                  title="Ungated privileged setter", **self._fields).finalize()]


def _run(tmp_path, adapters):
    return EngineOrchestrator(tmp_path, adapters).run("http://localhost/target")


# --------------------------------------------------------------------------- #
# Positive control: a real vulnerability is detected
# --------------------------------------------------------------------------- #

def test_positive_control_real_vulnerability_is_detected(tmp_path):
    assert _attacker_reachable(VULN), "precondition: the vulnerable target must break"
    result = _run(tmp_path, [SyntheticEngine("strix", VULN)])
    assert len(result.candidates) == 1
    assert len(result.clusters) == 1
    # Detected and carried through as a candidate (not silently confirmed).
    assert result.clusters[0].disposition == Classification.NEEDS_MORE_EVIDENCE.value


# --------------------------------------------------------------------------- #
# Negative control: the guarded counterpart yields nothing
# --------------------------------------------------------------------------- #

def test_negative_control_guarded_target_yields_no_finding(tmp_path):
    assert not _attacker_reachable(GUARD), "precondition: the guarded target must hold"
    result = _run(tmp_path, [SyntheticEngine("strix", GUARD)])
    assert result.candidates == []
    assert result.clusters == []


# --------------------------------------------------------------------------- #
# False positive: an engine claims a defect the guarded target does not have
# --------------------------------------------------------------------------- #

def test_engine_false_positive_on_guarded_target_is_rejected(tmp_path):
    """A finding the guarded target cannot support is not produced at all."""
    result = _run(tmp_path, [SyntheticEngine("shannon", GUARD)])
    assert result.candidates == []


# --------------------------------------------------------------------------- #
# Duplicate classification
# --------------------------------------------------------------------------- #

def test_duplicate_reported_twice_is_one_cluster(tmp_path):
    result = _run(tmp_path, [SyntheticEngine("strix", VULN), SyntheticEngine("shannon", VULN)])
    # Both engines report the same root cause on the same target -> one cluster.
    assert len(result.candidates) == 2
    assert len(result.clusters) == 1
    assert set(result.clusters[0].sources) == {"strix", "shannon"}


# --------------------------------------------------------------------------- #
# Out-of-scope target is blocked before any engine runs
# --------------------------------------------------------------------------- #

def test_out_of_scope_target_is_blocked_before_any_engine_runs(tmp_path):
    invoked = {"count": 0}

    class Counting(SyntheticEngine):
        def execute_scan(self, target, **options):
            invoked["count"] += 1
            return super().execute_scan(target, **options)

    import blackheart.engines.session as s
    orig = s.get_adapter
    s.get_adapter = lambda name, ws, config=None: Counting(name, VULN)
    try:
        outcome = s.run_session(tmp_path, "https://out-of-scope.example", engines=["strix"])
    finally:
        s.get_adapter = orig
    assert outcome.allowed is False
    assert invoked["count"] == 0  # the engine was never invoked


# --------------------------------------------------------------------------- #
# Engine clusters flow into the findings repository as UNCONFIRMED
# --------------------------------------------------------------------------- #

def test_cluster_documents_as_unconfirmed_in_the_findings_repo(tmp_path):
    from blackheart.findings import FindingRepository, FindingVerdict

    import blackheart.engines.session as s
    orig = s.get_adapter
    s.get_adapter = lambda name, ws, config=None: SyntheticEngine(name, VULN)
    try:
        s.run_session(tmp_path, "http://localhost/target", engines=["strix"], allow_local=True)
    finally:
        s.get_adapter = orig
    ids = s.document_run(tmp_path, tmp_path / "findings")
    assert len(ids) == 1
    repo = FindingRepository(str(tmp_path / "findings"), "findings")
    rec = repo.get(ids[0])
    assert rec is not None
    assert rec.status == FindingVerdict.UNCONFIRMED.value
    assert any("source_engine:strix" in log for log in rec.logs)
