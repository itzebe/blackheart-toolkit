"""Adversarial acceptance tests for engine-level compatibility enforcement.

PR #82 made the language-aware policy mandatory in the doctrine, the prompts, the
agents, the skills and the CLI. That is documentation *about* enforcement. These
tests prove the enforcement itself, at the boundaries where a target is actually
acted upon, and they are written the way the policy demands: a blocked run must
leave the engine's invocation count at exactly zero, not merely print an error.
Every negative test therefore spies on the real execution primitive and asserts
it was never entered.

The suite runs under the repository self-test record (see ``tests/conftest.py``);
the tests here suspend it with ``no_authority()`` or hand in a record bound to a
different target, which is what an unprivileged caller would have to do to try a
bypass.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from blackheart.authz import new_record
from blackheart.campaign import Campaign
from blackheart.engines.contract import (
    EngineAdapter,
    EngineState,
    ExecutionMetadata,
    ExecutionResult,
    Health,
)
from blackheart.engines.orchestrator import EngineOrchestrator
from blackheart.hunt import HuntConfig, hunt
from blackheart.invariants import engine as invariant_engine
from blackheart.models import utcnow
from blackheart.objectives import TargetProfile
from blackheart.statespace import (
    ExploreConfig,
    HypothesisGenerator,
    StateSpaceExplorer,
    make_fixture,
)
from blackheart.toolchain import CompatibilityRecord, status_meaning
from blackheart.toolchain.enforce import (
    CompatibilityError,
    ExecutionTarget,
    authorized_execution,
    bind,
    no_authority,
    self_test_record,
)

ROOT = Path(__file__).resolve().parent.parent


def record_for(target: str, **overrides) -> CompatibilityRecord:
    """A complete, official, smoke-tested record for ``target`` (Python stack)."""
    base = dict(
        target_component=target,
        language="Python",
        language_version=">=3.11",
        framework="pytest",
        runtime="CPython",
        tool="pytest",
        compatibility_evidence="https://docs.python.org/3/library/unittest.html",
        selection_reason="the target is a Python model run by the in-process engine",
        expected_coverage="the declared target only",
        known_limitations="a model is representative, not exhaustive",
        smoke_test="passed",
    )
    base.update(overrides)
    return CompatibilityRecord(**base)


class Spy:
    """A call counter used to prove an engine was never invoked."""

    def __init__(self) -> None:
        self.calls: list[tuple] = []

    def __call__(self, *args, **kwargs):
        self.calls.append((args, tuple(sorted(kwargs))))
        return None


@pytest.fixture
def target():
    return make_fixture("stale-authorization")


# --------------------------------------------------------------------------- #
# 1-5. Every engine entry point is blocked with no record, and never invoked
# --------------------------------------------------------------------------- #

def test_campaign_without_a_record_is_blocked_and_never_generates_objectives(
    tmp_path, monkeypatch
):
    spy = Spy()
    monkeypatch.setattr("blackheart.campaign.generate_objectives", spy)
    record = new_record("eng", "immunefi", "https://x", "https://scope")
    record.assets = {"Vault": "AUTHORIZED"}
    campaign = Campaign("eng", TargetProfile(name="Vault"), record, tmp_path)

    with no_authority():
        with pytest.raises(CompatibilityError) as exc:
            campaign.run_active("Vault")

    assert spy.calls == []
    assert "no compatibility record" in str(exc.value)
    assert exc.value.decision.decision == "BLOCK"


def test_hunt_without_a_record_is_blocked_and_runs_no_stage(target, monkeypatch):
    spy = Spy()
    monkeypatch.setattr("blackheart.hunt.orchestrator._search", spy)

    with no_authority():
        with pytest.raises(CompatibilityError):
            hunt(target, HuntConfig(stages=("search",)))

    assert spy.calls == []


def test_statespace_explore_without_a_record_is_blocked(target, monkeypatch):
    spy = Spy()
    monkeypatch.setattr("blackheart.statespace.explore._run_sequence", spy)
    hypotheses = HypothesisGenerator(target.model()).generate()

    with no_authority():
        with pytest.raises(CompatibilityError):
            StateSpaceExplorer(target, ExploreConfig()).explore(hypotheses.hypotheses)

    assert spy.calls == []


def test_run_sequence_directly_without_a_record_is_blocked(target):
    from blackheart.statespace.explore import run_sequence

    with no_authority():
        with pytest.raises(CompatibilityError):
            run_sequence(target, [])


def test_invariant_engine_without_a_record_is_blocked(monkeypatch):
    from blackheart.invariants.registry import make_target

    spy = Spy()
    monkeypatch.setattr("blackheart.invariants.engine._run_sequence", spy)
    t = make_target("vulnerable")

    with no_authority():
        with pytest.raises(CompatibilityError):
            invariant_engine.run_sequence(t, [])

    assert spy.calls == []


# --------------------------------------------------------------------------- #
# 6-9. Dispatch and adapters: no subprocess without the gate
# --------------------------------------------------------------------------- #

def _spy_engine(monkeypatch, calls: list) -> EngineAdapter:
    """An adapter whose scan records its own invocation and would spawn a process."""
    monkeypatch.setattr(
        "blackheart.engines.contract.run_bounded",
        lambda *a, **k: calls.append(("run_bounded", a)),
    )

    class SpyAdapter(EngineAdapter):
        name = "spy"

        def detect_installation(self) -> bool:
            return True

        def verify_health(self) -> Health:
            return Health(state=EngineState.INSTALLED, version="1")

        def execute_scan(self, target, **options):
            calls.append(("execute_scan", target))
            from blackheart.engines.contract import run_bounded

            run_bounded([sys.executable, "-c", "print(1)"], cwd=".")
            return ExecutionResult(
                metadata=ExecutionMetadata(engine="spy", version="1", argv=[], cwd=".",
                                           started_at=utcnow())
            )

    return SpyAdapter(".")


def test_orchestrator_run_without_a_record_is_blocked_and_launches_nothing(monkeypatch):
    calls: list = []
    adapter = _spy_engine(monkeypatch, calls)
    orchestrator = EngineOrchestrator(".", adapters=[adapter])

    with no_authority():
        with pytest.raises(CompatibilityError):
            orchestrator.run("target")

    assert calls == []


def test_adapter_execute_scan_directly_without_authority_is_blocked(monkeypatch):
    calls: list = []
    adapter = _spy_engine(monkeypatch, calls)

    with no_authority():
        with pytest.raises(CompatibilityError):
            adapter.execute_scan("target")

    assert calls == []


def test_a_new_adapter_subclass_cannot_skip_the_gate():
    calls: list = []

    class Rogue(EngineAdapter):
        name = "rogue"

        def detect_installation(self) -> bool:
            return True

        def verify_health(self) -> Health:
            return Health(state=EngineState.INSTALLED)

        def execute_scan(self, target, **options):
            calls.append(target)
            return ExecutionResult(
                metadata=ExecutionMetadata(engine="rogue", version="1", argv=[], cwd=".",
                                           started_at=utcnow())
            )

    with no_authority():
        with pytest.raises(CompatibilityError):
            Rogue(".").execute_scan("target")

    assert calls == []


def test_a_valid_record_permits_adapter_execution(monkeypatch):
    calls: list = []
    adapter = _spy_engine(monkeypatch, calls)

    with authorized_execution(record_for("target"), ExecutionTarget(name="target"), "test"):
        adapter.execute_scan("target")

    assert calls and calls[0][0] == "execute_scan"


# --------------------------------------------------------------------------- #
# 10-12. Identity: an authority never covers another target
# --------------------------------------------------------------------------- #

def test_nested_target_cannot_inherit_another_targets_authority(monkeypatch):
    calls: list = []
    monkeypatch.setattr(
        "blackheart.statespace.explore._run_sequence", lambda *a, **k: calls.append(a)
    )
    other = make_fixture("partial-failure")

    with authorized_execution(
        record_for("stale-authorization"),
        ExecutionTarget(name="stale-authorization"),
        "test",
    ):
        with pytest.raises(CompatibilityError) as exc:
            StateSpaceExplorer(other, ExploreConfig()).explore([])

    assert calls == []
    assert "not 'partial-failure'" in str(exc.value)


def test_a_tampered_target_identity_is_blocked():
    decision = bind(record_for("Vault"), ExecutionTarget(name="OtherVault"))
    assert decision.decision == "BLOCK"
    assert any("does not authorise a different target" in r for r in decision.reasons)


def test_repository_mismatch_is_blocked():
    decision = bind(
        record_for("Vault", repository="protocol-a"),
        ExecutionTarget(name="Vault", repository="protocol-b"),
    )
    assert decision.decision == "BLOCK"
    assert any("not 'protocol-b'" in r for r in decision.reasons)


def test_commit_mismatch_is_blocked_and_a_short_sha_is_accepted():
    record = record_for("Vault", repository="protocol-a", commit="abc1234")
    assert bind(record, ExecutionTarget("Vault", "protocol-a", "abc1234def")).admitted

    blocked = bind(record, ExecutionTarget("Vault", "protocol-a", "fffffff"))
    assert blocked.decision == "BLOCK"
    assert any("commit" in r for r in blocked.reasons)


# --------------------------------------------------------------------------- #
# 13-18. Language, tool, framework, runtime, evidence, smoke test
# --------------------------------------------------------------------------- #

def test_a_solidity_tool_on_a_rust_target_is_blocked():
    record = record_for(
        "Vault", language="Rust/Substrate", tool="slither",
        framework="Substrate FRAME", runtime="native host tests",
    )
    decision = bind(record, ExecutionTarget("Vault"))
    assert decision.decision == "BLOCK"
    assert any("not a verified tool" in r for r in decision.reasons)


def test_a_rust_tool_on_a_solidity_target_is_blocked():
    record = record_for(
        "Vault", language="Solidity", tool="cargo",
        framework="Foundry", runtime="EVM",
    )
    assert bind(record, ExecutionTarget("Vault")).decision == "BLOCK"


def test_framework_incompatibility_is_blocked():
    record = record_for(
        "Vault", language="Solidity", tool="slither",
        framework="Substrate FRAME", runtime="EVM",
    )
    decision = bind(record, ExecutionTarget("Vault"))
    assert decision.decision == "BLOCK"
    assert any("Substrate FRAME" in r or "FRAME" in r for r in decision.reasons)


def test_runtime_incompatibility_is_blocked():
    record = record_for(
        "Vault", language="Rust/Substrate", tool="cargo",
        framework="Substrate FRAME", runtime="local anvil",
    )
    decision = bind(record, ExecutionTarget("Vault"))
    assert decision.decision == "BLOCK"
    assert any("anvil" in r for r in decision.reasons)


def test_missing_official_evidence_is_blocked():
    record = record_for("Vault", compatibility_evidence="it worked on the last protocol")
    decision = bind(record, ExecutionTarget("Vault"))
    assert decision.decision == "BLOCK"
    assert any("official documentation" in r for r in decision.reasons)


def test_a_failed_smoke_test_is_blocked():
    record = record_for("Vault", smoke_test="failed")
    decision = bind(record, ExecutionTarget("Vault"))
    assert decision.decision == "BLOCK"
    assert any("smoke test failed" in r for r in decision.reasons)


def test_an_unknown_status_is_rejected():
    with pytest.raises(ValueError):
        status_meaning("MAYBE")


# --------------------------------------------------------------------------- #
# 19-22. Positive: a valid record still runs the engines
# --------------------------------------------------------------------------- #

def test_a_valid_record_permits_the_hunt():
    res = hunt(
        "vulnerable",
        HuntConfig(stages=("search",), corpus_sequences=200, random_runs=60),
        compatibility=record_for("vulnerable"),
    )
    assert res.candidates


def test_a_valid_record_permits_statespace_exploration(target):
    hypotheses = HypothesisGenerator(target.model()).generate()
    report = StateSpaceExplorer(target, ExploreConfig()).explore(
        hypotheses.hypotheses, compatibility=record_for(target.name)
    )
    assert report.target == target.name


def test_a_valid_record_permits_campaign(tmp_path):
    """The compatibility gate admits, and the authorization gate then decides.

    The asset is deliberately left unclassified, so the *authorization* gate is
    what blocks. If the compatibility gate had blocked instead, ``run_active``
    would have raised; a returned result proves the record was admitted.
    """
    record = new_record("eng", "immunefi", "https://x", "https://scope")
    campaign = Campaign("eng", TargetProfile(name="Vault"), record, tmp_path)

    result = campaign.run_active("Vault", compatibility=record_for("Vault"))

    assert not result.allowed
    assert "authorization" in result.blocked_reason.lower() or "asset" in result.blocked_reason.lower()
    assert "compatibility" not in result.blocked_reason.lower()


def test_the_self_test_record_cannot_authorise_a_target_without_a_repository():
    decision = bind(self_test_record(), ExecutionTarget(name="ThirdPartyProtocol"))
    assert decision.decision == "BLOCK"
    assert any("declares none" in r for r in decision.reasons)


# --------------------------------------------------------------------------- #
# 23-24. CLI: exit code and an actionable message
# --------------------------------------------------------------------------- #

def _cli(*args: str):
    return subprocess.run(
        [sys.executable, "-m", "blackheart", *args],
        cwd=ROOT, capture_output=True, text=True, timeout=300,
    )


def test_cli_hunt_without_a_record_exits_2_and_explains_the_remedy():
    r = _cli("hunt", "--target", "vulnerable", "--stages", "search")
    assert r.returncode == 2
    assert "compatibility gate BLOCKED" in r.stderr
    assert "remedy" in r.stderr


def test_cli_hunt_with_a_record_runs(tmp_path):
    path = tmp_path / "record.json"
    path.write_text(json.dumps(record_for("vulnerable").to_dict()), encoding="utf-8")

    r = _cli("hunt", "--target", "vulnerable", "--stages", "search",
             "--compatibility", str(path))

    assert r.returncode in (0, 1)
    assert "hunt target=vulnerable" in r.stdout


# --------------------------------------------------------------------------- #
# 25-28. The remaining execution surfaces: the fork executor and the CLI paths
# --------------------------------------------------------------------------- #

def test_fork_executor_without_a_record_is_blocked_before_any_transaction():
    from blackheart.deployed_multicontract import SequenceStep, run_sequence

    calls: list[object] = []

    class Node:
        address = "0x000000000000000000000000000000000000dEaD"

        def send(self, *args, **kwargs):  # pragma: no cover - must not be reached
            calls.append(args)

    step = SequenceStep(label="transfer", to=Node.address, data="0x",
                        sender="0x" + "0" * 40)

    with no_authority(), pytest.raises(CompatibilityError):
        run_sequence(Node(), [step])

    assert calls == [], "the fork executor sent a transaction without a record"


def test_fork_executor_runs_under_the_self_test_record():
    from blackheart.deployed_multicontract import SequenceStep, run_sequence

    class Node:
        address = "0x000000000000000000000000000000000000dEaD"

    result = run_sequence(Node(), [])
    assert result is not None


def test_cli_engines_run_without_a_record_exits_2(tmp_path):
    r = _cli("engines", "run", "--target", "./examples", "--engines", "strix",
             "--allow-local", "--workdir", str(tmp_path))
    assert r.returncode == 2
    assert "compatibility gate BLOCKED" in r.stderr


def test_cli_campaign_without_a_record_exits_2(tmp_path):
    r = _cli("campaign", "--asset", "asset-a", "--workdir", str(tmp_path))
    assert r.returncode == 2
    assert "compatibility" in r.stderr.lower()


# --------------------------------------------------------------------------- #
# 29-31. The cross-language rule must not fire on a language's own toolchain
# --------------------------------------------------------------------------- #

def test_cairos_own_harness_is_not_read_as_soliditys():
    """'Starknet Foundry' is Cairo's harness; 'Foundry' alone is Solidity's."""
    rec = record_for("x", language="Cairo", framework="Starknet Foundry",
                     runtime="Cairo VM", tool="Starknet Foundry")
    assert bind(rec, ExecutionTarget(name="x")).admitted


def test_a_substrate_runtime_may_name_the_evm():
    """Frontier is Substrate + EVM; naming the EVM is not a Solidity claim."""
    rec = record_for("x", language="Rust/Substrate", framework="FRAME",
                     runtime="EVM (Frontier)", tool="Cargo")
    assert bind(rec, ExecutionTarget(name="x")).admitted


def test_a_solidity_record_naming_frame_is_still_blocked():
    rec = record_for("x", language="Solidity", framework="FRAME", runtime="EVM",
                     tool="Foundry",
                     compatibility_evidence="https://book.getfoundry.sh/")
    decision = bind(rec, ExecutionTarget(name="x"))
    assert not decision.admitted
    assert any("FRAME" in r for r in decision.reasons)
