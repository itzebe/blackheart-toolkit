"""Close-the-loop pipeline: verified source -> price -> verify -> finding."""

from __future__ import annotations

from pathlib import Path

from blackheart.findings import FindingRepository
from blackheart.pipeline import PipelineConfig, run_pipeline
from blackheart.toolchain.enforce import (
    ExecutionTarget,
    authorized_execution,
    self_test_record,
)
from blackheart.watch.source import SourceBundle

VULNERABLE = """
contract Vault {
    mapping(address => uint) balance;
    uint totalSupply;
    function mint(uint amount) external { balance[msg.sender] += amount; }
}
"""

CLEAN = """
contract Vault {
    mapping(address => uint) balance;
    uint totalSupply;
    function deposit(uint amount) external { balance[msg.sender] += amount; totalSupply += amount; }
}
"""

ADDRESS = "0xAbCdEf01234567890123456789012345678901234"
CONTROL = "0x9999999999999999999999999999999999999999"


class FakeClient:
    def __init__(self, bundles):
        self.bundles = bundles

    def fetch(self, chain_id, address):
        bundle = self.bundles.get(address.lower())
        if bundle is not None:
            return bundle
        return SourceBundle(chain_id=chain_id, address=address.lower(),
                            status="not_verified", ok=False, error="not found")


def _bundle(address, source):
    return SourceBundle(
        chain_id=1, address=address.lower(), status="verified", ok=True,
        files={"Vault.sol": source}, compiler="solc",
        compiler_version="0.8.20",
    )


def _run(tmp_path: Path, *, control: bool = True, clean: bool = False,
         in_scope: bool = True, authorized: bool = True, repository: str = "blackheart",
         compatibility=None, mutation_audit: bool = False,
         bind_runtime: bool = True):
    client = FakeClient({
        ADDRESS.lower(): _bundle(ADDRESS, CLEAN if clean else VULNERABLE),
        CONTROL.lower(): _bundle(CONTROL, CLEAN),
    })
    config = PipelineConfig(
        chain_id=1, address=ADDRESS,
        control_address=CONTROL if control else "",
        repository=repository,
        findings_root=str(tmp_path / "findings"),
        evidence_root=str(tmp_path / "evidence"),
        reports_root=str(tmp_path / "reports"),
        client=client,
        in_scope=True if in_scope else None,
        authorization_gate_passed=True if authorized else None,
        compatibility=compatibility,
        run_mutation_audit=mutation_audit,
        runtime_code=b"\x60\x00" if bind_runtime else None,
        recompile=(lambda files, compiler: b"\x60\x00") if bind_runtime else None,
    )
    with authorized_execution(self_test_record(),
                              ExecutionTarget(name="ingest:Vault", repository="blackheart"),
                              "test"):
        return run_pipeline(config)


def test_verified_source_with_a_guarded_control_confirms_a_finding(tmp_path):
    result = _run(tmp_path)
    assert result.status == "VERIFIED"
    assert result.confirmed
    assert result.finding_status == "CONFIRMED"
    assert result.invariant_id.startswith("conservation:")
    assert result.economic["financial_impact_established"]
    assert result.economic["value_created"] > 0
    repo = FindingRepository(tmp_path / "findings")
    record = repo.get(result.finding_id)
    assert record is not None and record.status == "CONFIRMED"
    assert record.evidence_ids
    assert record.verification_result


def test_without_a_control_the_finding_stays_strongly_supported(tmp_path):
    result = _run(tmp_path, control=False)
    assert result.status == "REPRODUCED"
    assert not result.confirmed
    assert result.finding_status == "STRONGLY_SUPPORTED"
    assert "not confirmed" in result.verdict_line().lower()


def test_without_a_runtime_binding_the_finding_is_not_confirmed(tmp_path):
    result = _run(tmp_path, bind_runtime=False)
    assert result.status == "VERIFIED"
    assert not result.confirmed
    assert result.finding_status == "STRONGLY_SUPPORTED"
    record = FindingRepository(tmp_path / "findings").get(result.finding_id)
    assert record is not None
    assert record.deployment_truth["source_bound"] is False
    assert any("deployment truth" in item for item in record.missing_confirmation_fields())


def test_a_clean_target_is_a_bounded_negative_with_no_finding(tmp_path):
    result = _run(tmp_path, clean=True)
    assert result.status == "NO_VIOLATION"
    assert result.finding_id == ""
    assert "bounded" in result.verdict_line().lower()
    assert not (tmp_path / "findings").exists()


def test_a_control_that_also_violates_rejects_the_finding(tmp_path):
    client = FakeClient({
        ADDRESS.lower(): _bundle(ADDRESS, VULNERABLE),
        CONTROL.lower(): _bundle(CONTROL, VULNERABLE),
    })
    config = PipelineConfig(
        chain_id=1, address=ADDRESS, control_address=CONTROL,
        repository="blackheart",
        findings_root=str(tmp_path / "findings"),
        evidence_root=str(tmp_path / "evidence"),
        reports_root=str(tmp_path / "reports"),
        client=client, in_scope=True, authorization_gate_passed=True,
    )
    with authorized_execution(self_test_record(),
                              ExecutionTarget(name="ingest:Vault", repository="blackheart"),
                              "test"):
        result = run_pipeline(config)
    assert result.status == "CERTIFIED_LEAD"
    assert result.finding_id == ""
    assert result.verification["disposition"] == "REJECTED"


def test_an_unverified_address_is_not_a_model(tmp_path):
    client = FakeClient({})
    config = PipelineConfig(
        chain_id=1, address=ADDRESS, repository="blackheart",
        findings_root=str(tmp_path / "findings"),
        evidence_root=str(tmp_path / "evidence"),
        reports_root=str(tmp_path / "reports"),
        client=client,
    )
    result = run_pipeline(config)
    assert result.status == "NOT_VERIFIED"
    assert result.model is None
    assert result.finding_id == ""


def test_a_mismatched_compatibility_record_blocks_before_the_model(tmp_path):
    result = _run(tmp_path, repository="not-blackheart",
                  compatibility=self_test_record())
    assert result.status == "BLOCKED"
    assert result.model is None
    assert result.finding_id == ""
    assert not (tmp_path / "findings").exists()


def test_the_cli_runs_the_loop_and_returns_zero_on_a_verified_result(tmp_path, monkeypatch):
    from blackheart.cli import main

    fake_client = FakeClient({
        ADDRESS.lower(): _bundle(ADDRESS, VULNERABLE),
        CONTROL.lower(): _bundle(CONTROL, CLEAN),
    })
    def fake_attest(chain_id, address, client=None):
        bundle = fake_client.fetch(chain_id, address)  # the CLI supplies no client
        from blackheart.verified_source import Attestation
        return Attestation(chain_id=chain_id, address=address.lower(),
                           status=bundle.status, bundle=bundle,
                           files=sorted(bundle.files), compiler=bundle.compiler_version,
                           reason="verified source fetched")

    monkeypatch.setattr("blackheart.pipeline.attest", fake_attest)
    code = main([
        "pipeline", "--chain-id", "1", "--address", ADDRESS,
        "--control-address", CONTROL, "--repository", "blackheart",
        "--findings", str(tmp_path / "findings"),
        "--evidence", str(tmp_path / "evidence"),
        "--reports", str(tmp_path / "reports"),
        "--in-scope", "--authorized", "--report", "--json",
    ])
    assert code == 0
    assert (tmp_path / "findings" / "findings.jsonl").exists()
    assert list((tmp_path / "reports").glob("*.md"))


def test_no_authority_blocks_before_the_model(tmp_path):
    from blackheart.toolchain.enforce import no_authority

    client = FakeClient({ADDRESS.lower(): _bundle(ADDRESS, VULNERABLE)})
    config = PipelineConfig(
        chain_id=1, address=ADDRESS, repository="blackheart",
        findings_root=str(tmp_path / "findings"),
        evidence_root=str(tmp_path / "evidence"),
        reports_root=str(tmp_path / "reports"),
        client=client,
    )
    with no_authority():
        result = run_pipeline(config)
    assert result.status == "BLOCKED"
    assert result.model is None
    assert not (tmp_path / "findings").exists()


def test_the_optional_mutation_audit_is_a_stage_not_a_finding_upgrade(tmp_path):
    result = _run(tmp_path, mutation_audit=True)
    stage = next(s for s in result.stages if s.stage == "mutate")
    assert stage.status in ("TRUSTWORTHY", "WEAK")
    assert result.mutation
    # The audit informs the invariant, it does not change the verdict by itself.
    assert result.status == "VERIFIED"
