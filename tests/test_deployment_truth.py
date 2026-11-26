"""Deployment truth never upgrades bytecode-only to verified source."""

from __future__ import annotations

from types import SimpleNamespace

from blackheart.deployed import DeployedContract
from blackheart.ingest.truth import truth_for_deployment
from blackheart.verified_source import Attestation


def _deployed(**kwargs):
    base = dict(address="0xabc", chain_id=1, block_number=10, code="0x6000",
                code_sha256="abc", code_size=2, is_contract=True, verified=True)
    base.update(kwargs)
    return DeployedContract(**base)


def _att(status="verified", files=("Vault.sol",)):
    bundle = SimpleNamespace(fingerprint=lambda: "fp") if status == "verified" else None
    return Attestation(1, "0xabc", status, bundle=bundle, files=list(files),
                       compiler="0.8.20")


def test_no_code_is_unverified_or_unavailable():
    assert truth_for_deployment(_deployed(verified=False)).status == "UNVERIFIED"
    assert truth_for_deployment(
        _deployed(verified=False, limitations=["RPC unavailable"])).status == "UNAVAILABLE"


def test_real_code_without_source_is_bytecode_only():
    truth = truth_for_deployment(_deployed(), attestation=_att("not_verified"))
    assert truth.status == "BYTECODE_ONLY"
    assert not truth.has_verified_source
    assert any("no verified source" in item for item in truth.limitations)


def test_verified_source_is_recorded_with_its_fingerprint():
    truth = truth_for_deployment(_deployed(), attestation=_att())
    assert truth.status == "SOURCE_VERIFIED"
    assert truth.source_fingerprint == "fp"
    assert truth.source_compiler == "0.8.20"


def test_a_proxy_can_be_implementation_verified():
    truth = truth_for_deployment(
        _deployed(proxy=True, proxy_kind="eip1967", implementation="0xdef"),
        attestation=_att("not_verified"), implementation_attestation=_att())
    assert truth.status == "IMPLEMENTATION_VERIFIED"
    assert truth.implementation == "0xdef"
    assert truth.implementation_source_status == "verified"


def _bundle(files):
    return SimpleNamespace(fingerprint=lambda: "fp", files=files)


def _bound_att(files):
    return Attestation(1, "0xabc", "verified", bundle=_bundle(files),
                       files=list(files), compiler="0.8.20")


def test_bind_verified_source_reports_exact_and_mismatch():
    from blackheart.ingest.verified import bind_verified_source

    att = _bound_att({"Vault.sol": "contract Vault {}"})
    exact = bind_verified_source(att, b"\x60\x00",
                                 recompile=lambda files, compiler: b"\x60\x00")
    assert exact.status == "EXACT" and exact.bound
    mismatch = bind_verified_source(att, b"\x60\x00",
                                    recompile=lambda files, compiler: b"\x61\x00")
    assert mismatch.status == "MISMATCH" and not mismatch.bound


def _truth(**over):
    truth = {
        "status": "SOURCE_VERIFIED", "address": "0x" + "1" * 40, "chain_id": 1,
        "source_status": "verified", "source_bound": True,
        "runtime_binding": {"status": "EXACT", "bound": True},
    }
    truth.update(over)
    return truth


def test_validate_deployment_truth_requires_a_bound_runtime():
    from blackheart.ingest.truth import validate_deployment_truth

    assert validate_deployment_truth(_truth())[0] is True
    assert validate_deployment_truth({})[0] is False
    assert validate_deployment_truth(_truth(status="BYTECODE_ONLY"))[0] is False
    assert validate_deployment_truth(_truth(source_bound=False))[0] is False
    assert validate_deployment_truth(
        _truth(runtime_binding={"status": "MISMATCH"}))[0] is False
    assert validate_deployment_truth(_truth(address=""))[0] is False
    assert validate_deployment_truth(_truth(chain_id=None))[0] is False


def test_validate_deployment_truth_binds_a_proxy_implementation():
    from blackheart.ingest.truth import validate_deployment_truth

    truth = _truth(
        status="IMPLEMENTATION_VERIFIED",
        implementation_source_status="verified",
        implementation_source_bound=True,
        implementation_runtime_binding={"status": "METADATA_ONLY"},
    )
    assert validate_deployment_truth(truth)[0] is True
    assert validate_deployment_truth(
        dict(truth, implementation_source_bound=False))[0] is False


def test_an_address_finding_cannot_be_confirmed_without_deployment_truth():
    from dataclasses import replace

    from blackheart.findings import FindingRecord

    record = FindingRecord(
        finding_id="BH-ADDR-1", title="vault bug", target="0x" + "1" * 40,
        evidence_ids=["ev-1"], verification_result="reproduced",
        reviewer="reviewer-2", deployment_truth=_truth(),
    )
    assert record.confirm() is True
    refused = replace(record, deployment_truth={}, status="UNCONFIRMED")
    assert refused.confirm() is False
    assert any("deployment truth" in item
               for item in refused.missing_confirmation_fields())
    named = replace(record, target="reference-vault", deployment_truth={},
                    status="UNCONFIRMED")
    assert named.confirm() is True


def test_findings_confirm_requires_and_accepts_deployment_truth(tmp_path, capsys):
    import json

    from blackheart.cli import main as cli_main
    from blackheart.evidence import EvidenceStore

    evidence = EvidenceStore(str(tmp_path / "evidence")).put_json(
        {"run": "reproduced"}, kind="poc", description="address finding")
    finding = {
        "finding_id": "BH-ADDR-1", "title": "vault bug",
        "target": "0x" + "1" * 40, "evidence_ids": [evidence.evidence_id],
        "verification_result": "reproduced", "reviewer": "reviewer-2",
    }
    finding_path = tmp_path / "finding.json"
    finding_path.write_text(json.dumps(finding), encoding="utf-8")
    truth_path = tmp_path / "truth.json"
    truth_path.write_text(json.dumps(_truth()), encoding="utf-8")
    base = ["findings", "--dir", str(tmp_path / "findings")]

    assert cli_main([*base, "add", "--file", str(finding_path)]) == 0
    capsys.readouterr()
    assert cli_main([*base, "confirm", "--finding", "BH-ADDR-1",
                     "--evidence", str(tmp_path / "evidence")]) == 1
    refused = json.loads(capsys.readouterr().out)
    assert refused["confirmed"] is False
    assert "deployment truth" in refused["reason"]

    assert cli_main([*base, "confirm", "--finding", "BH-ADDR-1",
                     "--evidence", str(tmp_path / "evidence"),
                     "--deployment-truth", str(truth_path)]) == 0
    accepted = json.loads(capsys.readouterr().out)
    assert accepted["confirmed"] is True


def test_deployment_truth_binds_the_source_to_the_runtime(monkeypatch):
    from blackheart.ingest import truth as truth_mod

    deployed = _deployed(code="0x6000", code_sha256="sha")
    att = Attestation(1, "0xabc", "verified",
                      bundle=SimpleNamespace(fingerprint=lambda: "fp",
                                             files={"Vault.sol": "contract Vault {}"}),
                      files=["Vault.sol"], compiler="0.8.20")
    monkeypatch.setattr(truth_mod, "verify_contract", lambda *a, **k: deployed)
    monkeypatch.setattr(truth_mod, "attest", lambda *a, **k: att)
    out = truth_mod.deployment_truth(
        "0xabc", "http://rpc", recompile=lambda files, compiler: b"\x60\x00")
    assert out.status == "SOURCE_VERIFIED"
    assert out.source_bound is True
    assert out.runtime_binding["status"] == "EXACT"
    assert truth_mod.validate_deployment_truth(out.to_dict())[0] is True

    mismatch = truth_mod.deployment_truth(
        "0xabc", "http://rpc", recompile=lambda files, compiler: b"\x61\x00")
    assert mismatch.source_bound is False
    assert mismatch.runtime_binding["status"] == "MISMATCH"
    assert truth_mod.validate_deployment_truth(mismatch.to_dict())[0] is False
