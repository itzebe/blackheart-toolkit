"""The trigger and bounty CLI paths must be real, not just importable.

These tests drive the actual ``python -m blackheart`` entry points end to end so a
regression in argument wiring, ledger location, or exit codes fails the suite
rather than surfacing only when an operator runs the command.
"""

from __future__ import annotations

import json

import pytest

from blackheart.cli import main


def _authz_file(tmp_path):
    from blackheart.authz import new_record
    from blackheart.models import utcnow
    r = new_record("demo", "local", "http://localhost", "http://localhost/scope",
                   program_active=True, safe_harbor=True, poc_required=True,
                   nigerian_eligible=True, payout_feasible=True, zero_cost=True)
    r.asset_classes = {"vault": "AUTHORIZED"}
    r.verified = True
    r.evidence = [{"kind": "scope-capture", "url": "http://localhost/scope",
                   "retrieved_at": utcnow(), "sha256": "0" * 64}]
    p = tmp_path / "authz.json"
    p.write_text(json.dumps(r.to_dict()))
    return p


def test_cli_manual_trigger_creates_job(tmp_path, capsys):
    authz = _authz_file(tmp_path)
    payload = tmp_path / "payload.json"
    payload.write_text(json.dumps({"kind": "hunt", "target": "access-control",
                                   "asset": "vault"}))
    rc = main(["trigger", "--dir", str(tmp_path / "sched"), "--authz", str(authz),
               "manual", "--payload", str(payload)])
    out = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert out["state"] == "ACCEPTED"
    assert out["created_job"] is True

    # The job is really on disk and listed by the schedule CLI.
    rc = main(["schedule", "--dir", str(tmp_path / "sched"), "list"])
    jobs = json.loads(capsys.readouterr().out)
    assert len(jobs) == 1
    assert jobs[0]["job_id"] == out["job_id"]


def test_cli_trigger_unauthorized_exits_nonzero(tmp_path, capsys):
    authz = _authz_file(tmp_path)          # only 'vault' is authorized
    payload = tmp_path / "payload.json"
    payload.write_text(json.dumps({"kind": "hunt", "target": "x",
                                   "asset": "not-in-scope"}))
    rc = main(["trigger", "--dir", str(tmp_path / "sched"), "--authz", str(authz),
               "manual", "--payload", str(payload)])
    out = json.loads(capsys.readouterr().out)
    assert rc == 1
    assert out["state"] == "REJECTED"
    assert out["created_job"] is False


def test_cli_trigger_verify(tmp_path, capsys):
    authz = _authz_file(tmp_path)
    payload = tmp_path / "payload.json"
    payload.write_text(json.dumps({"kind": "hunt", "target": "access-control",
                                   "asset": "vault"}))
    main(["trigger", "--dir", str(tmp_path / "sched"), "--authz", str(authz),
          "manual", "--payload", str(payload)])
    capsys.readouterr()
    rc = main(["trigger", "--dir", str(tmp_path / "sched"), "verify"])
    out = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert out["status"] == "VERIFIED"


def test_cli_bounty_capture_and_evaluate(tmp_path, capsys):
    text = tmp_path / "policy.txt"
    text.write_text("Acme scope: vault in scope. reentrancy -> critical. "
                    "Payouts: critical $50000.")
    snap_path = tmp_path / "snapshot.json"
    rc = main(["bounty", "--dir", str(tmp_path / "bounty"), "capture",
               "--program", "Acme", "--source-url", "https://acme.example/scope",
               "--retrieved-at", "2026-01-01T00:00:00+00:00",
               "--text", str(text), "--out", str(snap_path)])
    assert rc == 0
    capsys.readouterr()

    from blackheart.bounty import PolicySnapshot, ProgramPolicy
    snap = PolicySnapshot.from_dict(json.loads(snap_path.read_text()))
    policy = ProgramPolicy(program="Acme", snapshot=snap,
                           assets={"vault": "in_scope"},
                           severity_definitions={"reentrancy": "critical"},
                           payouts={"critical": "$50000"})
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(json.dumps(policy.to_dict()))
    finding_path = tmp_path / "finding.json"
    finding_path.write_text(json.dumps({
        "finding_id": "F-1", "title": "Reentrancy", "target": "vault",
        "classification": "CONFIRMED", "severity": "critical",
        "category": "reentrancy", "impact": "theft", "evidence_ids": ["ev-1"],
    }))

    rc = main(["bounty", "--dir", str(tmp_path / "bounty"), "evaluate",
               "--policy", str(policy_path), "--finding", str(finding_path)])
    out = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert out["outcome"] == "VALID_AND_PAYABLE"
    assert out["policy_sha256"] == snap.sha256


def test_cli_bounty_verify_policy_detects_tamper(tmp_path, capsys):
    text = tmp_path / "policy.txt"
    text.write_text("original policy text")
    snap_path = tmp_path / "snapshot.json"
    main(["bounty", "--dir", str(tmp_path / "bounty"), "capture",
          "--program", "Acme", "--source-url", "https://acme.example/scope",
          "--retrieved-at", "2026-01-01T00:00:00+00:00",
          "--text", str(text), "--out", str(snap_path)])
    capsys.readouterr()

    # Tamper with the captured text: the stored hash no longer matches.
    data = json.loads(snap_path.read_text())
    data["captured_text"] = "tampered policy text"
    snap_path.write_text(json.dumps(data))
    rc = main(["bounty", "verify-policy", "--snapshot", str(snap_path)])
    out = json.loads(capsys.readouterr().out)
    assert rc == 1
    assert out["verified"] is False
