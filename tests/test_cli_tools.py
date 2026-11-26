"""Tests for the portability/health check and the generic class demonstration."""

from __future__ import annotations

import json

from blackheart.cli import main
from blackheart.demonstrations import run_class_demonstration


def test_doctor_reports_healthy(repo_root, tmp_path, capsys):
    # A valid registry file so the check does not depend on a prior install.
    reg = tmp_path / "registry.json"
    reg.write_text(json.dumps({"tools": [{"name": "forge", "status": "functional"}]}))
    rc = main(["doctor", "--registry", str(reg)])
    out = capsys.readouterr().out
    assert "targets>=10" in out
    assert "agents>=14" in out
    assert rc == 0


def test_doctor_flags_unreadable_registry(repo_root, tmp_path, capsys):
    bad = tmp_path / "not-json.json"
    bad.write_text("this is not json")
    rc = main(["doctor", "--registry", str(bad)])
    assert rc == 1, "a corrupt registry must be reported as an issue"


def test_doctor_never_claims_healthy_with_pending_setup(repo_root, tmp_path, capsys):
    """An incomplete install must not print a bare 'healthy'.

    The discovery layout is post-install setup, so a fresh clone is not a hard
    failure -- but the doctor must not falsely report a ready installation either.
    """
    reg = tmp_path / "registry.json"
    reg.write_text(json.dumps({"tools": [{"name": "forge", "status": "functional"}]}))
    rc = main(["doctor", "--registry", str(reg)])
    out = capsys.readouterr().out
    if "[!!] openhands discovery layout" in out:
        assert "\nhealthy\n" not in out
        assert "setup incomplete" in out
    assert rc == 0


def test_demonstrate_produces_confirmed_finding(tmp_path, capsys):
    rc = main([
        "demonstrate", "--pair", "lending-oracle/lending-oracle-guarded",
        "--runs", "400", "--workdir", str(tmp_path / "demo"),
    ])
    assert rc == 0
    summary = json.loads((tmp_path / "demo" / "demonstration-summary.json").read_text())
    assert summary["status"] == "CONFIRMED"
    assert summary["guarded_failures"] == 0
    assert summary["vulnerable_failures"] >= 1
    assert summary["submission_ready"] is True
    assert summary["report_path"]
    # The finding must be built from real engine output, not placeholders.
    assert summary["finding"]["reproduction_steps"]
    assert "seed=" in summary["finding"]["poc_path"]
    # The finding carries the universal value account, and the impact text is
    # priced from it (never an assumed consequence).
    assert summary["economic"]["tracked"] is True
    assert summary["finding"]["economic"] == summary["economic"]


def test_demonstrate_rejects_unknown_pair(tmp_path):
    import pytest

    with pytest.raises(ValueError):
        run_class_demonstration(tmp_path, pair="nope/nope")


def test_demonstrate_every_pair_confirms(tmp_path):
    """Every registered pair must reach a CONFIRMED finding end to end."""
    from blackheart.invariants import DIFFERENTIAL_PAIRS

    for vuln, guard, _hyp in DIFFERENTIAL_PAIRS:
        summary = run_class_demonstration(
            tmp_path / f"{vuln}", pair=f"{vuln}/{guard}", runs=300, steps_per_run=10
        )
        assert summary["status"] == "CONFIRMED", f"{vuln} did not confirm"
        assert summary["guarded_failures"] == 0
        assert summary["report_path"]
