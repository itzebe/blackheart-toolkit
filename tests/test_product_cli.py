"""Acceptance bar for the product surface: version/info/guide/init/demo."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from collections import Counter
from pathlib import Path

import pytest

from blackheart.authz import AuthorizationError, assert_authorized
from blackheart.cli import build_parser
from blackheart.findings.sarif import validate as validate_sarif
from blackheart.models import AuthorizationRecord
from blackheart.product import COMMAND_GROUPS, grouped_names, run_demo, scaffold

ROOT = Path(__file__).resolve().parent.parent


def run(*args: str, cwd: Path = ROOT) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "blackheart", *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=240,
    )


def test_global_version() -> None:
    result = run("--version")
    assert result.returncode == 0
    assert result.stdout.strip().startswith("blackheart ")


def test_version_json() -> None:
    result = run("version", "--json")
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["name"] == "blackheart"
    assert payload["version"]
    assert payload["python"].startswith("3.")
    assert Path(payload["root"]) == ROOT


def test_info_json_names_the_real_counts() -> None:
    result = run("info", "--json")
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["commands"] >= 84
    assert payload["objective_categories"] >= 25
    assert payload["executable_targets"] >= 10
    assert payload["capabilities"]["total"] >= 20
    assert payload["can_find_payable_bug_unaided"] is False


def test_guide_names_every_command_exactly_once() -> None:
    parser = build_parser()
    sub = next(a for a in parser._actions if isinstance(a, argparse._SubParsersAction))
    names = set(sub.choices)
    grouped = grouped_names()
    assert set(grouped) == names, (
        f"missing from guide: {sorted(names - set(grouped))}; "
        f"not a command: {sorted(set(grouped) - names)}"
    )
    assert [name for name, count in Counter(grouped).items() if count > 1] == []
    assert set(COMMAND_GROUPS) == {
        "Start here", "Research", "Ingest & model", "Evidence & findings",
        "Bounty & intelligence", "Engines & tools", "Operations",
    }


def test_init_scaffolds_a_closed_workspace(tmp_path: Path) -> None:
    result = run("init", str(tmp_path / "ws"), "--json")
    assert result.returncode == 0, result.stderr
    created = json.loads(result.stdout)
    root = Path(created["root"])
    assert root == (tmp_path / "ws").resolve()
    for name in ("findings", "evidence", "reports", "work", "targets"):
        assert (root / name).is_dir()

    record = AuthorizationRecord.from_dict(
        json.loads((root / "authorization.json").read_text(encoding="utf-8"))
    )
    assert record.verified is False
    assert record.evidence == []
    assert record.asset_classes == {}
    assert record.program_active is None
    with pytest.raises(AuthorizationError):
        assert_authorized(record, "any-asset")

    readme = (root / "README.md").read_text(encoding="utf-8")
    assert "fails closed" in readme
    ignore = (root / ".gitignore").read_text(encoding="utf-8")
    for line in ("findings/", "evidence/", "authorization.json", "baseline.json"):
        assert line in ignore

    again = run("init", str(root), "--json")
    assert again.returncode == 0
    kept = json.loads(again.stdout)
    assert "authorization.json" in kept["kept"]
    assert "README.md" in kept["kept"]


def test_init_force_replaces_generated_files(tmp_path: Path) -> None:
    root = tmp_path / "ws"
    root.mkdir()
    (root / "authorization.json").write_text("not json", encoding="utf-8")
    assert run("init", str(root), "--json").returncode == 0
    assert (root / "authorization.json").read_text(encoding="utf-8") == "not json"
    assert run("init", str(root), "--force", "--json").returncode == 0
    AuthorizationRecord.from_dict(
        json.loads((root / "authorization.json").read_text(encoding="utf-8"))
    )


def test_demo_runs_the_pipeline_offline(tmp_path: Path) -> None:
    result = run("demo", "--dir", str(tmp_path / "demo"), "--runs", "300", "--steps", "8", "--json")
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["ok"] is True
    assert payload["verdict"] == "CONFIRMED"
    assert payload["guarded_failures"] == 0
    assert payload["sequence"]
    assert payload["diff"] == {"new": 0, "resolved": 0, "changed": 0, "unchanged": 1}

    document = json.loads(Path(payload["sarif"]).read_text(encoding="utf-8"))
    assert validate_sarif(document) == []
    sarif_result = document["runs"][0]["results"][0]
    assert sarif_result["level"] == "error"
    assert sarif_result["properties"]["confirmed"] is True
    assert sarif_result["partialFingerprints"]["blackheart/v1"]


def test_demo_refuses_a_vacuous_success(tmp_path: Path) -> None:
    assert run_demo(tmp_path / "demo", runs=0, steps=1)["ok"] is False


def test_scaffold_is_a_pure_helper(tmp_path: Path) -> None:
    result = scaffold(tmp_path / "ws")
    assert "authorization.json" in result["created"]
    assert (tmp_path / "ws" / "authorization.json").is_file()


def test_doctor_json_is_machine_readable() -> None:
    result = run("doctor", "--json")
    payload = json.loads(result.stdout)
    assert {"status", "hard", "pending", "checks"} <= set(payload)
    assert payload["checks"]
    assert {"check", "ok", "detail"} <= set(payload["checks"][0])
    # The doctor may exit 1 on a host without the external toolchain; the JSON
    # must still be emitted, and it must never claim health it did not check.
    assert any(item["check"] == "python>=3.11" and item["ok"] for item in payload["checks"])
