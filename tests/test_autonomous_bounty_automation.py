"""Regression tests for the autonomous-bounty orchestrator.

The orchestrator must be: self-contained (no import of the blackheart package),
fail-closed (no verified policy -> no run), environment-confined (fork/devnet only
if the policy permits), and it must NEVER submit. These tests touch no network and
run no engine: ``module.run`` is replaced with a fake and state is redirected to a
tmp directory.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

_MAIN = Path(__file__).resolve().parents[1] / "automations" / "autonomous-bounty" / "main.py"


def _load(tmp_path, monkeypatch):
    spec = importlib.util.spec_from_file_location("bh_autonomous_bounty", _MAIN)
    module = importlib.util.module_from_spec(spec)
    sys.modules["bh_autonomous_bounty"] = module
    spec.loader.exec_module(module)
    monkeypatch.setattr(module, "PRIVATE_DIR", tmp_path / "ab")
    return module


def _program(**over):
    p = {
        "name": "Test", "report_to": "security@example.com",
        "policy_text_file": "/dev/null",  # replaced by tests that need real text
        "environments": ["local_fork", "devnet"],
        "source_paths": ["src/"], "contracts": [],
    }
    p.update(over)
    return p


def _fake_run_factory(records, rc_for=None):
    def fake(cmd, dry=False, timeout=3600):
        records.append(list(cmd))
        if dry:
            return 0, "", ""
        joined = " ".join(cmd)
        if rc_for:
            for needle, rc in rc_for.items():
                if needle in joined:
                    return rc, "", f"simulated rc={rc}"
        return 0, "", ""
    return fake


# --- self-containment --------------------------------------------------------

def test_no_import_of_blackheart_package(tmp_path, monkeypatch):
    _load(tmp_path, monkeypatch)
    src = _MAIN.read_text(encoding="utf-8")
    assert "import blackheart" not in src
    assert "from blackheart" not in src


def test_never_submits(tmp_path, monkeypatch):
    """No sending surface: no smtplib/requests/send, and it uses prepare-submission."""
    _load(tmp_path, monkeypatch)
    src = _MAIN.read_text(encoding="utf-8").lower()
    for forbidden in ("smtplib", "import requests", "sendmail", ".send(", "mailto:"):
        assert forbidden not in src, f"submission surface present: {forbidden}"
    assert "prepare-submission" in src  # prepares, never sends


# --- brief validation --------------------------------------------------------

def test_brief_requires_programs(tmp_path, monkeypatch):
    module = _load(tmp_path, monkeypatch)
    bad = tmp_path / "brief.json"
    bad.write_text(json.dumps({"programs": []}), encoding="utf-8")
    try:
        module.load_brief(bad)
        assert False, "expected ValueError"
    except ValueError:
        pass


# --- environment gate --------------------------------------------------------

def test_env_gate_drops_forbidden(tmp_path, monkeypatch):
    module = _load(tmp_path, monkeypatch)
    pol = "This program is MAINNET ONLY. Do not test on a fork or devnet."
    permitted = module.permitted_environments(_program(), pol)
    assert permitted == set()


def test_env_gate_permits_when_not_forbidden(tmp_path, monkeypatch):
    module = _load(tmp_path, monkeypatch)
    pol = "You may use a local fork or devnet to reproduce findings."
    permitted = module.permitted_environments(_program(), pol)
    assert permitted == {"local_fork", "devnet"}


# --- fail-closed -------------------------------------------------------------

def test_fail_closed_when_policy_unverifiable(tmp_path, monkeypatch):
    module = _load(tmp_path, monkeypatch)
    rec: list = []
    # capture fails -> policy cannot be verified -> program BLOCKED, no research step
    monkeypatch.setattr(module, "run", _fake_run_factory(rec, rc_for={"bounty capture": 1}))
    res = module.run_program(_program(), dry=False)
    assert res["status"] == "BLOCKED"
    assert res["steps"] == []          # nothing executed
    assert not any("bounty prepare-submission" in " ".join(c) for c in rec)


# --- dry-run ----------------------------------------------------------------

def test_dry_run_prints_plan_and_runs_nothing(tmp_path, monkeypatch, capsys):
    module = _load(tmp_path, monkeypatch)
    policy = tmp_path / "policy.txt"
    policy.write_text("Reproduce on a local fork. Devnet allowed.", encoding="utf-8")
    prog = _program(policy_text_file=str(policy))
    # In dry-run module.run is the real one (prints, no subprocess); ensure no findings dir.
    res = module.run_program(prog, dry=True)
    out = capsys.readouterr().out
    assert "mission" in out and "--source" in out and "--in-scope" in out
    assert res["status"] in ("NO_FINDING", "NEEDS_SUBMISSION")


# --- notification ------------------------------------------------------------

def _prog_with_finding(module, tmp_path, name="Test"):
    policy = tmp_path / "policy.txt"
    policy.write_text("Local fork and devnet are permitted.", encoding="utf-8")
    prog = _program(name=name, policy_text_file=str(policy))
    slug = "".join(c if c.isalnum() or c in "-_" else "_" for c in prog["name"]).lower()
    findings = module.PRIVATE_DIR / slug / "findings"
    findings.mkdir(parents=True)
    (findings / "finding1.json").write_text("{}", encoding="utf-8")
    return prog


def _fake_gate_run(pkg_json: str, rc: int = 0):
    def fake(cmd, dry=False, timeout=3600):
        if dry:
            return 0, "", ""
        if "bounty prepare-submission" in " ".join(cmd):
            return rc, pkg_json, ("eval failed" if rc else "")
        return 0, "", ""
    return fake


def test_needs_submission_only_on_A(tmp_path, monkeypatch):
    module = _load(tmp_path, monkeypatch)
    prog = _prog_with_finding(module, tmp_path)
    pkg = json.dumps({"disposition": "A_SUBMISSION_READY", "submission_allowed": True,
                      "disposition_label": "A - submission-ready"})
    monkeypatch.setattr(module, "run", _fake_gate_run(pkg))
    res = module.run_program(prog, dry=False)
    assert res["status"] == "NEEDS_SUBMISSION"
    assert res["packages"][0]["disposition"] == "A_SUBMISSION_READY"
    digest = module.write_reports([res], dry=False)
    text = digest.read_text(encoding="utf-8")
    assert digest.name == "NEEDS-SUBMISSION.md"
    assert "security@example.com" in text
    assert "SUBMITTABLE [A_SUBMISSION_READY]" in text
    assert "Nothing here has been sent" in text


def test_needs_submission_on_B(tmp_path, monkeypatch):
    module = _load(tmp_path, monkeypatch)
    prog = _prog_with_finding(module, tmp_path)
    pkg = json.dumps({"disposition": "B_POTENTIALLY_PAYABLE", "submission_allowed": False,
                      "disposition_label": "B - potentially payable"})
    monkeypatch.setattr(module, "run", _fake_gate_run(pkg))
    res = module.run_program(prog, dry=False)
    assert res["status"] == "NEEDS_SUBMISSION"
    assert res["packages"][0]["disposition"] == "B_POTENTIALLY_PAYABLE"


def test_C_not_submittable_goes_to_digest(tmp_path, monkeypatch):
    module = _load(tmp_path, monkeypatch)
    prog = _prog_with_finding(module, tmp_path)
    pkg = json.dumps({"disposition": "C_VALID_NOT_PAYABLE", "submission_allowed": False,
                      "disposition_label": "C - valid but not payable"})
    monkeypatch.setattr(module, "run", _fake_gate_run(pkg))
    res = module.run_program(prog, dry=False)
    assert res["status"] == "NO_FINDING"           # not A/B -> no wake-up
    assert res["gated"][0]["disposition"] == "C_VALID_NOT_PAYABLE"
    digest = module.write_reports([res], dry=False)
    assert digest.name == "RUN-DIGEST.md"
    assert "gated, not submittable: C_VALID_NOT_PAYABLE" in digest.read_text(encoding="utf-8")


def test_gate_error_not_submittable(tmp_path, monkeypatch):
    module = _load(tmp_path, monkeypatch)
    prog = _prog_with_finding(module, tmp_path)
    monkeypatch.setattr(module, "run", _fake_gate_run("", rc=1))
    res = module.run_program(prog, dry=False)
    assert res["status"] == "NO_FINDING"
    assert res["gated"][0]["disposition"] == "ERROR"


def test_ledger_is_hash_chained(tmp_path, monkeypatch):
    module = _load(tmp_path, monkeypatch)
    h1 = module.ledger_append({"program": "A", "status": "NO_FINDING"})
    h2 = module.ledger_append({"program": "A", "status": "NO_FINDING"})
    lines = (module.PRIVATE_DIR / "ledger.jsonl").read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 2
    first, second = json.loads(lines[0]), json.loads(lines[1])
    assert first["hash"] == h1 and second["hash"] == h2
    assert second["prev"] == h1  # chained
