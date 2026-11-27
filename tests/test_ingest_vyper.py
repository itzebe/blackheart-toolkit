"""Vyper ingestion must read the decorator-based surface and flag only real gaps."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from blackheart.ingest import detect_language
from blackheart.ingest.vyper import evaluate_vyper, scan_vyper

SAMPLE = '''# a small vault
owner: public(address)
balance: public(uint256)

@external
def withdraw(amount: uint256):
    self.balance -= amount
    send(msg.sender, amount)

@external
@payable
def deposit():
    self.balance += msg.value

@external
@nonreentrant("lock")
def safe_withdraw(amount: uint256):
    self.balance -= amount
    send(msg.sender, amount)

@external
def takeover():
    self.owner = msg.sender
'''


def test_scanner_recovers_functions_and_state():
    report = scan_vyper(SAMPLE, "vault.vy")
    names = [f.name for f in report.functions]
    assert names == ["withdraw", "deposit", "safe_withdraw", "takeover"]
    assert report.state_vars == {"owner": "public(address)", "balance": "public(uint256)"}
    assert report.functions[2].nonreentrant


def test_rules_flag_the_unguarded_and_clear_the_guarded_twin():
    report = scan_vyper(SAMPLE, "vault.vy")
    flags = evaluate_vyper(report)
    rules = {(f.rule, f.function) for f in flags}
    assert ("vyper-missing-nonreentrant", "withdraw") in rules
    assert ("vyper-missing-nonreentrant", "deposit") in rules
    assert ("vyper-missing-nonreentrant", "safe_withdraw") not in rules
    assert ("vyper-payable-without-guard", "deposit") in rules
    # takeover writes owner but checks msg.sender: it is the guarded form.
    assert ("vyper-unguarded-privileged-write", "takeover") not in rules
    assert ("vyper-ownerless-init", "withdraw") in rules
    assert all(f.category for f in flags)


def test_every_vyper_category_exists_in_the_objective_catalog():
    from blackheart.objectives import _OBJECTIVE_CATALOG

    report = scan_vyper(SAMPLE, "vault.vy")
    for flag in evaluate_vyper(report):
        assert flag.category in _OBJECTIVE_CATALOG


def test_detection_prefers_a_pure_vyper_tree(tmp_path: Path):
    (tmp_path / "Vault.vy").write_text(SAMPLE, encoding="utf-8")
    assert detect_language(str(tmp_path)) == "vyper"
    (tmp_path / "Other.sol").write_text("contract A {}", encoding="utf-8")
    assert detect_language(str(tmp_path)) == "unknown"


def test_cli_ingests_a_vyper_file(tmp_path: Path):
    target = tmp_path / "Vault.vy"
    target.write_text(SAMPLE, encoding="utf-8")
    result = subprocess.run(
        [sys.executable, "-m", "blackheart", "ingest", str(target), "--language", "vyper"],
        capture_output=True, text=True, timeout=120,
    )
    assert result.returncode == 0, result.stderr
    assert "Vyper surface" in result.stdout
    assert "vyper-missing-nonreentrant" in result.stdout
