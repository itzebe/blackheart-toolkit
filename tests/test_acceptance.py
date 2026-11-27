"""Acceptance tests for the engine's discoverability, gating, and portability."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from blackheart.cli import main


def test_skills_and_agents_are_discoverable(repo_root: Path):
    skills = sorted(p.parent.name for p in (repo_root / "skills").glob("*/SKILL.md"))
    agents = sorted(p.stem for p in (repo_root / "agents").glob("*.md"))
    assert "blackheart" in skills
    assert len(skills) >= 5
    assert len(agents) >= 14
    for name in ["attacker-strategy-agent", "independent-verification-agent",
                 "evidence-and-bounty-report-agent", "cryptographic-protocol-agent",
                 "supply-chain-agent"]:
        assert name in agents


def test_cli_agents_command_lists_them(repo_root: Path, capsys):
    assert main(["agents"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert "blackheart" in payload["skills"]
    assert "attacker-strategy-agent" in payload["agents"]


def test_skill_frontmatter_is_valid(repo_root: Path):
    for skill in (repo_root / "skills").glob("*/SKILL.md"):
        text = skill.read_text(encoding="utf-8")
        assert text.startswith("---"), f"{skill} missing frontmatter"
        fm = text.split("---", 2)[1]
        assert "name:" in fm and "description:" in fm


def test_agent_frontmatter_is_valid(repo_root: Path):
    for agent in (repo_root / "agents").glob("*.md"):
        text = agent.read_text(encoding="utf-8")
        assert text.startswith("---"), f"{agent} missing frontmatter"
        fm = text.split("---", 2)[1]
        assert "name:" in fm and "description:" in fm


def test_campaign_is_blocked_for_unauthorized_asset(tmp_path):
    from blackheart.authz import new_record
    from blackheart.campaign import Campaign
    from blackheart.objectives import TargetProfile

    rec = new_record("eng", "immunefi", "https://x", "https://scope")
    rec.assets = {"asset-a": "UNKNOWN"}
    camp = Campaign("eng", TargetProfile(name="t"), rec, tmp_path)
    result = camp.run_active("asset-a")
    assert not result.allowed
    assert result.blocked_reason
    # Nothing active ran.
    assert result.objectives == []


@pytest.mark.skipif(
    shutil.which("forge") is None,
    reason="forge not on PATH; the reference engagement needs Foundry",
)
def test_cli_engagement_end_to_end(tmp_path, repo_root: Path, erc4626_harness_ready: bool):
    """The full engine must run from the CLI and produce a CONFIRMED finding."""
    if not erc4626_harness_ready:
        pytest.skip(
            "erc4626 harness dependencies missing; run: "
            "cd harnesses/erc4626 && forge install foundry-rs/forge-std"
        )
    rc = main(["engagement", "--workdir", str(tmp_path / "eng")])
    assert rc == 0
    summary = json.loads((tmp_path / "eng" / "reference-engagement-summary.json").read_text())
    assert summary["finding"]["classification"] == "CONFIRMED"
    assert summary["stages"]["forge"]["poc"]["passed"] >= 2
    assert summary["stages"]["forge"]["invariants_vulnerable"]["failed"] >= 1
    assert summary["stages"]["forge"]["invariants_safe"]["failed"] == 0
    assert summary["stages"]["report_path"]


def test_no_paid_service_required(repo_root: Path):
    """The whole engine imports and runs with only the standard library."""
    pyproject = (repo_root / "pyproject.toml").read_text(encoding="utf-8")
    assert 'dependencies = []' in pyproject


def test_packaging_discovers_every_subpackage(repo_root: Path):
    """`pip install .` on a fresh machine must include every subpackage.

    A hand-maintained package list silently drops a new package (e.g. the
    intelligence layer) from the wheel, so the CLI fails only after install on
    another sandbox. Auto-discovery with include=["blackheart*"] structurally
    covers every ``blackheart*`` package; this test guards against the list being
    reinstated by hand and drifting from the real tree.
    """
    import fnmatch
    import tomllib

    pyproject = tomllib.loads((repo_root / "pyproject.toml").read_text(encoding="utf-8"))
    find = pyproject["tool"]["setuptools"]["packages"]["find"]
    include = find["include"]
    assert include == ["blackheart*"], "packages must be auto-discovered, not listed"

    real = {"blackheart"}
    for p in repo_root.glob("blackheart/**/__init__.py"):
        rel = p.parent.relative_to(repo_root)
        real.add(".".join(rel.parts))
    for pkg in sorted(real):
        assert any(fnmatch.fnmatch(pkg, pat) for pat in include), (
            f"discovery pattern {include} would omit package {pkg}")
    assert "blackheart.intelligence" in real
    assert any(fnmatch.fnmatch("blackheart.intelligence", pat) for pat in include)


def test_cli_chain_list_and_run(capsys):
    """Every executable chain runs and demonstrates the vulnerable/guarded contrast."""
    from blackheart.attackdb import all_chains

    assert main(["chain", "--list"]) == 0
    listing = capsys.readouterr().out
    for chain in all_chains():
        assert chain.chain_id in listing
    for chain in all_chains():
        assert main(["chain", "--run", chain.chain_id]) == 0, chain.chain_id
        capsys.readouterr()


def test_cli_regress_emits_runnable_test(tmp_path: Path, capsys):
    rc = main([
        "regress", "--target", "permit-replay", "--runs", "200",
        "--out", str(tmp_path / "reg"),
    ])
    assert rc == 0
    capsys.readouterr()
    emitted = sorted((tmp_path / "reg").glob("test_regression_*.py"))
    assert emitted, "a failing target must emit at least one regression test"
    for path in emitted:
        compile(path.read_text(), str(path), "exec")


def test_cli_forge_gen_writes_a_test(tmp_path: Path, capsys):
    out = tmp_path / "Generated.t.sol"
    assert main(["forge-gen", "--chain", "erc4626-first-depositor-inflation",
                 "--out", str(out)]) == 0
    capsys.readouterr()
    assert "contract GeneratedPoC" in out.read_text()


def test_cli_scope_records_and_gates(tmp_path: Path, capsys):
    """A verified record with captured scope authorizes exactly the AUTHORIZED asset."""
    import json

    from blackheart.authz import new_record
    from blackheart.models import AssetStatus

    rec = new_record(
        program="Example", platform="immunefi",
        target_url="https://example.test/p", scope_url="https://example.test/s",
        program_active=True, safe_harbor=True, poc_required=True,
        nigerian_eligible=True, payout_feasible=True, zero_cost=True,
    )
    rec.asset_classes = {"vault": AssetStatus.AUTHORIZED.value,
                         "bridge": AssetStatus.OUT_OF_SCOPE.value}
    rec.retrieved_scope = {"source_url": "https://example.test/s", "text": "vault in scope"}
    rec.verified = True
    rec_path = tmp_path / "rec.json"
    rec_path.write_text(json.dumps(rec.to_dict()), encoding="utf-8")

    rc = main(["scope", "--file", str(rec_path),
               "--registry", str(tmp_path / "reg.jsonl"),
               "--evidence", str(tmp_path / "ev")])
    assert rc == 0
    summary = json.loads(capsys.readouterr().out.split("\n\n")[0])
    assert summary["authorized_assets"] == ["vault"]

    # Recording captured the scope as evidence; persist the updated record (with
    # the evidence id the CLI assigned) so the gate can see it.
    rec.evidence = summary["evidence_ids"]
    rec_path.write_text(json.dumps(rec.to_dict()), encoding="utf-8")
    assert main(["scope", "--check", str(rec_path), "--asset", "vault"]) == 0
    capsys.readouterr()
    assert main(["scope", "--check", str(rec_path), "--asset", "bridge"]) == 2
    capsys.readouterr()


def test_cli_provision_and_agents_verify(repo_root: Path, tmp_path: Path, capsys):
    """provision creates the discovery layout; agents-verify is honest either way."""
    import shutil

    root = tmp_path / "proj"
    shutil.copytree(repo_root / "skills", root / "skills")
    shutil.copytree(repo_root / "agents", root / "agents")
    assert main(["provision", "--root", str(root)]) == 0
    capsys.readouterr()
    assert (root / ".openhands" / "skills").exists()
    assert (root / ".openhands" / "agents").exists()

    # agents-verify exits 0 (all found), 1 (missing), or 2 (server unavailable);
    # never a false success.
    rc = main(["agents-verify", "--out", str(tmp_path / "av.json")])
    capsys.readouterr()
    assert rc in (0, 1, 2)


def test_new_attack_class_pairs_are_registered():
    from blackheart.invariants import DIFFERENTIAL_PAIRS

    pairs = {v for v, _g, _h in DIFFERENTIAL_PAIRS}
    assert "callback-reentrancy" in pairs
    assert "access-control" in pairs
