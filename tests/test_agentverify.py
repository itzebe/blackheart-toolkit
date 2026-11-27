"""Tests for the specialist-agent invocation verifier and project provisioning
(mission sections 11, 12).

The agent-server is not always present (a plain CI container has none). These
tests therefore assert the verifier behaves honestly in **both** worlds: it either
reports a real, complete discovery, or reports ``available: false`` with a reason
-- it never fabricates success.
"""

from __future__ import annotations

from pathlib import Path

from blackheart.agentverify import _session_key, verify_agents
from blackheart.provision import provision_project


def test_provision_creates_discovery_layout(repo_root: Path, tmp_path: Path):
    """Provision a copy of the layout into a scratch root and check it works."""
    import shutil

    root = tmp_path / "proj"
    shutil.copytree(repo_root / "skills", root / "skills")
    shutil.copytree(repo_root / "agents", root / "agents")
    result = provision_project(root)
    assert (root / ".openhands" / "skills").exists()
    assert (root / ".openhands" / "agents").exists()
    assert result.method in {"symlink", "copy"}
    # The linked/copied tree exposes the same skills and agents.
    assert len(list((root / ".openhands" / "skills").glob("*/SKILL.md"))) == len(
        list((root / "skills").glob("*/SKILL.md"))
    )
    assert len(list((root / ".openhands" / "agents").glob("*.md"))) == len(
        list((root / "agents").glob("*.md"))
    )


def test_provision_is_idempotent(repo_root: Path, tmp_path: Path):
    import shutil

    root = tmp_path / "proj"
    shutil.copytree(repo_root / "skills", root / "skills")
    shutil.copytree(repo_root / "agents", root / "agents")
    first = provision_project(root)
    second = provision_project(root)
    assert first.method == second.method
    assert len(list((root / ".openhands" / "agents").glob("*.md"))) == len(
        list((root / "agents").glob("*.md"))
    )


def test_verify_agents_never_fabricates(repo_root: Path):
    """Either a complete real discovery, or an honest unavailability report."""
    result = verify_agents(repo_root, timeout=5.0)
    if result.available:
        assert result.skills_loaded, "an available server must return skills"
        # The repository's own agents must be present in the loaded set.
        for name in ("attacker-strategy-agent", "independent-verification-agent"):
            assert name in result.agents_loaded
    else:
        assert result.reason, "an unavailable server must give a reason"
        assert result.ok() is False


def test_verify_agents_fails_closed_without_discovery_layout(tmp_path: Path):
    """A reachable server that loads nothing is a misconfigured project, not a pass.

    Reproduces the fresh-clone state: the canonical ``skills/`` and ``agents/``
    trees exist, but the provisioned ``.openhands/`` discovery layout does not.
    The verifier must report ``available: false`` (with a fix-it reason) rather
    than ``available: true`` with an empty skills list.
    """
    (tmp_path / "skills" / "some-skill").mkdir(parents=True)
    (tmp_path / "skills" / "some-skill" / "SKILL.md").write_text("# s\n", encoding="utf-8")
    (tmp_path / "agents").mkdir()
    (tmp_path / "agents" / "some-agent.md").write_text("# a\n", encoding="utf-8")

    result = verify_agents(tmp_path, timeout=1.0)
    assert result.available is False
    assert result.ok() is False
    assert "provision" in result.reason
    # It still reports what it *would* have expected, honestly.
    assert result.skills_expected == ["some-skill"]
    assert result.agents_expected == ["some-agent"]


def test_expected_agents_match_repository(repo_root: Path):
    result = verify_agents(repo_root, timeout=5.0)
    on_disk = sorted(p.stem for p in (repo_root / "agents").glob("*.md"))
    assert result.agents_expected == on_disk
    on_disk_skills = sorted(p.parent.name for p in (repo_root / "skills").glob("*/SKILL.md"))
    assert result.skills_expected == on_disk_skills


def test_session_key_reader_does_not_crash():
    key = _session_key()
    assert isinstance(key, str)


def test_every_specialist_agent_carries_the_attacker_question(repo_root: Path):
    """The agents that execute a mission must hold the same question as the roles.

    This is a structural, deterministic check: it reads the agent definitions on
    disk and asserts the canonical question is present in each. It guards against
    the question reaching the orchestrator but being dropped at the executor.
    """
    from blackheart.mindset import ATTACKER_QUESTION

    agents = sorted((repo_root / "agents").glob("*.md"))
    assert agents, "expected specialist agent definitions"
    missing = [
        p.stem
        for p in agents
        if ATTACKER_QUESTION not in p.read_text(encoding="utf-8")
    ]
    assert not missing, f"agents missing the attacker question: {missing}"


def test_agent_lens_block_is_the_canonical_question():
    from blackheart.mindset import ATTACKER_QUESTION, agent_lens_block

    block = agent_lens_block()
    assert ATTACKER_QUESTION in block
    assert block.startswith("## The question you hold")
