"""Tests for the GitHub Actions supply-chain analyzer (blackheart/gha.py).

The regression these guard is the OSS-001 class: a `workflow_run` continuation
that checks out a repository/ref taken from a downloaded artifact without
binding it to `github.repository`. The analyzer must flag that data flow, and
must NOT flag the hardened variants (trusted-repo guard, base-repo checkout).
"""

from __future__ import annotations

from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")

from blackheart import gha

VULN = """\
name: Chained E2E
on:
  workflow_run:
    workflows: ['Trigger E2E']
    types: ['completed']
jobs:
  fetch:
    runs-on: ubuntu-latest
    outputs:
      repository: ${{ steps.ctx.outputs.REPO }}
      sha: ${{ steps.ctx.outputs.SHA }}
    steps:
      - uses: actions/download-artifact@v5
        with:
          name: repo_name
          run-id: ${{ github.event.workflow_run.id }}
      - id: ctx
        env:
          REPO: ${{ needs.fetch.outputs.repo_name || github.repository }}
          SHA: ${{ github.event.workflow_run.head_sha }}
        run: echo "REPO=$REPO" >> "$GITHUB_OUTPUT"
  test:
    needs: fetch
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          repository: ${{ needs.fetch.outputs.repository }}
          ref: ${{ needs.fetch.outputs.sha }}
      - run: npm ci
"""

GUARDED = VULN.replace(
    "  test:\n",
    "  test:\n    if: github.event.workflow_run.head_repository.full_name == github.repository\n",
)

BASE_CHECKOUT = VULN.replace(
    "          repository: ${{ needs.fetch.outputs.repository }}",
    "          repository: ${{ github.repository }}",
)


def _analyze(tmp_path: Path, text: str) -> list[gha.Candidate]:
    p = tmp_path / "wf.yml"
    p.write_text(text)
    return gha.analyze_file(p)


def test_flags_workflow_run_artifact_checkout(tmp_path):
    cands = _analyze(tmp_path, VULN)
    assert cands, "the artifact-driven checkout must be flagged"
    assert all(c.rule_id == gha.RULE_WORKFLOW_RUN_ARTIFACT_CHECKOUT for c in cands)
    assert all(c.severity == "high" for c in cands)
    # one candidate per affected job, not per with-key
    assert len(cands) == 1 and cands[0].job == "test"


def test_trusted_repo_guard_suppresses(tmp_path):
    assert _analyze(tmp_path, GUARDED) == []


def test_base_repo_checkout_suppresses(tmp_path):
    assert _analyze(tmp_path, BASE_CHECKOUT) == []


def test_no_workflow_run_trigger_not_flagged(tmp_path):
    text = VULN.replace("  workflow_run:\n    workflows: ['Trigger E2E']\n    types: ['completed']\n", "  pull_request:\n")
    assert _analyze(tmp_path, text) == []


def test_no_artifact_download_not_flagged(tmp_path):
    text = VULN.replace("      - uses: actions/download-artifact@v5\n        with:\n          name: repo_name\n          run-id: ${{ github.event.workflow_run.id }}\n", "")
    assert _analyze(tmp_path, text) == []


def test_candidate_carries_precondition_and_remediation(tmp_path):
    (c,) = _analyze(tmp_path, VULN)
    assert c.precondition and c.remediation
    assert "head_repository" in c.remediation
    assert any("repository:" in e for e in c.evidence)


def test_analyze_tree_walks_a_corpus_of_repositories(tmp_path):
    for repo in ("repo-a", "repo-b"):
        d = tmp_path / repo / ".github" / "workflows"
        d.mkdir(parents=True)
        (d / "ci.yml").write_text(VULN)
    files = {c.file for c in gha.analyze_tree(tmp_path)}
    assert len(files) == 2


def test_render_and_json(tmp_path):
    cands = _analyze(tmp_path, VULN)
    assert "GH-WORKFLOW-RUN-ARTIFACT-CHECKOUT" in gha.render(cands)
    assert gha.to_json(cands).startswith("[")
    assert "no reachable" in gha.render([])


# --- Rule 2: pull_request_target untrusted checkout ---------------------------

PRT_VULN = """\
name: pwn request
on: pull_request_target
permissions:
  contents: write
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
          repository: ${{ github.event.pull_request.head.repo.full_name }}
      - run: npm ci && npm test
"""


def test_flags_pull_request_target_untrusted_checkout(tmp_path):
    (c,) = _analyze(tmp_path, PRT_VULN)
    assert c.rule_id == gha.RULE_PR_TARGET_UNTRUSTED_CHECKOUT
    assert c.severity == "high"
    assert c.source and c.trust_transition and c.impact


def test_pr_target_without_privilege_not_flagged(tmp_path):
    text = PRT_VULN.replace("permissions:\n  contents: write\n", "")
    assert _analyze(tmp_path, text) == []


def test_pr_target_checkout_of_base_repo_not_flagged(tmp_path):
    text = PRT_VULN.replace(
        "          ref: ${{ github.event.pull_request.head.sha }}\n"
        "          repository: ${{ github.event.pull_request.head.repo.full_name }}\n",
        "          ref: ${{ github.sha }}\n")
    assert _analyze(tmp_path, text) == []


# --- Rule 3: untrusted script injection ---------------------------------------

INJECT_VULN = """\
name: triage
on:
  issue_comment:
    types: [created]
permissions:
  contents: write
jobs:
  triage:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ github.event.comment.body }}" >> out.txt
"""


def test_flags_untrusted_script_injection(tmp_path):
    (c,) = _analyze(tmp_path, INJECT_VULN)
    assert c.rule_id == gha.RULE_UNTRUSTED_SCRIPT_INJECTION
    assert "github.event.comment.body" in c.message


def test_script_injection_via_env_not_flagged(tmp_path):
    text = INJECT_VULN.replace(
        '      - run: echo "${{ github.event.comment.body }}" >> out.txt\n',
        "      - env:\n          BODY: ${{ github.event.comment.body }}\n"
        '        run: echo "$BODY" >> out.txt\n')
    assert _analyze(tmp_path, text) == []


def test_trusted_trigger_not_flagged_for_injection(tmp_path):
    text = INJECT_VULN.replace("  issue_comment:\n    types: [created]\n", "  push:\n")
    assert _analyze(tmp_path, text) == []


def test_real_oss001_workflow_is_detected():
    """The actual OSS-001 finding must be reproducible by this analyzer."""
    ev = Path(__file__).resolve().parent.parent / "research/private/findings/OSS-001/evidence"
    if not ev.is_dir():
        pytest.skip("private OSS-001 evidence not present (gitignored)")
    cands = gha.analyze_file(ev / "chained_e2e.yml")
    assert cands, "the pinned vulnerable workflow must be flagged"
    assert {c.job for c in cands} == {"e2e_linux", "e2e_mac", "e2e_windows", "evals"}
    assert gha.analyze_file(ev / "trigger_e2e.yml") == []
