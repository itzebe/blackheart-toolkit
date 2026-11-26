"""GitHub Actions supply-chain analysis.

A focused detector suite for *reachable* GitHub Actions attack chains — the
classes where untrusted input crosses a trust boundary and ends in code
execution, a secret read, or a write-privileged operation. It is deliberately
not a linter: it does not report isolated suspicious patterns (unpinned actions,
``write-all``, ``pull_request_target`` on its own). Those are leads, and on
hardened repositories they are almost always mitigated; reporting them buries
the one reachable flow that matters.

Rules
-----
GH-WORKFLOW-RUN-ARTIFACT-CHECKOUT
    A ``workflow_run`` continuation checks out a repository/ref taken from a
    downloaded artifact without binding it to ``github.repository``. The
    continuation runs with the base repo's token and secrets, so fork-controlled
    code reaches them. (The class behind finding OSS-001.)

GH-PR-TARGET-UNTRUSTED-CHECKOUT
    A ``pull_request_target`` (or ``workflow_run``) workflow checks out the
    *pull request's* ref/repository and then executes it, with secrets or write
    permissions in scope. The classic "pwn request".

GH-UNTRUSTED-SCRIPT-INJECTION
    An untrusted expression (issue/PR title, comment body, head ref, ...) is
    interpolated directly into a ``run:`` script, allowing shell injection in a
    privileged context.

Each candidate records the full data flow so a triager can dismiss it honestly:
source of untrusted data, where it is stored, the trust transition, the consumer,
the execution context, the privileges available, the attacker's required actions,
existing mitigations, and the demonstrated impact.

PyYAML is required to parse workflow structure and is declared as the optional
``gha`` extra. Without it the analyzer reports UNSUPPORTED rather than guessing.
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

try:  # optional dependency; the core package stays stdlib-only
    import yaml
except ImportError:  # pragma: no cover - exercised via monkeypatch in tests
    yaml = None


RULE_WORKFLOW_RUN_ARTIFACT_CHECKOUT = "GH-WORKFLOW-RUN-ARTIFACT-CHECKOUT"
RULE_PR_TARGET_UNTRUSTED_CHECKOUT = "GH-PR-TARGET-UNTRUSTED-CHECKOUT"
RULE_UNTRUSTED_SCRIPT_INJECTION = "GH-UNTRUSTED-SCRIPT-INJECTION"

_ALL_RULES = (
    RULE_WORKFLOW_RUN_ARTIFACT_CHECKOUT,
    RULE_PR_TARGET_UNTRUSTED_CHECKOUT,
    RULE_UNTRUSTED_SCRIPT_INJECTION,
)

_TRUSTED_REPO_GUARD = re.compile(
    r"(?:head_repo(?:sitory)?\.full_name|head\.repo\.full_name)\s*==\s*github\.repository"
)
_ARTIFACT_EXPR = re.compile(r"needs\.[A-Za-z0-9_-]+\.outputs\.[A-Za-z0-9_-]+")

# Expressions whose value an outside party can influence.
_UNTRUSTED_EXPRS = (
    "github.event.issue.title",
    "github.event.issue.body",
    "github.event.pull_request.title",
    "github.event.pull_request.body",
    "github.event.comment.body",
    "github.event.review.body",
    "github.event.review_comment.body",
    "github.event.discussion.title",
    "github.event.discussion.body",
    "github.event.head_commit.message",
    "github.event.head_commit.author.name",
    "github.event.head_commit.author.email",
    "github.event.workflow_run.head_branch",
    "github.event.workflow_run.head_commit.message",
    "github.event.pull_request.head.ref",
    "github.event.pull_request.head.label",
    "github.head_ref",
)
# NOTE: `head.repo.full_name` / `head_repository.full_name` are deliberately NOT
# listed. A repository full name is constrained to `owner/repo` characters and
# cannot carry shell metacharacters, so interpolating it is not an injection.
# Listing it produced a false positive on protocolbuffers/protobuf's
# forked_pr_workflow_check.yml (which compares that field inside a `run:`).

_UNTRUSTED_TRIGGERS = {
    "pull_request",
    "pull_request_target",
    "issues",
    "issue_comment",
    "pull_request_review",
    "pull_request_review_comment",
    "discussion",
    "discussion_comment",
    "workflow_run",
}

_EXEC_STEP = re.compile(r"\b(npm|yarn|pnpm|pip|make|gradle|mvn|go|python|node|bash|sh)\b|\./")
_WRITE_PERM = re.compile(
    r"(contents|packages|actions|checks|deployments|id-token|security-events|statuses|"
    r"pull-requests|issues|attestations):\s*write|write-all"
)


@dataclass
class Candidate:
    rule_id: str
    file: str
    job: str
    severity: str
    confidence: str
    message: str
    precondition: str
    remediation: str
    evidence: list[str] = field(default_factory=list)
    # data-flow metadata (mission section 5)
    source: str = ""
    storage: str = ""
    trust_transition: str = ""
    consumer: str = ""
    execution_context: str = ""
    privileges: str = ""
    attacker_actions: str = ""
    mitigations: str = ""
    impact: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _on_map(doc: dict) -> dict:
    o = doc.get("on") or doc.get(True)
    if isinstance(o, str):
        return {o: {}}
    if isinstance(o, list):
        return {k: {} for k in o}
    return o if isinstance(o, dict) else {}


def _jobs(doc: dict) -> dict:
    jobs = doc.get("jobs")
    return jobs if isinstance(jobs, dict) else {}


def _steps(job: dict) -> list:
    steps = job.get("steps")
    return steps if isinstance(steps, list) else []


def _has_trusted_repo_guard(text: str) -> bool:
    return bool(_TRUSTED_REPO_GUARD.search(text))


def _workflow_has_write_perms(text: str, doc: dict) -> bool:
    if _WRITE_PERM.search(text):
        return True
    for job in _jobs(doc).values():
        if isinstance(job, dict) and _WRITE_PERM.search(str(job.get("permissions", ""))):
            return True
    return False


def _uses_secrets(text: str) -> bool:
    return "secrets." in text


# --------------------------------------------------------------------------- #
# Rule 1: workflow_run artifact-driven checkout
# --------------------------------------------------------------------------- #
def _artifact_sourced_checkout(doc: dict) -> list[tuple[str, list[str]]]:
    """Return (job, evidence) for checkouts that select the *repository* from an artifact.

    Keying on `repository` (not `ref`) is deliberate: a checkout that pins
    `repository: github.repository` but takes only the `ref` from an artifact
    cannot reach another repository's code, so it is not this class. The `ref`
    value is still reported as context.
    """
    out: list[tuple[str, list[str]]] = []
    for jname, job in _jobs(doc).items():
        if not isinstance(job, dict):
            continue
        for s in _steps(job):
            if not isinstance(s, dict) or "actions/checkout" not in str(s.get("uses", "")):
                continue
            with_ = s.get("with") or {}
            if not isinstance(with_, dict):
                continue
            repo = str(with_.get("repository", ""))
            if "${{" not in repo or "github.repository" in repo or not _ARTIFACT_EXPR.search(repo):
                continue
            details = [f"repository: {repo.strip()}"]
            ref = str(with_.get("ref", ""))
            if ref:
                details.append(f"ref: {ref.strip()}")
            out.append((jname, details))
    return out


def _rule_workflow_run_artifact_checkout(doc, text, path) -> list[Candidate]:
    if "workflow_run" not in _on_map(doc):
        return []
    if _has_trusted_repo_guard(text):
        return []
    steps_all = [s for j in _jobs(doc).values() if isinstance(j, dict) for s in _steps(j)]
    if not any("download-artifact" in str(s.get("uses", "")) for s in steps_all if isinstance(s, dict)):
        return []
    by_job: dict[str, list[str]] = {}
    for jname, details in _artifact_sourced_checkout(doc):
        by_job.setdefault(jname, []).extend(details)
    out = []
    for jname, details in sorted(by_job.items()):
        out.append(Candidate(
            rule_id=RULE_WORKFLOW_RUN_ARTIFACT_CHECKOUT, file=path, job=jname,
            severity="high", confidence="high",
            message=("workflow_run job checks out a repository/ref taken from a downloaded "
                     "artifact without binding it to github.repository"),
            precondition=("a workflow_run source workflow must run for untrusted input (e.g. "
                          "pull_request) and place attacker-influenced data in the artifact"),
            remediation=("add `if: github.event.workflow_run.head_repository.full_name == "
                         "github.repository` and check out github.repository, not the artifact value"),
            evidence=details + ["downloads an artifact",
                                "no head_repository==github.repository guard"],
            source="artifact produced by the triggering (unprivileged) run",
            storage="actions artifact (repo_name / head_sha)",
            trust_transition="unprivileged trigger run -> privileged workflow_run run",
            consumer="actions/checkout repository/ref, then npm ci / build / test",
            execution_context="base repository, workflow_run",
            privileges="workflow-level permissions + any secrets.* in scope for the job",
            attacker_actions="open a pull request from a fork (returning contributor; no approval)",
            mitigations="none present (no head_repository==github.repository guard)",
            impact="fork-controlled code executes with the base repo's secrets in scope",
        ))
    return out


# --------------------------------------------------------------------------- #
# Rule 2: pull_request_target / workflow_run untrusted checkout
# --------------------------------------------------------------------------- #
def _rule_pr_target_untrusted_checkout(doc, text, path) -> list[Candidate]:
    on = _on_map(doc)
    if "pull_request_target" not in on and "workflow_run" not in on:
        return []
    privileged = _workflow_has_write_perms(text, doc) or _uses_secrets(text)
    if not privileged:
        return []
    out = []
    for jname, job in _jobs(doc).items():
        if not isinstance(job, dict):
            continue
        # A job bound to a protected `environment` requires deployment approval
        # before it runs, which is the documented mitigation for this class.
        if job.get("environment"):
            continue
        untrusted_checkout = False
        co_evidence: list[str] = []
        exec_after = False
        for s in _steps(job):
            if not isinstance(s, dict):
                continue
            uses = str(s.get("uses", ""))
            if "actions/checkout" in uses:
                with_ = s.get("with") or {}
                ref = str(with_.get("ref", ""))
                repo = str(with_.get("repository", ""))
                if ("pull_request.head" in ref or "pull_request.head" in repo
                        or "workflow_run.head" in ref or "github.head_ref" in ref):
                    untrusted_checkout = True
                    if ref:
                        co_evidence.append(f"checkout ref: {ref.strip()}")
                    if repo:
                        co_evidence.append(f"checkout repository: {repo.strip()}")
            elif untrusted_checkout and isinstance(s.get("run"), str) and _EXEC_STEP.search(s["run"]):
                exec_after = True
        if untrusted_checkout and exec_after:
            out.append(Candidate(
                rule_id=RULE_PR_TARGET_UNTRUSTED_CHECKOUT, file=path, job=jname,
                severity="high", confidence="high",
                message=("privileged pull_request_target/workflow_run job checks out the pull "
                         "request's code and then executes it"),
                precondition="an external contributor opens/updates a pull request",
                remediation=("do not check out or execute PR-controlled code in a privileged "
                             "context; run untrusted code in a `pull_request` workflow and pass "
                             "only validated data forward"),
                evidence=co_evidence + ["executes a command step after the untrusted checkout"],
                source="pull request head repository/ref (attacker-controlled)",
                storage="checked-out working tree",
                trust_transition="untrusted PR code -> privileged job (secrets/write perms)",
                consumer="run: shell step",
                execution_context="base repository, pull_request_target/workflow_run",
                privileges="job/flow permissions + secrets in scope",
                attacker_actions="open a pull request from a fork",
                mitigations="none detected in the checkout/execute path",
                impact="arbitrary code execution with the base repo's secrets and token",
            ))
    return out


# --------------------------------------------------------------------------- #
# Rule 3: untrusted expression interpolated into a run: script
# --------------------------------------------------------------------------- #
def _rule_untrusted_script_injection(doc, text, path) -> list[Candidate]:
    on = _on_map(doc)
    if not (set(on) & _UNTRUSTED_TRIGGERS):
        return []
    privileged = _workflow_has_write_perms(text, doc) or _uses_secrets(text)
    out = []
    for jname, job in _jobs(doc).items():
        if not isinstance(job, dict):
            continue
        for s in _steps(job):
            if not isinstance(s, dict):
                continue
            run = s.get("run")
            if not isinstance(run, str):
                continue
            hits = [e for e in _UNTRUSTED_EXPRS if f"${{{{ {e}" in run or f"${{{{{e}" in run]
            if hits:
                out.append(Candidate(
                    rule_id=RULE_UNTRUSTED_SCRIPT_INJECTION, file=path, job=jname,
                    severity="high" if privileged else "medium",
                    confidence="high",
                    message=("untrusted expression interpolated directly into a run: script "
                             f"({', '.join(sorted(set(hits)))})"),
                    precondition="the untrusted event field is populated by an external actor",
                    remediation=("pass the value through an `env:` variable and reference "
                                 "`\"$VAR\"` in the script; never interpolate untrusted data with "
                                 "`${{ }}` inside `run:`"),
                    evidence=[f"${{{{ {h} }}}} in run:" for h in sorted(set(hits))],
                    source=f"event field(s): {', '.join(sorted(set(hits)))}",
                    storage="shell command string",
                    trust_transition="untrusted event data -> shell interpreter",
                    consumer="run: shell step",
                    execution_context="base repository",
                    privileges="job/flow permissions + secrets in scope" if privileged else "read-only",
                    attacker_actions="set the untrusted field (issue/PR title, comment, head ref)",
                    mitigations="none (direct interpolation)",
                    impact="shell injection -> command execution in the workflow context",
                ))
    return out


_RULES = (
    _rule_workflow_run_artifact_checkout,
    _rule_pr_target_untrusted_checkout,
    _rule_untrusted_script_injection,
)


def analyze_document(doc: dict, text: str, path: str = "<memory>") -> list[Candidate]:
    """Analyze one parsed workflow. `text` is the raw file (for guard detection)."""
    if not isinstance(doc, dict):
        return []
    out: list[Candidate] = []
    for rule in _RULES:
        out.extend(rule(doc, text, path))
    return out


def analyze_file(path: Path) -> list[Candidate]:
    if yaml is None:
        raise RuntimeError("PyYAML is required for workflow analysis (pip install pyyaml)")
    text = path.read_text(encoding="utf-8", errors="replace")
    try:
        doc = yaml.safe_load(text)
    except yaml.YAMLError:
        return []
    return analyze_document(doc, text, path=str(path))


def _workflow_dirs(root: Path) -> list[Path]:
    direct = [root / ".github" / "workflows", root / ".github" / "actions"]
    dirs = [d for d in direct if d.is_dir()]
    if not dirs:
        dirs = [p for g in root.rglob(".github") if g.is_dir()
                for p in (g / "workflows", g / "actions") if p.is_dir()]
    return dirs


def analyze_tree(root: Path) -> list[Candidate]:
    """Analyze one repository or a corpus of repositories under `root`."""
    if yaml is None:
        raise RuntimeError("PyYAML is required for workflow analysis (pip install pyyaml)")
    out: list[Candidate] = []
    seen: set[Path] = set()
    for d in _workflow_dirs(root):
        for p in sorted(d.rglob("*")):
            if p.is_file() and p.suffix in (".yml", ".yaml") and p not in seen:
                seen.add(p)
                out.extend(analyze_file(p))
    return out


def render(cands: list[Candidate]) -> str:
    if not cands:
        return "no reachable GitHub Actions attack chains found"
    lines = []
    for c in sorted(cands, key=lambda c: (c.rule_id, c.file, c.job)):
        lines.append(f"[{c.severity.upper()}] {c.rule_id}  {c.file} :: {c.job}")
        lines.append(f"    {c.message}")
        lines.append(f"    precondition: {c.precondition}")
        lines.append(f"    fix: {c.remediation}")
    return "\n".join(lines)


def to_json(cands: list[Candidate]) -> str:
    return json.dumps([c.to_dict() for c in cands], indent=2)
